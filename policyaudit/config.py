"""FortiGate configuration parser.

Reads ``show full-configuration`` (or ``show``) output into a tree that keeps
VDOM boundaries, and splits quoted multi-value settings correctly::

    set srcaddr "Web Servers" "DB"   ->  ["Web Servers", "DB"]

Structural problems (an unclosed block, a stray ``end``, an unterminated
quote) are *errors*: a truncated backup must never be audited as if it were
complete. Lines the parser does not understand, such as a CLI prompt pasted
at the top of the file, are *warnings* and are skipped.

Go mapping: ``internal/config`` with ``type Node struct`` and
``func Parse(text string) (*Tree, error)``.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional


@dataclass
class Node:
    kind: str                      # "root", "config" or "edit"
    name: str
    line: int = 0
    settings: Dict[str, str] = field(default_factory=dict)
    children: List["Node"] = field(default_factory=list)

    def get(self, key: str, default: str = "") -> str:
        """Return one setting as a clean single string (quotes removed)."""
        raw = self.settings.get(key)
        if raw is None:
            return default
        vals = split_values(raw)
        return " ".join(vals) if vals else ""

    def get_list(self, key: str) -> List[str]:
        """Return a multi-value setting as a list of names."""
        raw = self.settings.get(key)
        return split_values(raw) if raw else []

    def has(self, key: str) -> bool:
        return key in self.settings

    def blocks(self, name: str) -> List["Node"]:
        return [c for c in self.children if c.kind == "config" and c.name == name]

    def objects(self, name: str) -> List["Node"]:
        return [o for b in self.blocks(name) for o in b.children if o.kind == "edit"]


@dataclass
class Tree:
    root: Node
    errors: List[str]              # structural: the file is incomplete or broken
    warnings: List[str]            # skipped lines that were not understood

    @property
    def complete(self) -> bool:
        return not self.errors


def split_values(raw: str) -> List[str]:
    """Split a FortiGate value into its items, honouring quotes.

    ``"a" "b c"`` -> ``["a", "b c"]``; ``accept`` -> ``["accept"]``.
    Falls back to whitespace splitting if the quotes are unbalanced.
    """
    if raw is None:
        return []
    raw = raw.strip()
    if not raw:
        return []
    if '"' not in raw and "'" not in raw and "\\" not in raw:
        return raw.split()
    try:
        return shlex.split(raw, posix=True)
    except ValueError:
        return [t.strip('"') for t in raw.split() if t.strip('"')]


def _quote_open(value: str) -> bool:
    quoted, escaped = False, False
    for ch in value:
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            quoted = not quoted
    return quoted


def parse(text: str) -> Tree:
    """Parse configuration text into a :class:`Tree`."""
    root = Node("root", "")
    stack: List[Node] = [root]
    errors: List[str] = []
    warnings: List[str] = []
    pending: List[str] = []
    pending_line = 0

    for number, raw in enumerate(text.splitlines(), 1):
        if pending:
            pending.append(raw)
            if not _quote_open(raw):
                continue
            line = "\n".join(pending).strip()
            pending = []
            number = pending_line
        else:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if _quote_open(line):
                pending, pending_line = [line], number
                continue

        parts = line.split(None, 1)
        command = parts[0]
        value = parts[1] if len(parts) > 1 else ""

        if command in ("config", "edit"):
            if not value:
                errors.append("Line {}: '{}' without a name".format(number, command))
                continue
            if command == "edit":
                if stack[-1].kind != "config":
                    errors.append("Line {}: 'edit' outside a config block".format(number))
                    continue
                names = split_values(value)
                name = names[0] if names else value
            else:
                name = " ".join(value.split())
            node = Node(command, name, number)
            stack[-1].children.append(node)
            stack.append(node)
        elif command in ("next", "end"):
            expected = "edit" if command == "next" else "config"
            if len(stack) == 1 or stack[-1].kind != expected:
                errors.append("Line {}: unmatched '{}'".format(number, command))
            else:
                stack.pop()
        elif command in ("set", "unset", "append", "select", "unselect"):
            bits = value.split(None, 1)
            key = bits[0] if bits else ""
            val = bits[1] if len(bits) > 1 else ""
            if len(stack) == 1 or not key:
                warnings.append("Line {}: setting outside any block skipped".format(number))
                continue
            target = stack[-1].settings
            if command == "unset":
                target.pop(key, None)
            elif command in ("append", "select"):
                target[key] = (target.get(key, "") + " " + val).strip()
            elif command == "unselect":
                drop = set(split_values(val))
                kept = [v for v in split_values(target.get(key, "")) if v not in drop]
                target[key] = " ".join('"{}"'.format(v) for v in kept)
            else:
                target[key] = val
        else:
            warnings.append("Line {}: unrecognised statement skipped: {}".format(
                number, line[:60]))

    if pending:
        errors.append("Line {}: quoted value never closed".format(pending_line))
    if len(stack) != 1:
        open_names = ", ".join("'{} {}'".format(n.kind, n.name) for n in stack[1:4])
        errors.append("Incomplete configuration: {} block(s) never closed ({}{})".format(
            len(stack) - 1, open_names, ", ..." if len(stack) > 4 else ""))
    return Tree(root, errors, warnings)


# ─────────────────────────────────────────────────────────────────────────────
# VDOM scopes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Scope:
    """One policy table's world: a VDOM (or the whole box without VDOMs).

    ``local`` holds the VDOM's own blocks; ``shared`` holds ``config global``,
    where interfaces live on multi-VDOM units.
    """
    name: str
    local: Node
    shared: Optional[Node] = None

    def objects(self, block: str) -> List[Node]:
        return self.local.objects(block)

    def blocks(self, block: str) -> List[Node]:
        return self.local.blocks(block)

    def flat(self, block: str) -> Node:
        """Merge the settings of a flat block such as ``config log setting``."""
        merged = Node("config", block)
        for b in self.local.blocks(block):
            merged.settings.update(b.settings)
            merged.children.extend(b.children)
        return merged

    def interfaces(self) -> List[Node]:
        """Interfaces that belong to this VDOM (from global on multi-VDOM units)."""
        own = self.local.objects("system interface")
        if self.shared is None:
            return own
        result = list(own)
        for intf in self.shared.objects("system interface"):
            vdom = intf.get("vdom")
            if not vdom or vdom == self.name:
                result.append(intf)
        return result


def scopes(tree: Tree) -> List[Scope]:
    """Split the tree into one :class:`Scope` per VDOM.

    A backup without VDOMs is a single scope called ``root``. Repeated
    ``edit <vdom>`` blocks for the same VDOM are combined; different VDOMs are
    never merged.
    """
    root = tree.root
    global_blocks = root.blocks("global")
    shared = None
    if global_blocks:
        shared = Node("config", "global")
        for g in global_blocks:
            shared.children.extend(g.children)

    vdom_nodes: Dict[str, Node] = {}
    order: List[str] = []
    for edit in root.objects("vdom"):
        if edit.name not in vdom_nodes:
            vdom_nodes[edit.name] = Node("edit", edit.name, edit.line)
            order.append(edit.name)
        vdom_nodes[edit.name].children.extend(edit.children)

    other = [c for c in root.children if c.name not in ("global", "vdom")]
    has_policies = [n for n in order if vdom_nodes[n].children]
    if not has_policies:
        local = Node("root", "")
        local.children = other + (shared.children if shared else [])
        return [Scope("root", local, None)]

    result = [Scope(n, vdom_nodes[n], shared) for n in order if vdom_nodes[n].children]
    if other:
        local = Node("root", "")
        local.children = other
        result.insert(0, Scope("unscoped", local, shared))
    return result


def read_text(path: str) -> str:
    """Read a config file. Undecodable bytes are replaced, never dropped silently."""
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def iter_settings(nodes: Iterable[Node], key: str) -> Iterable[str]:
    for n in nodes:
        for v in n.get_list(key):
            yield v
