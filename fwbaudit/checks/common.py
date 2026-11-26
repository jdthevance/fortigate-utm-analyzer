"""Shared check context and helpers.

Go mapping: ``internal/fortiweb/checks`` (``type Context struct``).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from policyaudit.config import Node
from policyaudit.model import Finding

from ..inventory import Inventory


@dataclass
class Options:
    domains: Optional[List[str]] = None     # None = every domain
    now: Optional[float] = None             # unix time, for tests
    cert_warn_days: int = 30
    signature_disable_warn: int = 20        # disabled signatures before it is worth a finding


@dataclass
class Context:
    inv: Inventory
    options: Options
    findings: List[Finding] = field(default_factory=list)
    extras: Dict[str, Any] = field(default_factory=dict)
    _groups: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    @property
    def now(self) -> float:
        return self.options.now if self.options.now is not None else time.time()

    def add(self, rule_id: str, severity: str, category: str, title: str, **kw) -> Finding:
        f = Finding(rule_id=rule_id, severity=severity, title=title, vdom=self.inv.name,
                    category=category, **kw)
        self.findings.append(f)
        return f

    def collect(self, rule_id: str, severity: str, category: str, title: str, item: str, **kw) -> None:
        """Gather a setting that is wrong on many objects into one finding.

        ``title`` may use ``{items}`` and ``{count}``; it is filled in by :meth:`flush`.
        """
        entry = self._groups.setdefault(rule_id, {"severity": severity, "category": category,
                                                  "title": title, "items": [], "kw": kw})
        if item not in entry["items"]:
            entry["items"].append(item)

    def flush(self) -> None:
        for rule_id, g in self._groups.items():
            kw = dict(g["kw"])
            kw.setdefault("objects", list(g["items"]))
            if g["kw"].get("policies") is not None:
                kw["policies"] = list(g["items"])
            if "{item}" in kw.get("cli", ""):
                kw["cli"] = kw["cli"].replace("{item}", g["items"][0])
            self.add(rule_id, g["severity"], g["category"],
                     g["title"].format(items=names(g["items"]), count=len(g["items"])), **kw)
        self._groups.clear()


def on(node: Node, key: str, default: str = "disable") -> bool:
    return (node.get(key, default) or default) == "enable"


def names(items, limit: int = 5) -> str:
    items = list(items)
    if not items:
        return "(none)"
    shown = ", ".join(items[:limit])
    return shown + (" +{} more".format(len(items) - limit) if len(items) > limit else "")
