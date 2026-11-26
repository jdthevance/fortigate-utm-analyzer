"""Core data types: findings and policies.

Findings are data, not text. Every finding carries a stable ``rule_id``, a
severity, the VDOM, the policies and objects involved, and evidence. Text,
JSON and the legacy ``utm.py`` summary are different views of the same list.

Go mapping: ``internal/model`` with ``type Finding struct`` and
``type Policy struct``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .config import Node
from .netset import EMPTY, IntervalSet

CRITICAL, HIGH, MEDIUM, INFO = "CRITICAL", "HIGH", "MEDIUM", "INFO"
SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, INFO: 3}

# How sure we are that a "remove this policy" recommendation is safe.
VALIDATED = "validated"         # hit counts say unused AND no dependency found
UNVALIDATED = "unvalidated"     # no hit counts: treat as a lead, not a decision
BLOCKED = "blocked"             # hits or a dependency say: do NOT remove


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    vdom: str
    category: str
    policies: List[str] = field(default_factory=list)
    objects: List[str] = field(default_factory=list)
    detail: str = ""
    recommendation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    validation: str = ""            # only for removal advice, see constants above
    cli: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def legacy_text(self) -> str:
        """``"HIGH: ..."`` string understood by utm.py's summary and HTML."""
        where = "[{} / {}]".format(self.vdom, self.rule_id)
        return "{}: {} {}".format(self.severity, where, self.title)


@dataclass
class HitRecord:
    hits: int
    last_used: Optional[int] = None      # unix time, if the export has it
    bytes: Optional[int] = None


@dataclass
class Policy:
    """One firewall policy with its names and its resolved match sets."""
    vdom: str
    table: str                       # "firewall policy" or "firewall policy6"
    position: int                    # 0-based evaluation order in the table
    policyid: str
    name: str
    node: Node
    enabled: bool
    action: str                      # accept / deny / ipsec
    srcintf: List[str]
    dstintf: List[str]
    srcaddr: List[str]               # IPv4 and IPv6 names together
    dstaddr: List[str]
    service: List[str]
    schedule: str
    # resolved match sets
    src_if: int = 0                  # bit mask over interface indexes; -1 = any
    dst_if: int = 0
    src: IntervalSet = EMPTY
    dst: IntervalSet = EMPTY
    svc: IntervalSet = EMPTY
    # "may overlap" versions: non-IP objects (FQDN, geo) widened to their family
    src_wide: IntervalSet = EMPTY
    dst_wide: IntervalSet = EMPTY
    svc_wide: IntervalSet = EMPTY
    conditions: Tuple[Tuple[str, str], ...] = ()   # users, groups, schedule ...
    uncertain: List[str] = field(default_factory=list)
    hits: Optional[HitRecord] = None

    @property
    def label(self) -> str:
        return "#{}{}".format(self.policyid, " ('{}')".format(self.name) if self.name else "")

    @property
    def accepts(self) -> bool:
        return self.action in ("accept", "ipsec")

    def setting(self, key: str, default: str = "") -> str:
        return self.node.get(key, default)

    def setting_list(self, key: str) -> List[str]:
        return self.node.get_list(key)
