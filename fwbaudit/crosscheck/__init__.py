"""FortiGate + FortiWeb cross-device checks.

    crosscheck/fortigate.py -> internal/crosscheck/fortigate  (FortiGate facts, on top of policyaudit)
    crosscheck/link.py      -> internal/crosscheck/link       (which FortiGate rule reaches what)
    crosscheck/checks.py    -> internal/crosscheck/checks     (XC-* rules)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from policyaudit import config as cfgmod
from policyaudit.model import Finding

from ..engine import sort_findings
from ..inventory import Inventory
from . import checks, fortigate, link


@dataclass
class CrossResult:
    findings: List[Finding]
    pairs: List[Dict[str, Any]]
    errors: List[str]
    warnings: List[str]
    elapsed: float
    topologies: List[link.Topology] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.errors


def run(fortigate_text: str, inventories: List[Inventory], vdom: Optional[str] = None,
        trust_map: Optional[Dict[str, str]] = None) -> CrossResult:
    started = time.time()
    tree = cfgmod.parse(fortigate_text)
    scopes = cfgmod.scopes(tree)
    if vdom:
        scopes = [s for s in scopes if s.name == vdom]
    warnings = []
    if not scopes:
        warnings.append("FortiGate VDOM '{}' not found".format(vdom))
    findings, pairs, topologies = [], [], []
    for scope in scopes:
        view = fortigate.build(scope, trust_map)
        if not view.policies and not view.vips:
            continue
        for inv in inventories:
            topo = link.build(inv, view)
            topologies.append(topo)
            findings.extend(checks.run_all(inv, view, topo))
            pairs.append({"fortigate_vdom": scope.name, "fortiweb": inv.name,
                          "paths": checks.path_table(topo),
                          "fortigate_log_servers": view.log_servers()})
    return CrossResult(sort_findings(findings), pairs, list(tree.errors), warnings,
                       round(time.time() - started, 3), topologies)
