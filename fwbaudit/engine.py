"""Run the FortiWeb audit, and optionally the FortiGate cross-check.

Go mapping: ``internal/fortiweb/engine`` with ``func Run(text, opts) *Result``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from policyaudit import config as cfgmod
from policyaudit.model import SEVERITY_ORDER, Finding

from .checks import DOMAINS
from .checks.common import Context, Options
from .inventory import Inventory, ip_text


@dataclass
class Result:
    findings: List[Finding]
    devices: List[Dict[str, Any]]
    errors: List[str]
    warnings: List[str]
    elapsed: float
    domains: List[str]
    inventories: List[Inventory] = field(default_factory=list)
    contexts: List[Context] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.errors


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.category, f.rule_id, f.title))


def parse(text: str):
    tree = cfgmod.parse(text)
    return tree, cfgmod.scopes(tree)


def run(text: str, options: Optional[Options] = None) -> Result:
    options = options or Options()
    started = time.time()
    tree, scopes = parse(text)
    selected = options.domains or list(DOMAINS)
    findings: List[Finding] = []
    devices, inventories, contexts = [], [], []
    for scope in scopes:
        inv = Inventory(scope)
        ctx = Context(inv, options)
        for dom in selected:
            for check in DOMAINS[dom][1]:
                check(ctx)
        ctx.flush()
        findings.extend(ctx.findings)
        inventories.append(inv)
        contexts.append(ctx)
        devices.append(summary(inv, ctx))
    warnings = list(tree.warnings[:50])
    for inv in inventories:
        if inv.unresolved:
            warnings.append("[{}] names not found in the backup: {}".format(
                inv.name, ", ".join(sorted(set(inv.unresolved))[:10])))
    return Result(sort_findings(findings), devices, list(tree.errors), warnings,
                  round(time.time() - started, 3), selected, inventories, contexts)


def summary(inv: Inventory, ctx: Context) -> Dict[str, Any]:
    """Inventory snapshot for the reports: what the FortiWeb publishes, and how."""
    apps = []
    for p in inv.policies:
        apps.append({
            "policy": p.name, "enabled": p.enabled, "mode": p.mode,
            "virtual_ips": ["{} ({})".format(ip_text(v.host), v.interface) for v in inv.vips_of(p)],
            "ports": {"http": p.http_ports, "https": p.https_ports},
            "profile": p.profile or None,
            "monitor_mode": p.get("monitor-mode") == "enable",
            "pool": p.pool or None,
            "servers": ["{}:{}{}".format(ip_text(s.host) if s.host is not None else s.domain, s.port,
                                         " ssl" if s.ssl else "") for s in inv.backends_of(p)],
        })
    return {
        "name": inv.name,
        "opmode": inv.opmode,
        "interfaces": {i.name: {"addresses": [ip_text(h) for h in i.hosts],
                                "admin_access": sorted(i.admin_services)} for i in inv.interfaces.values()},
        "applications": apps,
        "gateways": [ip_text(g) for g in inv.gateways()],
        "coverage": ctx.extras.get("coverage", {}),
        "other_features": ctx.extras.get("other_features", {}),
        "certificates": ctx.extras.get("certificates", []),
        "log_destinations": ctx.extras.get("log_destinations", {}),
        "ha_mode": ctx.extras.get("ha_mode"),
    }
