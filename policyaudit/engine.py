"""Run every policy-analysis check on every VDOM.

Go mapping: ``internal/engine`` with ``func Run(tree, opts) *Result``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import config as cfgmod
from . import policies as polmod
from . import relations
from .hits import HitData
from .model import SEVERITY_ORDER, Finding, Policy
from .objects import Resolver
from .trust import TrustModel


@dataclass
class Options:
    hit_window_days: Optional[float] = None    # how many days the hit counters cover
    min_unused_days: float = 30.0              # window needed before removal is "validated"
    stale_days: float = 90.0                   # last hit older than this = stale
    trust_map: Dict[str, str] = field(default_factory=dict)
    top: int = 25                              # rows in ranked tables
    now: Optional[float] = None                # for tests; default: current time


@dataclass
class Context:
    """Everything a check needs for one VDOM."""
    scope: cfgmod.Scope
    resolver: Resolver
    trust: TrustModel
    tables: Dict[str, List[Policy]]
    graphs: Dict[str, relations.Graph]
    hits: Optional[HitData]
    options: Options
    single_vdom: bool
    findings: List[Finding] = field(default_factory=list)
    extras: Dict[str, Any] = field(default_factory=dict)

    @property
    def vdom(self) -> str:
        return self.scope.name

    @property
    def now(self) -> float:
        return self.options.now if self.options.now is not None else time.time()

    def add(self, rule_id: str, severity: str, category: str, title: str, **kw) -> Finding:
        f = Finding(rule_id=rule_id, severity=severity, title=title, vdom=self.vdom,
                    category=category, **kw)
        self.findings.append(f)
        return f

    def all_policies(self) -> List[Policy]:
        return [p for t in self.tables.values() for p in t]

    def active(self) -> List[Policy]:
        return [p for p in self.all_policies() if p.enabled]


@dataclass
class Result:
    findings: List[Finding]
    vdoms: List[Dict[str, Any]]
    errors: List[str]
    warnings: List[str]
    hit_source: Optional[str]
    hit_window_days: Optional[float]
    elapsed: float

    @property
    def complete(self) -> bool:
        return not self.errors


def run(text: str, options: Optional[Options] = None, hits: Optional[HitData] = None) -> Result:
    from .checks import ALL_CHECKS

    options = options or Options()
    if hits is not None and options.hit_window_days is None:
        options.hit_window_days = hits.window_days
    started = time.time()
    tree = cfgmod.parse(text)
    scopes = cfgmod.scopes(tree)
    findings: List[Finding] = []
    vdom_info: List[Dict[str, Any]] = []
    warnings = list(tree.warnings[:50])
    if len(tree.warnings) > 50:
        warnings.append("... {} more skipped lines".format(len(tree.warnings) - 50))
    if hits is not None:
        warnings.extend(hits.warnings)

    single = len(scopes) == 1
    for scope in scopes:
        resolver = Resolver(scope)
        tables = {t: polmod.build(scope, resolver, t) for t in polmod.POLICY_TABLES}
        tables = {t: ps for t, ps in tables.items() if ps}
        if not tables:
            continue
        if hits is not None:
            for ps in tables.values():
                for p in ps:
                    p.hits = hits.lookup(scope.name, p.policyid, single)
        graphs = {t: relations.analyse(ps) for t, ps in tables.items()}
        ctx = Context(scope, resolver, TrustModel(resolver, options.trust_map), tables,
                      graphs, hits, options, single)
        for check in ALL_CHECKS:
            check(ctx)
        for t, g in graphs.items():
            if g.truncated:
                ctx.add("ENGINE-TRUNCATED", "INFO", "Engine",
                        "Relationship analysis stopped early on {} ({} policies): too many "
                        "overlapping rules to compare in a reasonable time".format(t, len(tables[t])))
        findings.extend(ctx.findings)
        vdom_info.append({
            "vdom": scope.name,
            "policies": {t: len(ps) for t, ps in tables.items()},
            "enabled": sum(1 for p in ctx.all_policies() if p.enabled),
            "relations": {t: _relation_counts(g) for t, g in graphs.items()},
            "relationships": ctx.extras.get("relationships", []),
            "unresolved_names": sorted(resolver.unresolved)[:200],
            "internet_interfaces": sorted(n for n, i in resolver.interfaces.items() if i.wan_reason),
            "internet_guessed_from_names": resolver.wan_guessed,
            "trust_levels": {n: ctx.trust.level(n)[0] for n in sorted(resolver.interfaces)},
            "exposure_ranking": ctx.extras.get("exposure", []),
            "ordering_suggestions": ctx.extras.get("ordering", []),
            "coverage": ctx.extras.get("coverage", {}),
            "hit_counts": ctx.extras.get("hit_summary", {}),
        })

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.vdom, f.category, f.rule_id))
    return Result(findings, vdom_info, list(tree.errors), warnings,
                  hits.source if hits else None, options.hit_window_days,
                  round(time.time() - started, 3))


def _relation_counts(g: relations.Graph) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in g.relations:
        out[r.kind] = out.get(r.kind, 0) + 1
    out["pairs_compared"] = g.pairs_checked
    return out
