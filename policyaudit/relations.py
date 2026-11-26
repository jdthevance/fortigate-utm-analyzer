"""Policy relationship engine.

FortiGate evaluates policies top to bottom and stops at the first match.
For every pair of enabled policies (A above B) this engine works out how
they relate, using the resolved interfaces, addresses, services and extra
conditions (schedule, users, groups):

=====================  ======================================================
Relationship           Meaning
=====================  ======================================================
``covers``             A matches everything B matches. B can never be
                       reached ("exact shadowing" when the actions differ,
                       "redundant" when they are the same).
``partial``            A and B share some traffic, neither covers the other.
                       The shared part always gets A's treatment.
``generalisation``     B covers A (a specific rule above a broad one). This
                       is normal, deliberate design and is not reported.
``possible``           They *might* overlap, but only through objects with no
                       fixed IP (FQDN, geography, dynamic, unknown names).
                       Never reported as fact; used as a safety barrier.
=====================  ======================================================

A downstream check also finds rules that are redundant because a broader
rule *below* them does the same thing and nothing in between disagrees.

To stay fast on large rule bases (20,000+ policies) the engine does not
compare every pair. It sorts policies along the most selective dimension
and only compares policies whose ranges can touch, then checks the exact
interval sets. See ``tests/test_policyaudit_scale.py``.

Go mapping: ``internal/relations`` with ``func Analyse([]*Policy) *Graph``.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .model import Policy

COVERS, PARTIAL, GENERAL, POSSIBLE, EQUAL = "covers", "partial", "generalisation", "possible", "equal"

# Hard stop so a pathological rule base cannot run for hours.
MAX_CANDIDATE_PAIRS = 25_000_000


@dataclass
class Relation:
    upper: int          # index (evaluation position) of the earlier policy
    lower: int          # index of the later policy
    kind: str


@dataclass
class Graph:
    policies: List[Policy]
    relations: List[Relation] = field(default_factory=list)
    by_lower: Dict[int, List[Relation]] = field(default_factory=dict)
    by_upper: Dict[int, List[Relation]] = field(default_factory=dict)
    truncated: bool = False
    pairs_checked: int = 0

    def add(self, rel: Relation) -> None:
        self.relations.append(rel)
        self.by_lower.setdefault(rel.lower, []).append(rel)
        self.by_upper.setdefault(rel.upper, []).append(rel)


def _conditions_cover(a: Policy, b: Policy) -> bool:
    """A's extra restrictions are all present, identically, on B."""
    if not a.conditions:
        return True
    return set(a.conditions) <= set(b.conditions)


def _conditions_compatible(a: Policy, b: Policy) -> bool:
    """Both can match the same session (no key restricted to different values)."""
    da, db = dict(a.conditions), dict(b.conditions)
    return all(da[k] == db[k] for k in da.keys() & db.keys())


def _if_overlap(a: int, b: int) -> bool:
    return (a & b) != 0


def _if_covers(a: int, b: int) -> bool:
    return (b & ~a) == 0


def may_overlap(a: Policy, b: Policy) -> bool:
    """Could any session match both? (Conservative: unsure counts as yes.)"""
    return (_if_overlap(a.src_if, b.src_if) and _if_overlap(a.dst_if, b.dst_if)
            and a.src_wide.overlaps(b.src_wide) and a.dst_wide.overlaps(b.dst_wide)
            and a.svc_wide.overlaps(b.svc_wide))


def classify(a: Policy, b: Policy) -> Optional[str]:
    """Relationship of earlier policy ``a`` to later policy ``b``."""
    if not (_if_overlap(a.src_if, b.src_if) and _if_overlap(a.dst_if, b.dst_if)):
        return None
    if not (a.src_wide.overlaps(b.src_wide) and a.dst_wide.overlaps(b.dst_wide)
            and a.svc_wide.overlaps(b.svc_wide)):
        return None
    sure = not a.uncertain and not b.uncertain
    definite = (sure and a.src.overlaps(b.src) and a.dst.overlaps(b.dst)
                and a.svc.overlaps(b.svc) and _conditions_compatible(a, b))
    if not definite:
        return POSSIBLE
    a_covers = (_if_covers(a.src_if, b.src_if) and _if_covers(a.dst_if, b.dst_if)
                and a.src.contains(b.src) and a.dst.contains(b.dst)
                and a.svc.contains(b.svc) and _conditions_cover(a, b))
    b_covers = (_if_covers(b.src_if, a.src_if) and _if_covers(b.dst_if, a.dst_if)
                and b.src.contains(a.src) and b.dst.contains(a.dst)
                and b.svc.contains(a.svc) and _conditions_cover(b, a))
    if a_covers and b_covers:
        return EQUAL
    if a_covers:
        return COVERS
    if b_covers:
        return GENERAL
    return PARTIAL


def _bounds(p: Policy, dim: str) -> Tuple[int, int]:
    s = getattr(p, dim)
    b = s.bounds
    return b if b else (0, -1)


def _estimate_pairs(items: List[Tuple[int, int]]) -> int:
    """Count overlapping interval pairs in O(n log n) without listing them."""
    los = sorted(lo for lo, hi in items if lo <= hi)
    his = sorted(hi for lo, hi in items if lo <= hi)
    total = 0
    for lo, hi in items:
        if lo > hi:
            continue
        total += bisect.bisect_right(los, hi) - bisect.bisect_left(his, lo)
    return (total - len(los)) // 2


def analyse(policies: List[Policy]) -> Graph:
    """Build the relationship graph for one policy table (enabled policies only)."""
    graph = Graph(policies)
    active = [p for p in policies if p.enabled]
    if len(active) < 2:
        return graph

    # 1. Group by interface pair: policies on unrelated interfaces never interact.
    groups: Dict[Tuple[int, int], List[int]] = {}
    for i, p in enumerate(active):
        groups.setdefault((p.src_if, p.dst_if), []).append(i)
    keys = list(groups)

    # 2. Pick the most selective dimension to sort on.
    dims = ("src_wide", "dst_wide", "svc_wide")
    bounds = {d: [_bounds(p, d) for p in active] for d in dims}
    best = min(dims, key=lambda d: _estimate_pairs(bounds[d]))
    o1, o2 = [bounds[d] for d in dims if d != best]
    main = bounds[best]

    checked = 0
    for gi, ka in enumerate(keys):
        for kb in keys[gi:]:
            if not (_if_overlap(ka[0], kb[0]) and _if_overlap(ka[1], kb[1])):
                continue
            same = ka == kb
            members = groups[ka] if same else groups[ka] + groups[kb]
            side = None if same else set(groups[ka])
            order = sorted(members, key=lambda i: main[i][0])
            los = [main[i][0] for i in order]
            # 3. Sweep: only policies whose sorted ranges touch are compared.
            for pos, i in enumerate(order):
                lo_i, hi_i = main[i]
                if lo_i > hi_i:
                    continue
                a1, a2 = o1[i], o2[i]
                in_a = side is not None and i in side
                end = bisect.bisect_right(los, hi_i, lo=pos + 1)
                for k in range(pos + 1, end):
                    j = order[k]
                    if side is not None and (j in side) == in_a:
                        continue
                    b1 = o1[j]
                    if b1[0] > a1[1] or a1[0] > b1[1]:
                        continue
                    b2 = o2[j]
                    if b2[0] > a2[1] or a2[0] > b2[1]:
                        continue
                    checked += 1
                    pi, pj = active[i], active[j]
                    upper, lower = (pi, pj) if pi.position < pj.position else (pj, pi)
                    kind = classify(upper, lower)
                    if kind:
                        graph.add(Relation(upper.position, lower.position, kind))
                if checked > MAX_CANDIDATE_PAIRS:
                    graph.truncated = True
                    break
            if graph.truncated:
                break
        if graph.truncated:
            break
    graph.pairs_checked = checked
    for rels in graph.by_lower.values():
        rels.sort(key=lambda r: r.upper)
    for rels in graph.by_upper.values():
        rels.sort(key=lambda r: r.lower)
    return graph


def first_cover(graph: Graph, lower: int) -> Optional[Relation]:
    """The first policy above ``lower`` that matches all of its traffic."""
    for rel in graph.by_lower.get(lower, []):
        if rel.kind in (COVERS, EQUAL):
            return rel
    return None


def downstream_cover(graph: Graph, upper: int) -> Optional[Relation]:
    """A later policy that covers ``upper`` with the same action, with nothing
    in between that could treat the shared traffic differently."""
    from .policies import profile_signature
    pols = graph.policies
    a = pols[upper]
    sig = profile_signature(a)
    for rel in graph.by_upper.get(upper, []):
        b = pols[rel.lower]
        if rel.kind in (GENERAL, EQUAL) and b.action == a.action:
            return rel
        if b.action == a.action and profile_signature(b) == sig:
            continue        # treats the shared traffic exactly like A would
        return None         # anything else in between is a barrier
    return None
