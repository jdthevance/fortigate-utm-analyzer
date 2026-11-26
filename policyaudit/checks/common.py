"""Helpers shared by the checks."""

from __future__ import annotations

import math
from typing import List, Tuple

from .. import netset as ns
from ..model import BLOCKED, UNVALIDATED, VALIDATED, Policy
from ..netset import IntervalSet

V4_REAL = IntervalSet([(ns.V4_LO, ns.V4_HI)])
V6_REAL = IntervalSet([(ns.V6_LO, ns.V6_HI)])
SVC_ALL = IntervalSet([ns.SVC_ALL])


def is_any(s: IntervalSet) -> bool:
    """Covers every IPv4 address (or every IPv6 address for a v6-only set)."""
    return s.contains(V4_REAL) or (not s.size_within(ns.V4_LO, ns.V4_TOK_HI) and s.contains(V6_REAL))


def is_all_services(s: IntervalSet) -> bool:
    return s.contains(SVC_ALL)


def addr_count(s: IntervalSet) -> int:
    return ns.v4_count(s) or (ns.v6_count(s) and min(ns.v6_count(s), 1 << 32))


def breadth(count: int, bits: int = 32) -> float:
    """0.0 for one address, 1.0 for the whole address space."""
    if count <= 1:
        return 0.0
    return min(1.0, math.log2(count) / bits)


def names(items: List[str], limit: int = 4) -> str:
    if not items:
        return "(none)"
    shown = ", ".join(items[:limit])
    return shown + (" +{} more".format(len(items) - limit) if len(items) > limit else "")


def is_wan_list(ctx, intfs: List[str]) -> bool:
    return any(i.lower() == "any" or ctx.resolver.is_wan(i) for i in intfs or ["any"])


def all_wan(ctx, intfs: List[str]) -> bool:
    return bool(intfs) and all(ctx.resolver.is_wan(i) for i in intfs)


def from_internet(ctx, p: Policy) -> bool:
    return all_wan(ctx, p.srcintf)


def to_internet(ctx, p: Policy) -> bool:
    return all_wan(ctx, p.dstintf)


def vip_only(ctx, p: Policy) -> bool:
    return bool(p.dstaddr) and all(ctx.resolver.is_vip(n) for n in p.dstaddr)


def move_cli(table: str, policy_id: str, before_id: str) -> str:
    return ("# Review example - check the effect before applying\n"
            "config {}\n    move {} before {}\nend".format(table, policy_id, before_id))


# ── Removal safety ───────────────────────────────────────────────────────────

def dependencies(ctx, p: Policy) -> List[str]:
    """Things that could break if this policy were deleted."""
    deps: List[str] = []
    refs = ctx.extras.get("_refcounts")
    if refs is None:     # count once per VDOM: how many enabled policies use each VIP / pool
        refs = {"vip": {}, "pool": {}}
        for q in ctx.active():
            for n in set(q.dstaddr):
                refs["vip"][n] = refs["vip"].get(n, 0) + 1
            for n in set(q.setting_list("poolname")):
                refs["pool"][n] = refs["pool"].get(n, 0) + 1
        ctx.extras["_refcounts"] = refs
    mine = 1 if p.enabled else 0
    for n in p.dstaddr:
        if ctx.resolver.is_vip(n) and refs["vip"].get(n, 0) - mine <= 0:
            deps.append("only enabled policy using VIP '{}' (removing it stops that port-forward)".format(n))
    for pool in p.setting_list("poolname"):
        if refs["pool"].get(pool, 0) - mine <= 0:
            deps.append("only policy using IP pool '{}'".format(pool))
    if p.action == "ipsec" or p.setting("vpntunnel"):
        deps.append("carries IPsec VPN traffic")
    if any(i.startswith("ssl.") for i in p.srcintf + p.dstintf):
        deps.append("carries SSL-VPN traffic")
    for f in ("users", "groups", "fsso-groups"):
        if p.setting(f):
            deps.append("identity-based rule ({} {})".format(f, p.setting(f)))
            break
    if p.setting("comments") and any(w in p.setting("comments").lower()
                                     for w in ("do not", "don't", "keep", "required", "change ")):
        deps.append("comment suggests it is deliberate: \"{}\"".format(p.setting("comments")[:80]))
    return deps


def assess_removal(ctx, p: Policy) -> Tuple[str, List[str]]:
    """Decide how safe "remove this policy" is. Returns (validation, notes).

    The engine never says "remove" as a plain instruction. It says
    *validated* only when hit counts show no traffic over a long enough
    window AND no dependency was found.
    """
    notes: List[str] = []
    deps = dependencies(ctx, p)
    notes.extend("Dependency: " + d for d in deps)
    if ctx.hits is None:
        notes.append("Unvalidated: no hit counts were imported, so actual traffic use is unknown. "
                     "Re-run with --hitcounts before removing anything.")
        return UNVALIDATED, notes
    rec = p.hits
    if rec is None:
        notes.append("Unvalidated: this policy is not in the hit-count export.")
        return UNVALIDATED, notes
    if rec.hits > 0:
        notes.append("Blocked: {:,} hits recorded, so traffic does use this policy. Do not remove "
                     "it; review why the analysis and the traffic disagree.".format(rec.hits))
        return BLOCKED, notes
    window = ctx.options.hit_window_days
    if window is None:
        notes.append("Unvalidated: 0 hits, but the period the counters cover is unknown "
                     "(pass --hit-window-days).")
        return UNVALIDATED, notes
    if window < ctx.options.min_unused_days:
        notes.append("Unvalidated: 0 hits, but the counters only cover {:g} days "
                     "(at least {:g} needed).".format(window, ctx.options.min_unused_days))
        return UNVALIDATED, notes
    if deps:
        notes.append("Unvalidated: 0 hits over {:g} days, but check the dependencies above first.".format(window))
        return UNVALIDATED, notes
    notes.append("Validated: 0 hits over {:g} days and no dependency found. Disable it first, "
                 "keep a backup, and delete after a quiet period.".format(window))
    return VALIDATED, notes
