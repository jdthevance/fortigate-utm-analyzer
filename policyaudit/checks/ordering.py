"""Capability 9: policy ordering suggestions. Suggestions only: never applied.

Two kinds:

* Security order (config only): a rule that can never match because a
  broader rule above it decides its traffic (see REL-SHADOW / REL-REDUNDANT).
  The fix is often to move the specific rule up.
* Busy rules first (needs hit counts): a heavily used rule far down the list
  can move up past rules it cannot overlap with. Moving across a rule that
  might share traffic would change behaviour, so any possible overlap stops
  the move. FortiGate's policy lookup is optimised and offloaded on most
  models, so the speed gain is usually small; treat this as tidy-up.
"""

from __future__ import annotations

from ..model import INFO
from ..relations import may_overlap
from .common import move_cli

CAT = "Policy ordering"
MIN_DISTANCE = 5


def check(ctx) -> None:
    suggestions = []
    for f in ctx.findings:
        if f.rule_id in ("REL-SHADOW", "REL-REDUNDANT") and f.cli:
            suggestions.append({"type": "security", "policy": f.policies[0], "move_before": f.policies[1],
                                "reason": f.title})
    if ctx.hits is not None:
        for table, pols in ctx.tables.items():
            suggestions.extend(_busy_first(ctx, table, pols))
    ctx.extras["ordering"] = suggestions


def _busy_first(ctx, table, pols):
    active = [p for p in pols if p.enabled]
    total = sum(p.hits.hits for p in active if p.hits) or 0
    if total == 0:
        return []
    out = []
    busiest = sorted((p for p in active if p.hits and p.hits.hits > 0),
                     key=lambda p: -p.hits.hits)[:ctx.options.top]
    for p in busiest:
        share = p.hits.hits / total
        idx = active.index(p)
        if idx < MIN_DISTANCE or share < 0.02:
            continue
        target = idx
        while target > 0 and not may_overlap(active[target - 1], p):
            target -= 1
        skipped = active[target:idx]
        if len(skipped) < MIN_DISTANCE:
            continue
        skipped_hits = sum(q.hits.hits for q in skipped if q.hits)
        if skipped_hits >= p.hits.hits:
            continue
        before = active[target]
        title = ("Busy policy {} ({:.0%} of hits) sits at position {}; it can move up {} places, "
                 "above {}, without changing what it matches".format(
                     p.label, share, idx + 1, len(skipped), before.label))
        ctx.add("ORDER-BUSY-FIRST", INFO, CAT, title, policies=[p.policyid, before.policyid],
                detail="None of the {} rules it would pass can share traffic with it, so the move "
                       "is behaviour-neutral. They have {:,} hits between them, against {:,}.".format(
                           len(skipped), skipped_hits, p.hits.hits),
                recommendation="Optional. Review and apply during a change window if you want "
                               "busy rules evaluated first.",
                cli=move_cli(table, p.policyid, before.policyid),
                evidence={"from_position": idx + 1, "to_position": target + 1, "hit_share": round(share, 4)})
        out.append({"type": "busy-first", "policy": p.policyid, "move_before": before.policyid,
                    "reason": title})
    return out
