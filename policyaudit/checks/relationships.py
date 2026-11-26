"""Capabilities 1-3: shadowing, partial overlap, duplicates and redundancy.

Built on the relationship graph (``relations.py``). Each lower policy is
reported once, for the most important relationship it has:

* ``REL-SHADOW``        exact shadowing: an earlier rule with a different
                        action matches all of its traffic.
* ``DUP-EXACT``         an earlier rule matches exactly the same traffic with
                        the same action.
* ``REL-REDUNDANT``     an earlier, broader rule with the same action already
                        matches all of its traffic.
* ``REL-REDUNDANT-DOWNSTREAM``  a later, broader rule with the same action
                        would match its traffic anyway.
* ``REL-PARTIAL``       partial overlap: some of its traffic is decided by an
                        earlier rule with a different action.
* ``DUP-NEAR``          rules identical except for one field: merge candidates.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .. import relations as rel
from ..model import HIGH, INFO, MEDIUM, Policy
from ..policies import profile_signature, profiles_of
from .common import assess_removal, move_cli, names

CAT = "Policy relationships"


def _desc(p: Policy) -> str:
    return "{} [{} -> {} | {} -> {} | {} | {}]".format(
        p.label, names(p.srcintf, 2), names(p.dstintf, 2), names(p.srcaddr, 2),
        names(p.dstaddr, 2), names(p.service, 3), p.action.upper())


def _sig_diff(a: Policy, b: Policy) -> List[str]:
    sa, sb = dict(profile_signature(a)), dict(profile_signature(b))
    return sorted(k for k in set(sa) | set(sb) if sa.get(k) != sb.get(k) and k != "action")


def _hits_note(p: Policy) -> str:
    if p.hits is None:
        return ""
    return " Hit counts: {:,}.".format(p.hits.hits)


def check(ctx) -> None:
    records = []
    for table, graph in ctx.graphs.items():
        pols = graph.policies
        reported = set()
        for b in pols:
            if not b.enabled:
                continue
            cover = rel.first_cover(graph, b.position)
            # An exact duplicate is the more useful thing to say, even if a broader
            # rule above both of them also covers it.
            for r in graph.by_lower.get(b.position, []):
                if r.kind == rel.EQUAL and pols[r.upper].action == b.action:
                    cover = r
                    break
            if cover is not None:
                a = pols[cover.upper]
                reported.add(b.position)
                records.append(_record(a, b, "exact duplicate" if cover.kind == rel.EQUAL else
                                       "covers"))
                _report_cover(ctx, table, a, b, cover.kind)
                continue
            partial = [pols[r.upper] for r in graph.by_lower.get(b.position, [])
                       if r.kind == rel.PARTIAL]
            conflicting = [a for a in partial if a.action != b.action]
            if conflicting:
                reported.add(b.position)
                for a in conflicting[:10]:
                    records.append(_record(a, b, "partial overlap"))
                _report_partial(ctx, table, conflicting, b)
            others = [a for a in partial if a.action == b.action and _sig_diff(a, b)]
            if others and b.position not in reported:
                for a in others[:10]:
                    records.append(_record(a, b, "partial overlap (same action)"))
                ctx.add("REL-PARTIAL-PROFILE", INFO, CAT,
                        "Policy {} partially overlaps earlier {} with the same action but "
                        "different profiles/logging".format(b.label, names([a.label for a in others], 3)),
                        policies=[b.policyid] + [a.policyid for a in others],
                        detail="The shared traffic is handled by the earlier rule, so it gets "
                               "that rule's settings ({}), not this one's.".format(
                                   ", ".join(_sig_diff(others[0], b))),
                        recommendation="Confirm the shared traffic should get the earlier rule's "
                                       "security profiles and logging.")
        # downstream redundancy: needs no earlier cover
        for a in pols:
            if not a.enabled or a.position in reported:
                continue
            down = rel.downstream_cover(graph, a.position)
            if down is None:
                continue
            c = pols[down.lower]
            if down.kind == rel.EQUAL:
                continue  # already reported as DUP-EXACT on the lower one
            records.append(_record(a, c, "redundant (covered below)"))
            validation, notes = assess_removal(ctx, a)
            diff = _sig_diff(a, c)
            ctx.add("REL-REDUNDANT-DOWNSTREAM", INFO, CAT,
                    "Policy {} is redundant: later policy {} matches all of its traffic with "
                    "the same action, and no rule in between treats it differently".format(
                        a.label, c.label),
                    policies=[a.policyid, c.policyid],
                    detail=_desc(a) + " is inside " + _desc(c) + "." +
                    (" Their settings differ ({}): removing {} would apply {}'s settings "
                     "instead.".format(", ".join(diff), a.label, c.label) if diff else ""),
                    recommendation="Removal candidate, only after validation. " + " ".join(notes),
                    validation=validation,
                    evidence={"covered_by": c.policyid, "settings_differ": diff})
        # near-duplicates: same everything except one of source, destination, service
        _near_duplicates(ctx, table, pols)
    ctx.extras["relationships"] = records[:2000]


def _record(a: Policy, b: Policy, kind: str) -> Dict[str, str]:
    return {"earlier": a.policyid, "later": b.policyid, "relationship": kind,
            "earlier_action": a.action, "later_action": b.action}


def _report_cover(ctx, table: str, a: Policy, b: Policy, kind: str) -> None:
    pids = [b.policyid, a.policyid]
    detail = "{} is evaluated first and matches every session that {} would match.".format(
        _desc(a), _desc(b))
    if a.action != b.action:
        if b.action == "deny":
            sev, effect = HIGH, "the block in {} never applies: that traffic is ACCEPTED by {}".format(
                b.label, a.label)
        else:
            sev, effect = MEDIUM, "the access {} is meant to allow never works: {} blocks it first".format(
                b.label, a.label)
        ctx.add("REL-SHADOW", sev, CAT,
                "Exact shadowing: policy {} can never match because earlier policy {} covers "
                "all of its traffic with a different action".format(b.label, a.label),
                policies=pids, detail=detail + " Result: " + effect + "." + _hits_note(b),
                recommendation="Decide which intent is correct. If {}'s {} is intended, move it "
                               "above {}. Do not delete either rule until the intent is "
                               "confirmed.".format(b.label, b.action, a.label),
                cli=move_cli(table, b.policyid, a.policyid),
                evidence={"shadowed": b.policyid, "by": a.policyid, "relationship": "exact shadowing"})
        return
    validation, notes = assess_removal(ctx, b)
    diff = _sig_diff(a, b)
    if kind == rel.EQUAL:
        ctx.add("DUP-EXACT", MEDIUM, CAT,
                "Duplicate policy: {} matches exactly the same traffic as earlier {} "
                "(same action)".format(b.label, a.label),
                policies=pids,
                detail=detail + (" Settings that differ and never take effect: {}.".format(
                    ", ".join(diff)) if diff else " Settings are the same.") + _hits_note(b),
                recommendation="Keep one. " + " ".join(notes), validation=validation,
                evidence={"duplicate_of": a.policyid, "settings_differ": diff})
        return
    sev = MEDIUM if diff else INFO
    ctx.add("REL-REDUNDANT", sev, CAT,
            "Policy {} is unreachable: earlier policy {} already matches all of its traffic "
            "with the same action".format(b.label, a.label),
            policies=pids,
            detail=detail + (" {}'s own settings never take effect ({}), so its traffic gets "
                             "{}'s profiles and logging instead.".format(b.label, ", ".join(diff), a.label)
                             if diff else "") + _hits_note(b),
            recommendation=("If {}'s stricter settings are intended, move it above {}. "
                            "Otherwise it is a removal candidate. ".format(b.label, a.label)
                            if diff else "Removal candidate. ") + " ".join(notes),
            validation=validation, cli=move_cli(table, b.policyid, a.policyid) if diff else "",
            evidence={"covered_by": a.policyid, "settings_differ": diff})


def _report_partial(ctx, table: str, uppers: List[Policy], b: Policy) -> None:
    worst = uppers[0]
    ctx.add("REL-PARTIAL", MEDIUM, CAT,
            "Partial overlap: part of policy {}'s traffic is decided by earlier {} with a "
            "different action".format(b.label, names([a.label for a in uppers], 3)),
            policies=[b.policyid] + [a.policyid for a in uppers],
            detail="Neither rule covers the other, so this is not full shadowing. Sessions in "
                   "the shared part get {}'s action ({}) instead of {} ({}). {} vs {}.".format(
                       worst.label, worst.action, b.label, b.action, _desc(worst), _desc(b)),
            recommendation="Check which action the shared traffic should get, then narrow one of "
                           "the rules so they no longer overlap, or order them deliberately. "
                           "Neither rule is a removal candidate on this evidence.",
            evidence={"overlaps_with": [a.policyid for a in uppers], "relationship": "partial overlap"})


def _near_duplicates(ctx, table: str, pols: List[Policy]) -> None:
    active = [p for p in pols if p.enabled and not p.uncertain]
    seen_groups = set()
    for dim in ("src", "dst", "svc"):
        groups = defaultdict(list)
        for p in active:
            key = [p.action, p.src_if, p.dst_if, p.conditions, profile_signature(p)]
            for d in ("src", "dst", "svc"):
                if d != dim:
                    key.append(getattr(p, d))
            groups[tuple(key)].append(p)
        for members in groups.values():
            distinct = {getattr(p, dim) for p in members}
            if len(members) < 2 or len(distinct) < 2:
                continue
            ids = tuple(sorted(p.policyid for p in members))
            if ids in seen_groups:
                continue
            seen_groups.add(ids)
            field = {"src": "source address", "dst": "destination address", "svc": "service"}[dim]
            ctx.add("DUP-NEAR", INFO, CAT,
                    "Near-duplicate policies {} differ only in {}: they could be merged into "
                    "one rule".format(names([p.label for p in members], 5), field),
                    policies=[p.policyid for p in members],
                    detail="Same interfaces, action, conditions and security profiles. Only the "
                           "{} differs.".format(field),
                    recommendation="Consider one rule with the combined {} objects. Merging is "
                                   "optional and should be checked against change records.".format(field),
                    evidence={"differs_in": field, "profiles": profiles_of(members[0])})
