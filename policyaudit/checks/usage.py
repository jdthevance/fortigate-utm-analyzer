"""Capability 3 (unused half): unused, stale, disabled and dead policies.

Unused and stale policies need hit counts. Without them the report says
the check could not run, instead of guessing. Every removal suggestion goes
through ``assess_removal``, which checks dependencies and traffic first.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..model import INFO, MEDIUM
from .common import assess_removal, names

CAT = "Unused policies"


def check(ctx) -> None:
    pols = ctx.all_policies()
    for p in pols:
        if not p.enabled:
            validation, notes = assess_removal(ctx, p)
            ctx.add("POL-DISABLED", INFO, CAT, "Policy {} is disabled".format(p.label),
                    policies=[p.policyid],
                    recommendation="Removal candidate, after validation. " + " ".join(notes),
                    validation=validation)
            continue
        empty = [what for what, s, names_ in (("source", p.src, p.srcaddr),
                                              ("destination", p.dst, p.dstaddr),
                                              ("service", p.svc, p.service)) if not s]
        if empty:
            validation, notes = assess_removal(ctx, p)
            ctx.add("POL-NEVER-MATCHES", MEDIUM, CAT,
                    "Policy {} can never match: its {} resolves to nothing".format(p.label, " and ".join(empty)),
                    policies=[p.policyid],
                    detail="Usually an empty group, 'none', or an exclusion that removes everything.",
                    recommendation="Fix the objects if the rule is still needed; otherwise it is a "
                                   "removal candidate. " + " ".join(notes),
                    validation=validation)

    if ctx.hits is None:
        ctx.add("USAGE-NEEDS-HITS", INFO, CAT,
                "Unused-policy detection did not run: no hit counts imported",
                detail="The config shows what rules allow, not what traffic uses them.",
                recommendation="Export policy hit counts (FortiGate GUI, REST API "
                               "/api/v2/monitor/firewall/policy, or FortiManager) and re-run with "
                               "--hitcounts FILE --hit-window-days N.")
        return

    window = ctx.options.hit_window_days
    missing = []
    unused = 0
    for p in pols:
        if not p.enabled:
            continue
        rec = p.hits
        if rec is None:
            missing.append(p)
            continue
        if rec.hits == 0:
            unused += 1
            validation, notes = assess_removal(ctx, p)
            ctx.add("POL-UNUSED", MEDIUM if p.accepts else INFO, CAT,
                    "Policy {} has no hits{}".format(
                        p.label, " in {:g} days".format(window) if window else " (counter period unknown)"),
                    policies=[p.policyid],
                    detail="An unused accept rule is open access nobody needs." if p.accepts else
                           "An unused deny rule may still be a deliberate safety net.",
                    recommendation="Removal candidate. " + " ".join(notes),
                    validation=validation, evidence={"hits": 0, "window_days": window})
        elif rec.last_used:
            age = (ctx.now - rec.last_used) / 86400.0
            if age >= ctx.options.stale_days:
                ctx.add("POL-STALE", INFO, CAT,
                        "Policy {} was last used {:.0f} days ago ({})".format(
                            p.label, age, datetime.fromtimestamp(rec.last_used, timezone.utc).strftime("%Y-%m-%d")),
                        policies=[p.policyid],
                        recommendation="Confirm with the owner whether it is still needed. Not a "
                                       "removal candidate on this evidence alone.",
                        evidence={"hits": rec.hits, "days_since_last_use": round(age)})
    if missing:
        ctx.add("USAGE-NOT-IN-EXPORT", INFO, CAT,
                "{} enabled polic{} not found in the hit-count file".format(
                    len(missing), "y is" if len(missing) == 1 else "ies are"),
                policies=[p.policyid for p in missing],
                detail="Policies: {}. Check the export covers this VDOM.".format(names([p.label for p in missing], 8)))
    ctx.extras["hit_summary"] = {"policies_with_data": sum(1 for p in pols if p.hits is not None),
                                 "unused": unused, "missing_from_export": len(missing),
                                 "window_days": window}
