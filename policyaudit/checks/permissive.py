"""Capability 4: overly permissive source and destination objects.

Uses resolved addresses, so it sees what names hide: an object called
``Internal_Hosts`` that is really ``0.0.0.0/0``, or a ``/8`` group behind a
friendly name. Literal ``all`` is reported as INFO here because ``utm.py -f``
already scores it.
"""

from __future__ import annotations

from collections import defaultdict

from .. import netset as ns
from ..model import HIGH, INFO, MEDIUM
from .common import (addr_count, from_internet, is_all_services, is_any, names,
                     to_internet)

CAT = "Permissive objects"
BROAD_HIGH = 1 << 24       # a /8 or more
BROAD_MED = 1 << 16        # a /16 or more


def check(ctx) -> None:
    hidden_any = defaultdict(list)
    for p in ctx.active():
        if not p.accepts:
            continue
        for side, names_, family in (("source", p.srcaddr, "src"), ("destination", p.dstaddr, "dst")):
            for n in names_:
                if n.lower() == "all":
                    continue
                v4 = ctx.resolver.address(n, "v4")
                if is_any(v4):
                    hidden_any[n].append(p)
        _breadth(ctx, p)
        _unrestricted(ctx, p)

    for obj, pols in hidden_any.items():
        ctx.add("PERM-HIDDEN-ANY", HIGH, CAT,
                "Object '{}' looks specific but resolves to every IP address (same as 'all')".format(obj),
                policies=[p.policyid for p in pols], objects=[obj],
                detail="Used by {} accept polic{}: {}. Reviewers reading the rule see a named "
                       "object and may not notice it allows everything.".format(
                           len(pols), "y" if len(pols) == 1 else "ies", names([p.label for p in pols], 5)),
                recommendation="Redefine '{}' to the subnets it is meant to represent, or rename it "
                               "so the breadth is obvious.".format(obj))


def _breadth(ctx, p) -> None:
    checks = []
    if not from_internet(ctx, p):          # internet sources are expected to be broad
        checks.append(("source", p.src, p.srcaddr))
    if not to_internet(ctx, p):            # internet destinations are the internet check's job
        checks.append(("destination", p.dst, p.dstaddr))
    for side, s, objs in checks:
        count = addr_count(s)
        if is_any(s):
            literal = all(n.lower() == "all" for n in objs)
            if literal:
                ctx.add("PERM-ANY-" + ("SRC" if side == "source" else "DST"), INFO, CAT,
                        "Policy {} uses 'all' as {}".format(p.label, side),
                        policies=[p.policyid], objects=objs,
                        detail="Also scored by the legacy firewall policy audit (-f).",
                        recommendation="Restrict the {} to the networks that need this rule.".format(side))
            continue
        if count >= BROAD_HIGH:
            sev = MEDIUM if side == "source" else HIGH
        elif count >= BROAD_MED and side == "destination":
            sev = MEDIUM
        else:
            continue        # a /16 of clients as a source is normal
        ctx.add("PERM-BROAD-" + ("SRC" if side == "source" else "DST"), sev, CAT,
                "Policy {} has a very broad {}: {:,} IPv4 addresses (about a /{})".format(
                    p.label, side, count, ns.prefix_equivalent(count)),
                policies=[p.policyid], objects=objs,
                detail="{} objects {} resolve to {}.".format(side.capitalize(), names(objs, 4),
                                                               ns.describe_v4(s)),
                recommendation="Narrow the {} to the hosts or subnets that actually need this "
                               "access.".format(side),
                evidence={"addresses": count, "prefix_equivalent": ns.prefix_equivalent(count)})


def _unrestricted(ctx, p) -> None:
    """Any destination on any service, not to the internet: lateral free-for-all."""
    if to_internet(ctx, p) or from_internet(ctx, p):
        return
    if not (is_any(p.dst) and is_all_services(p.svc)):
        return
    hits = ""
    if p.hits is not None:
        hits = " It has {:,} hits, so it is in use: hit counts show that, not which " \
               "destinations are used.".format(p.hits.hits)
    ctx.add("PERM-UNRESTRICTED", HIGH, CAT,
            "Policy {} permits access to every destination on every service, beyond any "
            "single business requirement".format(p.label),
            policies=[p.policyid], objects=p.srcaddr,
            detail="From {} ({}) to any address on {} with all protocols.{}".format(
                names(p.srcaddr, 3), names(p.srcintf, 2), names(p.dstintf, 2), hits),
            recommendation="Use traffic logs (FortiAnalyzer or FortiView) to list the destinations "
                           "and ports actually used, then replace this rule with specific ones. "
                           "Keep it until replacements are in place.")
