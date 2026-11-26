"""Capability 7: unrestricted internet access, outbound and inbound.

Internet-facing interfaces are found from interface roles, default routes,
SD-WAN members and PPPoE, not just names. Name guessing is used only when
nothing else is available, and the report says so.
"""

from __future__ import annotations

from .. import netset as ns
from ..model import CRITICAL, HIGH, INFO, MEDIUM
from .common import (addr_count, from_internet, is_all_services, is_any, names,
                     to_internet, vip_only)

CAT = "Internet access"


def check(ctx) -> None:
    r = ctx.resolver
    if r.wan_guessed:
        guessed = sorted(n for n, i in r.interfaces.items() if i.wan_reason)
        ctx.add("INET-WAN-GUESSED", INFO, CAT,
                "Internet-facing interfaces were guessed from their names: {}".format(names(guessed, 6)),
                objects=guessed,
                detail="No interface has the wan role and no default route or SD-WAN member was "
                       "found, so internet checks rely on names like 'wan' or 'ppp'.",
                recommendation="Set 'role wan' on internet interfaces, or use --trust-map.")
    for p in ctx.active():
        if not p.accepts:
            continue
        if to_internet(ctx, p) and is_any(p.dst):
            wide = is_all_services(p.svc) or ns.port_count(p.svc) > 1000
            if not wide:
                continue
            inspected = all(p.setting(k) for k in ("ips-sensor", "av-profile", "webfilter-profile")) \
                and p.setting("utm-status") == "enable"
            ctx.add("INET-OUTBOUND-OPEN", MEDIUM if inspected else HIGH, CAT,
                    "Unrestricted internet access: policy {} lets {} reach any internet host "
                    "on {}".format(p.label, "any source" if is_any(p.src) else names(p.srcaddr, 3),
                                   "any service" if is_all_services(p.svc) else "{:,} ports".format(
                                       ns.port_count(p.svc))),
                    policies=[p.policyid], objects=p.srcaddr,
                    detail="Source: {:,} addresses via {}. {}".format(
                        addr_count(p.src), names(p.srcintf, 2),
                        "IPS, antivirus and web filtering are applied." if inspected else
                        "Not all of IPS, antivirus and web filtering are applied, so malware "
                        "downloads, command-and-control and data exfiltration are unchecked."),
                    recommendation="Allow web (HTTP/HTTPS) and DNS through inspected rules, and "
                                   "allow other services only to the destinations that need them.",
                    evidence={"inspected": inspected})
        if from_internet(ctx, p) and is_any(p.src) and not vip_only(ctx, p):
            count = addr_count(p.dst)
            if not (is_any(p.dst) or count >= 256):
                continue
            ctx.add("INET-INBOUND-OPEN", CRITICAL if is_all_services(p.svc) else HIGH, CAT,
                    "Policy {} lets anyone on the internet reach {} on {}".format(
                        p.label, "any address behind " + names(p.dstintf, 2) if is_any(p.dst)
                        else "{:,} addresses behind {}".format(count, names(p.dstintf, 2)),
                        "any service" if is_all_services(p.svc) else names(p.service, 4)),
                    policies=[p.policyid], objects=p.dstaddr,
                    detail="Inbound from {} with source 'any' and no VIP (port-forward) in the "
                           "destination.".format(names(p.srcintf, 2)),
                    recommendation="Publish only specific servers through VIPs, restrict the source "
                                   "where possible, and remove broad inbound rules.")
