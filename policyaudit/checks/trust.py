"""Inappropriate trust relationships between network zones.

Flags accept policies that let a less trusted network (internet, guest,
DMZ) reach a more trusted one (internal, management). Published servers
(destination is a VIP) are left to the service-exposure check.
"""

from __future__ import annotations

from .. import netset as ns
from ..model import CRITICAL, HIGH, INFO, MEDIUM
from ..trust import RANK
from .common import addr_count, is_all_services, is_any, names, vip_only

CAT = "Trust relationships"


def _a(word: str) -> str:
    return "an" if word[0] in "aeiou" else "a"


def _broad(p) -> bool:
    return is_all_services(p.svc) or ns.port_count(p.svc) > 100 or is_any(p.dst)


def check(ctx) -> None:
    for p in ctx.active():
        if not p.accepts:
            continue
        src_lv, src_if, src_why = ctx.trust.lowest(p.srcintf)
        dst_lv, dst_if, dst_why = ctx.trust.highest(p.dstintf)
        if RANK[src_lv] >= RANK[dst_lv]:
            continue
        broad = _broad(p)
        sev = None
        if src_lv == "internet" and dst_lv in ("internal", "management"):
            if vip_only(ctx, p):
                continue
            if is_any(p.src) and (is_any(p.dst) or addr_count(p.dst) >= 256) and \
                    all(ctx.resolver.is_wan(i) for i in p.srcintf):
                continue    # reported as INET-INBOUND-OPEN by the internet check
            sev = CRITICAL if broad and is_any(p.src) else HIGH
        elif src_lv == "guest" and dst_lv in ("dmz", "remote", "internal", "management"):
            sev = HIGH if broad else MEDIUM
        elif src_lv == "dmz" and dst_lv in ("internal", "management"):
            sev = MEDIUM if broad else INFO
        elif dst_lv == "management" and broad:
            sev = MEDIUM
        if sev is None:
            continue
        what = "all services" if is_all_services(p.svc) else "services " + names(p.service, 4)
        dst_txt = "any destination" if is_any(p.dst) else "{} ({:,} addresses)".format(
            names(p.dstaddr, 3), addr_count(p.dst))
        ctx.add("TRUST-" + src_lv.upper() + "-TO-" + dst_lv.upper(), sev, CAT,
                "Inappropriate trust relationship: policy {} lets {} ({}) reach {} ({}) on {}".format(
                    p.label, src_if, src_lv, dst_if, dst_lv, what),
                policies=[p.policyid], objects=p.srcintf + p.dstintf,
                detail="Source network trust: {} ({}). Destination trust: {} ({}). Destination: {}. "
                       "{} {} network should not have this kind of access to {} {} network.".format(
                           src_lv, src_why, dst_lv, dst_why, dst_txt, _a(src_lv).capitalize(), src_lv,
                           _a(dst_lv), dst_lv),
                recommendation="Limit this policy to the specific servers and ports the business "
                               "needs, or remove the access. If the zone guess is wrong, set the "
                               "real trust level with --trust-map.",
                evidence={"source_trust": src_lv, "destination_trust": dst_lv,
                          "source_reason": src_why, "destination_reason": dst_why, "broad": broad})
