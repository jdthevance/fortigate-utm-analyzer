"""Capability 10: risk based on actual source and destination exposure.

Gives every enabled accept policy a 0-100 exposure score from five factors.
The formula is deliberately simple so a reviewer can check it by hand:

    score = 100 x source x destination x service x mitigation x activity

* source (0-1): how untrusted the source network is (internet 1.0, guest
  0.9, DMZ 0.6, VPN 0.5, internal 0.4, management 0.3), scaled by how many
  source addresses are allowed (one host 0.7x, everything 1.0x).
* destination (0-1): how valuable the destination is (management 1.0,
  internal 0.9, DMZ 0.7, VPN 0.6, guest 0.4, internet 0.3), scaled the
  same way by the number of destination addresses. A published server
  (VIP) counts as internal.
* service (0-1): ALL is 1.0; otherwise grows with the number of open ports,
  at least 0.8 if a risky service (RDP, SMB, Telnet ...) is open.
* mitigation (0.4-1): IPS, antivirus, deep SSL inspection and application
  control each lower it; no logging raises it by 10%.
* activity: from hit counts, when imported. Never used = 0.6 (latent, a
  removal candidate rather than live exposure); used = 1.0-1.3. Without hit
  counts it is 1.0 and the score is "config only".

"Actual" destination exposure also reports how many destination addresses
sit in subnets directly connected to the destination interface.

Policies scoring 80+ are HIGH and 60+ MEDIUM findings; every score is in the
JSON ranking.
"""

from __future__ import annotations

import math

from .. import netset as ns
from ..model import HIGH, MEDIUM
from ..netset import IntervalSet
from .common import addr_count, breadth, is_all_services, vip_only
from .services import RISKY, _has, effective_service

CAT = "Exposure risk"
SRC_WEIGHT = {"internet": 1.0, "guest": 0.9, "dmz": 0.6, "remote": 0.5, "internal": 0.4, "management": 0.3}
DST_WEIGHT = {"management": 1.0, "internal": 0.9, "dmz": 0.7, "remote": 0.6, "guest": 0.4, "internet": 0.3}


def score_policy(ctx, p):
    src_lv, _, _ = ctx.trust.lowest(p.srcintf)
    dst_lv, _, _ = ctx.trust.highest(p.dstintf)
    if vip_only(ctx, p) and dst_lv == "internet":
        dst_lv = "internal"
    src_n, dst_n = addr_count(p.src), addr_count(p.dst)
    src_f = SRC_WEIGHT[src_lv] * (0.7 + 0.3 * breadth(src_n))
    dst_f = DST_WEIGHT[dst_lv] * (0.7 + 0.3 * breadth(dst_n))
    svc = effective_service(ctx, p)
    if is_all_services(svc):
        svc_f = 1.0
    else:
        ports = ns.port_count(svc)
        svc_f = min(1.0, 0.3 + 0.7 * (math.log2(ports + 1) / 16))
        if any(_has(svc, k[0], k[1]) for k in RISKY):
            svc_f = max(svc_f, 0.8)
    utm = p.setting("utm-status") == "enable"
    reduce = 0.0
    if utm and p.setting("ips-sensor"):
        reduce += 0.25
    if utm and p.setting("av-profile"):
        reduce += 0.1
    ssl = p.setting("ssl-ssh-profile")
    if utm and ssl and "cert" not in ssl.lower():
        reduce += 0.15
    if utm and p.setting("application-list"):
        reduce += 0.1
    mit = max(0.4, 1.0 - reduce)
    if (p.setting("logtraffic") or "utm") == "disable":
        mit = min(1.0, mit * 1.1)
    if p.hits is None:
        act, act_txt = 1.0, "config only (no hit counts)"
    elif p.hits.hits == 0:
        act, act_txt = 0.6, "latent: no traffic recorded"
    else:
        act = 1.0 + min(0.3, math.log10(p.hits.hits) / 20)
        act_txt = "active: {:,} hits".format(p.hits.hits)
    score = min(100.0, 100.0 * src_f * dst_f * svc_f * mit * act)
    connected = IntervalSet()
    for i in p.dstintf:
        info = ctx.resolver.interfaces.get(i)
        if info:
            connected = connected.union(IntervalSet(info.networks))
    return {
        "policy": p.policyid, "name": p.name, "score": round(score, 1),
        "source": {"trust": src_lv, "addresses": src_n, "factor": round(src_f, 3)},
        "destination": {"trust": dst_lv, "addresses": dst_n, "factor": round(dst_f, 3),
                        "in_connected_subnets": ns.v4_count(p.dst.intersect(connected))},
        "service": {"description": ns.describe_service(svc), "factor": round(svc_f, 3)},
        "mitigation": round(mit, 3), "activity": act_txt,
    }


def check(ctx) -> None:
    ranking = [score_policy(ctx, p) for p in ctx.active() if p.accepts]
    ranking.sort(key=lambda r: -r["score"])
    for r in ranking:
        if r["score"] < 60:
            break
        ctx.add("EXPOSURE-SCORE", HIGH if r["score"] >= 80 else MEDIUM, CAT,
                "Policy #{}{} has exposure score {:.0f}/100: {} ({:,} addresses) to {} ({:,} "
                "addresses) on {}".format(
                    r["policy"], " ('{}')".format(r["name"]) if r["name"] else "", r["score"],
                    r["source"]["trust"], r["source"]["addresses"], r["destination"]["trust"],
                    r["destination"]["addresses"], r["service"]["description"]),
                policies=[r["policy"]],
                detail="Mitigation factor {} (1.0 = no inspection). Activity: {}.".format(
                    r["mitigation"], r["activity"]),
                recommendation="Reduce the source, destination or services, or add inspection. "
                               "Highest scores first.",
                evidence=r)
    ctx.extras["exposure"] = ranking[:max(ctx.options.top, 50)]
