"""Capability 6: policies without UTM inspection (ported from utm.py, made smarter).

The legacy check lists every missing profile on every accept rule. This
one only asks for profiles that fit the traffic: no email filter nagging on
a rule that carries no mail ports, no web filter on a rule with no web
ports, WAF only for published web servers.
"""

from __future__ import annotations

from .. import netset as ns
from ..model import HIGH, INFO, MEDIUM
from ..netset import IntervalSet
from ..policies import profiles_of
from .common import from_internet, is_all_services, names, to_internet, vip_only
from .services import effective_service

CAT = "UTM inspection"

WEB = [("TCP", 80), ("TCP", 443), ("TCP", 8080), ("TCP", 8443)]
TLS = [("TCP", 443), ("TCP", 8443), ("TCP", 993), ("TCP", 995), ("TCP", 465), ("TCP", 636)]
MAIL = [("TCP", 25), ("TCP", 465), ("TCP", 587), ("TCP", 110), ("TCP", 995), ("TCP", 143), ("TCP", 993)]
FILES = WEB + MAIL + [("TCP", 21), ("TCP", 445), ("TCP", 139)]
DNS = [("UDP", 53), ("TCP", 53)]


def _any_port(svc: IntervalSet, ports) -> bool:
    for proto, port in ports:
        base = ns.TCP_BASE if proto == "TCP" else ns.UDP_BASE
        if svc.overlaps(IntervalSet([(base + port, base + port)])):
            return True
    return False


def relevant_profiles(ctx, p, svc: IntervalSet):
    """Which security profiles make sense for this rule's traffic."""
    everything = is_all_services(svc)
    outbound = to_internet(ctx, p)
    want = {"ips-sensor": "IPS"}
    if everything or _any_port(svc, FILES):
        want["av-profile"] = "antivirus"
    if (everything or _any_port(svc, WEB)) and outbound:
        want["webfilter-profile"] = "web filter"
    if (everything or _any_port(svc, DNS)) and outbound:
        want["dnsfilter-profile"] = "DNS filter"
    if everything or ns.port_count(svc) > 100:
        want["application-list"] = "application control"
    if _any_port(svc, MAIL) and not everything:
        want["emailfilter-profile"] = "email filter"
    if vip_only(ctx, p) and _any_port(svc, WEB):
        want["waf-profile"] = "WAF"
    return want


def check(ctx) -> None:
    stats = {"accept": 0, "utm_enabled": 0, "with_ips": 0, "with_av": 0, "deep_ssl": 0}
    for p in ctx.active():
        if not p.accepts:
            continue
        stats["accept"] += 1
        svc = effective_service(ctx, p)
        utm_on = p.setting("utm-status") == "enable"
        present = profiles_of(p)
        exposed = from_internet(ctx, p) or to_internet(ctx, p) or \
            ctx.trust.lowest(p.srcintf)[0] in ("internet", "guest")
        if utm_on:
            stats["utm_enabled"] += 1
        if utm_on and p.setting("ips-sensor"):
            stats["with_ips"] += 1
        if utm_on and p.setting("av-profile"):
            stats["with_av"] += 1
        ssl = p.setting("ssl-ssh-profile")
        if utm_on and ssl and ssl != "certificate-inspection" and "cert" not in ssl.lower():
            stats["deep_ssl"] += 1

        if not utm_on:
            ignored = [k for k in present if k not in ("ssl-ssh-profile",)]
            ctx.add("INSPECT-NONE", HIGH if exposed else MEDIUM, CAT,
                    "Policy {} accepts traffic with no security inspection{}".format(
                        p.label, " (profiles are set but ignored because utm-status is not enable)"
                        if ignored else ""),
                    policies=[p.policyid],
                    detail="{} -> {} on {}. Without utm-status enable, IPS, antivirus and other "
                           "profiles do not run.".format(names(p.srcintf, 2), names(p.dstintf, 2),
                                                         names(p.service, 3)),
                    recommendation="Enable UTM and apply at least an IPS sensor and antivirus.",
                    evidence={"profiles_set_but_ignored": ignored})
            continue
        want = relevant_profiles(ctx, p, svc)
        missing = [label for key, label in want.items() if not p.setting(key)]
        skipped = [lbl for key, lbl in (("emailfilter-profile", "email filter"),
                                        ("webfilter-profile", "web filter"),
                                        ("waf-profile", "WAF")) if key not in want]
        if missing:
            sev = MEDIUM if exposed and ("IPS" in missing or "antivirus" in missing) else INFO
            ctx.add("INSPECT-MISSING", sev, CAT,
                    "Policy {} is missing security profiles that fit its traffic: {}".format(
                        p.label, ", ".join(missing)),
                    policies=[p.policyid],
                    detail="Chosen from the services it allows ({}). Not asked for, because they "
                           "do not fit this traffic: {}.".format(ns.describe_service(svc), ", ".join(skipped) or "none"),
                    recommendation="Add the missing profiles to the policy.",
                    evidence={"missing": missing, "present": present})
        if _any_port(svc, TLS) or is_all_services(svc):
            if not ssl or ssl == "certificate-inspection" or "cert" in ssl.lower():
                ctx.add("INSPECT-TLS-SHALLOW", INFO if not exposed else MEDIUM, CAT,
                        "Policy {} carries encrypted traffic with {}".format(
                            p.label, "certificate inspection only" if ssl else "no SSL/SSH inspection profile"),
                        policies=[p.policyid],
                        detail="IPS and antivirus cannot see inside TLS without deep inspection.",
                        recommendation="Use a deep-inspection profile where policy and privacy rules allow.")
    ctx.extras["coverage"] = stats
