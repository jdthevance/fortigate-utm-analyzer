"""Build :class:`Policy` objects for one VDOM and resolve what they match.

Go mapping: ``internal/engine`` (``func BuildPolicies(scope, resolver)``).
"""

from __future__ import annotations

from typing import List, Tuple

from . import netset as ns
from .config import Scope
from .model import Policy
from .netset import EMPTY, IntervalSet
from .objects import Resolver

POLICY_TABLES = ("firewall policy", "firewall policy6")

PROFILE_FIELDS = (
    "av-profile", "ips-sensor", "webfilter-profile", "dnsfilter-profile",
    "application-list", "ssl-ssh-profile", "dlp-profile", "dlp-sensor",
    "casb-profile", "waf-profile", "emailfilter-profile", "file-filter-profile",
    "virtual-patch-profile", "ssh-filter-profile", "voip-profile", "icap-profile",
    "videofilter-profile", "llm-profile", "profile-group",
)

# Settings that restrict who/when a policy matches, beyond the 5-tuple.
CONDITION_FIELDS = (
    "users", "groups", "fsso-groups", "application", "app-category", "app-group",
    "url-category", "ztna-ems-tag", "ztna-geo-tag", "src-vendor-mac", "internet-service-src-name",
)


def build(scope: Scope, resolver: Resolver, table: str) -> List[Policy]:
    out: List[Policy] = []
    for position, node in enumerate(scope.objects(table)):
        pid = node.get("policyid") or node.name
        v4 = table == "firewall policy"
        srcaddr4 = node.get_list("srcaddr") if v4 else []
        dstaddr4 = node.get_list("dstaddr") if v4 else []
        srcaddr6 = node.get_list("srcaddr6") if v4 else node.get_list("srcaddr")
        dstaddr6 = node.get_list("dstaddr6") if v4 else node.get_list("dstaddr")
        services = node.get_list("service")
        p = Policy(
            vdom=scope.name, table=table, position=position, policyid=pid,
            name=node.get("name"), node=node,
            enabled=node.get("status", "enable") != "disable",
            action=node.get("action", "deny") or "deny",
            srcintf=node.get_list("srcintf"), dstintf=node.get_list("dstintf"),
            srcaddr=srcaddr4 + srcaddr6, dstaddr=dstaddr4 + dstaddr6,
            service=services, schedule=node.get("schedule", "always") or "always",
        )
        _resolve(p, resolver, srcaddr4, dstaddr4, srcaddr6, dstaddr6)
        out.append(p)
    return out


def _resolve(p: Policy, r: Resolver, s4, d4, s6, d6) -> None:
    node = p.node
    p.src_if = r.interface_mask(p.srcintf) if p.srcintf else -1
    p.dst_if = r.interface_mask(p.dstintf) if p.dstintf else -1

    src = r.addresses(s4, "v4").union(r.addresses(s6, "v6"))
    if node.get("internet-service") == "enable":
        names = node.get_list("internet-service-name") + node.get_list("internet-service-id") \
            + node.get_list("internet-service-group") + node.get_list("internet-service-custom")
        dst = EMPTY
        for n in names:
            dst = dst.union(r._token("isdb:" + n, "v4"))
        svc = r._token("isdb-service", "svc")
        p.uncertain.append("destination uses Internet Service Database entries")
    else:
        dst = r.addresses(d4, "v4").union(r.addresses(d6, "v6"))
        svc = r.services(p.service) if p.service else EMPTY
    if node.get("internet-service-src") == "enable":
        src = EMPTY
        for n in node.get_list("internet-service-src-name") + node.get_list("internet-service-src-id"):
            src = src.union(r._token("isdb-src:" + n, "v4"))
        p.uncertain.append("source uses Internet Service Database entries")

    src_wide, dst_wide = r.widen(src), r.widen(dst)
    if node.get("srcaddr-negate") == "enable" or node.get("srcaddr6-negate") == "enable":
        src, src_wide = _negate(src, p, "source")
    if node.get("dstaddr-negate") == "enable" or node.get("dstaddr6-negate") == "enable":
        dst, dst_wide = _negate(dst, p, "destination")
    svc_wide = r.widen_service(svc)
    if node.get("service-negate") == "enable":
        if svc.size_within(ns.SVC_TOK_LO, ns.SVC_TOK_HI):
            p.uncertain.append("negated service contains items that are not plain ports")
        svc = svc.complement(0, ns.SVC_TOK_LO - 1)
        svc_wide = IntervalSet([ns.SVC_ALL])

    p.src, p.dst, p.svc = src, dst, svc
    p.src_wide, p.dst_wide, p.svc_wide = src_wide, dst_wide, svc_wide

    cond: List[Tuple[str, str]] = []
    if p.schedule.lower() != "always":
        cond.append(("schedule", p.schedule))
    for f in CONDITION_FIELDS:
        vals = node.get_list(f)
        if vals:
            cond.append((f, " ".join(sorted(vals))))
    p.conditions = tuple(sorted(cond))


def _negate(s: IntervalSet, p: Policy, what: str):
    if ns.has_tokens(s):
        p.uncertain.append("negated {} contains FQDN/geo/unknown objects".format(what))
    parts = []
    if s.size_within(ns.V4_LO, ns.V4_TOK_HI) or not s:
        parts.append(s.complement(ns.V4_LO, ns.V4_HI))
    if s.size_within(ns.V6_LO, ns.V6_TOK_HI):
        parts.append(s.complement(ns.V6_LO, ns.V6_HI))
    result = EMPTY
    for part in parts:
        result = result.union(part)
    wide = result.union(ns.V4_ALL if parts else EMPTY)
    return result, wide


def profile_signature(p: Policy) -> Tuple[Tuple[str, str], ...]:
    """What happens to matched traffic: profiles, logging and NAT."""
    keys = ("action", "utm-status", "logtraffic", "nat", "poolname", "inspection-mode") + PROFILE_FIELDS
    return tuple((k, p.setting(k)) for k in keys if p.setting(k))


def profiles_of(p: Policy) -> List[str]:
    return [k for k in PROFILE_FIELDS if p.setting(k)]
