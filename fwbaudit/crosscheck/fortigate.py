"""The FortiGate side of the cross-check, built on the policy engine.

Nothing here re-parses FortiOS: the config tree, VDOM scopes, object
resolver (addresses, groups, services, zones), policy builder and trust
levels all come from ``policyaudit``. This module only adds the few facts the
cross-check needs that the policy engine does not model: where each VIP
really sends traffic (mapped IP and port), interface host addresses, source
NAT, SSL inspection mode, and log/NTP settings.

Go mapping: ``internal/crosscheck/fortigate``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from policyaudit import netset as ns
from policyaudit import policies as polmod
from policyaudit.config import Node, Scope
from policyaudit.model import Policy
from policyaudit.netset import EMPTY, IntervalSet
from policyaudit.objects import Resolver
from policyaudit.trust import TrustModel

from ..inventory import ip_of, network_of

# FortiOS default for "set ssl-min-version" on a load-balancing VIP. The
# FortiOS CLI reference lists tls-1.1 for 7.x; treated as inferred.
FGT_VIP_SSL_MIN_DEFAULT = "tls-1.1"


def _ranges(values: List[str]) -> IntervalSet:
    out = []
    for item in values:
        try:
            if "-" in item:
                a, b = item.split("-", 1)
                out.append(ns.v4_range(a.strip(), b.strip()))
            else:
                out.append(ns.v4_network(item))
        except ValueError:
            continue
    return IntervalSet(out)


def _ports(values: List[str]) -> List[Tuple[int, int]]:
    out = []
    for item in values:
        lo, _, hi = item.partition("-")
        if lo.isdigit():
            out.append((int(lo), int(hi) if hi.isdigit() else int(lo)))
    return out


def tcp(ports: List[Tuple[int, int]]) -> IntervalSet:
    return IntervalSet((ns.TCP_BASE + lo, ns.TCP_BASE + hi) for lo, hi in ports if 0 < lo <= hi <= 65535)


@dataclass
class FgVip:
    name: str
    node: Node
    mapped: IntervalSet
    extintf: List[str]
    portforward: bool
    extports: List[Tuple[int, int]]
    mappedports: List[Tuple[int, int]]
    kind: str                     # static-nat / server-load-balance / ...
    server_type: str              # http / https / ssl / tcp ...
    ssl_mode: str                 # "" / half / full
    ssl_min: str
    adds_xff: bool                # http-ip-header enable

    @property
    def decrypts(self) -> bool:
        return self.kind == "server-load-balance" and self.server_type in ("https", "ssl")

    @property
    def reencrypts(self) -> bool:
        return self.decrypts and self.ssl_mode == "full"

    @property
    def mapped_tcp(self) -> Optional[IntervalSet]:
        """Ports the inside host receives, or None when every port is forwarded."""
        if self.kind == "server-load-balance":
            return tcp(self.mappedports or self.extports) if (self.mappedports or self.extports) else None
        if not self.portforward:
            return None
        return tcp(self.mappedports or self.extports)


@dataclass
class FgView:
    scope: Scope
    resolver: Resolver
    trust: TrustModel
    policies: List[Policy]
    vips: Dict[str, FgVip] = field(default_factory=dict)
    vipgroups: Dict[str, List[str]] = field(default_factory=dict)
    iface_addrs: Dict[str, List[Tuple[int, Tuple[int, int]]]] = field(default_factory=dict)
    iface_access: Dict[str, List[str]] = field(default_factory=dict)
    ippools: Dict[str, IntervalSet] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.scope.name

    # ── lookups ─────────────────────────────────────────────────────────────
    def vips_in(self, p: Policy) -> List[FgVip]:
        out = []
        for n in p.dstaddr:
            for m in self.vipgroups.get(n, [n]):
                if m in self.vips:
                    out.append(self.vips[m])
        return out

    def direct_destination(self, p: Policy) -> IntervalSet:
        """Destination of a policy without its VIP names (traffic that is only routed)."""
        plain = [n for n in p.dstaddr if n not in self.vips and n not in self.vipgroups]
        if not plain:
            return EMPTY
        return self.resolver.addresses(plain, "v4").intersect(IntervalSet([(ns.V4_LO, ns.V4_HI)]))

    def interface_for(self, host: int) -> Optional[str]:
        for name, addrs in self.iface_addrs.items():
            for _, (lo, hi) in addrs:
                if lo <= host <= hi:
                    return name
        return None

    def routed(self, host: int) -> bool:
        for route in self.scope.objects("router static"):
            dst = route.get("dst")
            net = network_of(dst) if dst else None
            if net and net != (0, 0xFFFFFFFF) and net[0] <= host <= net[1]:
                return True
        return False

    def egress(self, host: int) -> Optional[str]:
        """Interface FortiGate would send traffic for ``host`` out of: connected subnet first,
        then the most specific enabled static route (a default route counts)."""
        connected = self.interface_for(host)
        if connected:
            return connected
        best, best_size = None, None
        for route in self.scope.objects("router static"):
            if route.get("status") == "disable" or route.get("blackhole") == "enable":
                continue
            dst = route.get("dst")
            net = network_of(dst) if dst else (0, 0xFFFFFFFF)
            dev = route.get("device")
            if net and dev and net[0] <= host <= net[1] and (best_size is None or net[1] - net[0] < best_size):
                best, best_size = dev, net[1] - net[0]
        return best

    def delivers(self, p: Policy, host: int) -> bool:
        """Can a routed (non-VIP) policy actually deliver to ``host``? Its destination
        interface must be the one FortiGate routes the host through. With no connected subnet
        or static route for the host, only dynamic routing (BGP/OSPF) could reach it."""
        out = self.egress(host)
        if out is None:
            return self.dynamic_routing()
        if not p.dstintf or any(i.lower() == "any" for i in p.dstintf):
            return True
        allowed = set(p.dstintf)
        for name in p.dstintf:
            info = self.resolver.interfaces.get(name)
            if info is not None:
                allowed.update(info.members)
        for name in list(allowed):
            info = self.resolver.interfaces.get(name)
            if info is not None and info.is_zone:
                allowed.update(info.members)
        return out in allowed

    def dynamic_routing(self) -> bool:
        return any(self.scope.blocks(b) for b in ("router bgp", "router ospf", "router isis", "router rip"))

    def hosts(self) -> Dict[int, str]:
        return {h: n for n, addrs in self.iface_addrs.items() for h, _ in addrs}

    def snat_sources(self, p: Policy) -> Optional[IntervalSet]:
        """Addresses the next hop sees as source after FortiGate NAT, or None without NAT."""
        if p.setting("nat") != "enable":
            return None
        if p.setting("ippool") == "enable" and p.setting_list("poolname"):
            out = EMPTY
            for n in p.setting_list("poolname"):
                out = out.union(self.ippools.get(n, EMPTY))
            return out
        hosts = [h for i in p.dstintf for h, _ in self.iface_addrs.get(i, [])]
        return IntervalSet((h, h) for h in hosts)

    def ssl_profile(self, name: str) -> Optional[Node]:
        for prof in self.scope.objects("firewall ssl-ssh-profile"):
            if prof.name == name:
                return prof
        return None

    def deep_inspection(self, p: Policy) -> bool:
        name = p.setting("ssl-ssh-profile")
        if not name:
            return False
        prof = self.ssl_profile(name)
        if prof is None:
            return "deep" in name.lower()
        for block in prof.blocks("https") + prof.blocks("ssl"):
            if block.get("inspection-all") == "deep-inspection" or block.get("status") == "deep-inspection":
                return True
        return prof.get("server-cert-mode") in ("replace", "re-sign") and bool(prof.get("server-cert"))

    def flat(self, block: str) -> Node:
        merged = Node("config", block)
        for src in ([self.scope.shared] if self.scope.shared is not None else []) + [self.scope.local]:
            for b in src.blocks(block):
                merged.settings.update(b.settings)
        return merged

    def log_servers(self) -> Dict[str, List[str]]:
        def enabled(blocks):
            out = []
            for block in blocks:
                node = self.flat(block)
                if node.get("status") == "enable" and node.get("server"):
                    out.append(node.get("server"))
            return out
        faz = enabled("log fortianalyzer{} setting".format(i) for i in ("", "2", "3"))
        syslog = enabled("log syslogd{} setting".format(i) for i in ("", "2", "3", "4"))
        cloud = self.flat("log fortiguard setting").get("status") == "enable"
        return {"fortianalyzer": faz, "syslog": syslog, "fortianalyzer_cloud": ["FortiAnalyzer Cloud"] if cloud else []}

    def ntp_state(self) -> str:
        """enable / disable / unknown (block missing: FortiOS default is enabled)."""
        ntp = self.flat("system ntp")
        if not ntp.settings:
            return "unknown"
        return ntp.get("ntpsync", "enable") or "enable"


def build(scope: Scope, trust_map: Optional[Dict[str, str]] = None) -> FgView:
    resolver = Resolver(scope)
    view = FgView(scope, resolver, TrustModel(resolver, trust_map or {}),
                  polmod.build(scope, resolver, "firewall policy"))
    for intf in scope.interfaces():
        addrs = []
        for text in [intf.get("ip")] + [s.get("ip") for b in intf.blocks("secondaryip") for s in b.children]:
            host, net = ip_of(text), network_of(text)
            if host and net:
                addrs.append((host, net))
        view.iface_addrs[intf.name] = addrs
        view.iface_access[intf.name] = [a.lower() for a in intf.get_list("allowaccess")]
    for v in scope.objects("firewall vip"):
        mapped = _ranges(v.get_list("mappedip"))
        for b in v.blocks("realservers"):
            for rs in b.children:
                mapped = mapped.union(_ranges([rs.get("ip")]))
        kind = v.get("type", "static-nat") or "static-nat"
        if kind in ("fqdn", "access-proxy", "dns-translation"):
            continue
        view.vips[v.name] = FgVip(
            name=v.name, node=v, mapped=mapped, extintf=v.get_list("extintf") or ["any"],
            portforward=v.get("portforward") == "enable",
            extports=_ports(v.get_list("extport")), mappedports=_ports(v.get_list("mappedport")),
            kind=kind, server_type=v.get("server-type"), ssl_mode=v.get("ssl-mode"),
            ssl_min=v.get("ssl-min-version") or FGT_VIP_SSL_MIN_DEFAULT,
            adds_xff=v.get("http-ip-header") == "enable")
    for g in scope.objects("firewall vipgrp"):
        view.vipgroups[g.name] = g.get_list("member")
    for pool in scope.objects("firewall ippool"):
        try:
            view.ippools[pool.name] = IntervalSet([ns.v4_range(pool.get("startip"), pool.get("endip") or pool.get("startip"))])
        except ValueError:
            pass
    return view
