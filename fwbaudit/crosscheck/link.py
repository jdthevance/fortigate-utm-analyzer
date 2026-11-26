"""Join the two configs: which FortiGate rules deliver traffic where.

For every enabled FortiGate accept policy, work out the inside addresses and
TCP ports it delivers traffic to (through a VIP's mapped IP and port, or by
plain routing), then classify each address:

==============  ==============================================================
``waf``         a FortiWeb virtual server address: the protected path
``waf-admin``   a FortiWeb interface address that accepts admin logins
``backend``     a server that FortiWeb protects (a server pool member):
                traffic that reaches it here does **not** pass the WAF
``waf-origin``  traffic from FortiWeb itself to its servers (expected)
==============  ==============================================================

Go mapping: ``internal/crosscheck/link``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from policyaudit import netset as ns
from policyaudit.model import Policy
from policyaudit.netset import IntervalSet

from ..inventory import BackendServer, Inventory, ServerPolicy, ip_text
from .fortigate import FgView, FgVip

def single(host: int) -> IntervalSet:
    return IntervalSet([(host, host)])


def tcp_ports(s: IntervalSet) -> List[int]:
    """TCP ports in a service set, as a short list (ranges are capped)."""
    out = []
    for lo, hi in ns.ports_of(s, "TCP").ranges:
        out.extend(range(lo, min(hi, lo + 20) + 1))
    return out


@dataclass
class Path:
    kind: str                       # waf / waf-admin / backend / waf-origin
    policy: Policy
    vip: Optional[FgVip]
    host: int                       # inside address the traffic reaches
    ports: IntervalSet              # TCP ports (service set) that reach it
    source_trust: str
    source_interface: str
    fwb_policies: List[ServerPolicy] = field(default_factory=list)
    backends: List[BackendServer] = field(default_factory=list)
    admin_services: List[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        via = "VIP {}".format(self.vip.name) if self.vip else "routed"
        return "FortiGate policy {} ({}) -> {}".format(self.policy.label, via, ip_text(self.host))

    def all_ports(self) -> bool:
        return ns.port_count(self.ports) >= 65535


@dataclass
class Topology:
    paths: List[Path]
    fwb_hosts: Dict[int, str]        # FortiWeb address -> what it is
    backend_hosts: Dict[int, List[BackendServer]]
    admin_ports: Dict[int, List[tuple]]


def admin_ports(inv: Inventory) -> Dict[int, List[tuple]]:
    """FortiWeb address -> [(service, TCP port)] for administrator logins."""
    g = inv.flat("system global")
    port_of = {"https": int(g.get("admin-sport", "443") or 443), "http": int(g.get("admin-port", "80") or 80),
               "ssh": 22}
    out = {}
    for intf in inv.interfaces.values():
        svc = [(name, port_of[name]) for name in ("https", "http", "ssh") if name in intf.admin_services]
        for h in intf.hosts:
            if svc:
                out[h] = svc
    return out


def build(inv: Inventory, fg: FgView) -> Topology:
    vip_hosts = {v.host: v for v in inv.vips if v.host is not None and v.enabled}
    iface_hosts = {h: i.name for i in inv.interfaces.values() for h in i.hosts}
    backends: Dict[int, List[BackendServer]] = {}
    for p in inv.active_policies():
        for s in inv.backends_of(p):
            if s.host is not None and s.enabled:
                backends.setdefault(s.host, []).append(s)
    admin = admin_ports(inv)
    fwb_all = IntervalSet((h, h) for h in list(vip_hosts) + list(iface_hosts))
    candidates = sorted(set(vip_hosts) | set(admin) | set(backends))
    paths: List[Path] = []
    for p in fg.policies:
        if not p.enabled or not p.accepts:
            continue
        level, intf, _ = fg.trust.lowest(p.srcintf)
        targets = []                                   # (host, ports, vip)
        for vip in fg.vips_in(p):
            mapped_ports = vip.mapped_tcp
            ports = p.svc if mapped_ports is None else p.svc.intersect(mapped_ports)
            for h in candidates:
                if vip.mapped.overlaps(single(h)):
                    targets.append((h, ports, vip))
        direct = fg.direct_destination(p)
        for h in candidates:
            if direct.overlaps(single(h)) and fg.delivers(p, h):
                targets.append((h, p.svc, None))
        from_fwb = bool(p.src) and fwb_all.contains(p.src.intersect(IntervalSet([(ns.V4_LO, ns.V4_HI)])))
        for h, ports, vip in targets:
            if not ports:
                continue
            if h in vip_hosts:
                paths.append(Path("waf", p, vip, h, ports, level, intf, fwb_policies=inv.policies_on_vip(h)))
            reached = [svc for svc, port in admin.get(h, []) if ports.overlaps(single(ns.TCP_BASE + port))]
            if reached:
                paths.append(Path("waf-admin", p, vip, h, ports, level, intf, admin_services=reached))
            if h in backends:
                kind = "waf-origin" if from_fwb else "backend"
                paths.append(Path(kind, p, vip, h, ports, level, intf, backends=backends[h]))
    hosts = {h: "virtual server {}".format(v.vserver) for h, v in vip_hosts.items()}
    hosts.update({h: "interface {}".format(n) for h, n in iface_hosts.items()})
    return Topology(paths, hosts, backends, admin)
