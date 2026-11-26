"""Object resolver: turns names into real IP ranges, ports and interfaces.

A policy says ``srcaddr "Branch_LANs"`` and ``service "Web_Services"``. To
know whether one rule covers another, we need what those names *mean*.
The resolver looks names up in the VDOM's address, address-group, VIP,
service and service-group tables, expands nested groups (with loop
detection), applies group exclusions, and returns :class:`IntervalSet`
values (see ``netset.py``).

Rules it follows, so results stay trustworthy:

* A name it cannot find becomes its own unique "unknown" item. It can match
  itself, but never makes a rule look broader or narrower than it is.
* FQDN, geography and dynamic (SDN) objects have no fixed IPs. They are
  kept as unique items: ``all`` covers them, a subnet never does.
* Common FortiGate predefined services (HTTP, HTTPS, ALL ...) are known
  even when a plain ``show`` backup leaves them out.

Go mapping: ``internal/objects`` with ``type Resolver struct``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from . import netset as ns
from .config import Node, Scope
from .netset import EMPTY, IntervalSet

# Predefined services, used only when the backup does not define them.
# protocol: list of (proto, low, high)
BUILTIN_SERVICES: Dict[str, List[Tuple[str, int, int]]] = {
    "ALL": [("ALL", 0, 0)],
    "ALL_TCP": [("TCP", 1, 65535)],
    "ALL_UDP": [("UDP", 1, 65535)],
    "ALL_ICMP": [("ICMP", 0, 255)],
    "ALL_ICMP6": [("ICMP6", 0, 255)],
    "PING": [("ICMP", 8, 8)],
    "PING6": [("ICMP6", 128, 128)],
    "TRACEROUTE": [("UDP", 33434, 33535)],
    "HTTP": [("TCP", 80, 80)],
    "HTTPS": [("TCP", 443, 443)],
    "WEB": [("TCP", 80, 80), ("TCP", 443, 443)],
    "SSH": [("TCP", 22, 22)],
    "TELNET": [("TCP", 23, 23)],
    "FTP": [("TCP", 21, 21)],
    "TFTP": [("UDP", 69, 69)],
    "SMTP": [("TCP", 25, 25)],
    "SMTPS": [("TCP", 465, 465)],
    "POP3": [("TCP", 110, 110)],
    "POP3S": [("TCP", 995, 995)],
    "IMAP": [("TCP", 143, 143)],
    "IMAPS": [("TCP", 993, 993)],
    "DNS": [("TCP", 53, 53), ("UDP", 53, 53)],
    "NTP": [("TCP", 123, 123), ("UDP", 123, 123)],
    "SNMP": [("TCP", 161, 162), ("UDP", 161, 162)],
    "SYSLOG": [("UDP", 514, 514)],
    "LDAP": [("TCP", 389, 389)],
    "LDAP_UDP": [("UDP", 389, 389)],
    "LDAPS": [("TCP", 636, 636)],
    "KERBEROS": [("TCP", 88, 88), ("UDP", 88, 88)],
    "RADIUS": [("UDP", 1812, 1813)],
    "RDP": [("TCP", 3389, 3389)],
    "SMB": [("TCP", 445, 445)],
    "SAMBA": [("TCP", 139, 139)],
    "NetBIOS": [("UDP", 137, 138), ("TCP", 139, 139)],
    "DCE-RPC": [("TCP", 135, 135), ("UDP", 135, 135)],
    "MS-SQL": [("TCP", 1433, 1434)],
    "MYSQL": [("TCP", 3306, 3306)],
    "VNC": [("TCP", 5900, 5900)],
    "SIP": [("UDP", 5060, 5060)],
    "IKE": [("UDP", 500, 500), ("UDP", 4500, 4500)],
    "DHCP": [("UDP", 67, 68)],
    "BGP": [("TCP", 179, 179)],
    "NNTP": [("TCP", 119, 119)],
    "X-WINDOWS": [("TCP", 6000, 6063)],
    "WINS": [("TCP", 1512, 1512), ("UDP", 1512, 1512)],
    "AFS3": [("TCP", 7000, 7009), ("UDP", 7000, 7009)],
    "GRE": [("IP", 47, 47)],
    "ESP": [("IP", 50, 50)],
    "AH": [("IP", 51, 51)],
    "OSPF": [("IP", 89, 89)],
}

IP_PROTO_REGION = {6: "TCP", 17: "UDP", 132: "SCTP", 1: "ICMP", 58: "ICMP6"}

WAN_NAME_HINTS = ("wan", "ppp", "vdsl", "adsl", "ftth", "internet", "outside",
                  "untrust", "isp", "lte", "modem")


@dataclass
class InterfaceInfo:
    name: str
    index: int
    role: str = ""
    alias: str = ""
    itype: str = ""
    mode: str = ""
    networks: List[Tuple[int, int]] = field(default_factory=list)
    members: List[str] = field(default_factory=list)    # for zones
    is_zone: bool = False
    wan_reason: str = ""                                 # why we think it faces the internet


class Resolver:
    """Resolve names for one VDOM scope. Results are cached."""

    def __init__(self, scope: Scope):
        self.scope = scope
        self.unresolved: Set[str] = set()
        self._tokens: Dict[str, int] = {}
        self._addr4 = self._table(["firewall address", "firewall multicast-address"])
        self._addr6 = self._table(["firewall address6", "firewall multicast-address6"])
        self._grp4 = self._table(["firewall addrgrp"])
        self._grp6 = self._table(["firewall addrgrp6"])
        self._vip4 = self._table(["firewall vip"])
        self._vip6 = self._table(["firewall vip6"])
        self._vipgrp4 = self._table(["firewall vipgrp"])
        self._vipgrp6 = self._table(["firewall vipgrp6"])
        self._svc = self._table(["firewall service custom"])
        self._svcgrp = self._table(["firewall service group"])
        self._cache: Dict[Tuple[str, str], IntervalSet] = {}
        self._kinds: Dict[Tuple[str, str], str] = {}
        self._build_interfaces()

    # ── tables ───────────────────────────────────────────────────────────────
    def _table(self, blocks: List[str]) -> Dict[str, Node]:
        out: Dict[str, Node] = {}
        for b in blocks:
            for obj in self.scope.objects(b):
                out.setdefault(obj.name, obj)
        return out

    def _token(self, key: str, family: str) -> IntervalSet:
        idx = self._tokens.setdefault(key, len(self._tokens))
        base = {"v4": ns.V4_TOK_LO, "v6": ns.V6_TOK_LO, "svc": ns.SVC_TOK_LO}[family]
        return IntervalSet([(base + idx, base + idx)])

    def address_names(self) -> Dict[str, Node]:
        return dict(self._addr4)

    def kind(self, family: str, name: str) -> str:
        """What a name is: address, group, vip, fqdn, geography, unknown ..."""
        self.address(name, family)
        return self._kinds.get((family, name), "unknown")

    def is_vip(self, name: str) -> bool:
        return name in self._vip4 or name in self._vip6 or name in self._vipgrp4 or name in self._vipgrp6

    # ── addresses ────────────────────────────────────────────────────────────
    def addresses(self, names: List[str], family: str = "v4") -> IntervalSet:
        result = EMPTY
        for n in names:
            result = result.union(self.address(n, family))
        return result

    def address(self, name: str, family: str = "v4", _stack: Tuple[str, ...] = ()) -> IntervalSet:
        key = (family, name)
        if key in self._cache:
            return self._cache[key]
        if name in _stack:                      # group loop: stop, mark unknown
            self.unresolved.add(name)
            return self._token("loop:" + name, family)
        value, kind = self._address_uncached(name, family, _stack + (name,))
        self._cache[key] = value
        self._kinds[key] = kind
        return value

    def _address_uncached(self, name: str, family: str, stack: Tuple[str, ...]):
        addr = self._addr4 if family == "v4" else self._addr6
        grp = self._grp4 if family == "v4" else self._grp6
        vip = self._vip4 if family == "v4" else self._vip6
        vipgrp = self._vipgrp4 if family == "v4" else self._vipgrp6
        full = ns.V4_ALL if family == "v4" else ns.V6_ALL

        if name in addr:
            return self._address_object(addr[name], family)
        if name in grp:
            g = grp[name]
            members = self.addresses_stack(g.get_list("member"), family, stack)
            if g.get("exclude") == "enable":
                excl = self.addresses_stack(g.get_list("exclude-member"), family, stack)
                lo, hi = (ns.V4_LO, ns.V4_HI) if family == "v4" else (ns.V6_LO, ns.V6_HI)
                members = members.intersect(excl.complement(lo, hi).union(
                    IntervalSet([(ns.V4_TOK_LO, ns.V4_TOK_HI), (ns.V6_TOK_LO, ns.V6_TOK_HI)])))
            return members, "group"
        if name in vip:
            return self._vip_object(vip[name], family), "vip"
        if name in vipgrp:
            return self.addresses_stack(vipgrp[name].get_list("member"), family, stack), "vipgroup"
        if name.lower() == "all":
            return full, "all"
        if name.lower() == "none":
            return EMPTY, "none"
        self.unresolved.add(name)
        return self._token("unknown:" + name, family), "unknown"

    def addresses_stack(self, names: List[str], family: str, stack: Tuple[str, ...]) -> IntervalSet:
        result = EMPTY
        for n in names:
            result = result.union(self.address(n, family, stack))
        return result

    def _address_object(self, obj: Node, family: str):
        typ = obj.get("type") or ("ipprefix" if family == "v6" else "ipmask")
        try:
            if family == "v4":
                if typ in ("ipmask", "interface-subnet") or (not obj.has("type") and obj.has("subnet")):
                    parts = obj.get("subnet", "0.0.0.0 0.0.0.0").split()
                    rng = ns.v4_network(parts[0], parts[1] if len(parts) > 1 else "")
                    if rng == (ns.V4_LO, ns.V4_HI):
                        return ns.V4_ALL, "all"     # 0.0.0.0/0 also covers FQDN/geo objects
                    return IntervalSet([rng]), "subnet"
                if typ == "iprange":
                    return IntervalSet([ns.v4_range(obj.get("start-ip"), obj.get("end-ip"))]), "range"
                if typ in ("multicastrange", "broadcastmask"):
                    start, end = obj.get("start-ip"), obj.get("end-ip")
                    if start and end:
                        return IntervalSet([ns.v4_range(start, end)]), "range"
            else:
                if typ == "ipprefix":
                    rng = ns.v6_network(obj.get("ip6", "::/0"))
                    if rng == (ns.V6_LO, ns.V6_HI):
                        return ns.V6_ALL, "all"
                    return IntervalSet([rng]), "subnet"
                if typ == "iprange":
                    return IntervalSet([ns.v6_range(obj.get("start-ip"), obj.get("end-ip"))]), "range"
        except (ValueError, IndexError):
            self.unresolved.add(obj.name)
            return self._token("bad:" + obj.name, family), "unknown"
        # fqdn, geography, wildcard, dynamic, mac, template: no fixed IP range
        return self._token("{}:{}".format(typ, obj.name), family), typ

    def _vip_object(self, obj: Node, family: str) -> IntervalSet:
        if obj.get("type") in ("fqdn", "access-proxy"):
            return self._token("vip:" + obj.name, family)
        ranges = []
        for item in obj.get_list("extip"):
            try:
                if "-" in item:
                    a, b = item.split("-", 1)
                    ranges.append(ns.v4_range(a, b) if family == "v4" else ns.v6_range(a, b))
                else:
                    ranges.append(ns.v4_network(item) if family == "v4" else ns.v6_network(item))
            except ValueError:
                pass
        if not ranges:
            return self._token("vip:" + obj.name, family)
        return IntervalSet(ranges)

    def vip_ports(self, name: str) -> Optional[IntervalSet]:
        """Ports a port-forwarding VIP accepts, or None if it forwards everything."""
        obj = self._vip4.get(name) or self._vip6.get(name)
        if obj is None or obj.get("portforward") != "enable":
            return None
        proto = (obj.get("protocol") or "tcp").upper()
        if proto not in ("TCP", "UDP", "SCTP"):
            return None
        rng = []
        for item in obj.get_list("extport"):
            lo, _, hi = item.partition("-")
            try:
                rng.append(_port_range(proto, int(lo), int(hi or lo)))
            except ValueError:
                return None
        return IntervalSet(rng) if rng else None

    @staticmethod
    def widen(s: IntervalSet) -> IntervalSet:
        """Treat non-IP items as 'could be any IP of the family' (for may-overlap)."""
        out = s
        if s.size_within(ns.V4_TOK_LO, ns.V4_TOK_HI):
            out = out.union(ns.V4_ALL)
        if s.size_within(ns.V6_TOK_LO, ns.V6_TOK_HI):
            out = out.union(ns.V6_ALL)
        return out

    # ── services ─────────────────────────────────────────────────────────────
    def services(self, names: List[str]) -> IntervalSet:
        result = EMPTY
        for n in names:
            result = result.union(self.service(n))
        return result

    def service(self, name: str, _stack: Tuple[str, ...] = ()) -> IntervalSet:
        key = ("svc", name)
        if key in self._cache:
            return self._cache[key]
        if name in _stack:
            self.unresolved.add(name)
            return self._token("svcloop:" + name, "svc")
        if name in self._svc:
            value = self._service_object(self._svc[name])
        elif name in self._svcgrp:
            value = EMPTY
            for m in self._svcgrp[name].get_list("member"):
                value = value.union(self.service(m, _stack + (name,)))
        elif name in BUILTIN_SERVICES or name.upper() in BUILTIN_SERVICES:
            value = _from_spec(BUILTIN_SERVICES.get(name) or BUILTIN_SERVICES[name.upper()])
        else:
            self.unresolved.add(name)
            value = self._token("unknown-service:" + name, "svc")
        self._cache[key] = value
        return value

    def _service_object(self, obj: Node) -> IntervalSet:
        proto = (obj.get("protocol") or "TCP/UDP/SCTP").upper()
        if obj.get("iprange") not in ("", "0.0.0.0") or obj.get("fqdn"):
            # Service restricted to destination IPs: cannot be expressed as ports alone.
            return self._token("svc-dest:" + obj.name, "svc")
        if proto in ("TCP/UDP/SCTP", "TCP/UDP/UDP-LITE/SCTP", "TCP", "UDP", "SCTP"):
            ranges: List[Tuple[int, int]] = []
            restricted = False
            for p_name, key in (("TCP", "tcp-portrange"), ("UDP", "udp-portrange"),
                                ("SCTP", "sctp-portrange")):
                for item in obj.get_list(key):
                    dst, _, src = item.partition(":")
                    if src and src not in ("1-65535", "0-65535"):
                        restricted = True
                    lo, _, hi = dst.partition("-")
                    try:
                        ranges.append(_port_range(p_name, int(lo), int(hi or lo)))
                    except ValueError:
                        restricted = True
            if restricted:
                return self._token("svc-srcport:" + obj.name, "svc")
            return IntervalSet(ranges)
        if proto in ("ICMP", "ICMP6"):
            base = ns.ICMP_BASE if proto == "ICMP" else ns.ICMP6_BASE
            t = obj.get("icmptype")
            if t == "" or not t.isdigit():
                return IntervalSet([(base, base + 255)])
            return IntervalSet([(base + int(t), base + int(t))])
        if proto == "IP":
            num = obj.get("protocol-number", "0")
            try:
                n = int(num)
            except ValueError:
                return self._token("svc-ip:" + obj.name, "svc")
            return _from_spec([("IP", n, n)])
        if proto == "ALL":
            return IntervalSet([ns.SVC_ALL])
        # explicit-proxy services (HTTP, CONNECT, SOCKS ...) do not apply to firewall policies
        return self._token("svc-proxy:" + obj.name, "svc")

    @staticmethod
    def widen_service(s: IntervalSet) -> IntervalSet:
        if s.size_within(ns.SVC_TOK_LO, ns.SVC_TOK_HI):
            return IntervalSet([ns.SVC_ALL])
        return s

    # ── interfaces and zones ─────────────────────────────────────────────────
    def _build_interfaces(self) -> None:
        self.interfaces: Dict[str, InterfaceInfo] = {}
        for intf in self.scope.interfaces():
            info = self._intf(intf.name)
            info.role = intf.get("role")
            info.alias = intf.get("alias")
            info.itype = intf.get("type")
            info.mode = intf.get("mode")
            ip = intf.get_list("ip")
            if len(ip) >= 2 or (ip and "/" in ip[0]):
                try:
                    info.networks.append(ns.v4_network(ip[0], ip[1] if len(ip) > 1 else ""))
                except ValueError:
                    pass
        for zone in self.scope.objects("system zone"):
            info = self._intf(zone.name)
            info.is_zone = True
            info.members = zone.get_list("interface")
            for m in info.members:
                self._intf(m)
        sdwan = self.scope.flat("system sdwan")
        if not sdwan.children and not sdwan.settings:
            sdwan = self.scope.flat("system virtual-wan-link")
        sd_members = [m for b in sdwan.blocks("members") for m in b.children]
        sd_zones = {z.name: [] for b in sdwan.blocks("zone") for z in b.children}
        for m in sd_members:
            iface = m.get("interface")
            if not iface:
                continue
            self._intf(iface)
            zone = m.get("zone") or "virtual-wan-link"
            sd_zones.setdefault(zone, []).append(iface)
        for zname, members in sd_zones.items():
            info = self._intf(zname)
            info.is_zone = True
            info.members = members
            info.wan_reason = info.wan_reason or "SD-WAN zone"
            for m in members:
                self._intf(m).wan_reason = self._intf(m).wan_reason or "SD-WAN member"
        # default routes mark the egress interface as internet-facing
        for route in self.scope.objects("router static"):
            dst = route.get_list("dst")
            is_default = (not dst) or dst in (["0.0.0.0", "0.0.0.0"], ["0.0.0.0/0"])
            if is_default and route.get("status") != "disable" and route.get("blackhole") != "enable":
                dev = route.get("device") or route.get("sdwan-zone")
                if dev:
                    self._intf(dev).wan_reason = self._intf(dev).wan_reason or "default route"
                # "set sdwan enable" routes point at SD-WAN members, marked above.
        for info in self.interfaces.values():
            if info.wan_reason:
                continue
            if info.role == "wan":
                info.wan_reason = "interface role is wan"
            elif info.mode == "pppoe":
                info.wan_reason = "PPPoE interface"
        # zones inherit WAN status from members
        for info in self.interfaces.values():
            if info.is_zone and not info.wan_reason:
                if any(self._intf(m).wan_reason for m in info.members):
                    info.wan_reason = "zone contains an internet-facing interface"
        self.wan_guessed = False
        if not any(i.wan_reason for i in self.interfaces.values()):
            # No role, route or SD-WAN data: fall back to names, and say so.
            for info in self.interfaces.values():
                low = (info.name + " " + info.alias).lower()
                if any(h in low for h in WAN_NAME_HINTS):
                    info.wan_reason = "guessed from the name (no wan role or default route found)"
                    self.wan_guessed = True

    def _intf(self, name: str) -> InterfaceInfo:
        if name not in self.interfaces:
            self.interfaces[name] = InterfaceInfo(name, len(self.interfaces))
        return self.interfaces[name]

    def interface_mask(self, names: List[str]) -> int:
        """Bit mask of interfaces; zones expand to members; ``any`` is -1."""
        mask = 0
        for n in names:
            if n.lower() == "any":
                return -1
            info = self._intf(n)
            mask |= 1 << info.index
            for m in info.members:
                mask |= 1 << self._intf(m).index
        return mask

    def is_wan(self, name: str) -> bool:
        info = self.interfaces.get(name)
        return bool(info and info.wan_reason)

    def wan_reason(self, name: str) -> str:
        info = self.interfaces.get(name)
        return info.wan_reason if info else ""

    def internal_networks(self) -> IntervalSet:
        """Subnets of non-WAN interfaces: the networks the firewall protects."""
        nets = []
        for info in self.interfaces.values():
            if not info.wan_reason:
                nets.extend(info.networks)
        return IntervalSet(nets)


def _port_range(proto: str, lo: int, hi: int) -> Tuple[int, int]:
    base = {"TCP": ns.TCP_BASE, "UDP": ns.UDP_BASE, "SCTP": ns.SCTP_BASE}[proto]
    lo = max(1, lo)
    if hi < lo or hi > 65535:
        raise ValueError("bad port range")
    return (base + lo, base + hi)


def _from_spec(spec: List[Tuple[str, int, int]]) -> IntervalSet:
    ranges = []
    for proto, lo, hi in spec:
        if proto == "ALL" or (proto == "IP" and lo == 0):
            return IntervalSet([ns.SVC_ALL])
        if proto in ("TCP", "UDP", "SCTP"):
            ranges.append(_port_range(proto, lo, hi))
        elif proto == "ICMP":
            ranges.append((ns.ICMP_BASE + lo, ns.ICMP_BASE + hi))
        elif proto == "ICMP6":
            ranges.append((ns.ICMP6_BASE + lo, ns.ICMP6_BASE + hi))
        elif proto == "IP":
            region = IP_PROTO_REGION.get(lo)
            if region in ("TCP", "UDP", "SCTP"):
                ranges.append(_port_range(region, 1, 65535))
            elif region == "ICMP":
                ranges.append((ns.ICMP_BASE, ns.ICMP_BASE + 255))
            elif region == "ICMP6":
                ranges.append((ns.ICMP6_BASE, ns.ICMP6_BASE + 255))
            else:
                ranges.append((ns.PROTO_BASE + lo, ns.PROTO_BASE + hi))
    return IntervalSet(ranges)


def is_private_v4(lo: int, hi: int) -> bool:
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"):
        n = ipaddress.IPv4Network(net)
        if int(n.network_address) <= lo and hi <= int(n.broadcast_address):
            return True
    return False
