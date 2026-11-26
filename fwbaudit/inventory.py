"""Typed model of a FortiWeb configuration.

The FortiWeb CLI is the same ``config / edit / set / next / end`` language as
FortiOS, so the file is parsed by ``policyaudit.config`` (same parser, same
handling of quoted lists and truncated files). This module turns the parsed
tree into the objects a WAF audit talks about:

    interface -> virtual IP -> virtual server -> server policy
                                                   |-> web protection profile -> signatures, DoS, bots ...
                                                   '-> server pool -> back-end servers

Names follow the CLI (``server-policy policy``, ``waf signature`` ...), so a
finding can always be traced back to the exact block in the backup.

Go mapping: ``internal/fortiweb/inventory`` with ``type Inventory struct``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from policyaudit.config import Node, Scope

# Predefined FortiWeb services, used when the backup does not list them.
BUILTIN_SERVICES = {"HTTP": 80, "HTTPS": 443, "FTP": 21, "FTPS": 990}
# Predefined signature policies and protection profiles (CLI reference, waf signature /
# inline-protection). Their contents are maintained by FortiGuard and are not in the backup.
BUILTIN_SIGNATURES = ("High Level Security", "Medium Level Security", "Alert Only")
ADMIN_SERVICES = ("http", "https", "ssh", "snmp", "fortiweb-manager", "telnet")


def ip_of(text: str) -> Optional[int]:
    """Host address from ``10.0.0.5``, ``10.0.0.5/24`` or ``10.0.0.5 255.255.255.0``."""
    if not text:
        return None
    first = text.replace('"', "").split()[0].split("/")[0]
    try:
        return int(ipaddress.IPv4Address(first))
    except ValueError:
        return None


def network_of(text: str) -> Optional[Tuple[int, int]]:
    """Subnet range of an interface address, or None."""
    if not text:
        return None
    parts = text.replace('"', "").split()
    try:
        if len(parts) >= 2 and "/" not in parts[0]:
            net = ipaddress.IPv4Network("{}/{}".format(parts[0], parts[1]), strict=False)
        else:
            net = ipaddress.IPv4Network(parts[0], strict=False)
    except ValueError:
        return None
    return int(net.network_address), int(net.broadcast_address)


def ip_text(value: Optional[int]) -> str:
    return str(ipaddress.IPv4Address(value)) if value is not None else "?"


@dataclass
class Interface:
    name: str
    node: Node
    addresses: List[Tuple[int, Tuple[int, int]]] = field(default_factory=list)  # (host, subnet)
    allowaccess: Set[str] = field(default_factory=set)
    up: bool = True

    @property
    def hosts(self) -> List[int]:
        return [h for h, _ in self.addresses]

    @property
    def admin_services(self) -> Set[str]:
        return {a for a in self.allowaccess if a in ADMIN_SERVICES}


@dataclass
class VirtualIP:
    """One entry of a virtual server's ``vip-list``, already resolved to an address."""
    vserver: str
    vip_name: str
    host: Optional[int]
    interface: str
    enabled: bool
    use_interface_ip: bool


@dataclass
class BackendServer:
    pool: str
    index: str
    node: Node
    host: Optional[int]
    domain: str
    port: int
    ssl: bool
    enabled: bool


@dataclass
class ServerPool:
    name: str
    node: Node
    servers: List[BackendServer] = field(default_factory=list)


@dataclass
class ServerPolicy:
    name: str
    node: Node
    enabled: bool
    mode: str                         # deployment-mode
    vserver: str
    pool: str
    http_service: str
    https_service: str
    profile: str                      # web-protection-profile
    http_ports: List[int] = field(default_factory=list)
    https_ports: List[int] = field(default_factory=list)

    @property
    def https(self) -> bool:
        return bool(self.https_service) or self.node.get("ssl") == "enable"

    @property
    def ports(self) -> List[int]:
        return sorted(set(self.http_ports + self.https_ports))

    def get(self, key: str, default: str = "") -> str:
        return self.node.get(key, default)


class Inventory:
    """Everything an audit check needs to know about one FortiWeb (or ADOM)."""

    def __init__(self, scope: Scope):
        self.scope = scope
        self.name = scope.name
        self.interfaces: Dict[str, Interface] = {}
        self.vips: List[VirtualIP] = []
        self.pools: Dict[str, ServerPool] = {}
        self.policies: List[ServerPolicy] = []
        self.unresolved: List[str] = []
        self._build()

    # ── generic lookups ─────────────────────────────────────────────────────
    def objects(self, block: str) -> List[Node]:
        """Objects of a table block, from the ADOM first and then from global."""
        own = self.scope.objects(block)
        if self.scope.shared is not None:
            names = {o.name for o in own}
            own = own + [o for o in self.scope.shared.objects(block) if o.name not in names]
        return own

    def table(self, block: str) -> Dict[str, Node]:
        return {o.name: o for o in self.objects(block)}

    def flat(self, block: str) -> Node:
        """A settings block such as ``config system global`` (ADOM, then global)."""
        merged = Node("config", block)
        sources = [self.scope.local] + ([self.scope.shared] if self.scope.shared is not None else [])
        for src in reversed(sources):
            for b in src.blocks(block):
                merged.settings.update(b.settings)
                merged.children.extend(b.children)
        return merged

    def has_block(self, block: str) -> bool:
        if self.scope.local.blocks(block):
            return True
        return bool(self.scope.shared is not None and self.scope.shared.blocks(block))

    @staticmethod
    def sub(node: Node, block: str) -> List[Node]:
        """Entries of a nested table, e.g. ``config pserver-list`` inside a pool."""
        return [c for b in node.blocks(block) for c in b.children if c.kind == "edit"]

    # ── settings ────────────────────────────────────────────────────────────
    @property
    def opmode(self) -> str:
        return self.flat("system settings").get("opmode", "reverse-proxy") or "reverse-proxy"

    def service_port(self, name: str) -> Optional[int]:
        if not name:
            return None
        custom = self.table("server-policy service custom").get(name)
        if custom is not None and custom.get("port").isdigit():
            return int(custom.get("port"))
        predefined = self.table("server-policy service predefined").get(name)
        if predefined is not None and predefined.get("port").isdigit():
            return int(predefined.get("port"))
        if name.upper() in BUILTIN_SERVICES:
            return BUILTIN_SERVICES[name.upper()]
        self.unresolved.append("service " + name)
        return None

    # ── build ───────────────────────────────────────────────────────────────
    def _build(self) -> None:
        for node in self.objects("system interface"):
            intf = Interface(node.name, node, up=node.get("status", "up") != "down")
            for text in [node.get("ip")] + [e.get("ip") for e in self.sub(node, "secondaryip")]:
                host, net = ip_of(text), network_of(text)
                if host is not None and net is not None and host != 0:
                    intf.addresses.append((host, net))
            intf.allowaccess = {a.lower() for a in node.get_list("allowaccess")}
            self.interfaces[node.name] = intf

        sys_vips = self.table("system vip")
        for vs in self.objects("server-policy vserver"):
            for entry in self.sub(vs, "vip-list"):
                vip_name = entry.get("vip")
                iface = entry.get("interface")
                use_if = entry.get("use-interface-ip") == "enable"
                host = None
                if use_if and iface in self.interfaces and self.interfaces[iface].hosts:
                    host = self.interfaces[iface].hosts[0]
                elif vip_name in sys_vips:
                    host = ip_of(sys_vips[vip_name].get("vip"))
                    iface = iface or sys_vips[vip_name].get("interface")
                else:
                    host = ip_of(vip_name)          # literal address, as in the CLI example
                    if host is None and vip_name:
                        self.unresolved.append("vip " + vip_name)
                self.vips.append(VirtualIP(vs.name, vip_name, host, iface,
                                           entry.get("status", "enable") != "disable", use_if))

        for pool in self.objects("server-policy server-pool"):
            sp = ServerPool(pool.name, pool)
            for entry in self.sub(pool, "pserver-list"):
                port = entry.get("port")
                sp.servers.append(BackendServer(
                    pool=pool.name, index=entry.name, node=entry,
                    host=ip_of(entry.get("ip")), domain=entry.get("domain"),
                    port=int(port) if port.isdigit() else 80,
                    ssl=entry.get("ssl") == "enable",
                    enabled=entry.get("status", "enable") == "enable"))
            self.pools[pool.name] = sp

        for node in self.objects("server-policy policy"):
            p = ServerPolicy(
                name=node.name, node=node,
                enabled=node.get("status", "enable") != "disable",
                mode=node.get("deployment-mode", "server-pool") or "server-pool",
                vserver=node.get("vserver"), pool=node.get("server-pool"),
                http_service=node.get("service"), https_service=node.get("HTTPS-service"),
                profile=node.get("web-protection-profile"))
            if p.http_service:
                port = self.service_port(p.http_service)
                if port:
                    p.http_ports.append(port)
            if p.https_service:
                port = self.service_port(p.https_service)
                if port:
                    p.https_ports.append(port)
            self.policies.append(p)

    # ── derived views ───────────────────────────────────────────────────────
    def active_policies(self) -> List[ServerPolicy]:
        return [p for p in self.policies if p.enabled]

    def vips_of(self, policy: ServerPolicy) -> List[VirtualIP]:
        return [v for v in self.vips if v.vserver == policy.vserver]

    def policies_on_vip(self, host: int) -> List[ServerPolicy]:
        servers = {v.vserver for v in self.vips if v.host == host and v.enabled}
        return [p for p in self.active_policies() if p.vserver in servers]

    def backends_of(self, policy: ServerPolicy) -> List[BackendServer]:
        pool = self.pools.get(policy.pool)
        return list(pool.servers) if pool else []

    def data_interfaces(self) -> Set[str]:
        """Interfaces that receive client traffic (they carry a virtual server)."""
        used = {v.vserver for v in self.vips}
        active = {p.vserver for p in self.active_policies()}
        return {v.interface for v in self.vips if v.interface and v.vserver in (active or used)}

    def all_addresses(self) -> Set[int]:
        out = {h for i in self.interfaces.values() for h in i.hosts}
        out.update(v.host for v in self.vips if v.host is not None)
        return out

    def profile(self, name: str) -> Optional[Node]:
        if not name:
            return None
        return (self.table("waf web-protection-profile inline-protection").get(name)
                or self.table("waf web-protection-profile offline-protection").get(name))

    def profiles_in_use(self) -> Dict[str, List[ServerPolicy]]:
        out: Dict[str, List[ServerPolicy]] = {}
        for p in self.active_policies():
            if p.profile:
                out.setdefault(p.profile, []).append(p)
        return out

    def gateways(self) -> List[int]:
        out = []
        for r in self.objects("router static"):
            dst = r.get("dst")
            if not dst or dst.startswith("0.0.0.0"):
                gw = ip_of(r.get("gateway"))
                if gw is not None:
                    out.append(gw)
        gw = ip_of(self.flat("system settings").get("gateway"))
        if gw is not None and gw != 0:
            out.append(gw)
        return out
