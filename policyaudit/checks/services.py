"""Capability 5: excessive service exposure.

Looks at the ports a policy really opens (groups expanded, port-forwarding
VIPs taken into account) and flags ALL, very wide port ranges and risky
services, most strongly when the source is the internet or a guest network.
"""

from __future__ import annotations

from .. import netset as ns
from ..model import CRITICAL, HIGH, INFO, MEDIUM
from ..netset import IntervalSet
from .common import from_internet, is_all_services, names

CAT = "Service exposure"

# (protocol, port): (name, severity from the internet, why)
RISKY = {
    ("TCP", 23): ("Telnet", CRITICAL, "cleartext remote login"),
    ("TCP", 445): ("SMB", CRITICAL, "file sharing; ransomware and worm target"),
    ("TCP", 3389): ("RDP", CRITICAL, "remote desktop; brute-force and exploit target"),
    ("TCP", 5900): ("VNC", CRITICAL, "remote desktop with weak authentication"),
    ("TCP", 1433): ("MS SQL", CRITICAL, "database"),
    ("TCP", 1521): ("Oracle", CRITICAL, "database"),
    ("TCP", 3306): ("MySQL", CRITICAL, "database"),
    ("TCP", 5432): ("PostgreSQL", CRITICAL, "database"),
    ("TCP", 6379): ("Redis", CRITICAL, "no authentication by default"),
    ("TCP", 27017): ("MongoDB", CRITICAL, "database, often unauthenticated"),
    ("TCP", 9200): ("Elasticsearch", CRITICAL, "often unauthenticated"),
    ("TCP", 2375): ("Docker API", CRITICAL, "unauthenticated container control"),
    ("TCP", 4899): ("Radmin", CRITICAL, "remote administration"),
    ("TCP", 135): ("MS-RPC", HIGH, "Windows RPC"),
    ("TCP", 139): ("NetBIOS", HIGH, "Windows file sharing"),
    ("UDP", 137): ("NetBIOS", HIGH, "Windows name service"),
    ("TCP", 389): ("LDAP", HIGH, "directory, credential enumeration"),
    ("TCP", 5985): ("WinRM", HIGH, "PowerShell remoting"),
    ("TCP", 5986): ("WinRM", HIGH, "PowerShell remoting"),
    ("TCP", 22): ("SSH", HIGH, "remote login; brute-force target"),
    ("TCP", 21): ("FTP", HIGH, "cleartext file transfer"),
    ("UDP", 69): ("TFTP", HIGH, "unauthenticated file transfer"),
    ("UDP", 161): ("SNMP", HIGH, "device management, often weak communities"),
    ("UDP", 1900): ("SSDP", MEDIUM, "amplification"),
    ("UDP", 11211): ("Memcached", HIGH, "amplification"),
    ("TCP", 25): ("SMTP", MEDIUM, "mail; use a mail gateway"),
    ("UDP", 53): ("DNS", MEDIUM, "amplification if a resolver is exposed"),
}
CLEARTEXT_INTERNAL = {("TCP", 23), ("TCP", 21), ("UDP", 69)}


def _has(svc: IntervalSet, proto: str, port: int) -> bool:
    base = {"TCP": ns.TCP_BASE, "UDP": ns.UDP_BASE}[proto]
    return svc.overlaps(IntervalSet([(base + port, base + port)]))


def effective_service(ctx, p) -> IntervalSet:
    """Policy services, limited to the VIP ports when every destination is a port-forward."""
    if not p.dstaddr:
        return p.svc
    allowed = None
    for n in p.dstaddr:
        ports = ctx.resolver.vip_ports(n)
        if ports is None:
            return p.svc
        allowed = ports if allowed is None else allowed.union(ports)
    return p.svc.intersect(allowed) if allowed is not None else p.svc


def check(ctx) -> None:
    for p in ctx.active():
        if not p.accepts:
            continue
        svc = effective_service(ctx, p)
        src_lv = ctx.trust.lowest(p.srcintf)[0]
        inbound = from_internet(ctx, p)
        untrusted = inbound or src_lv in ("internet", "guest")
        where = "from the internet" if inbound else "from {} networks".format(src_lv)

        if is_all_services(svc):
            hidden = [n for n in p.service if n.upper() != "ALL"]
            ctx.add("SVC-ALL", HIGH if inbound else MEDIUM, CAT,
                    "Policy {} allows all services {}{}".format(
                        p.label, where, " (via {})".format(names(hidden, 3)) if hidden else ""),
                    policies=[p.policyid], objects=p.service,
                    detail="Every protocol and port is allowed from {} to {}.".format(
                        names(p.srcaddr, 3), names(p.dstaddr, 3)),
                    recommendation="Replace ALL with the specific services the application needs.")
            continue
        count = ns.port_count(svc)
        if count > 1000:
            ctx.add("SVC-WIDE", MEDIUM if untrusted else INFO, CAT,
                    "Policy {} opens {:,} ports {}".format(p.label, count, where),
                    policies=[p.policyid], objects=p.service,
                    detail="Services {} resolve to {}.".format(names(p.service, 4), ns.describe_service(svc)),
                    recommendation="Narrow the port ranges to what the application uses.",
                    evidence={"ports": count})
        risky = [(k, v) for k, v in RISKY.items() if _has(svc, k[0], k[1])]
        if not risky:
            continue
        if untrusted:
            worst = min(risky, key=lambda kv: ["CRITICAL", "HIGH", "MEDIUM", "INFO"].index(kv[1][1]))
            sev = worst[1][1] if inbound else (HIGH if worst[1][1] == CRITICAL else MEDIUM)
            listed = ", ".join("{} ({}/{})".format(v[0], k[0].lower(), k[1]) for k, v in risky[:8])
            ctx.add("SVC-RISKY", sev, CAT,
                    "Policy {} exposes risky services {}: {}".format(p.label, where, listed),
                    policies=[p.policyid], objects=p.service,
                    detail="; ".join("{}: {}".format(v[0], v[2]) for k, v in risky[:8]) + ".",
                    recommendation="Put these services behind VPN or ZTNA, or restrict the source "
                                   "to known addresses.",
                    evidence={"services": [v[0] for k, v in risky]})
        else:
            clear = [RISKY[k][0] for k, v in risky if k in CLEARTEXT_INTERNAL]
            if clear:
                ctx.add("SVC-CLEARTEXT", INFO, CAT,
                        "Policy {} allows cleartext services internally: {}".format(p.label, ", ".join(clear)),
                        policies=[p.policyid], objects=p.service,
                        recommendation="Prefer SSH/SFTP/HTTPS equivalents.")
