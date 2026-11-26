"""Weaknesses that only show up when the FortiGate and FortiWeb are read together.

Rule IDs (all ``XC-*``):

* Path: ``XC-NO-LINK``, ``XC-BYPASS-VIP``, ``XC-BYPASS-POLICY``, ``XC-BYPASS-SEGMENT``,
  ``XC-WAF-ADMIN-EXPOSED``, ``XC-VIP-ALL-PORTS``, ``XC-PORT-MISMATCH``, ``XC-SVC-WIDER``,
  ``XC-UNPROTECTED-APP``
* Client identity and trust: ``XC-SNAT-HIDES-CLIENT``, ``XC-FWB-TRUSTS-FGT``, ``XC-XFF-SPOOFABLE``
* TLS: ``XC-TLS-CLEAR-HOP``, ``XC-TLS-DOUBLE``, ``XC-TLS-WEAK-EDGE``
* Inspection: ``XC-INSPECT-NO-IPS``, ``XC-INSPECT-DUP-WAF``
* Addressing and routing: ``XC-ADDR-UNKNOWN``, ``XC-RETURN-PATH``
* Logging and time: ``XC-LOG-FGT-OFF``, ``XC-LOG-NO-COMMON``, ``XC-NTP``
* Integration: ``XC-QUARANTINE-*``

Go mapping: ``internal/crosscheck/checks``.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from policyaudit import netset as ns
from policyaudit.model import CRITICAL, HIGH, INFO, MEDIUM, Finding
from policyaudit.netset import IntervalSet
from policyaudit.trust import RANK

from ..checks import clientip, logging as fwblog, tls as fwbtls
from ..checks.common import on
from ..inventory import Inventory, ip_of, ip_text
from .fortigate import FgView
from .link import Path, Topology, single, tcp_ports

CAT_PATH = "WAF path and bypass"
CAT_ID = "Client identity and trust"
CAT_TLS = "TLS between the appliances"
CAT_INSPECT = "Inspection consistency"
CAT_NET = "Addressing and routing"
CAT_LOG = "Logging and time"
CAT_INT = "FortiGate integration"

TLS_RANK = {"ssl-3.0": 0, "tls-1.0": 1, "tls-1.1": 2, "tls-1.2": 3, "tls-1.3": 4}


class XContext:
    def __init__(self, inv: Inventory, fg: FgView, topo: Topology):
        self.inv, self.fg, self.topo = inv, fg, topo
        self.findings: List[Finding] = []
        self._seen = set()

    def add(self, rule_id, severity, category, title, **kw) -> Optional[Finding]:
        """Record a finding once (one FortiGate policy often has several VIPs to the same site)."""
        if (rule_id, title) in self._seen:
            return None
        self._seen.add((rule_id, title))
        f = Finding(rule_id=rule_id, severity=severity, title=title,
                    vdom="{} <-> {}".format(self.fg.name, self.inv.name), category=category, **kw)
        self.findings.append(f)
        return f


def by_trust(level: str, internet=CRITICAL, low=HIGH, other=MEDIUM) -> str:
    if level == "internet":
        return internet
    if RANK[level] <= RANK["dmz"]:
        return low
    return other


def run(x: XContext) -> None:
    waf = [p for p in x.topo.paths if p.kind == "waf"]
    if not waf:
        x.add("XC-NO-LINK", MEDIUM, CAT_PATH,
              "No FortiGate policy delivers traffic to a FortiWeb virtual server",
              detail="Either the two configs are not from the same site, the FortiWeb sits in a "
                     "transparent mode, or published sites reach their servers without the WAF. "
                     "Path checks below are limited.",
              evidence={"fortiweb_addresses": [ip_text(h) for h in x.topo.fwb_hosts]})
    _bypass(x)
    _waf_paths(x, waf)
    _admin(x)
    _identity(x, waf)
    _tls(x, waf)
    _inspection(x, waf)
    _addressing(x)
    _logging(x, waf)
    _quarantine(x)


# ── WAF bypass ───────────────────────────────────────────────────────────────

def _bypass(x: XContext) -> None:
    transparent = x.inv.opmode in ("transparent", "transparent-inspection", "wccp")
    groups: Dict[tuple, List[Path]] = {}
    for path in [p for p in x.topo.paths if p.kind == "backend"]:
        groups.setdefault((path.policy.policyid, path.vip.name if path.vip else ""), []).append(path)
    for group in groups.values():
        path = group[0]
        hit = []
        for g in group:
            for s in g.backends:
                if g.ports.overlaps(IntervalSet([(ns.TCP_BASE + s.port, ns.TCP_BASE + s.port)])):
                    hit.append(s)
        if not hit:
            continue
        reach = sorted({s.port for s in hit})
        servers = ", ".join(sorted({"{}:{} (pool {})".format(ip_text(s.host), s.port, s.pool) for s in hit}))
        if transparent:
            x.add("XC-BYPASS-TRANSPARENT", INFO, CAT_PATH,
                  "{}: the server {} is published directly; with FortiWeb in {} mode it is protected only "
                  "if the cabling puts FortiWeb inline".format(path.label, servers, x.inv.opmode),
                  policies=[path.policy.policyid])
            continue
        if path.vip is not None:
            x.add("XC-BYPASS-VIP", by_trust(path.source_trust), CAT_PATH,
                  "FortiGate VIP '{}' publishes a FortiWeb-protected server directly: {}".format(
                      path.vip.name, servers),
                  policies=[path.policy.policyid], objects=[path.vip.name],
                  detail="Policy {} lets {} traffic (from {}) reach the server without passing FortiWeb, so "
                         "none of the WAF protection applies on this path.".format(
                             path.policy.label, path.source_trust, path.source_interface),
                  recommendation="Point the VIP's mapped IP at the FortiWeb virtual server instead, or remove "
                                 "the VIP if the FortiWeb publishing replaces it.",
                  evidence={"vip": path.vip.name, "servers": servers, "ports": reach})
        else:
            x.add("XC-BYPASS-POLICY", by_trust(path.source_trust), CAT_PATH,
                  "FortiGate policy {} lets {} networks reach FortiWeb-protected servers directly: {}".format(
                      path.policy.label, path.source_trust, servers),
                  policies=[path.policy.policyid],
                  detail="Traffic from {} reaches the web servers on port(s) {} without the WAF.".format(
                      path.source_interface, ", ".join(str(p) for p in reach)),
                  recommendation="Only FortiWeb should reach the servers on web ports. Narrow the "
                                 "destination or service, or send these users through the FortiWeb "
                                 "virtual server.")
    # Servers sharing the FortiWeb's client-facing segment on the FortiGate
    for host, servers in x.topo.backend_hosts.items():
        fg_if = x.fg.interface_for(host)
        if not fg_if:
            continue
        vip_ifs = {x.fg.interface_for(v.host) for v in x.inv.vips if v.host is not None}
        if fg_if in vip_ifs and not transparent:
            x.add("XC-BYPASS-SEGMENT", MEDIUM, CAT_PATH,
                  "Protected server {} sits on the same FortiGate segment ({}) as the FortiWeb virtual "
                  "servers".format(ip_text(host), fg_if),
                  objects=[s.pool for s in servers],
                  detail="Anything on that segment, or any FortiGate policy towards it, can reach the "
                         "server without the WAF. A separate server segment that only FortiWeb can "
                         "reach is safer.")


def _waf_paths(x: XContext, waf: List[Path]) -> None:
    for path in waf:
        listen = set()
        for sp in path.fwb_policies:
            listen.update(sp.ports)
        reaching = tcp_ports(path.ports)
        if path.vip is not None and path.vip.mapped_tcp is None and path.all_ports():
            x.add("XC-VIP-ALL-PORTS", HIGH if path.source_trust == "internet" else MEDIUM, CAT_PATH,
                  "FortiGate VIP '{}' forwards every port to the FortiWeb address {}".format(
                      path.vip.name, ip_text(path.host)),
                  policies=[path.policy.policyid], objects=[path.vip.name],
                  detail="The VIP has no port forwarding and policy {} allows all services, so every "
                         "service FortiWeb runs on that address is reachable.".format(path.policy.label),
                  recommendation="Enable port forwarding on the VIP for the web ports only.")
        elif listen and not path.all_ports():
            extra = [pt for pt in reaching if pt not in listen]
            if extra:
                x.add("XC-SVC-WIDER", INFO, CAT_PATH,
                      "{} allows port(s) {} that no FortiWeb server policy listens on".format(
                          path.label, ", ".join(str(p) for p in extra[:8])),
                      policies=[path.policy.policyid])
        if listen and path.vip is not None and path.vip.mapped_tcp is not None:
            mapped = tcp_ports(path.vip.mapped_tcp)
            if mapped and not any(pt in listen for pt in mapped):
                x.add("XC-PORT-MISMATCH", MEDIUM, CAT_PATH,
                      "FortiGate VIP '{}' sends port(s) {} to FortiWeb {}, which listens on {}".format(
                          path.vip.name, ", ".join(str(p) for p in mapped), ip_text(path.host),
                          ", ".join(str(p) for p in sorted(listen))),
                      policies=[path.policy.policyid], objects=[path.vip.name],
                      detail="Requests on this path match no FortiWeb server policy and are dropped.")
        if not path.fwb_policies:
            x.add("XC-UNPROTECTED-APP", MEDIUM, CAT_PATH,
                  "{} reaches a FortiWeb virtual server with no enabled server policy".format(path.label),
                  policies=[path.policy.policyid])
        for sp in path.fwb_policies:
            weak = []
            if not sp.profile:
                weak.append("no protection profile")
            if sp.get("monitor-mode") == "enable":
                weak.append("monitor mode (log only)")
            if sp.get("noparse") == "enable":
                weak.append("noparse (no inspection)")
            if weak:
                x.add("XC-UNPROTECTED-APP", by_trust(path.source_trust, CRITICAL, HIGH, MEDIUM), CAT_PATH,
                      "Published through FortiGate policy {}, FortiWeb server policy '{}' does not block "
                      "attacks: {}".format(path.policy.label, sp.name, ", ".join(weak)),
                      policies=[path.policy.policyid, sp.name],
                      detail="The FortiGate treats this site as WAF-protected, but the WAF only passes or logs it.")


def _admin(x: XContext) -> None:
    for path in [p for p in x.topo.paths if p.kind == "waf-admin"]:
        x.add("XC-WAF-ADMIN-EXPOSED", by_trust(path.source_trust, CRITICAL, HIGH, INFO), CAT_PATH,
              "{} reaches the FortiWeb management interface ({})".format(path.label, ", ".join(path.admin_services)),
              policies=[path.policy.policyid],
              detail="FortiWeb accepts {} on {} and FortiGate policy {} lets {} sources reach it.".format(
                  "/".join(path.admin_services), ip_text(path.host), path.policy.label, path.source_trust),
              recommendation="Allow FortiWeb administration only from a management network or VPN.")


# ── Client identity ──────────────────────────────────────────────────────────

def _identity(x: XContext, waf: List[Path]) -> None:
    inv = x.inv
    xff_rules = inv.table("waf x-forwarded-for")
    ip_lists = inv.objects("waf ip-list")
    for path in waf:
        snat = x.fg.snat_sources(path.policy)
        for sp in path.fwb_policies:
            prof = inv.profile(sp.profile)
            rule = xff_rules.get(prof.get("x-forwarded-for-rule")) if prof is not None else None
            trusted = clientip.trusted_ips(inv, rule) if rule is not None else []
            reads_header = rule is not None and (on(rule, "tracing-original-ip") or on(rule, "block-based-on-original-ip"))
            if snat is not None:
                ip_features = []
                if prof is not None:
                    for key, label in (("ip-intelligence", "IP reputation"), ("geo-block-list-policy", "geo blocking"),
                                       ("application-layer-dos-prevention", "per-client DoS limits"),
                                       ("ip-list-policy", "IP lists"), ("bot-mitigate-policy", "bot detection")):
                        if (prof.get(key) == "enable") if key == "ip-intelligence" else prof.get(key):
                            ip_features.append(label)
                trusts_fg = reads_header and any(_in(snat, t) for t in trusted)
                if not trusts_fg or not path.vip or not path.vip.adds_xff:
                    x.add("XC-SNAT-HIDES-CLIENT", HIGH if ip_features else MEDIUM, CAT_ID,
                          "FortiGate policy {} source-NATs traffic to FortiWeb policy '{}': every request appears "
                          "to come from {}".format(path.policy.label, sp.name, ns.describe_v4(snat) or "the FortiGate"),
                          policies=[path.policy.policyid, sp.name],
                          detail="FortiWeb blocks, rate limits and logs by source address. With NAT, {} "
                                 "act on the FortiGate's address, so one bad client can get everyone blocked "
                                 "(block-period), and attack logs lose the real client.".format(
                                     ", ".join(ip_features) or "these features"),
                          recommendation="Disable NAT on the inbound policy (VIP traffic keeps the client source), "
                                         "or use an HTTP load-balancing VIP that inserts X-Forwarded-For and "
                                         "trust only the FortiGate address in the FortiWeb XFF rule.")
                for lst in ip_lists:
                    for m in inv.sub(lst, "members"):
                        if m.get("type") == "trust-ip" and _in(snat, m.get("ip")):
                            x.add("XC-FWB-TRUSTS-FGT", CRITICAL, CAT_ID,
                                  "FortiWeb IP list '{}' trusts {}, the address every FortiGate-NATed request comes "
                                  "from: all traffic on policy {} skips the scans after the IP list check".format(
                                      lst.name, m.get("ip"), path.policy.label),
                                  policies=[path.policy.policyid, sp.name], objects=[lst.name])
            if reads_header and path.vip is not None and not path.vip.adds_xff:
                spoof_src = snat if snat is not None else None
                if not trusted or (spoof_src is not None and any(_in(spoof_src, t) for t in trusted)):
                    x.add("XC-XFF-SPOOFABLE", HIGH, CAT_ID,
                          "FortiWeb trusts X-Forwarded-For on '{}', but FortiGate policy {} does not set it: "
                          "clients can choose their own address".format(sp.name, path.policy.label),
                          policies=[path.policy.policyid, sp.name], objects=[rule.name],
                          detail="VIP '{}' is not an HTTP load-balancing VIP with http-ip-header, so the "
                                 "client's own header passes untouched, and FortiWeb accepts it from {}.".format(
                                     path.vip.name, "anyone" if not trusted else "the FortiGate NAT address"),
                          recommendation="Either stop reading the header (no proxy in front), or make the "
                                         "FortiGate set it (HTTP load-balancing VIP with http-ip-header) and "
                                         "trust only the FortiGate address.")


def _in(s: IntervalSet, text: str) -> bool:
    host = ip_of(text or "")
    return host is not None and s.overlaps(single(host))


# ── TLS ──────────────────────────────────────────────────────────────────────

def _tls(x: XContext, waf: List[Path]) -> None:
    for path in waf:
        vip = path.vip
        https_policies = [sp for sp in path.fwb_policies if sp.https]
        if vip is not None and vip.decrypts:
            if vip.ssl_mode != "full" and not https_policies:
                x.add("XC-TLS-CLEAR-HOP", MEDIUM, CAT_TLS,
                      "FortiGate VIP '{}' decrypts HTTPS (ssl-mode {}) and sends it to FortiWeb in clear".format(
                          vip.name, vip.ssl_mode or "half"),
                      policies=[path.policy.policyid], objects=[vip.name],
                      detail="Passwords and cookies cross the FortiGate-FortiWeb link unencrypted, and "
                             "FortiWeb's own TLS hardening (versions, ciphers, HSTS) does not apply to clients.")
            elif https_policies:
                x.add("XC-TLS-DOUBLE", INFO, CAT_TLS,
                      "TLS is terminated twice: by FortiGate VIP '{}' and again by FortiWeb ({})".format(
                          vip.name, ", ".join(sp.name for sp in https_policies)),
                      policies=[path.policy.policyid], objects=[vip.name],
                      detail="Clients see the FortiGate certificate and TLS settings. Both appliances hold "
                             "private keys for the site; keep versions and ciphers aligned.")
            if TLS_RANK.get(vip.ssl_min, 2) < TLS_RANK["tls-1.2"]:
                x.add("XC-TLS-WEAK-EDGE", HIGH, CAT_TLS,
                      "Clients reach the site through FortiGate VIP '{}', which accepts {} or newer{}".format(
                          vip.name, vip.ssl_min, " (FortiOS default, inferred)" if not vip.node.get("ssl-min-version") else ""),
                      policies=[path.policy.policyid], objects=[vip.name],
                      detail="FortiGate terminates the client TLS, so its settings, not FortiWeb's, decide "
                             "what clients can negotiate.",
                      cli="config firewall vip\n    edit \"{}\"\n        set ssl-min-version tls-1.2\n    next\nend".format(vip.name))
        if x.fg.deep_inspection(path.policy) and https_policies:
            x.add("XC-TLS-DOUBLE", INFO, CAT_TLS,
                  "FortiGate policy {} deep-inspects HTTPS that FortiWeb also decrypts".format(path.policy.label),
                  policies=[path.policy.policyid],
                  detail="FortiGate needs the server certificate and key (inbound inspection) and both "
                         "appliances must present the same certificate. Consider letting FortiWeb do the "
                         "web-layer TLS and using certificate inspection on the FortiGate.")
        for sp in https_policies:
            if vip is None or not vip.decrypts:
                old = [v for v in fwbtls.versions(sp.node) if v in ("1.0", "1.1")]
                if old and path.source_trust == "internet":
                    x.add("XC-TLS-WEAK-EDGE", HIGH, CAT_TLS,
                          "Internet clients reach FortiWeb policy '{}' through FortiGate policy {} and can "
                          "negotiate TLS {}".format(sp.name, path.policy.label, "/".join(old)),
                          policies=[path.policy.policyid, sp.name])


# ── Inspection ───────────────────────────────────────────────────────────────

def _inspection(x: XContext, waf: List[Path]) -> None:
    seen = set()
    for path in waf:
        p = path.policy
        if p.policyid in seen:
            continue
        seen.add(p.policyid)
        if path.source_trust == "internet" and not p.setting("ips-sensor") and not p.setting("profile-group"):
            x.add("XC-INSPECT-NO-IPS", MEDIUM, CAT_INSPECT,
                  "Inbound FortiGate policy {} to FortiWeb has no IPS sensor".format(p.label),
                  policies=[p.policyid],
                  detail="FortiWeb covers HTTP. IPS on the FortiGate still protects the FortiWeb itself and "
                         "catches network-level attacks (TLS, TCP) before they reach it.")
        if p.setting("waf-profile"):
            x.add("XC-INSPECT-DUP-WAF", INFO, CAT_INSPECT,
                  "FortiGate policy {} also applies FortiOS WAF profile '{}' to traffic FortiWeb inspects".format(
                      p.label, p.setting("waf-profile")),
                  policies=[p.policyid],
                  detail="Two WAFs with different rules make false positives harder to trace.")


# ── Addressing and routing ───────────────────────────────────────────────────

def _addressing(x: XContext) -> None:
    fg_hosts = x.fg.hosts()
    for v in x.inv.vips:
        if v.host is None or not v.enabled:
            continue
        if not x.fg.interface_for(v.host) and not x.fg.routed(v.host):
            x.add("XC-ADDR-UNKNOWN", INFO, CAT_NET,
                  "FortiWeb virtual server address {} ({}) is not on a FortiGate subnet or static route".format(
                      ip_text(v.host), v.vserver),
                  detail="The FortiGate may reach it through a dynamic route, or the configs may not be "
                         "from the same site.")
    for gw in x.inv.gateways():
        on_fg_subnet = x.fg.interface_for(gw)
        if gw in fg_hosts or not on_fg_subnet:
            continue
        x.add("XC-RETURN-PATH", MEDIUM, CAT_NET,
              "FortiWeb's default gateway {} is on the FortiGate segment {} but is not the FortiGate".format(
                  ip_text(gw), on_fg_subnet),
              detail="Replies may leave through another router and bypass the FortiGate (asymmetric "
                     "routing): FortiGate drops them or loses visibility. If it is a FortiGate HA or VRRP "
                     "virtual address, this is expected.")


# ── Logging and time ─────────────────────────────────────────────────────────

def _logging(x: XContext, waf: List[Path]) -> None:
    for path in waf:
        if path.policy.setting("logtraffic") == "disable":
            x.add("XC-LOG-FGT-OFF", MEDIUM, CAT_LOG,
                  "FortiGate policy {} to FortiWeb does not log traffic".format(path.policy.label),
                  policies=[path.policy.policyid],
                  detail="Without FortiGate logs the network side of an attack seen by FortiWeb cannot be traced.")
    fg = x.fg.log_servers()
    fw = fwblog.destinations(x.inv)
    fg_all = set(fg["fortianalyzer"] + fg["syslog"])
    fw_all = set(fw["fortianalyzer"] + [s for s, _ in fw["syslog"]])
    if not (fg_all & fw_all):
        x.add("XC-LOG-NO-COMMON", MEDIUM if (fg_all or fw_all) else HIGH, CAT_LOG,
              "FortiGate and FortiWeb do not send logs to a common FortiAnalyzer or syslog server",
              detail="FortiGate logs to {}; FortiWeb logs to {}. Correlating one attack across both "
                     "appliances needs both log streams in one place.".format(
                         ", ".join(sorted(fg_all)) or "nowhere remote", ", ".join(sorted(fw_all)) or "nowhere remote"),
              evidence={"fortigate": sorted(fg_all), "fortiweb": sorted(fw_all)})
    fwb_ntp = on(x.inv.flat("system global"), "ntpsync") or on(x.inv.flat("system ntp"), "ntpsync")
    fg_ntp = x.fg.ntp_state()
    if not fwb_ntp or fg_ntp == "disable":
        x.add("XC-NTP", MEDIUM, CAT_LOG,
              "Clocks are not both NTP-synchronised (FortiGate: {}, FortiWeb: {})".format(
                  fg_ntp, "enable" if fwb_ntp else "not enabled"),
              detail="Log timestamps from the two appliances cannot be lined up reliably.")


# ── FortiGate integration ────────────────────────────────────────────────────

def _quarantine(x: XContext) -> None:
    fgi = x.inv.flat("system fortigate-integration")
    server = ip_of(fgi.get("server"))
    if server is None:
        return
    fg_hosts = x.fg.hosts()
    if server not in fg_hosts:
        x.add("XC-QUARANTINE-WRONG-FGT", MEDIUM, CAT_INT,
              "FortiWeb's FortiGate integration points to {}, which is not an address of this FortiGate".format(
                  fgi.get("server")))
        return
    intf = fg_hosts[server]
    if "https" not in x.fg.iface_access.get(intf, []) and fgi.get("protocol", "HTTPS") == "HTTPS":
        x.add("XC-QUARANTINE-NO-ACCESS", MEDIUM, CAT_INT,
              "FortiWeb polls FortiGate {} over HTTPS, but interface {} does not allow HTTPS administration".format(
                  fgi.get("server"), intf),
              detail="The quarantine list download will fail.")
    if fgi.get("protocol") == "HTTP":
        x.add("XC-QUARANTINE-HTTP", HIGH, CAT_INT,
              "FortiWeb logs in to FortiGate {} over plain HTTP to fetch quarantined IPs".format(fgi.get("server")),
              detail="The FortiGate administrator credentials stored on FortiWeb cross the network in clear.")


def run_all(inv: Inventory, fg: FgView, topo: Topology) -> List[Finding]:
    x = XContext(inv, fg, topo)
    run(x)
    return x.findings


def path_table(topo: Topology) -> List[Dict]:
    rows = []
    for p in topo.paths:
        rows.append({
            "kind": p.kind,
            "fortigate_policy": p.policy.policyid,
            "fortigate_policy_name": p.policy.name,
            "source": "{} ({})".format(p.source_interface, p.source_trust),
            "vip": p.vip.name if p.vip else None,
            "target": ip_text(p.host),
            "target_is": topo.fwb_hosts.get(p.host) or ("server " + ", ".join(sorted({s.pool for s in p.backends}))),
            "ports": ns.describe_service(p.ports),
            "nat": p.policy.setting("nat") == "enable",
            "fortiweb_policies": [sp.name for sp in p.fwb_policies],
        })
    return rows
