"""Text, JSON and executive-summary reports, in the same style as utm.py.

The risk score uses utm.py's formula (CRITICAL x10, HIGH x5, MEDIUM x2,
INFO x0.5; CRITICAL rating with any critical finding or a score of 50+,
HIGH at 25+, MEDIUM at 10+), so FortiGate and FortiWeb scores can be compared.

Go mapping: ``internal/fortiweb/report``.
"""

from __future__ import annotations

import json
import textwrap
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from policyaudit.model import SEVERITY_ORDER, Finding

from . import DOCS_VERSION, __version__
from .catalog import ALL_FEATURES, OTHER_FEATURES, PROFILE_FEATURES

W = 80
ICON = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED] ", "INFO": "[INFO]"}
WEIGHTS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "INFO": 0.5}


def now_text() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def score(findings: List[Finding]) -> Dict[str, Any]:
    counts = Counter(f.severity for f in findings)
    total = sum(WEIGHTS[s] * counts.get(s, 0) for s in WEIGHTS)
    if counts.get("CRITICAL") or total >= 50:
        risk = "CRITICAL"
    elif total >= 25:
        risk = "HIGH"
    elif total >= 10:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    return {"counts": {s: counts.get(s, 0) for s in SEVERITY_ORDER}, "total": len(findings),
            "score": round(total, 1), "risk": risk}


def _wrap(text: str, indent: str) -> List[str]:
    out = []
    for para in text.split("\n"):
        out.extend(textwrap.wrap(para, W - len(indent), initial_indent=indent,
                                 subsequent_indent=indent) or [indent])
    return out


def _findings(L: List[str], findings: List[Finding], order: Optional[List[str]] = None) -> None:
    by_cat = defaultdict(list)
    for f in findings:
        by_cat[f.category].append(f)
    cats = [c for c in (order or []) if c in by_cat] + sorted(c for c in by_cat if c not in (order or []))
    for cat in cats:
        items = sorted(by_cat[cat], key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule_id))
        L += ["", "-" * W, "  {} ({})".format(cat.upper(), len(items)), "-" * W]
        for f in items:
            L.append("")
            L.extend(_wrap("{} {} [{}]".format(ICON.get(f.severity, ""), f.title, f.rule_id), "  "))
            if f.detail:
                L.extend(_wrap(f.detail, "         "))
            if f.recommendation:
                L.extend(_wrap("Action: " + f.recommendation, "         "))
            if f.cli:
                L.extend("           " + line for line in f.cli.splitlines())


def _header(L: List[str], title: str, rows: List[tuple], errors: List[str]) -> None:
    L += ["=" * W, " {} ".format(title).center(W, "="), "=" * W]
    if errors:
        L += ["", "!" * W, "  INCOMPLETE CONFIGURATION - results below may be wrong or missing."]
        L += ["  " + e for e in errors[:10]]
        L.append("!" * W)
    L.append("")
    for k, v in rows:
        L.append("  {:<14}: {}".format(k, v))


FWB_ORDER = ["Deployment mode", "Server policies", "Signatures", "Web protection profiles", "DoS protection",
             "Bot mitigation", "API protection", "Access & input rules", "Machine learning",
             "Client IP & X-Forwarded-For", "TLS & certificates", "Server pools & health checks",
             "System & admin access", "Authentication", "High availability", "Logging", "Updates & integrations"]


def render_fortiweb(result, config_path: str) -> str:
    s = score(result.findings)
    L: List[str] = []
    _header(L, "FORTIWEB SECURITY AUDIT", [
        ("Config", config_path), ("Generated", now_text()),
        ("Rules source", DOCS_VERSION),
        ("Risk", "{}  (score {}, CRITICAL x10 + HIGH x5 + MEDIUM x2 + INFO x0.5)".format(s["risk"], s["score"])),
        ("Findings", "  ".join("{} {}".format(k, v) for k, v in s["counts"].items())),
    ], result.errors)
    for dev in result.devices:
        L += ["", "  FortiWeb '{}' - operation mode {}{}".format(
            dev["name"], dev["opmode"], ", HA " + dev["ha_mode"] if dev.get("ha_mode") else "")]
        L.append("  {:<22} {:<26} {:<14} {}".format("Server policy", "Virtual IP", "Profile", "Servers"))
        for a in dev["applications"]:
            state = "" if a["enabled"] else " (disabled)"
            L.append("  {:<22} {:<26} {:<14} {}".format(
                (a["policy"] + state)[:22], ", ".join(a["virtual_ips"])[:26] or "-",
                (a["profile"] or "NONE")[:14] + (" [mon]" if a["monitor_mode"] else ""),
                ", ".join(a["servers"])[:40] or "-"))
    _coverage(L, result.devices)
    _findings(L, result.findings, FWB_ORDER)
    _certs(L, result.devices)
    L += ["", "=" * W, "  This tool reads configuration backups only and never changes the FortiWeb.",
          "  CLI shown is a review example. Finished in {:.2f} s".format(result.elapsed)]
    return "\n".join(L) + "\n"


def _coverage(L: List[str], devices) -> None:
    for dev in devices:
        cov = dev.get("coverage") or {}
        if not cov:
            continue
        L += ["", "-" * W, "  PROTECTION COVERAGE - which functions each in-use profile switches on", "-" * W]
        profiles = list(cov)
        L.append("  {:<36} {:<12} {}".format("Function", "Level", " ".join(p[:14].ljust(14) for p in profiles)))
        for feat in PROFILE_FEATURES:
            vals = [("on" if cov[p].get(feat.name) else "-") for p in profiles]
            L.append("  {:<36} {:<12} {}".format(feat.name[:36], feat.level, " ".join(v.ljust(14) for v in vals)))
        L.append("")
        L.append("  Other functions (not set per profile):")
        other = dev.get("other_features") or {}
        for feat in OTHER_FEATURES:
            depth = {"runtime": "config + needs live data", "deep": "audited", "generic": "presence"}[feat.depth]
            L.append("    {:<44} {:<11} ({})".format(feat.name[:44], other.get(feat.name) or "not set", depth))


def _certs(L: List[str], devices) -> None:
    for dev in devices:
        certs = dev.get("certificates") or []
        if not certs:
            continue
        L += ["", "-" * W, "  CERTIFICATES", "-" * W]
        L.append("  {:<22} {:<12} {:>6} {:<9} {:<14} {}".format("Name", "Expires", "Days", "Key", "Signature", "Used by"))
        for c in certs:
            if not c["readable"]:
                L.append("  {:<22} (certificate body not in the backup or unreadable)".format(c["name"][:22]))
                continue
            L.append("  {:<22} {:<12} {:>6} {:<9} {:<14} {}".format(
                c["name"][:22], c["not_after"] or "?", c["days_left"] if c["days_left"] is not None else "?",
                c["key"][:9], c["signature"][:14] + (" self" if c["self_signed"] else ""),
                ", ".join(c["used_by"])[:30] or "-"))


XC_ORDER = ["WAF path and bypass", "Client identity and trust", "TLS between the appliances",
            "Inspection consistency", "Addressing and routing", "Logging and time", "FortiGate integration"]


def render_cross(cross, fwb_path: str, fgt_path: str) -> str:
    s = score(cross.findings)
    L: List[str] = []
    _header(L, "FORTIGATE <-> FORTIWEB CROSS-CHECK", [
        ("FortiGate", fgt_path), ("FortiWeb", fwb_path), ("Generated", now_text()),
        ("Risk", "{}  (score {})".format(s["risk"], s["score"])),
        ("Findings", "  ".join("{} {}".format(k, v) for k, v in s["counts"].items())),
    ], cross.errors)
    L += [""] + _wrap("How to read this: each line in the path map is one way the FortiGate lets traffic "
                      "reach the FortiWeb or the servers behind it. 'waf' is the protected path. 'backend' "
                      "means the FortiGate delivers traffic straight to a protected server, so the WAF is "
                      "bypassed. 'waf-admin' means the FortiWeb management login is reachable.", "  ")
    for pair in cross.pairs:
        L += ["", "-" * W, "  PATH MAP - FortiGate VDOM {} -> FortiWeb {}".format(pair["fortigate_vdom"], pair["fortiweb"]),
              "-" * W]
        if not pair["paths"]:
            L.append("  (no FortiGate policy reaches a FortiWeb address or protected server)")
        L.append("  {:<10} {:<7} {:<20} {:<16} {:<16} {}".format("Kind", "Policy", "From", "VIP", "Target", "Ports"))
        for r in pair["paths"]:
            L.append("  {:<10} {:<7} {:<20} {:<16} {:<16} {}{}".format(
                r["kind"], r["fortigate_policy"][:7], r["source"][:20], (r["vip"] or "routed")[:16],
                r["target"][:16], r["ports"][:30], " NAT" if r["nat"] else ""))
    _findings(L, cross.findings, XC_ORDER)
    L += ["", "=" * W, "  Read-only analysis of two configuration backups. Live routing, cabling and HA state",
          "  are not visible in a backup. Finished in {:.2f} s".format(cross.elapsed)]
    return "\n".join(L) + "\n"


def render_summary(sections: Dict[str, List[Finding]], paths: Dict[str, str]) -> str:
    allf = [f for fs in sections.values() for f in fs]
    s = score(allf)
    L: List[str] = []
    _header(L, "FORTIWEB AUDIT - EXECUTIVE SUMMARY", [(k, v) for k, v in paths.items()] + [
        ("Risk Rating", s["risk"]), ("Risk Score", "{}  (CRITICAL x10 + HIGH x5 + MEDIUM x2 + INFO x0.5)".format(s["score"])),
        ("Total", s["total"])], [])
    L += [""] + ["  {:<12}{:>5}".format(k, v) for k, v in s["counts"].items()]
    L += ["", "  FINDINGS BY SECTION:", "  " + "-" * (W - 2),
          "  {:<40}  {:>4}  {:>4}  {:>4}  {:>4}  {:>5}".format("Section", "CRIT", "HIGH", "MED", "INFO", "TOT"),
          "  " + "-" * (W - 2)]
    by = defaultdict(Counter)
    for name, fs in sections.items():
        for f in fs:
            by["{}: {}".format(name, f.category)][f.severity] += 1
    for sec in sorted(by):
        c = by[sec]
        L.append("  {:<40}  {:>4}  {:>4}  {:>4}  {:>4}  {:>5}".format(
            sec[:40], c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["INFO"], sum(c.values())))
    L += ["", "  CRITICAL & HIGH FINDINGS:", "  " + "-" * (W - 2)]
    for name, fs in sections.items():
        for f in fs:
            if f.severity in ("CRITICAL", "HIGH"):
                L.extend(_wrap("[{}] {}: {} [{}]".format(name, f.severity, f.title, f.rule_id), "  "))
    L += ["", "=" * W]
    return "\n".join(L) + "\n"


def to_json(result, config_path: str, cross=None, fortigate_path: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "tool": "fwbaudit", "version": __version__, "rules_source": DOCS_VERSION,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "config": config_path, "complete": result.complete,
        "parse_errors": result.errors, "parse_warnings": result.warnings,
        "domains": result.domains,
        "summary": score(result.findings),
        "devices": result.devices,
        "feature_catalog": [{"name": f.name, "setting": f.key, "blocks": list(f.blocks), "area": f.area,
                             "level": f.level, "depth": f.depth} for f in ALL_FEATURES],
        "findings": [f.to_dict() for f in result.findings],
    }
    if cross is not None:
        out["crosscheck"] = {
            "fortigate_config": fortigate_path, "complete": cross.complete,
            "parse_errors": cross.errors, "warnings": cross.warnings,
            "summary": score(cross.findings), "pairs": cross.pairs,
            "findings": [f.to_dict() for f in cross.findings],
        }
    return out


def write(path, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def write_json(path, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
