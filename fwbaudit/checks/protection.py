"""Web protection profiles and every protection feature they switch on.

Three generic checks run for all features in ``catalog.PROFILE_FEATURES``
(coverage, broken references, detect-only actions). Deeper rules follow for
the features where the configuration says enough to judge quality: HTTP
constraints, application DoS, IP reputation, bots, allowed methods, cookies,
security headers, uploads and machine learning.

Rule IDs: ``COV-*``, ``REF-*``, ``ACT-*``, ``CONS-*``, ``DOS-*``, ``IPREP-*``,
``BOT-*``, ``METH-*``, ``COOKIE-*``, ``HDR-*``, ``UPLOAD-*``, ``ML-*``.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from policyaudit.config import Node
from policyaudit.model import INFO, MEDIUM

from ..catalog import CORE, DETECT_ONLY, OTHER_FEATURES, PROFILE_FEATURES, RECOMMENDED
from .common import Context, names, on

CAT = "Web protection profiles"
BOT_KEYS = ("bot-mitigate-policy", "advanced-bot-protection")


def lookup(ctx: Context, blocks, name: str) -> Optional[Node]:
    for b in blocks:
        node = ctx.inv.table(b).get(name)
        if node is not None:
            return node
    return None


def detect_only_actions(node: Node) -> List[str]:
    """Settings in an object (and its entries) whose action lets traffic through."""
    out = []
    stack = [("", node)]
    while stack:
        prefix, n = stack.pop()
        for key in n.settings:
            if key == "action" or (key.endswith("-action") and key != "default-action"):
                if n.get(key) in DETECT_ONLY:
                    out.append((prefix + key).strip())
        for child in n.children:
            stack.append(((prefix + child.name + " ") if child.kind == "edit" else prefix, child))
    return sorted(set(out))


def check(ctx: Context) -> None:
    inv = ctx.inv
    coverage: Dict[str, Dict[str, str]] = {}
    for prof_name, policies in inv.profiles_in_use().items():
        prof = inv.profile(prof_name)
        pol_names = [p.name for p in policies]
        if prof is None:
            continue
        row = coverage.setdefault(prof_name, {})
        missing_core, missing_rec = [], []
        for feat in PROFILE_FEATURES:
            value = prof.get(feat.key)
            if feat.key == "ip-intelligence":
                value = "enable" if on(prof, "ip-intelligence") else ""
            row[feat.name] = value
            if feat.key in BOT_KEYS:
                continue
            if not value:
                if feat.level == CORE and feat.key != "signature-rule":
                    missing_core.append(feat)
                elif feat.level == RECOMMENDED:
                    missing_rec.append(feat)
                continue
            if feat.blocks and feat.key not in ("signature-rule",):
                obj = lookup(ctx, feat.blocks, value)
                if obj is None:
                    ctx.add("REF-MISSING", INFO, CAT,
                            "Profile '{}' uses {} '{}', which is not defined in the backup "
                            "(predefined object or broken reference)".format(prof_name, feat.name, value),
                            objects=[prof_name, value], policies=pol_names)
                    continue
                weak = detect_only_actions(obj)
                if weak:
                    ctx.add("ACT-DETECT-ONLY", MEDIUM if feat.level != "situational" else INFO, feat.area,
                            "{} '{}' only logs, it does not block ({})".format(feat.name, value, names(weak, 4)),
                            objects=[value], policies=pol_names,
                            detail="An action of alert records the violation and lets the request through.")
        bots = [prof.get(k) for k in BOT_KEYS if prof.get(k)]
        row["Bot mitigation (any)"] = ", ".join(bots)
        if not bots:
            missing_core.append(next(f for f in PROFILE_FEATURES if f.key == "bot-mitigate-policy"))
        for feat in missing_core:
            ctx.add("COV-CORE-MISSING", MEDIUM, feat.area,
                    "Profile '{}' has no {}".format(prof_name, feat.name),
                    objects=[prof_name], policies=pol_names, detail=feat.why,
                    evidence={"feature": feat.name, "setting": feat.key})
        if missing_rec:
            ctx.add("COV-RECOMMENDED-MISSING", INFO, CAT,
                    "Profile '{}' does not use: {}".format(prof_name, ", ".join(f.name for f in missing_rec)),
                    objects=[prof_name], policies=pol_names,
                    detail="; ".join("{}: {}".format(f.name, f.why) for f in missing_rec))
        _deep(ctx, prof, pol_names)
    ctx.extras["coverage"] = coverage
    _other_features(ctx)


def _deep(ctx: Context, prof: Node, pols: List[str]) -> None:
    inv = ctx.inv
    cons = inv.table("waf HTTP-protocol-parameter-restriction").get(prof.get("HTTP-protocol-parameter-restriction"))
    if cons is not None:
        checks = [k for k in cons.settings if k.endswith("-check")]
        enabled = [k for k in checks if cons.get(k) == "enable"]
        if checks and not enabled:
            ctx.add("CONS-ALL-OFF", MEDIUM, CAT,
                    "HTTP protocol constraints '{}' have every check disabled".format(cons.name),
                    objects=[cons.name], policies=pols)
    dos = inv.table("waf application-layer-dos-prevention").get(prof.get("application-layer-dos-prevention"))
    if dos is not None:
        refs = {
            "HTTP-request-flood-prevention-rule": "waf HTTP-request-flood-prevention-rule",
            "HTTP-connection-flood-check-rule": "waf HTTP-connection-flood-check-rule",
            "layer4-access-limit-rule": "waf layer4-access-limit-rule",
            "layer4-connection-flood-check-rule": "waf layer4-connection-flood-check-rule",
        }
        used = [k for k in refs if dos.get(k)]
        if not used:
            ctx.add("DOS-EMPTY", MEDIUM, "DoS protection",
                    "DoS prevention policy '{}' references no flood or access-limit rule".format(dos.name),
                    objects=[dos.name], policies=pols)
        if dos.get(next(iter(refs))) and not on(dos, "enable-HTTP-session-based-prevention"):
            ctx.add("DOS-SESSION-OFF", INFO, "DoS protection",
                    "DoS policy '{}' sets an HTTP request flood rule but session-based prevention is off".format(
                        dos.name), objects=[dos.name], policies=pols)
        for key in used:
            rule = inv.table(refs[key]).get(dos.get(key))
            if rule is None:
                continue
            weak = detect_only_actions(rule)
            if weak:
                ctx.add("DOS-ALERT-ONLY", MEDIUM, "DoS protection",
                        "DoS rule '{}' ({}) only logs floods".format(rule.name, key),
                        objects=[rule.name], policies=pols)
    if on(prof, "ip-intelligence"):
        cats = inv.objects("waf ip-intelligence")
        live = [c for c in cats if c.get("status", "enable") == "enable"]
        if cats and not live:
            ctx.add("IPREP-ALL-OFF", MEDIUM, CAT,
                    "IP reputation is switched on in '{}' but every category is disabled".format(prof.name),
                    objects=[prof.name], policies=pols)
        weak = [c.get("category") or c.name for c in live if c.get("action", "alert_deny") in DETECT_ONLY]
        if weak:
            ctx.add("IPREP-ALERT", MEDIUM, CAT,
                    "IP reputation categories only log: {}".format(names(weak)), policies=pols)
    bmp = inv.table("waf bot-mitigate-policy").get(prof.get("bot-mitigate-policy"))
    if bmp is not None:
        kb = inv.table("waf known-bots").get(bmp.get("known-bots"))
        if kb is None and not bmp.get("threshold-based-detection") and not bmp.get("biometrics-based-detection"):
            ctx.add("BOT-EMPTY", MEDIUM, "Bot mitigation",
                    "Bot mitigation policy '{}' has no known-bots, threshold or biometrics detection".format(bmp.name),
                    objects=[bmp.name], policies=pols)
        if kb is not None:
            off = [k.split("-")[0] for k in ("scanner-status", "trojan-status", "dos-status", "spam-status",
                                            "crawler-status") if kb.get(k) == "disable"]
            if off:
                ctx.add("BOT-KNOWN-OFF", MEDIUM, "Bot mitigation",
                        "Known-bots rule '{}' does not detect: {}".format(kb.name, ", ".join(off)),
                        objects=[kb.name], policies=pols)
            weak = detect_only_actions(kb)
            if weak:
                ctx.add("BOT-ALERT-ONLY", MEDIUM, "Bot mitigation",
                        "Known-bots rule '{}' only logs: {}".format(kb.name, names(weak)),
                        objects=[kb.name], policies=pols)
        tb = inv.table("waf threshold-based-detection").get(bmp.get("threshold-based-detection"))
        if tb is not None:
            off = [k for k in ("crawler-detection", "scanner-detection", "slow-attack-detection",
                               "content-scraping-detection") if tb.get(k) == "disable"]
            if off:
                ctx.add("BOT-THRESHOLD-OFF", INFO, "Bot mitigation",
                        "Threshold bot detection '{}' has these detections off: {}".format(tb.name, ", ".join(off)),
                        objects=[tb.name], policies=pols)
    meth = inv.table("waf allow-method-policy").get(prof.get("allow-method-policy"))
    if meth is not None:
        allowed = [m.lower() for m in meth.get_list("allow-method")]
        risky = [m for m in allowed if m in ("trace", "connect")]
        if risky:
            ctx.add("METH-RISKY", MEDIUM, "Access & input rules",
                    "Allowed-methods policy '{}' permits {}".format(meth.name, ", ".join(m.upper() for m in risky)),
                    objects=[meth.name], policies=pols,
                    detail="TRACE enables cross-site tracing; CONNECT can turn the site into a proxy.")
        if "webdav" in allowed:
            ctx.add("METH-WEBDAV", INFO, "Access & input rules",
                    "Allowed-methods policy '{}' permits WebDAV methods".format(meth.name),
                    objects=[meth.name], policies=pols)
    ck = inv.table("waf cookie-security").get(prof.get("cookie-security-policy"))
    if ck is not None:
        if ck.get("security-mode", "no") == "no":
            ctx.add("COOKIE-NO-PROTECTION", MEDIUM, CAT,
                    "Cookie security policy '{}' neither signs nor encrypts cookies (security-mode no)".format(ck.name),
                    objects=[ck.name], policies=pols)
        flags = [f for f in ("secure-cookie", "HTTP-only") if ck.get(f) != "enable"]
        if flags:
            ctx.add("COOKIE-FLAGS", INFO, CAT,
                    "Cookie security policy '{}' does not add: {}".format(ck.name, ", ".join(flags)),
                    objects=[ck.name], policies=pols)
    hdr = inv.table("waf http-header-security").get(prof.get("HTTP-header-security"))
    if hdr is not None:
        present = {e.get("name") for e in inv.sub(hdr, "HTTP-header-security-list")}
        missing = [h for h in ("x-frame-options", "x-content-type-options", "content-security-policy")
                   if h not in present]
        if missing:
            ctx.add("HDR-MISSING", INFO, CAT,
                    "Security header policy '{}' does not add: {}".format(hdr.name, ", ".join(missing)),
                    objects=[hdr.name], policies=pols)
    up = inv.table("waf file-upload-restriction-policy").get(prof.get("file-upload-policy"))
    if up is not None:
        if not any(on(up, k) for k in ("av-scan", "trojan-detection", "fortisandbox-check", "icap-server-check")):
            ctx.add("UPLOAD-NO-SCAN", MEDIUM, CAT,
                    "Upload policy '{}' does not scan uploaded files for malware".format(up.name),
                    objects=[up.name], policies=pols,
                    cli="config waf file-upload-restriction-policy\n    edit \"{}\"\n        set av-scan enable\n"
                        "        set trojan-detection enable\n    next\nend".format(up.name))
        if on(up, "fortisandbox-check") and not ctx.inv.flat("system fortisandbox").get("server") and \
                ctx.inv.flat("system fortisandbox").get("type", "fsa") == "fsa":
            ctx.add("UPLOAD-FSA-MISSING", MEDIUM, CAT,
                    "Upload policy '{}' sends files to FortiSandbox, but no FortiSandbox is configured".format(up.name),
                    objects=[up.name], policies=pols)


def _other_features(ctx: Context) -> None:
    """Functions outside the profile: list which are configured (for the coverage table)."""
    inv = ctx.inv
    status = {}
    for feat in OTHER_FEATURES:
        configured = any(inv.objects(b) or inv.flat(b).settings for b in feat.blocks)
        status[feat.name] = "configured" if configured else ""
    ctx.extras["other_features"] = status
    ml = inv.objects("waf machine-learning-policy")
    if inv.active_policies() and not ml:
        ctx.add("ML-NONE", INFO, "Machine learning",
                "Machine-learning anomaly detection is not configured",
                detail="ML anomaly detection learns normal parameter values and catches zero-day "
                       "injection attacks that signatures miss. Its effectiveness depends on the "
                       "learned model, which a config backup does not contain.")
    for m in ml:
        if m.get("status", "enable") == "disable":
            ctx.add("ML-DISABLED", INFO, "Machine learning",
                    "Machine-learning policy {} is disabled".format(m.name), objects=[m.name])
        elif m.get("action-anomaly", "alert_deny") == "alert":
            ctx.add("ML-ALERT-ONLY", MEDIUM, "Machine learning",
                    "Machine-learning policy {} only logs anomalies (action-anomaly alert)".format(m.name),
                    objects=[m.name],
                    detail="Reasonable while the model is still learning; switch to alert_deny once tuned.")
