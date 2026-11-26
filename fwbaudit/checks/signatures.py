"""Attack signature policies (``config waf signature``) and signature updates.

Rule IDs: ``SIG-*``.

Signature classes and the default action come from the FortiWeb 8.0 CLI
Reference (``waf signature``): every ``main_class_list`` entry has the
default action **alert** (log only). A class that does not set
``action alert_deny`` (or another blocking action) therefore only logs.
"""

from __future__ import annotations

from policyaudit.model import HIGH, INFO, MEDIUM

from ..catalog import DETECT_ONLY
from ..inventory import BUILTIN_SIGNATURES
from .common import Context, names

CAT = "Signatures"

CLASSES = {
    "010000000": "Cross Site Scripting",
    "020000000": "Cross Site Scripting (Extended)",
    "030000000": "SQL Injection",
    "040000000": "SQL Injection (Extended)",
    "050000000": "Generic Attacks",
    "060000000": "Generic Attacks (Extended)",
    "070000000": "Trojans",
    "080000000": "Information Disclosure",
    "090000000": "Known Exploits",
    "100000000": "Personally Identifiable Information",
    "110000000": "Bad Robot",
    "120000000": "Other",
}
# Classes that should block on any internet-facing site.
MUST_BLOCK = ("010000000", "030000000", "050000000", "070000000", "090000000")


def check(ctx: Context) -> None:
    inv = ctx.inv
    sigs = inv.table("waf signature")
    in_use = {}
    for prof_name, policies in inv.profiles_in_use().items():
        prof = inv.profile(prof_name)
        if prof is None:
            continue
        rule = prof.get("signature-rule")
        if not rule:
            ctx.add("SIG-NONE", HIGH, CAT,
                    "Protection profile '{}' has no signature policy: SQL injection, XSS and known "
                    "exploits are not detected".format(prof_name),
                    objects=[prof_name], policies=[p.name for p in policies],
                    cli="config waf web-protection-profile inline-protection\n    edit \"{}\"\n"
                        "        set signature-rule \"<signature policy>\"\n    next\nend".format(prof_name))
            continue
        in_use.setdefault(rule, []).extend(p.name for p in policies)

    for rule, policies in in_use.items():
        if rule == "Alert Only":
            ctx.add("SIG-ALERT-ONLY", HIGH, CAT,
                    "Signature policy 'Alert Only' is in use: attacks are logged but never blocked",
                    objects=[rule], policies=policies)
            continue
        node = sigs.get(rule)
        if node is None:
            if rule not in BUILTIN_SIGNATURES:
                ctx.add("SIG-MISSING", MEDIUM, CAT,
                        "Signature policy '{}' is referenced but not defined".format(rule),
                        objects=[rule], policies=policies)
            continue
        _signature_set(ctx, node, policies)

    upd = inv.flat("waf signature_update_policy")
    if upd.settings and upd.get("status") == "disable":
        ctx.add("SIG-AUTO-APPLY-OFF", INFO, CAT,
                "New signatures from FortiGuard are staged and not applied automatically",
                detail="That is a valid change-control choice, but staged signatures must be reviewed "
                       "and applied regularly.")
    staged = [s for s in inv.objects("waf staged_signature_list") if s.get("status", "unapplied") == "unapplied"]
    if staged:
        ctx.add("SIG-STAGED", MEDIUM, CAT,
                "{} new signature(s) are staged and not applied".format(len(staged)),
                objects=[s.name for s in staged][:20])


def _signature_set(ctx: Context, node, policies) -> None:
    inv = ctx.inv
    classes = {e.name: e for e in inv.sub(node, "main_class_list")}
    disabled_classes = {e.name for e in inv.sub(node, "sub_class_disable_list")}
    not_blocking, off = [], []
    for cid in MUST_BLOCK:
        entry = classes.get(cid)
        if cid in disabled_classes or (entry is not None and entry.get("status") == "disable"):
            off.append(cid)
            continue
        action = (entry.get("action") if entry is not None else "") or "alert"
        if action in DETECT_ONLY:
            not_blocking.append(cid)
    label = lambda ids: ", ".join("{} ({})".format(CLASSES[i], i) for i in ids)  # noqa: E731
    if off:
        ctx.add("SIG-CLASS-DISABLED", HIGH, CAT,
                "Signature policy '{}' disables core attack classes: {}".format(node.name, label(off)),
                objects=[node.name], policies=policies)
    if not_blocking:
        ctx.add("SIG-CLASS-ALERT", HIGH, CAT,
                "Signature policy '{}' only logs (action alert) for: {}".format(node.name, label(not_blocking)),
                objects=[node.name], policies=policies,
                detail="alert is the default action for every signature class. Attacks are recorded "
                       "and still reach the server.",
                cli="config waf signature\n    edit \"{}\"\n        config main_class_list\n"
                    "            edit \"{}\"\n                set action alert_deny\n            next\n"
                    "        end\n    next\nend".format(node.name, not_blocking[0]))
    leak = [cid for cid in ("080000000", "100000000")
            if ((classes.get(cid).get("action") if classes.get(cid) is not None else "") or "alert") in DETECT_ONLY
            and cid not in disabled_classes]
    if leak:
        ctx.add("SIG-LEAK-ALERT", MEDIUM, CAT,
                "Signature policy '{}' does not hide data leaks for: {}".format(node.name, label(leak)),
                objects=[node.name], policies=policies,
                detail="Use alert_erase (cloaking) so server error pages and card numbers are removed "
                       "from responses.")
    no_log = [cid for cid, e in classes.items() if e.get("action") == "deny_no_log"]
    if no_log:
        ctx.add("SIG-NO-LOG", INFO, CAT,
                "Signature policy '{}' blocks without logging for: {}".format(
                    node.name, ", ".join(CLASSES.get(c, c) for c in no_log)),
                objects=[node.name], policies=policies)
    disabled_sigs = inv.sub(node, "signature_disable_list")
    if len(disabled_sigs) >= ctx.options.signature_disable_warn:
        ctx.add("SIG-MANY-DISABLED", MEDIUM, CAT,
                "Signature policy '{}' disables {} individual signatures".format(node.name, len(disabled_sigs)),
                objects=[node.name], policies=policies,
                recommendation="Review them: exceptions scoped by host and URL (filter_list) are safer "
                               "than disabling a signature everywhere.")
    elif disabled_sigs:
        ctx.add("SIG-SOME-DISABLED", INFO, CAT,
                "Signature policy '{}' disables {} signature(s): {}".format(
                    node.name, len(disabled_sigs), names([s.name for s in disabled_sigs])),
                objects=[node.name], policies=policies)
    alert_only = inv.sub(node, "alert_only_list")
    if alert_only:
        ctx.add("SIG-ALERT-LIST", MEDIUM, CAT,
                "Signature policy '{}' downgrades {} signature(s) to alert only".format(node.name, len(alert_only)),
                objects=[node.name], policies=policies)
    broad = []
    for e in inv.sub(node, "filter_list"):
        target, value = e.get("match-target"), e.get("value")
        if target in ("URI", "FULL_URL") and value in ("/", "/*", ".*", "*"):
            broad.append(e.name)
        elif target == "CLIENT_IP" and (e.get("ip", "").startswith("0.0.0.0") or e.get("ip", "").endswith("/0")):
            broad.append(e.name)
    if broad:
        ctx.add("SIG-EXCEPTION-BROAD", HIGH, CAT,
                "Signature policy '{}' has exceptions that match every URL or every client (entries {})".format(
                    node.name, ", ".join(broad)), objects=[node.name], policies=policies)
