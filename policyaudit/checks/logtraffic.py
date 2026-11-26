"""Capability 8: policies with no logging (ported from utm.py).

Difference from the legacy check: a plain ``show`` backup leaves default
values out. FortiOS logs security events (``utm``) by default on accept
rules, so a missing ``logtraffic`` line is not reported as "disabled".
"""

from __future__ import annotations

from ..model import HIGH, INFO, MEDIUM
from .common import from_internet, names, to_internet

CAT = "Logging"


def check(ctx) -> None:
    utm_only = []
    for p in ctx.active():
        explicit = p.node.has("logtraffic")
        log = p.setting("logtraffic") or ("utm" if p.accepts else "disable")
        exposed = from_internet(ctx, p) or to_internet(ctx, p)
        if p.accepts and log == "disable":
            ctx.add("LOG-NONE", HIGH if exposed else MEDIUM, CAT,
                    "Policy {} accepts traffic without logging it".format(p.label),
                    policies=[p.policyid],
                    detail="logtraffic is disable: no record of who connected where, which "
                           "blocks incident investigation.",
                    recommendation="Set logtraffic all (or at least utm).",
                    cli="config firewall policy\n    edit {}\n        set logtraffic all\n    next\nend".format(p.policyid))
        elif p.accepts and log == "utm":
            utm_only.append(p)
        elif not p.accepts and log == "disable" and from_internet(ctx, p):
            ctx.add("LOG-DENY-NONE", MEDIUM, CAT,
                    "Deny policy {} drops internet traffic without logging{}".format(
                        p.label, "" if explicit else " (FortiOS default)"),
                    policies=[p.policyid],
                    recommendation="Log denied internet traffic so attacks and scans are visible.")
    if utm_only:
        ctx.add("LOG-UTM-ONLY", INFO, CAT,
                "{} accept polic{} only security events, not every session".format(
                    len(utm_only), "y logs" if len(utm_only) == 1 else "ies log"),
                policies=[p.policyid for p in utm_only],
                detail="Policies: {}. Sessions with no security event leave no log.".format(
                    names([p.label for p in utm_only], 8)),
                recommendation="Use logtraffic all on rules where you need full flow records.")
    log_setting = ctx.scope.flat("log setting")
    if log_setting.settings and log_setting.get("fwpolicy-implicit-log") != "enable":
        ctx.add("LOG-IMPLICIT-DENY", MEDIUM, CAT,
                "Traffic dropped by the implicit deny rule is not logged",
                detail="config log setting: fwpolicy-implicit-log is not enable.",
                recommendation="Enable it to see traffic no policy allows.",
                cli="config log setting\n    set fwpolicy-implicit-log enable\nend")
