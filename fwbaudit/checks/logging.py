"""Logging: attack, event and traffic logs, and remote log destinations.

Rule IDs: ``LOG-*``. Defaults from the FortiWeb 8.0 CLI Reference
(``log attack-log`` status default enable, ``log syslog-policy`` proto
default udp).
"""

from __future__ import annotations

from policyaudit.model import HIGH, INFO, MEDIUM

from .common import Context, on

CAT = "Logging"


def destinations(inv) -> dict:
    """Remote log servers: {"fortianalyzer": [ips], "syslog": [(ip, proto)]}."""
    faz, syslog = [], []
    fa = inv.flat("log forti-analyzer")
    if on(fa, "status"):
        policies = inv.table("log fortianalyzer-policy")
        pol = policies.get(fa.get("fortianalyzer-policy"))
        for entry in inv.sub(pol, "fortianalyzer-server-list") if pol is not None else []:
            faz.append(entry.get("ip-address"))
    sl = inv.flat("log syslogd")
    if on(sl, "status"):
        pol = inv.table("log syslog-policy").get(sl.get("policy"))
        if pol is not None:
            for block in ("syslog-server-list", "log-server-list"):
                for entry in inv.sub(pol, block):
                    syslog.append((entry.get("server"), entry.get("proto", "udp") or "udp"))
    return {"fortianalyzer": [x for x in faz if x], "syslog": [s for s in syslog if s[0]]}


def check(ctx: Context) -> None:
    inv = ctx.inv
    attack = inv.flat("log attack-log")
    if attack.get("status") == "disable":
        ctx.add("LOG-ATTACK-OFF", HIGH, CAT, "Attack logging is disabled: blocked and detected attacks leave no record",
                cli="config log attack-log\n    set status enable\nend")
    disk = inv.flat("log disk")
    if disk.get("status") == "disable":
        ctx.add("LOG-DISK-OFF", MEDIUM, CAT, "Local disk logging is disabled",
                detail="The CLI reference notes that attack logs are written to disk only when disk "
                       "logging is enabled.")
    event = inv.flat("log event-log")
    if event.get("status") == "disable":
        ctx.add("LOG-EVENT-OFF", MEDIUM, CAT, "Event logging (admin logins, configuration changes) is disabled",
                cli="config log event-log\n    set status enable\nend")
    traffic = inv.flat("log traffic-log")
    if traffic.get("status", "disable") != "enable":
        ctx.add("LOG-TRAFFIC-OFF", INFO, CAT, "Traffic logging is disabled globally",
                detail="Per-policy traffic logs (tlog) are only written when this is on.")

    dest = destinations(inv)
    ctx.extras["log_destinations"] = dest
    if not dest["fortianalyzer"] and not dest["syslog"]:
        ctx.add("LOG-NO-REMOTE", MEDIUM, CAT,
                "Logs are kept only on the FortiWeb itself (no FortiAnalyzer or syslog server)",
                detail="An attacker who gains admin access can delete local logs, and a failed disk loses them.")
    for server, proto in dest["syslog"]:
        if proto == "udp":
            ctx.add("LOG-SYSLOG-UDP", MEDIUM, CAT,
                    "Syslog to {} uses UDP: unencrypted and lost without notice under load".format(server),
                    recommendation="Use proto tls (or tcp).")
        elif proto == "tcp":
            ctx.add("LOG-SYSLOG-TCP", INFO, CAT, "Syslog to {} uses TCP without TLS".format(server))
    fa = inv.flat("log forti-analyzer")
    if on(fa, "status") and not dest["fortianalyzer"]:
        ctx.add("LOG-FAZ-BROKEN", MEDIUM, CAT,
                "FortiAnalyzer logging is enabled but its policy '{}' lists no server".format(fa.get("fortianalyzer-policy")))
