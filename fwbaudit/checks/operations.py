"""Operations: FortiGuard updates, backups, HA, config sync, authentication
servers and integrations.

Rule IDs: ``UPD-*``, ``BKP-*``, ``HA-*``, ``SYNC-*``, ``AUTH-*``, ``INT-*``.
"""

from __future__ import annotations

from policyaudit.model import HIGH, INFO, MEDIUM

from .common import Context, on

CAT_UPD = "Updates & integrations"
CAT_HA = "High availability"
CAT_AUTH = "Authentication"


def check(ctx: Context) -> None:
    _updates(ctx)
    _backup(ctx)
    _ha(ctx)
    _auth(ctx)
    _integrations(ctx)


def _updates(ctx: Context) -> None:
    sched = ctx.inv.flat("system autoupdate schedule")
    if sched.get("status") == "disable":
        ctx.add("UPD-OFF", HIGH, CAT_UPD,
                "Scheduled FortiGuard updates are disabled: signatures, IP reputation and AV go stale",
                cli="config system autoupdate schedule\n    set status enable\n    set frequency daily\nend")
    elif not sched.settings:
        ctx.add("UPD-UNKNOWN", INFO, CAT_UPD,
                "No 'system autoupdate schedule' in the backup; check FortiGuard updates on the unit",
                detail="Signature and database versions are run-time state and are not in a config backup.")
    elif sched.get("frequency") == "weekly":
        ctx.add("UPD-WEEKLY", MEDIUM, CAT_UPD, "FortiGuard updates run only weekly",
                cli="config system autoupdate schedule\n    set frequency daily\nend")


def _backup(ctx: Context) -> None:
    backups = ctx.inv.objects("system backup")
    if not backups:
        ctx.add("BKP-NONE", INFO, CAT_UPD, "No scheduled configuration backup is configured")
    for b in backups:
        if b.get("protocol-type", "ftp") == "ftp":
            ctx.add("BKP-FTP", MEDIUM, CAT_UPD,
                    "Configuration backup '{}' is sent over plain FTP".format(b.name), objects=[b.name],
                    detail="The backup contains password hashes, keys and the whole security design.",
                    cli="config system backup\n    edit \"{}\"\n        set protocol-type sftp\n    next\nend".format(b.name))
        if not on(b, "encryption"):
            ctx.add("BKP-UNENCRYPTED", MEDIUM, CAT_UPD,
                    "Configuration backup '{}' is not encrypted".format(b.name), objects=[b.name])


def _ha(ctx: Context) -> None:
    ha = ctx.inv.flat("system ha")
    mode = ha.get("mode", "standalone") or "standalone"
    ctx.extras["ha_mode"] = mode
    if mode == "standalone":
        if ctx.inv.active_policies():
            ctx.add("HA-NONE", INFO, CAT_HA,
                    "FortiWeb is standalone: if it fails, the protected sites go down (or are exposed if "
                    "traffic is rerouted around it)")
        return
    if not on(ha, "encryption"):
        ctx.add("HA-NO-ENCRYPTION", MEDIUM, CAT_HA,
                "HA heartbeat and session-sync traffic is not encrypted",
                cli="config system ha\n    set encryption enable\nend")
    if not ha.get("hbdev-backup"):
        ctx.add("HA-ONE-HB", INFO, CAT_HA, "Only one HA heartbeat interface is set (no hbdev-backup)")
    if not ha.get("monitor"):
        ctx.add("HA-NO-MONITOR", MEDIUM, CAT_HA,
                "HA does not monitor any interface: a failed traffic link does not trigger failover")
    sync = ctx.inv.flat("system conf-sync")
    if sync.get("ip") and not sync.get("password"):
        ctx.add("SYNC-NO-PASSWORD", MEDIUM, CAT_HA, "Configuration sync peer has no password")


def _auth(ctx: Context) -> None:
    for ldap in ctx.inv.objects("user ldap-user"):
        secure = on(ldap, "ssl-connection") or ldap.get("protocol") in ("ldaps", "starttls") or ldap.get("port") == "636"
        if not secure:
            ctx.add("AUTH-LDAP-CLEAR", HIGH, CAT_AUTH,
                    "LDAP server '{}' is queried without TLS: user passwords cross the network in clear".format(ldap.name),
                    objects=[ldap.name],
                    cli="config user ldap-user\n    edit \"{}\"\n        set ssl-connection enable\n"
                        "        set protocol ldaps\n        set port 636\n    next\nend".format(ldap.name))
        elif not ldap.get("ca-cert"):
            ctx.add("AUTH-LDAP-NOCA", MEDIUM, CAT_AUTH,
                    "LDAP server '{}' uses TLS without a CA certificate to verify the server".format(ldap.name),
                    objects=[ldap.name])
        if ldap.get("bind-type") == "anonymous":
            ctx.add("AUTH-LDAP-ANON", INFO, CAT_AUTH, "LDAP server '{}' uses anonymous bind".format(ldap.name),
                    objects=[ldap.name])
    for rad in ctx.inv.objects("user radius-user"):
        if rad.get("auth-type") in ("pap", "chap"):
            ctx.add("AUTH-RADIUS-WEAK", MEDIUM, CAT_AUTH,
                    "RADIUS server '{}' uses {} authentication".format(rad.name, rad.get("auth-type").upper()),
                    objects=[rad.name], recommendation="Use MS-CHAPv2 or EAP where the server supports it.")
    for rule in ctx.inv.objects("waf site-publish-helper rule"):
        if rule.get("client-auth-method") == "HTTP-auth" and rule.get("auth-delegation") == "HTTP-basic":
            ctx.add("AUTH-BASIC", INFO, CAT_AUTH,
                    "Site publishing rule '{}' uses HTTP Basic authentication and delegation".format(rule.name),
                    objects=[rule.name], detail="Basic credentials are only protected by the TLS session.")


def _integrations(ctx: Context) -> None:
    inv = ctx.inv
    fgi = inv.flat("system fortigate-integration")
    uses_quarantine = any(inv.profile(n) is not None and on(inv.profile(n), "fortigate-quarantined-ips")
                          for n in inv.profiles_in_use())
    if fgi.get("server"):
        if fgi.get("protocol", "HTTPS") == "HTTP":
            ctx.add("INT-FGT-HTTP", HIGH, CAT_UPD,
                    "FortiGate integration to {} uses HTTP: the FortiGate admin credentials cross the network "
                    "in clear".format(fgi.get("server")),
                    cli="config system fortigate-integration\n    set protocol HTTPS\n    set port 443\n"
                        "    set server-verification enable\nend")
        elif not on(fgi, "server-verification"):
            ctx.add("INT-FGT-NOVERIFY", MEDIUM, CAT_UPD,
                    "FortiGate integration does not verify the FortiGate certificate", objects=[fgi.get("server")])
    if uses_quarantine and (not fgi.get("server") or not on(fgi, "flag")):
        ctx.add("INT-QUARANTINE-BROKEN", MEDIUM, CAT_UPD,
                "A protection profile blocks FortiGate-quarantined IPs, but FortiGate integration is not "
                "configured or not enabled (flag disable)",
                detail="FortiWeb never receives the quarantine list, so the setting has no effect.")
    for res in inv.objects("system external-resource"):
        if res.get("protocol", "HTTPS") == "HTTP" or res.get("verify-host-cert") == "disable":
            ctx.add("INT-FEED-INSECURE", MEDIUM, CAT_UPD,
                    "External IP feed '{}' is fetched without verified HTTPS".format(res.name), objects=[res.name],
                    detail="Someone on the path could inject addresses into a block or trust list.")
    fsa = inv.flat("system fortisandbox")
    if fsa.settings and fsa.get("type", "fsa") == "fsa" and not fsa.get("server"):
        ctx.add("INT-FSA-NOSERVER", INFO, CAT_UPD, "FortiSandbox is selected but no server address is set")
