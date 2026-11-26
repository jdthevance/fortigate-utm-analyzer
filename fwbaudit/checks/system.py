"""Operation mode, administrator access and system hardening.

Rule IDs: ``MODE-*``, ``ADMIN-*``, ``IFACE-*``, ``SYS-*``, ``SNMP-*``.
Defaults quoted below come from the FortiWeb 8.0 CLI Reference
(``system global``, ``system admin``, ``system interface``,
``system password-policy``, ``system settings``).
"""

from __future__ import annotations

import ipaddress

from policyaudit.model import HIGH, INFO, MEDIUM

from .common import Context, names, on

CAT_MODE = "Deployment mode"
CAT = "System & admin access"


def check(ctx: Context) -> None:
    _mode(ctx)
    _admins(ctx)
    _interfaces(ctx)
    _global(ctx)
    _password_policy(ctx)
    _snmp(ctx)


def _mode(ctx: Context) -> None:
    mode = ctx.inv.opmode
    ctx.extras["opmode"] = mode
    if mode == "offline-protection":
        ctx.add("MODE-OFFLINE", HIGH, CAT_MODE,
                "FortiWeb runs in Offline Protection mode: it only watches a copy of the traffic",
                detail="In this mode FortiWeb is not in the traffic path. It can log attacks and try to "
                       "reset connections, but it cannot reliably block a request before it reaches "
                       "the server, and it cannot apply cookie, header or rewrite protection.",
                recommendation="Use Reverse Proxy (or True Transparent Proxy) mode for production "
                               "protection once tuning is finished.",
                cli="config system settings\n    set opmode reverse-proxy\nend")
    elif mode == "transparent-inspection":
        ctx.add("MODE-TI", MEDIUM, CAT_MODE,
                "FortiWeb runs in Transparent Inspection mode: requests are inspected asynchronously",
                detail="Transparent Inspection forwards packets while it inspects them, so the first "
                       "packets of an attack can reach the server before a block takes effect.",
                recommendation="Prefer True Transparent Proxy or Reverse Proxy where blocking must be "
                               "guaranteed.")
    elif mode == "wccp":
        ctx.add("MODE-WCCP", INFO, CAT_MODE,
                "FortiWeb runs in WCCP mode: protection depends on the FortiGate/WCCP router redirecting traffic",
                detail="Only traffic that the WCCP router sends to FortiWeb is inspected.")


def _trusted_hosts(admin):
    """Trusted hosts from ``trusthosts`` (8.0 syntax) or ``trusthost1..10`` (older syntax).

    Values look like ``10.0.0.0/24`` or ``10.0.0.0 255.255.255.0``.
    """
    tokens = admin.get_list("trusthosts")
    for i in range(1, 11):
        tokens += admin.get_list("trusthost{}".format(i))
    out, i = [], 0
    while i < len(tokens):
        item = tokens[i]
        if "/" not in item and i + 1 < len(tokens) and "/" not in tokens[i + 1]:
            item = "{}/{}".format(item, tokens[i + 1])
            i += 1
        try:
            out.append(ipaddress.IPv4Network(item, strict=False))
        except ValueError:
            pass
        i += 1
    return out


def _admins(ctx: Context) -> None:
    admins = ctx.inv.objects("system admin")
    open_admins = []
    for a in admins:
        nets = _trusted_hosts(a)
        if not nets or all(n.prefixlen == 0 for n in nets):
            open_admins.append(a.name)
        elif any(n.prefixlen < 16 for n in nets):
            ctx.add("ADMIN-TRUSTHOST-BROAD", MEDIUM, CAT,
                    "Administrator '{}' may log in from very large networks ({})".format(
                        a.name, ", ".join(str(n) for n in nets if n.prefixlen < 16)),
                    objects=[a.name],
                    recommendation="Limit trusted hosts to the management subnet or jump hosts.")
    if open_admins:
        ctx.add("ADMIN-NO-TRUSTHOST", HIGH, CAT,
                "{} administrator account(s) can log in from any IP address: {}".format(
                    len(open_admins), names(open_admins)),
                objects=open_admins,
                detail="No trusted host is set, or it is 0.0.0.0/0 (the default). Anyone who can "
                       "reach an interface with HTTPS or SSH access can try to log in.",
                recommendation="Set trusted hosts on every administrator account.",
                cli="config system admin\n    edit \"{}\"\n        set trusthosts 10.0.0.0/24\n    next\nend".format(
                    open_admins[0]))
    if any(a.name == "admin" for a in admins):
        ctx.add("ADMIN-DEFAULT-NAME", INFO, CAT,
                "The default 'admin' account still exists",
                objects=["admin"],
                recommendation="Create named administrator accounts and rename or restrict 'admin'; "
                               "default names are the first ones attackers try.")
    super_admins = [a.name for a in admins if a.get("access-profile") in ("prof_admin", "super_admin_prof")]
    if len(super_admins) > 3:
        ctx.add("ADMIN-MANY-SUPER", INFO, CAT,
                "{} accounts have full super-admin rights".format(len(super_admins)),
                objects=super_admins,
                recommendation="Give day-to-day accounts restricted access profiles.")
    ctx.extras["admins"] = [{"name": a.name, "trusted_hosts": [str(n) for n in _trusted_hosts(a)],
                             "profile": a.get("access-profile"), "type": a.get("type", "local-user")}
                            for a in admins]


def _interfaces(ctx: Context) -> None:
    data = ctx.inv.data_interfaces()
    for intf in ctx.inv.interfaces.values():
        svc = intf.admin_services
        if not svc or not intf.up:
            continue
        if "http" in svc:
            ctx.add("IFACE-HTTP-ADMIN", HIGH, CAT,
                    "Interface {} allows administration over plain HTTP".format(intf.name),
                    objects=[intf.name],
                    detail="Passwords and session cookies cross the network unencrypted.",
                    recommendation="Remove HTTP from allowaccess; keep HTTPS.",
                    cli="config system interface\n    edit \"{}\"\n        set allowaccess {}\n    next\nend".format(
                        intf.name, " ".join(sorted(a for a in intf.allowaccess if a != "http")) or "ping"))
        if intf.name in data and (svc & {"https", "ssh", "http"}):
            ctx.add("IFACE-ADMIN-ON-DATA", HIGH, CAT,
                    "Interface {} receives web traffic and also accepts administrator logins ({})".format(
                        intf.name, ", ".join(sorted(svc & {"https", "ssh", "http"}))),
                    objects=[intf.name],
                    detail="The same interface hosts a virtual server, so the management GUI/SSH is "
                           "reachable from wherever the protected website is reachable.",
                    recommendation="Use a dedicated management interface or network and remove admin "
                                   "access from traffic interfaces.")
        if "snmp" in svc:
            ctx.add("IFACE-SNMP", INFO, CAT, "Interface {} answers SNMP".format(intf.name),
                    objects=[intf.name], recommendation="Allow SNMP only on the management interface.")
        if "telnet" in svc:
            ctx.add("IFACE-TELNET", HIGH, CAT, "Interface {} allows Telnet".format(intf.name),
                    objects=[intf.name])


def _global(ctx: Context) -> None:
    g = ctx.inv.flat("system global")
    if not g.settings:
        ctx.add("SYS-NO-GLOBAL", INFO, CAT, "No 'config system global' block in the backup; "
                "global hardening could not be checked")
        return
    timeout = g.get("admintimeout", "5")
    if timeout.isdigit() and int(timeout) > 15:
        ctx.add("SYS-ADMIN-TIMEOUT", MEDIUM, CAT,
                "Idle administrator sessions stay open for {} minutes (default 5)".format(timeout),
                recommendation="Set admintimeout to 15 minutes or less.",
                cli="config system global\n    set admintimeout 10\nend")
    thr = g.get("admin-lockout-threshold", "3")
    if thr.isdigit() and int(thr) > 5:
        ctx.add("SYS-LOCKOUT", MEDIUM, CAT,
                "Accounts lock only after {} failed logins (default 3)".format(thr),
                cli="config system global\n    set admin-lockout-threshold 3\nend")
    for v in ("10", "11"):
        if on(g, "admin-tls-v" + v):
            ctx.add("SYS-ADMIN-TLS-OLD", HIGH, CAT,
                    "The management GUI accepts TLS 1.{} (deprecated, default disabled)".format(int(v) - 10),
                    cli="config system global\n    set admin-tls-v{} disable\nend".format(v))
    if g.get("multi-factor-authentication", "optional") != "mandatory":
        ctx.add("SYS-MFA-OPTIONAL", MEDIUM, CAT,
                "Two-factor authentication is optional for administrators",
                detail="FortiWeb supports mandatory 2FA (multi-factor-authentication mandatory); "
                       "with 'optional' a stolen password is enough to log in.",
                cli="config system global\n    set multi-factor-authentication mandatory\nend")
    if on(g, "shell-access"):
        sev = HIGH if not (g.get("shell-trusthostv4") or g.get("shell-trusthostv6")) else MEDIUM
        ctx.add("SYS-SHELL", sev, CAT,
                "Back-end shell access over SSH is enabled{}".format(
                    "" if sev == MEDIUM else " with no shell trusted hosts"),
                detail="Shell access bypasses the CLI's permission model. It is meant for support sessions.",
                cli="config system global\n    set shell-access disable\nend")
    if not on(g, "pre-login-banner"):
        ctx.add("SYS-BANNER", INFO, CAT, "No pre-login warning banner for administrators",
                cli="config system global\n    set pre-login-banner enable\nend")
    dh = g.get("dh-params", "2048")
    if dh.isdigit() and int(dh) < 2048:
        ctx.add("SYS-DH-WEAK", MEDIUM, "TLS & certificates",
                "Diffie-Hellman key size is {} bits (minimum 2048)".format(dh),
                cli="config system global\n    set dh-params 2048\nend")
    if on(g, "tftp"):
        ctx.add("SYS-TFTP", INFO, CAT, "TFTP is enabled for file transfers",
                recommendation="Disable TFTP when it is not needed for a firmware or backup task.")
    ntp_on = on(g, "ntpsync") or on(ctx.inv.flat("system ntp"), "ntpsync")
    explicit_off = g.get("ntpsync") == "disable" or ctx.inv.flat("system ntp").get("ntpsync") == "disable"
    if not ntp_on:
        ctx.add("SYS-NTP", MEDIUM if explicit_off else INFO, CAT,
                "Time is not synchronised with NTP{}".format("" if explicit_off else " (not found in the backup)"),
                detail="Without NTP, log timestamps drift and cannot be lined up with FortiGate, "
                       "FortiAnalyzer or server logs during an investigation.",
                cli="config system global\n    set ntpsync enable\n    set ntpserver \"pool.ntp.org\"\nend")
    ctx.extras["ntp"] = ntp_on


def _password_policy(ctx: Context) -> None:
    pp = ctx.inv.flat("system password-policy")
    if not pp.settings or not on(pp, "status"):
        ctx.add("SYS-PASSWORD-POLICY", MEDIUM, CAT,
                "No administrator password policy is enforced",
                recommendation="Enable a password policy with a minimum length of 12, character "
                               "requirements and no reuse.",
                cli="config system password-policy\n    set status enable\n    set min-length-option enable\n"
                    "    set mini-length 12\n    set character-requirements enable\n"
                    "    set forbid-password-reuse enable\nend")
        return
    length = pp.get("mini-length", "8")
    if on(pp, "min-length-option") and length.isdigit() and int(length) < 12:
        ctx.add("SYS-PASSWORD-LENGTH", INFO, CAT,
                "Minimum administrator password length is {}".format(length),
                recommendation="Use at least 12 characters.")
    if not on(pp, "character-requirements"):
        ctx.add("SYS-PASSWORD-COMPLEXITY", INFO, CAT, "Password policy does not require mixed characters")


def _snmp(ctx: Context) -> None:
    for c in ctx.inv.objects("system snmp community"):
        if c.get("status", "enable") == "disable":
            continue
        name = c.get("name") or c.name
        if name.lower() in ("public", "private"):
            ctx.add("SNMP-DEFAULT-COMMUNITY", HIGH, CAT,
                    "SNMP community uses the well-known name '{}'".format(name), objects=[name])
        hosts = [h.get("ip") for h in ctx.inv.sub(c, "hosts")]
        if not hosts or any(h.startswith("0.0.0.0") for h in hosts):
            ctx.add("SNMP-ANY-HOST", MEDIUM, CAT,
                    "SNMP community '{}' accepts queries from any manager".format(name), objects=[name])
        elif c.get("query-v1-status") == "enable":
            ctx.add("SNMP-V1", INFO, CAT, "SNMP v1 queries are enabled for community '{}'".format(name),
                    recommendation="Prefer SNMPv3 users (config system snmp user).")
