"""Server policies, virtual servers, server pools and health checks.

Rule IDs: ``POL-*``, ``POOL-*``, ``HLTH-*``.
Defaults from the FortiWeb 8.0 CLI Reference (``server-policy policy``,
``server-policy server-pool``, ``server-policy health``).
"""

from __future__ import annotations

from policyaudit.model import HIGH, INFO, MEDIUM

from .common import Context, names, on

CAT = "Server policies"
CAT_POOL = "Server pools & health checks"


def check(ctx: Context) -> None:
    inv = ctx.inv
    vservers = inv.table("server-policy vserver")
    allow_hosts = inv.table("server-policy allow-hosts")
    if not inv.policies:
        ctx.add("POL-NONE", INFO, CAT, "No server policies are configured: FortiWeb protects no website")
    for p in inv.policies:
        if not p.enabled:
            ctx.add("POL-DISABLED", INFO, CAT, "Server policy '{}' is disabled".format(p.name), policies=[p.name])
            continue
        _policy(ctx, p, vservers, allow_hosts)
    _pools(ctx)


def _policy(ctx: Context, p, vservers, allow_hosts) -> None:
    inv = ctx.inv
    if on(p.node, "noparse"):
        ctx.add("POL-NOPARSE", HIGH, CAT,
                "Server policy '{}' is a pure proxy (noparse): no protection rule is applied".format(p.name),
                policies=[p.name],
                detail="With noparse enabled FortiWeb forwards traffic without parsing HTTP, so "
                       "signatures, constraints and every other rule are skipped.",
                cli="config server-policy policy\n    edit \"{}\"\n        set noparse disable\n    next\nend".format(p.name))
    if on(p.node, "monitor-mode"):
        ctx.add("POL-MONITOR-MODE", HIGH, CAT,
                "Server policy '{}' is in monitor mode: attacks are logged but never blocked".format(p.name),
                policies=[p.name],
                detail="monitor-mode overrides every deny and redirect action in the protection profile.",
                recommendation="Finish tuning, then disable monitor mode.",
                cli="config server-policy policy\n    edit \"{}\"\n        set monitor-mode disable\n    next\nend".format(p.name))
    if p.mode == "offline-protection":
        ctx.add("POL-OFFLINE", HIGH, CAT,
                "Server policy '{}' uses offline-protection deployment (monitoring only)".format(p.name),
                policies=[p.name])
    if not p.profile:
        ctx.add("POL-NO-PROFILE", HIGH, CAT,
                "Server policy '{}' has no web protection profile: traffic passes uninspected".format(p.name),
                policies=[p.name],
                recommendation="Attach an inline protection profile (for example a copy of "
                               "'Inline Standard Protection' tuned for this application).",
                cli="config server-policy policy\n    edit \"{}\"\n        set web-protection-profile \"<profile>\"\n    next\nend".format(p.name))
    elif inv.profile(p.profile) is None and not p.profile.lower().startswith("inline "):
        ctx.add("POL-PROFILE-MISSING", MEDIUM, CAT,
                "Server policy '{}' uses protection profile '{}', which is not defined in the backup".format(
                    p.name, p.profile),
                policies=[p.name], objects=[p.profile],
                detail="It may be a predefined profile (contents not in the backup) or a broken "
                       "reference. Predefined profiles are not audited.")
    if p.mode == "server-pool" and p.vserver and p.vserver not in vservers:
        ctx.add("POL-VSERVER-MISSING", MEDIUM, CAT,
                "Server policy '{}' uses virtual server '{}', which is not defined".format(p.name, p.vserver),
                policies=[p.name], objects=[p.vserver])
    if p.mode == "server-pool" and p.pool and p.pool not in inv.pools:
        ctx.add("POL-POOL-MISSING", MEDIUM, CAT,
                "Server policy '{}' uses server pool '{}', which is not defined".format(p.name, p.pool),
                policies=[p.name], objects=[p.pool])

    # Cleartext and redirect
    if p.http_service and not p.https:
        ctx.add("POL-HTTP-ONLY", MEDIUM, CAT,
                "Server policy '{}' serves the site over plain HTTP only".format(p.name), policies=[p.name],
                detail="Credentials and session cookies cross the internet unencrypted.",
                recommendation="Add an HTTPS service with a certificate, and redirect HTTP to HTTPS.")
    elif p.http_service and p.https and not on(p.node, "HTTP-to-HTTPS"):
        ctx.add("POL-NO-REDIRECT", MEDIUM, CAT,
                "Server policy '{}' accepts HTTP and HTTPS but does not redirect HTTP to HTTPS".format(p.name),
                policies=[p.name],
                cli="config server-policy policy\n    edit \"{}\"\n        set HTTP-to-HTTPS enable\n    next\nend".format(p.name))
    if p.https and not on(p.node, "hsts-header"):
        ctx.add("POL-NO-HSTS", MEDIUM, CAT,
                "Server policy '{}' does not send Strict-Transport-Security (HSTS)".format(p.name),
                policies=[p.name],
                detail="Without HSTS a browser can be tricked into a first plain-HTTP request (SSL stripping).",
                cli="config server-policy policy\n    edit \"{}\"\n        set hsts-header enable\n"
                    "        set hsts-max-age 31536000\n    next\nend".format(p.name))
    elif p.https and p.get("hsts-max-age").isdigit() and int(p.get("hsts-max-age")) < 15552000:
        ctx.add("POL-HSTS-SHORT", INFO, CAT,
                "HSTS max-age on '{}' is {} seconds (recommended at least 180 days)".format(
                    p.name, p.get("hsts-max-age")), policies=[p.name])
    if p.https and not (on(p.node, "internal-cookie-secure") and on(p.node, "internal-cookie-HTTPonly")):
        ctx.collect("POL-COOKIE-FLAGS", INFO, CAT,
                    "FortiWeb's own session cookies are not marked Secure and HttpOnly on: {items}", p.name,
                    policies=[],
                    cli="config server-policy policy\n    edit \"{item}\"\n        set internal-cookie-secure enable\n"
                        "        set internal-cookie-HTTPonly enable\n    next\nend")
    if not on(p.node, "syncookie"):
        ctx.collect("POL-NO-SYNCOOKIE", MEDIUM, "DoS protection",
                    "SYN cookies are off (default disabled) on {count} server policies: {items}", p.name,
                    policies=[],
                    detail="SYN cookies protect the virtual server against TCP SYN floods.",
                    cli="config server-policy policy\n    edit \"{item}\"\n        set syncookie enable\n    next\nend")
    # Host header restriction
    if not p.get("allow-hosts"):
        ctx.collect("POL-NO-ALLOW-HOSTS", INFO, CAT,
                    "{count} server policies accept any Host: header: {items}", p.name, policies=[],
                    detail="A protected-hosts list rejects requests for names the site does not serve "
                           "(host header attacks, scanning by IP address).",
                    recommendation="Create a server-policy allow-hosts list and set it on the policy.")
    elif p.get("allow-hosts") in allow_hosts:
        ah = allow_hosts[p.get("allow-hosts")]
        if ah.get("default-action", "allow") == "allow":
            ctx.add("POL-ALLOW-HOSTS-OPEN", MEDIUM, CAT,
                    "Protected-hosts list '{}' on '{}' still allows unknown hosts (default-action allow)".format(
                        ah.name, p.name), policies=[p.name], objects=[ah.name],
                    cli="config server-policy allow-hosts\n    edit \"{}\"\n        set default-action deny\n    next\nend".format(ah.name))
    if p.get("tlog", "disable") != "enable":
        ctx.collect("POL-NO-TRAFFIC-LOG", INFO, "Logging",
                    "Traffic logging is off on {count} server policies: {items}", p.name, policies=[],
                detail="Attack logs are still written; traffic logs record every request and help "
                       "investigations. They cost performance, so enable them where needed.")


def _pools(ctx: Context) -> None:
    inv = ctx.inv
    health = inv.table("server-policy health")
    used = {p.pool for p in inv.active_policies()}
    for pool in inv.pools.values():
        if pool.name not in used:
            continue
        servers = [s for s in pool.servers if s.enabled]
        if not servers:
            ctx.add("POOL-EMPTY", HIGH, CAT_POOL,
                    "Server pool '{}' has no enabled server: the site behind it is down".format(pool.name),
                    objects=[pool.name])
            continue
        balanced = pool.node.get("server-balance") == "enable"
        if balanced and len(servers) > 1 and not pool.node.get("health"):
            if not all(s.node.get("health-check-inherit", "enable") == "disable" and s.node.get("health")
                       for s in servers):
                ctx.add("HLTH-NONE", MEDIUM, CAT_POOL,
                        "Server pool '{}' load-balances {} servers with no health check".format(
                            pool.name, len(servers)),
                        objects=[pool.name],
                        detail="A failed server keeps receiving its share of requests.",
                        cli="config server-policy server-pool\n    edit \"{}\"\n        set health \"<health-check>\"\n    next\nend".format(pool.name))
        elif pool.node.get("health") and pool.node.get("health") not in health and \
                not pool.node.get("health").startswith("HLTHCK_"):
            ctx.add("HLTH-MISSING", MEDIUM, CAT_POOL,
                    "Server pool '{}' uses health check '{}', which is not defined".format(
                        pool.name, pool.node.get("health")), objects=[pool.name])
        if balanced and len(servers) == 1 and not any(s.node.get("backup-server") == "enable" for s in pool.servers):
            ctx.add("POOL-SINGLE", INFO, CAT_POOL,
                    "Server pool '{}' has a single server and no backup server".format(pool.name),
                    objects=[pool.name])
        domains = [s.domain for s in servers if not s.host and s.domain]
        if domains:
            ctx.add("POOL-DOMAIN", INFO, CAT_POOL,
                    "Server pool '{}' uses DNS names for servers ({}): their addresses are resolved at "
                    "run time and cannot be checked offline".format(pool.name, names(domains)),
                    objects=[pool.name])
    for h in health.values():
        for entry in inv.sub(h, "health-list"):
            if entry.get("type", "icmp") in ("icmp", "tcp", "tcp-half-open") and any(
                    pool.node.get("health") == h.name for pool in inv.pools.values()):
                ctx.add("HLTH-SHALLOW", INFO, CAT_POOL,
                        "Health check '{}' only tests {} reachability, not that the web application "
                        "answers".format(h.name, entry.get("type", "icmp").upper()), objects=[h.name],
                        recommendation="Use an HTTP check with a URL and expected response code or content.")
                break
