"""Real client IP handling: X-Forwarded-For rules and trusted IP lists.

Rule IDs: ``XFF-*``, ``IPLIST-*``.

From the FortiWeb 8.0 CLI Reference (``waf x-forwarded-for``): FortiWeb trusts
the header named in ``original-ip-header`` only when the packet comes from an
address in the rule's ``config ip-list``. With an empty list, any client can
write its own X-Forwarded-For value. ``waf signature`` warns that
``block-period`` actions behind a NAT device without an X-header rule can
end up blocking every client.
"""

from __future__ import annotations

import ipaddress

from policyaudit.model import HIGH, INFO, MEDIUM

from .common import Context, names, on

CAT = "Client IP & X-Forwarded-For"


def trusted_ips(inv, rule) -> list:
    """Upstream proxies whose X-Forwarded-For header FortiWeb believes."""
    return [e.get("ip") for e in inv.sub(rule, "ip-list") if e.get("ip")]


def check(ctx: Context) -> None:
    inv = ctx.inv
    rules = inv.table("waf x-forwarded-for")
    used = {}
    for prof_name, policies in inv.profiles_in_use().items():
        prof = inv.profile(prof_name)
        if prof is not None and prof.get("x-forwarded-for-rule"):
            used.setdefault(prof.get("x-forwarded-for-rule"), []).extend(p.name for p in policies)
    for name, policies in used.items():
        rule = rules.get(name)
        if rule is None:
            continue
        reads = on(rule, "tracing-original-ip") or on(rule, "block-based-on-original-ip")
        if reads and not trusted_ips(inv, rule):
            ctx.add("XFF-SPOOFABLE", HIGH, CAT,
                    "X-Forwarded-For rule '{}' trusts the client IP header from anyone (empty ip-list)".format(name),
                    objects=[name], policies=policies,
                    detail="An attacker can put any address in {} and FortiWeb will use it for blocking, "
                           "IP reputation and logs. They can dodge blocks or get an innocent address "
                           "blocked.".format(rule.get("original-ip-header") or "the header"),
                    recommendation="List the upstream proxy / FortiGate addresses in config ip-list.",
                    cli="config waf x-forwarded-for\n    edit \"{}\"\n        config ip-list\n"
                        "            edit 1\n                set ip \"<upstream proxy IP>\"\n            next\n"
                        "        end\n    next\nend".format(name))
        if on(rule, "tracing-original-ip") and not rule.get("original-ip-header"):
            ctx.add("XFF-NO-HEADER", MEDIUM, CAT,
                    "X-Forwarded-For rule '{}' traces the original IP but names no header".format(name),
                    objects=[name], policies=policies)
        if not on(rule, "x-forwarded-for-support") and not on(rule, "x-real-ip"):
            ctx.add("XFF-NOT-FORWARDED", INFO, CAT,
                    "X-Forwarded-For rule '{}' does not pass the client IP to the servers".format(name),
                    objects=[name], policies=policies,
                    detail="Back-end logs will show FortiWeb's address for every request.")
    ctx.extras["xff_rules"] = {n: {"policies": p, "trusted": trusted_ips(inv, rules[n]) if n in rules else [],
                                   "reads_header": bool(n in rules and (on(rules[n], "tracing-original-ip") or
                                                                        on(rules[n], "block-based-on-original-ip")))}
                               for n, p in used.items()}

    for lst in inv.objects("waf ip-list"):
        broad, trusted = [], []
        for m in inv.sub(lst, "members"):
            if m.get("type") != "trust-ip":
                continue
            ip = m.get("ip")
            trusted.append(ip)
            low = ip.split("-")[0].strip()
            try:
                if "/" in low:
                    net = ipaddress.IPv4Network(low, strict=False)
                    if net.prefixlen <= 16:
                        broad.append(ip)
                elif "-" in ip:
                    a, b = (int(ipaddress.IPv4Address(x.strip())) for x in ip.split("-", 1))
                    if b - a >= 65535:
                        broad.append(ip)
            except ValueError:
                continue
        if broad:
            ctx.add("IPLIST-TRUST-BROAD", HIGH, "Access & input rules",
                    "IP list '{}' trusts very large ranges ({}): requests from them skip every scan after the IP list check".format(
                        lst.name, names(broad)), objects=[lst.name])
        elif trusted:
            ctx.add("IPLIST-TRUSTED", INFO, "Access & input rules",
                    "IP list '{}' lets {} trusted address(es) skip the scans after the IP list check: {}".format(
                        lst.name, len(trusted), names(trusted)), objects=[lst.name])
