"""TLS settings on the client side and server side, and certificates.

Rule IDs: ``TLS-*``, ``CERT-*``.

Important default, from the FortiWeb 8.0 CLI Reference (``server-policy
policy``): ``tls-v10`` and ``tls-v11`` are **enabled** by default, ``tls-v13``
is disabled, and ``ssl-cipher`` is ``medium``. A policy that does not set
them explicitly therefore accepts TLS 1.0 and 1.1.
"""

from __future__ import annotations

from datetime import datetime, timezone

from policyaudit.model import HIGH, INFO, MEDIUM

from .. import certs as certmod
from .common import Context, names

CAT = "TLS & certificates"
TLS_DEFAULTS = {"tls-v10": "enable", "tls-v11": "enable", "tls-v12": "enable", "tls-v13": "disable"}


def versions(node) -> list:
    out = []
    for key, label in (("tls-v10", "1.0"), ("tls-v11", "1.1"), ("tls-v12", "1.2"), ("tls-v13", "1.3")):
        if (node.get(key) or TLS_DEFAULTS[key]) == "enable":
            out.append(label)
    return out


def check(ctx: Context) -> None:
    inv = ctx.inv
    cert_table = inv.table("system certificate local")
    used_certs = {}
    for p in inv.active_policies():
        if not p.https:
            continue
        v = versions(p.node)
        ctx.extras.setdefault("tls", {})[p.name] = v
        old = [x for x in v if x in ("1.0", "1.1")]
        if old:
            implicit = [x for x in old if not p.node.has("tls-v1" + x[-1])]
            ctx.add("TLS-OLD-CLIENT", HIGH, CAT,
                    "Server policy '{}' accepts TLS {} from clients{}".format(
                        p.name, " and ".join(old), " (FortiWeb default)" if implicit else ""),
                    policies=[p.name],
                    detail="TLS 1.0 and 1.1 are deprecated (RFC 8996) and fail PCI DSS. FortiWeb "
                           "enables them by default on server policies.",
                    cli="config server-policy policy\n    edit \"{}\"\n        set tls-v10 disable\n"
                        "        set tls-v11 disable\n        set tls-v13 enable\n    next\nend".format(p.name))
        if "1.3" not in v:
            ctx.collect("TLS-NO-13", INFO, CAT, "TLS 1.3 is not offered on: {items}", p.name, policies=[])
        cipher = p.get("ssl-cipher", "medium") or "medium"
        if cipher == "medium":
            ctx.collect("TLS-CIPHER-MEDIUM", MEDIUM, CAT,
                        "{count} HTTPS server policies use the 'medium' cipher set (default): {items}", p.name,
                        policies=[],
                        detail="The medium set keeps older CBC and non-forward-secret suites for old clients.",
                        cli="config server-policy policy\n    edit \"{item}\"\n        set ssl-cipher high\n    next\nend")
        elif cipher == "custom":
            weak = [c for c in p.node.get_list("ssl-custom-cipher")
                    if any(w in c.upper() for w in ("RC4", "DES", "NULL", "EXPORT", "MD5", "ANON"))]
            if weak:
                ctx.add("TLS-CIPHER-WEAK", HIGH, CAT,
                        "Server policy '{}' allows weak ciphers: {}".format(p.name, names(weak)),
                        policies=[p.name])
        if p.get("ssl-noreg", "enable") == "disable":
            ctx.add("TLS-RENEGOTIATION", MEDIUM, CAT,
                    "Server policy '{}' accepts client-initiated TLS renegotiation".format(p.name),
                    policies=[p.name], detail="Renegotiation can be abused for denial of service.",
                    cli="config server-policy policy\n    edit \"{}\"\n        set ssl-noreg enable\n    next\nend".format(p.name))
        cert = p.get("certificate")
        if not cert and p.get("certificate-type") != "enable" and not p.get("lets-certificate") \
                and not p.get("certificate-group"):
            ctx.add("TLS-NO-CERT", MEDIUM, CAT,
                    "HTTPS server policy '{}' names no certificate".format(p.name), policies=[p.name],
                    detail="FortiWeb would present its default certificate, which browsers do not trust.")
        elif cert:
            used_certs.setdefault(cert, []).append(p.name)
        if p.get("ssl-client-verify"):
            ctx.extras.setdefault("client_cert_policies", []).append(p.name)

        # Server side: FortiWeb -> back-end servers
        servers = inv.backends_of(p)
        clear = [s for s in servers if s.enabled and not s.ssl]
        if clear and servers:
            ctx.add("TLS-BACKEND-CLEAR", MEDIUM, CAT,
                    "Server policy '{}' decrypts HTTPS and forwards it unencrypted to {} server(s) in "
                    "pool '{}'".format(p.name, len(clear), p.pool),
                    policies=[p.name], objects=[p.pool],
                    detail="Anything on the server network can read passwords and session cookies.",
                    recommendation="Enable SSL on the pool members (re-encryption), or make sure the "
                                   "server segment is isolated and only FortiWeb can reach it.")
        for s in servers:
            if not (s.enabled and s.ssl):
                continue
            if s.node.get("server-certificate-verify") != "enable" and not s.node.get("certificate-verify"):
                ctx.collect("TLS-BACKEND-NOVERIFY", MEDIUM, CAT,
                            "FortiWeb does not verify the back-end server certificate in pool(s): {items}", s.pool,
                            detail="Someone on the server network could impersonate the back end.")
            old = [x for x in versions(s.node) if x in ("1.0", "1.1")]
            if old:
                ctx.collect("TLS-OLD-BACKEND", MEDIUM, CAT,
                            "TLS 1.0/1.1 (FortiWeb default) is allowed towards back-end servers in pool(s): {items}",
                            s.pool)
    _certificates(ctx, cert_table, used_certs)


def _certificates(ctx: Context, table, used) -> None:
    now = datetime.fromtimestamp(ctx.now, timezone.utc)
    report = []
    for name, node in table.items():
        info = certmod.parse_pem(node.get("certificate"))
        policies = used.get(name, [])
        if info is None:
            report.append({"name": name, "readable": False, "used_by": policies})
            continue
        days = (info.not_after - now).days if info.not_after else None
        report.append({"name": name, "readable": True, "subject": info.subject_cn, "issuer": info.issuer_cn,
                       "not_after": info.not_after.strftime("%Y-%m-%d") if info.not_after else None,
                       "days_left": days, "key": "{} {}".format(info.key_type, info.key_bits),
                       "signature": info.signature, "self_signed": info.self_signed, "used_by": policies})
        where = " (used by {})".format(names(policies)) if policies else " (not used by a server policy)"
        sev_bump = bool(policies)
        if days is not None and days < 0:
            ctx.add("CERT-EXPIRED", HIGH if sev_bump else INFO, CAT,
                    "Certificate '{}' expired on {}{}".format(name, info.not_after.strftime("%Y-%m-%d"), where),
                    objects=[name], policies=policies)
        elif days is not None and days < ctx.options.cert_warn_days:
            ctx.add("CERT-EXPIRING", MEDIUM if sev_bump else INFO, CAT,
                    "Certificate '{}' expires in {} days{}".format(name, days, where),
                    objects=[name], policies=policies)
        if info.key_type == "RSA" and 0 < info.key_bits < 2048:
            ctx.add("CERT-WEAK-KEY", HIGH if sev_bump else MEDIUM, CAT,
                    "Certificate '{}' has a {}-bit RSA key{}".format(name, info.key_bits, where),
                    objects=[name], policies=policies)
        if info.weak_signature:
            ctx.add("CERT-WEAK-SIG", MEDIUM, CAT,
                    "Certificate '{}' is signed with {}{}".format(name, info.signature, where),
                    objects=[name], policies=policies)
        if info.self_signed and policies:
            ctx.add("CERT-SELF-SIGNED", MEDIUM, CAT,
                    "Self-signed certificate '{}' is presented to clients{}".format(name, where),
                    objects=[name], policies=policies,
                    detail="Browsers warn on self-signed certificates, which trains users to click through "
                           "warnings.")
    for name, policies in used.items():
        if name not in table and name not in {r["name"] for r in report}:
            ctx.add("CERT-MISSING", MEDIUM, CAT,
                    "Server policy uses certificate '{}', which is not in the backup".format(name),
                    objects=[name], policies=policies,
                    detail="Some backups leave out certificate bodies. If it is really missing, HTTPS fails.")
    ctx.extras["certificates"] = report
