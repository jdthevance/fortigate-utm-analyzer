# FortiWeb Security Analyzer (`fwb.py`)

`fwb.py` audits a **FortiWeb** configuration backup offline, the same way `utm.py` audits a FortiGate. If you also give it the **FortiGate** backup, it checks how the two appliances work together. It looks for traffic that skips the WAF, real client addresses that get lost, TLS gaps between the boxes, and logging or time that doesn't match.

It needs only Python 3.8 or newer. Nothing else is installed and nothing is sent anywhere.

## Quick start

```bash
python3 fwb.py -c fortiweb.conf                              # audit every FortiWeb area
python3 fwb.py -c fortiweb.conf -tls -sig                    # only TLS and signatures
python3 fwb.py -c fortiweb.conf -fg fortigate.conf --all     # FortiWeb + cross-check + summary
python3 fwb.py -c fortiweb.conf -fg fortigate.conf --fortigate-vdom dmz --fail-on high
python3 -m fwbaudit -c fortiweb.conf                         # same thing, as a module
```

To get the backups:

* **FortiWeb:** run `show full-configuration` on the CLI, or use *System > Maintenance > Backup*. A full backup is better because it includes the default values. With a plain `show`, settings left at their default are missing. The tool then assumes the documented default, which is usually what you want.
* **FortiGate:** run `show full-configuration`, the same backup `utm.py` uses.

## Options

| Flag | What it does |
|---|---|
| `-c, --config FILE` | FortiWeb backup (required) |
| `-sys` | System: admin access, interfaces, SNMP, password policy, FortiGuard updates, backups, HA, authentication servers, integrations |
| `-pol` | Server policies, server pools, health checks, protected host names |
| `-tls` | TLS versions and ciphers on each policy, server-side TLS, certificates |
| `-sig` | Attack signatures: which classes block, which only alert, disabled signatures, exceptions |
| `-wp` | Web protection profiles and every protection feature (see the coverage table below) |
| `-ip` | Real client IP: X-Forwarded-For rules and trusted IP lists |
| `-log` | Attack, event and traffic logs, FortiAnalyzer and syslog destinations |
| `-fg, --fortigate FILE` | Also read the FortiGate backup and run the cross-check |
| `--fortigate-vdom NAME` | Only cross-check this FortiGate VDOM |
| `--trust-map FILE` | JSON that names the trust level of FortiGate interfaces or zones, for example `{"port1": "internet", "port5": "dmz"}`. This is the same format `utm.py -pa` uses. Without it, levels are guessed from interface names and roles. |
| `--summary` | Scored executive summary in the `utm.py` style |
| `--all` | Every domain, plus the summary |
| `--out-dir DIR` | Where to write reports. The default is the FortiWeb file name without its extension. |
| `--allow-incomplete` | Audit a truncated or broken backup anyway. Reports are marked INCOMPLETE. |
| `--fail-on critical\|high\|medium` | Exit with code 1 when a finding at or above that level exists. Use it in CI. |
| `--cert-warn-days N` | Warn about certificates that expire within N days (default 30) |

If you pass no domain flag, every domain runs.

## Output

All files go into the output folder:

| File | Contents |
|---|---|
| `<name>_fortiweb_audit_report.txt` | The published applications table, then the protection coverage matrix, findings grouped by area and a certificate table |
| `<name>_crosscheck_report.txt` | Only with `-fg`. A path map that shows every FortiGate rule that delivers traffic to the FortiWeb or its servers, then the cross-check findings |
| `<name>_fortiweb_summary.txt` | Only with `--summary` or `--all`. Score, rating, counts and the top issues |
| `<name>_fortiweb_audit.json` | Everything above in machine-readable form, including the feature catalog |

**Score and rating** are calculated the same way as in `utm.py`: CRITICAL × 10 + HIGH × 5 + MEDIUM × 2 + INFO × 0.5. Any CRITICAL finding, or a score of 50 or more, rates CRITICAL. A score of 25 or more rates HIGH, 10 or more rates MEDIUM, and anything lower rates LOW.

**Exit codes:** 0 means the run worked. 1 means `--fail-on` was met. 2 means an input problem, such as a missing file, a broken backup without `--allow-incomplete`, or a bad trust map.

Every finding carries a rule ID, a severity, a title, the policies and objects involved, a detail line, a recommendation and, where it helps, the CLI to fix it.

## How it works

1. **Parsing.** FortiWeb uses the same CLI layout as FortiOS (`config` / `edit` / `set` / `next` / `end`). The tool therefore reuses the parser from `policyaudit/`, which the FortiGate policy engine already uses and tests.
2. **Inventory** (`fwbaudit/inventory.py`). This step turns the parsed tree into the objects a FortiWeb publishes. Server policies point to a virtual server (the VIP clients connect to), a server pool (the real web servers), a web protection profile and a certificate.
3. **FortiWeb checks** (`fwbaudit/checks/`). One module covers each area. Each check reads the inventory and adds findings.
4. **Feature catalog** (`fwbaudit/catalog.py`). This is a list of every FortiWeb function in the 8.0 docs. It records whether the function is *core*, *recommended* or *situational*, and how deeply the tool can judge it from a backup. That list drives three checks that apply to every feature:
   * Is it missing from profiles that should have it? (`COV-*`)
   * Does the profile point to an object that doesn't exist? (`REF-MISSING`)
   * Is it set to only alert instead of block? (`ACT-DETECT-ONLY`)
5. **Cross-check** (`fwbaudit/crosscheck/`). This step reads the FortiGate backup with the `policyaudit` resolver, so every address, group, VIP, service and zone becomes real IP ranges and ports. For every enabled accept policy, it works out which inside addresses and TCP ports the policy actually delivers to. That can be through a VIP's mapped address and port, or by plain routing (it follows connected subnets and static routes). It then labels each address:
   * **waf**: a FortiWeb virtual server. This is the protected path.
   * **waf-admin**: a FortiWeb interface that accepts admin logins.
   * **backend**: a server that FortiWeb protects. Traffic that arrives here skipped the WAF. This is the key finding.
   * **waf-origin**: FortiWeb's own traffic to its servers. This is expected.

   The cross-check rules then work on these paths.

## What "every FortiWeb function" means here

JayDee asked for the whole product. The table below lists each FortiWeb function and how far the tool goes:

* **deep**: specific checks that judge how the feature is set up.
* **generic**: the tool checks whether the feature is in use, whether its references resolve, and whether it blocks or only alerts. A backup can't say much more than that.
* **runtime**: the result depends on live data that a backup doesn't contain, such as a trained ML model, the signature database version or scanner results. The tool checks the configuration and says live data is needed.

The coverage matrix in the report shows, for each web protection profile, which of these features it uses.

| Function | Area | Importance | Depth |
|---|---|---|---|
| Attack signatures | Signatures | core | deep |
| HTTP protocol constraints | Web protection | core | deep |
| Application DoS prevention (plus TCP SYN cookies on the policy) | DoS | core | deep |
| IP reputation (FortiGuard) | Web protection | core | deep |
| Bot mitigation | Bot mitigation | core | deep |
| Advanced bot protection (cloud) | Bot mitigation | situational | generic |
| Syntax-based SQLi/XSS detection | Signatures | recommended | generic |
| Allowed HTTP methods | Access & input | recommended | deep |
| Cookie security | Web protection | recommended | deep |
| HTTP security headers | Web protection | recommended | deep |
| File upload restriction and AV | Web protection | recommended | deep |
| X-Forwarded-For / real client IP | Client IP | recommended | deep |
| IP allow/block lists | Access & input | situational | deep |
| Geo IP blocking | Access & input | situational | generic |
| URL access rules | Access & input | situational | generic |
| Custom access (combination) rules | Access & input | situational | generic |
| Input (parameter) validation | Access & input | situational | generic |
| Hidden field protection | Access & input | situational | generic |
| CSRF protection | Web protection | situational | generic |
| Padding oracle protection | Web protection | situational | generic |
| User tracking | Web protection | situational | generic |
| Man-in-the-browser protection | Web protection | situational | generic |
| Client-side (JavaScript) protection | Web protection | situational | generic |
| Subresource integrity | Web protection | situational | generic |
| URL encryption | Web protection | situational | generic |
| OpenAPI schema validation | API protection | situational | generic |
| JSON validation | API protection | situational | generic |
| API gateway (keys and rate limits) | API protection | situational | generic |
| Mobile API protection | API protection | situational | generic |
| WebSocket security | API protection | situational | generic |
| CORS protection | API protection | situational | generic |
| Site publishing / SSO | Authentication | situational | deep |
| URL rewriting | Web protection | situational | generic |
| Compression | Web protection | situational | generic |
| Threat scoring | Web protection | situational | generic |
| File list policy | Web protection | situational | generic |
| Machine-learning anomaly detection | Machine learning | recommended | runtime |
| Machine-learning bot detection | Bot mitigation | situational | runtime |
| API discovery (learning) | API protection | situational | runtime |
| Web shell detection | Web protection | situational | generic |
| Waiting room | DoS | situational | generic |
| Server health checks | Server pools | recommended | deep |
| Session persistence | Server pools | situational | generic |
| Protected host names | Server policies | recommended | deep |
| ZTNA | Authentication | situational | generic |
| Authentication servers (LDAP, RADIUS) | Authentication | situational | deep |
| Web vulnerability scanner | Integrations | situational | runtime |
| FTP protection | Server policies | situational | generic |
| Malware scanning back ends (AV, FortiSandbox, ICAP) | Integrations | situational | deep |
| High availability | HA | recommended | deep |
| FortiGuard updates | Integrations | core | deep |
| Scheduled configuration backup | Integrations | recommended | deep |
| FortiGate quarantine integration | Integrations | situational | deep |
| Security Fabric | Integrations | situational | generic |
| Cloud connectors and threat feeds | Integrations | situational | deep |
| Automation stitches | Integrations | situational | generic |
| Certificate services (ACME, OCSP, CRL) | TLS & certificates | situational | deep |
| FIPS / Common Criteria mode | System | situational | generic |
| Server policies, TLS, admin access, SNMP, logging | (their own domains) | core | deep |

**What a backup can't tell you.** It can't tell you whether ML models finished learning, which signature and IP reputation database versions are loaded, whether health checks are currently passing, what the vulnerability scanner found, or how much traffic each rule really matches. For those, use the FortiWeb GUI or FortiAnalyzer.

## Rule reference

The severity shown is the usual one. Some rules go up or down with context: certificates by how soon they expire, and cross-check paths by how untrusted the source interface is. Internet-facing sources are the most serious.

### System and admin access (`-sys`)

| Rule | Sev | Meaning |
|---|---|---|
| MODE-OFFLINE | HIGH | Offline protection mode: FortiWeb only watches a copy of the traffic and can't block |
| MODE-TI | MEDIUM | Transparent inspection: packets are forwarded while being inspected, so the first packets of an attack can reach the server |
| MODE-WCCP | INFO | WCCP mode: the protection depends on the redirecting router |
| ADMIN-NO-TRUSTHOST | HIGH | An admin account can log in from any address |
| ADMIN-TRUSTHOST-BROAD | MEDIUM | An admin's trusted hosts are very large ranges |
| ADMIN-DEFAULT-NAME | INFO | The built-in `admin` account is still in use |
| ADMIN-MANY-SUPER | INFO | Many accounts have full (super admin) rights |
| IFACE-HTTP-ADMIN | HIGH | Admin GUI over plain HTTP |
| IFACE-ADMIN-ON-DATA | HIGH | Admin access on an interface that carries web traffic |
| IFACE-TELNET | HIGH | Telnet admin access |
| IFACE-SNMP | INFO | SNMP enabled on an interface |
| SYS-NO-GLOBAL | INFO | No `system global` block in the backup, so defaults are assumed |
| SYS-ADMIN-TIMEOUT | MEDIUM | Admin idle timeout is long |
| SYS-LOCKOUT | MEDIUM | Login lockout is weak or disabled |
| SYS-ADMIN-TLS-OLD | HIGH | Admin GUI accepts TLS 1.0 or 1.1 |
| SYS-MFA-OPTIONAL | MEDIUM | Multi-factor login is not required |
| SYS-SHELL | MEDIUM / HIGH | Back-end shell over SSH is enabled (HIGH when no shell trusted hosts are set) |
| SYS-BANNER | INFO | No pre-login banner |
| SYS-DH-WEAK | MEDIUM | Small Diffie-Hellman size |
| SYS-TFTP | INFO | TFTP allowed |
| SYS-NTP | MEDIUM / INFO | NTP is off (INFO when the backup doesn't show it) |
| SYS-PASSWORD-POLICY / -LENGTH / -COMPLEXITY | MEDIUM / INFO | Admin password policy off or weak |
| SNMP-DEFAULT-COMMUNITY | HIGH | SNMP community `public` or `private` |
| SNMP-ANY-HOST | MEDIUM | SNMP answers any host |
| SNMP-V1 | INFO | SNMP v1/v2c in use |
| UPD-OFF / UPD-UNKNOWN / UPD-WEEKLY | HIGH / INFO / MEDIUM | FortiGuard signature updates off, not set, or infrequent |
| BKP-NONE / BKP-FTP / BKP-UNENCRYPTED | INFO / MEDIUM / MEDIUM | No scheduled backup, backup over FTP, or backup not encrypted |
| HA-NONE / HA-NO-ENCRYPTION / HA-ONE-HB / HA-NO-MONITOR | INFO / MEDIUM / INFO / MEDIUM | No HA, clear HA traffic, a single heartbeat link, or no monitored ports |
| SYNC-NO-PASSWORD | MEDIUM | Config sync with no shared key |
| AUTH-LDAP-CLEAR / -NOCA / -ANON | HIGH / MEDIUM / INFO | LDAP in clear text, LDAPS without a CA check, or anonymous bind |
| AUTH-RADIUS-WEAK | MEDIUM | RADIUS uses a weak authentication type such as PAP |
| AUTH-BASIC | INFO | A site publishing rule uses HTTP Basic authentication |
| INT-FGT-HTTP / INT-FGT-NOVERIFY | HIGH / MEDIUM | FortiGate integration over HTTP, or without certificate checks |
| INT-QUARANTINE-BROKEN | MEDIUM | FortiGate quarantine enabled but not usable |
| INT-FEED-INSECURE | MEDIUM | Threat feed or connector over HTTP |
| INT-FSA-NOSERVER | INFO | Sandbox scanning on, but no FortiSandbox set |

### Server policies and pools (`-pol`)

| Rule | Sev | Meaning |
|---|---|---|
| POL-NONE | INFO | No server policies, so FortiWeb protects nothing |
| POL-DISABLED | INFO | A disabled policy |
| POL-NOPARSE | HIGH | Pure proxy (noparse): HTTP isn't parsed, so no protection rule applies |
| POL-MONITOR-MODE | HIGH | Monitor mode: attacks are logged but never blocked |
| POL-OFFLINE | HIGH | The policy uses offline-protection (monitoring only) |
| POL-NO-PROFILE | HIGH | No web protection profile |
| POL-PROFILE-MISSING / POL-VSERVER-MISSING / POL-POOL-MISSING | MEDIUM | The policy points to an object that doesn't exist |
| POL-HTTP-ONLY | MEDIUM | The application is served only over HTTP |
| POL-NO-REDIRECT | MEDIUM | HTTP isn't redirected to HTTPS |
| POL-NO-HSTS / POL-HSTS-SHORT | MEDIUM / INFO | No HSTS header, or a short max-age |
| POL-ALLOW-HOSTS-OPEN / POL-NO-ALLOW-HOSTS | MEDIUM / INFO | Any Host header is accepted |
| POL-COOKIE-FLAGS | INFO | FortiWeb's own cookies lack the Secure or HttpOnly flags |
| POL-NO-SYNCOOKIE | MEDIUM | No TCP SYN cookie protection |
| POL-NO-TRAFFIC-LOG | INFO | Traffic logging off on the policy |
| POOL-EMPTY | HIGH | Server pool with no servers |
| POOL-SINGLE / POOL-DOMAIN | INFO | A single server, or servers given by domain name |
| HLTH-NONE / HLTH-MISSING / HLTH-SHALLOW | MEDIUM / MEDIUM / INFO | No health check, a missing check, or only a ping or TCP check |

### TLS and certificates (`-tls`)

| Rule | Sev | Meaning |
|---|---|---|
| TLS-OLD-CLIENT | HIGH | Clients may use TLS 1.0 or 1.1. These are on by default in FortiWeb, and the title says so when that is the cause. |
| TLS-NO-13 | INFO | TLS 1.3 is off (also the default) |
| TLS-CIPHER-WEAK / TLS-CIPHER-MEDIUM | HIGH / MEDIUM | Weak cipher set, or the default `medium` set |
| TLS-RENEGOTIATION | MEDIUM | Client-initiated renegotiation allowed |
| TLS-NO-CERT | MEDIUM | HTTPS policy without a certificate |
| TLS-BACKEND-CLEAR | MEDIUM | FortiWeb talks to the servers in clear text |
| TLS-BACKEND-NOVERIFY | MEDIUM | Server certificates aren't verified |
| TLS-OLD-BACKEND | MEDIUM | Old TLS to the servers |
| CERT-EXPIRED / CERT-EXPIRING | HIGH / MEDIUM | Certificate expired or about to expire |
| CERT-WEAK-KEY / CERT-WEAK-SIG | HIGH / MEDIUM | RSA key under 2048 bits, or a SHA-1 or MD5 signature |
| CERT-SELF-SIGNED | MEDIUM | Self-signed certificate on a published site |
| CERT-MISSING | MEDIUM | A certificate is named but not in the backup |

### Attack signatures (`-sig`)

| Rule | Sev | Meaning |
|---|---|---|
| SIG-NONE | HIGH | A profile with no signature rule |
| SIG-MISSING | MEDIUM | The signature rule named in a profile doesn't exist |
| SIG-ALERT-ONLY | HIGH | Every class only alerts. This is the default action for the classes. |
| SIG-CLASS-DISABLED / SIG-CLASS-ALERT | HIGH | A must-block class (XSS, SQL injection, generic attacks, trojans, known exploits) is off or only alerts |
| SIG-LEAK-ALERT | MEDIUM | Information disclosure or personal data leaks are only alerted on |
| SIG-NO-LOG | INFO | A class doesn't log |
| SIG-STAGED | MEDIUM | New signatures are staged (alert only) |
| SIG-AUTO-APPLY-OFF | INFO | New signatures aren't applied automatically |
| SIG-MANY-DISABLED / SIG-SOME-DISABLED | MEDIUM / INFO | Many, or some, individual signatures are disabled |
| SIG-ALERT-LIST | MEDIUM | Individual signatures forced to alert |
| SIG-EXCEPTION-BROAD | HIGH | A signature exception that matches everything |

### Web protection profiles (`-wp`)

| Rule | Sev | Meaning |
|---|---|---|
| COV-CORE-MISSING | MEDIUM | A profile lacks a core feature (signatures, protocol constraints, DoS, IP reputation or bot mitigation) |
| COV-RECOMMENDED-MISSING | INFO | A profile lacks recommended features |
| REF-MISSING | INFO | A profile names an object that doesn't exist |
| ACT-DETECT-ONLY | MEDIUM / INFO | A feature only alerts or passes instead of blocking |
| CONS-ALL-OFF | MEDIUM | Protocol constraints exist but every check is off |
| DOS-EMPTY / DOS-SESSION-OFF / DOS-ALERT-ONLY | MEDIUM / INFO / MEDIUM | DoS policy is empty, has no per-session limits, or only alerts |
| IPREP-ALL-OFF / IPREP-ALERT | MEDIUM | IP reputation categories are off or only alert |
| BOT-EMPTY / BOT-KNOWN-OFF / BOT-ALERT-ONLY / BOT-THRESHOLD-OFF | MEDIUM / MEDIUM / MEDIUM / INFO | Bot policy is empty, doesn't stop known bad bots, only alerts, or has no rate-based detection |
| METH-RISKY / METH-WEBDAV | MEDIUM / INFO | TRACE, CONNECT or PUT/DELETE allowed, or WebDAV methods allowed |
| COOKIE-NO-PROTECTION / COOKIE-FLAGS | MEDIUM / INFO | Cookie security doesn't protect against tampering, or doesn't add Secure or HttpOnly |
| HDR-MISSING | INFO | Security headers missing from the header policy |
| UPLOAD-NO-SCAN / UPLOAD-FSA-MISSING | MEDIUM | Uploads aren't scanned for malware, or sandboxing is on but no FortiSandbox is set |
| ML-NONE / ML-DISABLED / ML-ALERT-ONLY | INFO / INFO / MEDIUM | No ML policy for an application, ML is off, or ML only alerts |

### Real client IP and trusted lists (`-ip`)

| Rule | Sev | Meaning |
|---|---|---|
| XFF-SPOOFABLE | HIGH | FortiWeb believes X-Forwarded-For from any sender, so attackers can choose their own address |
| XFF-NO-HEADER | MEDIUM | The XFF rule names no header to read |
| XFF-NOT-FORWARDED | INFO | The real client IP isn't passed on to the servers |
| IPLIST-TRUST-BROAD | HIGH | An IP list trusts a /16 or larger range. Trusted IPs skip every scan after the IP list check. |
| IPLIST-TRUSTED | INFO | Trusted addresses that skip those scans, listed for review |

### Logging (`-log`)

| Rule | Sev | Meaning |
|---|---|---|
| LOG-ATTACK-OFF | HIGH | Attack logging off |
| LOG-DISK-OFF / LOG-EVENT-OFF | MEDIUM | Local or event logging off |
| LOG-TRAFFIC-OFF | INFO | Traffic logging off |
| LOG-NO-REMOTE | MEDIUM | No FortiAnalyzer or syslog destination |
| LOG-SYSLOG-UDP / LOG-SYSLOG-TCP | MEDIUM / INFO | Syslog over UDP, or over TCP without TLS |
| LOG-FAZ-BROKEN | MEDIUM | FortiAnalyzer enabled but no address set |

### FortiGate ↔ FortiWeb cross-check (`-fg`)

| Rule | Sev | Meaning |
|---|---|---|
| XC-BYPASS-VIP | by source | A FortiGate VIP maps straight to a protected server and skips FortiWeb. From the internet this is CRITICAL. |
| XC-BYPASS-POLICY | by source | A FortiGate policy routes to a protected server directly |
| XC-BYPASS-TRANSPARENT | INFO | A server is published directly while FortiWeb runs in a transparent mode: it is protected only if the cabling puts FortiWeb inline |
| XC-BYPASS-SEGMENT | MEDIUM | A protected server sits on the same FortiGate segment as the FortiWeb virtual servers, so it can be reached without the WAF |
| XC-NO-LINK | MEDIUM | No FortiGate rule reaches the FortiWeb. Wrong pair of backups, or the site isn't published. |
| XC-VIP-ALL-PORTS | HIGH / MEDIUM | The VIP forwards every port to FortiWeb (no port forwarding) |
| XC-SVC-WIDER | INFO | The FortiGate allows more ports than FortiWeb listens on |
| XC-PORT-MISMATCH | MEDIUM | The FortiGate sends traffic to a port FortiWeb doesn't serve |
| XC-UNPROTECTED-APP | MEDIUM | A FortiWeb policy that no FortiGate rule reaches |
| XC-WAF-ADMIN-EXPOSED | by source | FortiWeb admin login reachable through the FortiGate (CRITICAL from the internet) |
| XC-SNAT-HIDES-CLIENT | HIGH / MEDIUM | The FortiGate NATs the source, so FortiWeb sees every client as one address. IP reputation, geo blocking, rate limits and DoS rules stop working. |
| XC-FWB-TRUSTS-FGT | CRITICAL | FortiWeb trusts the FortiGate's NAT address. Because every client arrives from it, all that traffic skips the scans after the IP list check. |
| XC-XFF-SPOOFABLE | HIGH | FortiWeb trusts X-Forwarded-For, but the FortiGate doesn't set it, so the client's own header gets through |
| XC-TLS-CLEAR-HOP | MEDIUM | One leg between the two boxes runs without encryption |
| XC-TLS-DOUBLE | INFO | Both boxes decrypt the same traffic |
| XC-TLS-WEAK-EDGE | HIGH | The FortiGate SSL VIP accepts weaker TLS than FortiWeb |
| XC-INSPECT-NO-IPS | MEDIUM | No IPS on the FortiGate policy in front of the WAF |
| XC-INSPECT-DUP-WAF | INFO | The FortiGate also applies its own WAF profile to traffic FortiWeb inspects |
| XC-ADDR-UNKNOWN | INFO | A FortiWeb virtual server address isn't on any FortiGate subnet or static route |
| XC-RETURN-PATH | MEDIUM | FortiWeb's gateway isn't the FortiGate, so replies may take another path |
| XC-LOG-FGT-OFF | MEDIUM | Logging is off on the FortiGate policy in front of the WAF |
| XC-LOG-NO-COMMON | MEDIUM / HIGH | The two boxes don't log to a common FortiAnalyzer or syslog server (HIGH when neither one logs remotely) |
| XC-NTP | MEDIUM | Time sync differs, so log timestamps won't line up |
| XC-QUARANTINE-WRONG-FGT / -NO-ACCESS / -HTTP | MEDIUM / MEDIUM / HIGH | FortiWeb's quarantine integration points to another address, can't reach the FortiGate's API, or uses HTTP |

## Documented versus inferred

Everything with a default value or a CLI name was taken from the **FortiWeb 8.0 CLI Reference**. The online 8.0 pages at docs.fortinet.com didn't render for automated reading, so the 8.0.2 download (whose content is version 8.0.1) was used. The following are **my inferences** and should be checked against a real device:

* **FortiGate SSL VIP default minimum TLS.** For `XC-TLS-WEAK-EDGE`, it is assumed to be TLS 1.1 when the backup doesn't say.
* **Trusted IPs.** The reference says a trust-ip "is trusted and allowed to access your web servers, unless it fails a previous scan". The tool reads that as "skips the scans that come after the IP list check", which matches the "Sequence of scans" chapter. Scans that run *before* the IP list still apply.
* **Predefined profiles.** Built-in protection profiles and signature sets (the `Inline Standard Protection` style names) aren't in a backup. They are treated as present and are not audited.
* **Defaults in `show` backups.** When a setting is missing, the tool assumes the documented default. If a firmware version uses a different default, the result can be wrong. A `show full-configuration` backup avoids this.
* **Certificate bodies.** Some backups leave out certificate PEMs. Then expiry and key checks can't run, and the tool says so.
* **Routing model.** The cross-check follows connected subnets and static routes. If the FortiGate uses BGP or OSPF, routed paths are assumed to work. Policy routes and SD-WAN rules aren't modelled.
* **Rule severities.** These are judgments in the `utm.py` style, not Fortinet ratings.

The sample configs in `tests/fixtures/fortiweb/` were written by hand from the reference to look like real backups. They are not exports from a real device.

## Tests and sample configs

```bash
python3 -m unittest tests.test_fwbaudit -v
python3 fwb.py -c tests/fixtures/fortiweb/fwb_weak.conf -fg tests/fixtures/fortiweb/fgt_weak.conf --all --out-dir /tmp/weak
python3 fwb.py -c tests/fixtures/fortiweb/fwb_hardened.conf -fg tests/fixtures/fortiweb/fgt_hardened.conf --all --out-dir /tmp/good
```

The *weak* pair contains common mistakes on purpose: a VIP that skips the WAF, SNAT in front of FortiWeb, FortiWeb trusting the FortiGate's address, the admin GUI published through a VIP, an expired SHA-1 certificate and alert-only signatures. It scores 269 (CRITICAL). The *hardened* pair scores 0.5 (one INFO finding).

## Go rewrite mapping

Each Python module names its Go package in its docstring:

| Python | Go package |
|---|---|
| `fwbaudit/inventory.py` | `internal/fortiweb/inventory` |
| `fwbaudit/catalog.py` | `internal/fortiweb/catalog` |
| `fwbaudit/certs.py` | `internal/fortiweb/certs` (or use `crypto/x509` from the standard library) |
| `fwbaudit/checks/*.py` | `internal/fortiweb/checks` (one file for each domain) |
| `fwbaudit/engine.py` | `internal/fortiweb/engine` |
| `fwbaudit/crosscheck/fortigate.py` | `internal/crosscheck/fortigate` |
| `fwbaudit/crosscheck/link.py` | `internal/crosscheck/link` |
| `fwbaudit/crosscheck/checks.py` | `internal/crosscheck/checks` |
| `fwbaudit/report.py` | `internal/fortiweb/report` |
| `fwbaudit/cli.py`, `fwb.py` | `cmd/fwb` |

The parser and resolver are shared with the FortiGate engine (`policyaudit/`), so in Go they belong in one shared `internal/config` and `internal/netset`.
