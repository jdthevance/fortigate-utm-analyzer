# Policy analysis engine (`-pa`)

The policy analysis engine looks at the whole firewall rule base, not one rule at a time. It answers questions like: *can this rule ever be reached? Does it let a guest network into the LAN? Is this object really as narrow as its name suggests? Is anybody using this rule?*

It lives in the `policyaudit/` folder next to `utm.py`, uses only the Python standard library (3.8+), and never changes the firewall. Any CLI it prints is a review example.

## Running it

```bash
# As part of the existing tool (also included in --all)
python3 utm.py -c firewall.conf -pa
python3 utm.py -c firewall.conf -pa --summary --html

# With hit counts: unlocks unused policies, busy-rule ordering and validated removal advice
python3 utm.py -c firewall.conf -pa --hitcounts hits.json --hit-window-days 90

# Standalone, with exit codes for scripts and CI
python3 -m policyaudit -c firewall.conf --fail-on high
```

| Option | What it does |
|---|---|
| `--hitcounts FILE` | Import policy hit counts (see below). |
| `--hit-window-days N` | How many days the counters cover: time since the last reboot or counter reset. Removal advice can only be VALIDATED when this is known. |
| `--min-unused-days N` | How long a policy must have had zero hits before removal is VALIDATED (default 30). |
| `--trust-map FILE` | Correct the engine's guess of how trusted each interface or zone is. |
| `--allow-incomplete` | Analyse a truncated or broken config anyway. Every report is marked INCOMPLETE. |
| `--fail-on LEVEL` | Standalone only: exit 1 when a finding at `critical`, `high` or `medium` or above exists. |

Outputs: `<config>_policy_analysis_report.txt` (for people) and `<config>_policy_analysis.json` (for scripts, and for checking the future Go version gives the same answers). With `utm.py`, findings are also added to the summary and HTML dashboard under **Policy Analysis**.

Exit codes (standalone): `0` finished, `1` `--fail-on` threshold reached, `2` input problem (missing file, incomplete config, bad hit-count file). `utm.py` now also exits `2` for a missing file or an incomplete config.

## How it works, in plain words

1. **Parse once, keep VDOMs apart.** The config is read into a tree. Each VDOM is analysed on its own, with its own objects and policy order. Quoted lists such as `set srcaddr "Web Servers" "DB"` are split correctly. A file that ends mid-block is refused (or marked INCOMPLETE) instead of being audited as if it were complete.
2. **Resolve names into real values.** The object resolver turns every address, address group (nested groups and exclusions included), VIP, service, service group and zone into real IP ranges, ports and interfaces. FQDN, geography and dynamic objects have no fixed IP, so they are kept as "only equal to themselves": `all` covers them, but a subnet never does. A name the config doesn't define is reported and treated the same way, so it can never make a rule look broader or narrower than it is.
3. **Compare policies.** The relationship engine compares policies the way the FortiGate evaluates them, top to bottom, first match wins. It includes interfaces, addresses, services and extra conditions (schedule, users, groups). To stay fast on big rule bases it only compares policies whose ranges can touch. 5,000 heavily overlapping policies take about 1.5 seconds; the generated 20,000-policy test config takes about 5 seconds.
4. **Run the checks** described below and write the reports.

## The policy relationship engine

For each pair of enabled policies, A above B:

| Relationship | Meaning | Reported as |
|---|---|---|
| A covers B, different action | **Exact shadowing.** B can never match. Its block (or allow) never happens. | `REL-SHADOW` (HIGH if B is a deny, MEDIUM if B is an accept) |
| A covers B, same action | B is **unreachable / redundant.** If B has different profiles or logging, those never apply. | `REL-REDUNDANT` (MEDIUM if settings differ, else INFO) |
| A and B match exactly the same traffic | **Duplicate.** | `DUP-EXACT` |
| A and B share some traffic, neither covers the other, different actions | **Partial overlap.** The shared part always gets A's action. This is *not* shadowing. | `REL-PARTIAL` |
| Same, but same action and different profiles | The shared part gets A's profiles. | `REL-PARTIAL-PROFILE` (INFO) |
| B covers A (specific rule above a broad one) | Normal, deliberate design. | not reported |
| They might overlap only through FQDN/geo/unknown objects | Possible overlap. Never reported as fact; counted in the summary and used as a safety barrier for ordering advice. | not reported |
| A later rule C covers B with the same action, and nothing in between treats B's traffic differently | B is redundant "downstream". | `REL-REDUNDANT-DOWNSTREAM` (INFO) |
| Rules identical except for one of source, destination or service | Merge candidates. | `DUP-NEAR` (INFO) |

The example from the request is in `tests/fixtures/relationships.conf` and is checked by `tests/test_policyaudit.py`:

* Policy 10 (LAN to ALL, all services) covers policy 20 (LAN to Critical-Servers, HTTPS): `REL-REDUNDANT`, noting that policy 20's IPS profile never applies.
* Policy 30 (Guest-WiFi to Internal-Network, all services): `TRUST-GUEST-TO-INTERNAL`, HIGH.
* Policy 10 also gets `PERM-UNRESTRICTED`: every destination on every service is wider than any single business need.

### Removal advice is never a bare instruction

Every finding that suggests removing a policy carries a **validation** state:

| State | When |
|---|---|
| `VALIDATED` | Hit counts show zero use over at least `--min-unused-days`, the counter period is known, and no dependency was found. The advice is still "disable first, keep a backup, delete after a quiet period". |
| `UNVALIDATED` | No hit counts, the policy is missing from the export, the counter period is unknown or too short, or a dependency was found. Treat it as a lead, not a decision. |
| `BLOCKED` | Hit counts show the policy is in use. Do not remove it, and look at why the analysis and the traffic disagree. |

Dependencies checked: the only enabled policy using a VIP (removing it would stop a port-forward), the only policy using an IP pool, IPsec or SSL-VPN traffic, identity-based rules (users, groups), and comments such as "do not remove".

## All checks

| Rule ID | Capability | What it flags |
|---|---|---|
| `REL-SHADOW`, `REL-PARTIAL`, `REL-PARTIAL-PROFILE` | 1. Shadowing and partial shadowing | See the table above |
| `DUP-EXACT`, `DUP-NEAR` | 2. Duplicates and near-duplicates | Same traffic, or same except one field |
| `REL-REDUNDANT`, `REL-REDUNDANT-DOWNSTREAM`, `POL-UNUSED`, `POL-STALE`, `POL-DISABLED`, `POL-NEVER-MATCHES`, `USAGE-NEEDS-HITS`, `USAGE-NOT-IN-EXPORT` | 3. Unused and redundant policies | Covered rules, zero-hit rules, last used long ago, disabled, rules whose objects resolve to nothing |
| `PERM-HIDDEN-ANY`, `PERM-BROAD-SRC`, `PERM-BROAD-DST`, `PERM-ANY-SRC`, `PERM-ANY-DST`, `PERM-UNRESTRICTED` | 4. Overly permissive objects | Objects that really mean "all", /8 and /16-scale ranges, any-destination any-service internal rules |
| `SVC-ALL`, `SVC-WIDE`, `SVC-RISKY`, `SVC-CLEARTEXT` | 5. Excessive service exposure | ALL (also when hidden in a group), more than 1,000 ports, RDP/SMB/Telnet/databases from internet or guest networks. Port-forward VIPs limit the ports actually exposed. |
| `INSPECT-NONE`, `INSPECT-MISSING`, `INSPECT-TLS-SHALLOW` | 6. Missing UTM inspection | No inspection, or profiles that *fit the traffic* are missing (no email-filter nagging on a rule with no mail ports) |
| `INET-OUTBOUND-OPEN`, `INET-INBOUND-OPEN`, `INET-WAN-GUESSED` | 7. Unrestricted internet access | Any internet host on any port, or anyone on the internet reaching internal ranges without a VIP |
| `LOG-NONE`, `LOG-DENY-NONE`, `LOG-UTM-ONLY`, `LOG-IMPLICIT-DENY` | 8. No logging | Accept rules without logs, unlogged internet denies, implicit deny not logged. A missing `logtraffic` line uses the FortiOS default (`utm`) |
| `ORDER-BUSY-FIRST` (plus the move suggestions on `REL-SHADOW`/`REL-REDUNDANT`) | 9. Ordering | Security fixes (move the specific rule up), and with hit counts, busy rules that can move up without changing behaviour. Suggestions only. |
| `EXPOSURE-SCORE` | 10. Exposure risk | 0-100 score per policy; HIGH at 80+, MEDIUM at 60+; full ranking in the report and JSON |
| `TRUST-<FROM>-TO-<TO>` | Trust relationships | A less trusted network reaching a more trusted one, e.g. `TRUST-GUEST-TO-INTERNAL` |

### Trust levels

Each interface and zone gets a level. Lowest to highest: `internet` (WAN role, default route, SD-WAN member, PPPoE), `guest` (name or alias contains guest/visitor/public/byod/hotspot, or an open SSID), `dmz`, `remote` (SSL-VPN and IPsec tunnels), `internal`, `management` (mgmt/management/oob in the name). Override any guess with a JSON file:

```json
{"Guest-WiFi": "guest", "port5": "dmz", "OT-Zone": "management"}
```

### Exposure score

`score = 100 × source × destination × service × mitigation × activity`, explained factor by factor at the top of `policyaudit/checks/exposure.py`. In short: untrusted and broad sources, valuable and broad destinations, many or risky ports, little inspection, and real traffic all push it up. With hit counts, a never-used rule is scored as *latent* (0.6×) because it is a removal candidate rather than live exposure. The report also shows how many destination addresses sit in subnets directly connected to the destination interface.

## Hit counts

Hit counts come from the firewall, not the config. Export them any of these ways:

* **FortiGate REST API** (recommended): save the JSON from `GET /api/v2/monitor/firewall/policy?vdom=*` as-is.
* **FortiGate GUI**: Policy & Objects, Firewall Policy, then export to CSV.
* **FortiManager / FortiAnalyzer**: any CSV with a policy ID column and a hit count column.

CSV headers are matched loosely (case, spaces and underscores ignored): policy id (`policyid`, `Policy ID`, `id`, `seq`), hit count (`hit_count`, `hits`, `Hit Count`, `count`), and optionally last used (`last_used`, `Last Hit`; unix time or `YYYY-MM-DD`), bytes, and `vdom`. Counters reset on reboot, so pass `--hit-window-days` with the days since the last reboot or reset (`get system performance status` shows uptime).

## Known limits

* Rules covered only by the *combination* of several earlier rules are not detected as shadowed; only single-rule coverage is.
* Routing is not modelled. The exposure score uses interface trust and connected subnets, not the full routing table.
* `config firewall security-policy` (NGFW policy-based mode), proxy policies and local-in policies are not analysed by this engine.
* Services restricted by source port, or by destination IP inside the service, are treated as "equal only to themselves".
* Hit counts say a rule is used, not which destinations it is used for. Narrowing a broad rule still needs traffic logs.

## Map to the Go rewrite

Each module is written to become one Go package, with the same rule IDs and JSON fields, so the Go version can be checked against this one on the same fixtures.

| Python | Go package | Notes |
|---|---|---|
| `policyaudit/config.py` | `internal/config` | `Node`, `Tree`, `Scope`; `Parse(text) (*Tree, error)` |
| `policyaudit/netset.py` | `internal/netset` | `Set []Range`; IPv6 needs two `uint64`s or `math/big` |
| `policyaudit/objects.py` | `internal/objects` | `Resolver` per VDOM |
| `policyaudit/model.py` | `internal/model` | `Finding`, `Policy`, `HitRecord` structs |
| `policyaudit/policies.py` | `internal/engine` | building policies from the tree |
| `policyaudit/relations.py` | `internal/relations` | relationship graph |
| `policyaudit/trust.py` | `internal/trust` | trust levels |
| `policyaudit/hits.py` | `internal/hits` | JSON/CSV import |
| `policyaudit/checks/*.py` | `internal/checks/<name>` | one file per capability |
| `policyaudit/report.py` | `internal/report` | text and JSON writers |
| `policyaudit/cli.py` | `cmd/policyaudit` | flags and exit codes |
