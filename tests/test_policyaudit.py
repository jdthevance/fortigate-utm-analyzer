"""Tests for the policy analysis engine (policyaudit/)."""

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from policyaudit import config, engine, hits, netset as ns, relations  # noqa: E402
from policyaudit import policies as polmod  # noqa: E402
from policyaudit.model import BLOCKED, UNVALIDATED, VALIDATED  # noqa: E402
from policyaudit.objects import Resolver  # noqa: E402
from pa_helpers import INTERFACES, block, policy, q, random_config  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"


def run(text, **opts):
    hit_data = opts.pop("hits", None)
    return engine.run(text, engine.Options(**opts), hit_data)


def rules(result, rule_id=None):
    if rule_id is None:
        return {f.rule_id for f in result.findings}
    return [f for f in result.findings if f.rule_id == rule_id]


def resolver_for(text):
    tree = config.parse(text)
    return Resolver(config.scopes(tree)[0])


class ParserTests(unittest.TestCase):
    def test_quoted_multi_values(self):
        t = config.parse('config firewall policy\n edit 1\n  set srcaddr "Web Servers" "DB"\n next\nend')
        self.assertEqual(t.errors, [])
        self.assertEqual(t.root.objects("firewall policy")[0].get_list("srcaddr"), ["Web Servers", "DB"])

    def test_truncated_config_is_an_error(self):
        t = config.parse("config firewall policy\n edit 1\n  set action accept\n")
        self.assertFalse(t.complete)
        self.assertIn("never closed", t.errors[0])

    def test_cli_prompt_is_only_a_warning(self):
        t = config.parse("FGT60F # show full-configuration\nconfig system global\nend")
        self.assertTrue(t.complete)
        self.assertTrue(t.warnings)

    def test_append_and_unselect(self):
        t = config.parse('config firewall addrgrp\n edit "g"\n  set member "a" "b"\n  append member "c"\n'
                         '  unselect member "a"\n next\nend')
        self.assertEqual(t.root.objects("firewall addrgrp")[0].get_list("member"), ["b", "c"])

    def test_vdoms_are_separate_scopes(self):
        text = ("config vdom\nedit root\nnext\nedit dmz\nnext\nend\n"
                "config global\n" + INTERFACES + "\nend\n"
                "config vdom\nedit root\n" + block("firewall policy", [policy(1)]) + "\nnext\n"
                "edit dmz\n" + block("firewall policy", [policy(1, svc='"RDP"')]) + "\nnext\nend\n")
        scopes = config.scopes(config.parse(text))
        self.assertEqual([s.name for s in scopes], ["root", "dmz"])
        self.assertEqual(len(scopes[1].objects("firewall policy")), 1)
        self.assertTrue(scopes[1].interfaces())


class ResolverTests(unittest.TestCase):
    def setUp(self):
        self.r = resolver_for("\n".join([
            INTERFACES,
            block("firewall address", [
                ("h1", {"subnet": "10.0.0.5 255.255.255.255"}),
                ("net", {"subnet": "10.0.0.0/24"}),
                ("rng", {"type": "iprange", "start-ip": "10.0.1.1", "end-ip": "10.0.1.10"}),
                ("web", {"type": "fqdn", "fqdn": "example.com"}),
                ("wide", {"subnet": "0.0.0.0 0.0.0.0"}),
            ]),
            block("firewall addrgrp", [
                ("g1", {"member": q("h1", "rng")}),
                ("g2", {"member": q("g1", "web")}),
                ("loop1", {"member": q("loop2")}), ("loop2", {"member": q("loop1")}),
                ("ex", {"member": q("net"), "exclude": "enable", "exclude-member": q("h1")}),
            ]),
            block("firewall service custom", [
                ("web-ports", {"tcp-portrange": "80 443 8000-8100"}),
                ("srcport", {"tcp-portrange": "80:1024-2000"}),
            ]),
            block("firewall service group", [("sg", {"member": q("web-ports", "SSH")})]),
        ]))

    def test_nested_groups_and_ranges(self):
        s = self.r.address("g1")
        self.assertEqual(ns.v4_count(s), 11)
        self.assertTrue(self.r.address("net").contains(self.r.address("h1")))

    def test_fqdn_is_covered_by_all_but_not_by_subnet(self):
        web = self.r.address("web")
        self.assertTrue(self.r.address("all").contains(web))
        self.assertFalse(self.r.address("net").contains(web))
        self.assertTrue(self.r.address("g2").contains(web))

    def test_group_loop_does_not_hang(self):
        self.r.address("loop1")
        self.assertIn("loop1", self.r.unresolved)

    def test_exclusion(self):
        self.assertEqual(ns.v4_count(self.r.address("ex")), 255)

    def test_hidden_any(self):
        self.assertEqual(self.r.address("wide"), self.r.address("all"))

    def test_services(self):
        self.assertEqual(ns.port_count(self.r.service("web-ports")), 103)
        self.assertTrue(self.r.service("sg").contains(self.r.service("SSH")))
        self.assertTrue(self.r.service("ALL").contains(self.r.service("sg")))
        self.assertFalse(self.r.service("HTTP").contains(self.r.service("srcport")))
        self.assertTrue(self.r.service("UNKNOWN-SVC"))
        self.assertIn("UNKNOWN-SVC", self.r.unresolved)

    def test_internet_interfaces(self):
        self.assertTrue(self.r.is_wan("wan1"))
        self.assertFalse(self.r.is_wan("lan"))
        self.assertFalse(self.r.wan_guessed)


class RelationshipExampleTests(unittest.TestCase):
    """JayDee's example: policies 10, 20 and 30 (tests/fixtures/relationships.conf)."""

    @classmethod
    def setUpClass(cls):
        cls.result = run((FIXTURES / "relationships.conf").read_text())

    def by(self, rule_id, pid):
        return [f for f in rules(self.result, rule_id) if f.policies and f.policies[0] == pid]

    def test_policy_10_makes_20_unreachable(self):
        f = self.by("REL-REDUNDANT", "20")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].policies, ["20", "10"])
        self.assertIn("ips-sensor", f[0].evidence["settings_differ"])

    def test_exact_shadowing_with_different_action(self):
        f = self.by("REL-SHADOW", "40")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "HIGH")
        self.assertIn("move 40 before 10", f[0].cli)

    def test_policy_30_inappropriate_trust(self):
        f = self.by("TRUST-GUEST-TO-INTERNAL", "30")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "HIGH")

    def test_policy_10_beyond_business_need(self):
        self.assertEqual(len(self.by("PERM-UNRESTRICTED", "10")), 1)

    def test_duplicate_preferred_over_broad_cover(self):
        f = self.by("DUP-EXACT", "50")
        self.assertEqual(f[0].policies, ["50", "20"])

    def test_hidden_any_object(self):
        self.assertEqual(rules(self.result, "PERM-HIDDEN-ANY")[0].objects, ["Everything-Internal"])

    def test_removal_advice_unvalidated_without_hits(self):
        for f in self.result.findings:
            if "emoval" in f.recommendation and f.rule_id != "USAGE-NEEDS-HITS":
                self.assertIn(f.validation, (UNVALIDATED, ""), f.rule_id)
        self.assertEqual(self.by("DUP-EXACT", "50")[0].validation, UNVALIDATED)


class RelationshipEngineTests(unittest.TestCase):
    def table(self, *pols, extra=""):
        text = "\n".join([INTERFACES, extra, block("firewall policy", list(pols))])
        return run(text)

    def test_partial_overlap_is_not_shadowing(self):
        extra = block("firewall address", [("a", {"subnet": "10.0.0.0/24"}), ("b", {"subnet": "10.0.0.128/25"}),
                                           ("c", {"subnet": "10.0.1.0/24"})])
        extra += "\n" + block("firewall addrgrp", [("bc", {"member": q("b", "c")})])
        r = self.table(policy(1, da='"a"', svc='"HTTPS"', action="deny"),
                       policy(2, da='"bc"', svc='"HTTPS"'), extra=extra)
        self.assertEqual(len(rules(r, "REL-PARTIAL")), 1)
        self.assertFalse(rules(r, "REL-SHADOW"))

    def test_specific_deny_above_broad_accept_is_fine(self):
        extra = block("firewall address", [("h", {"subnet": "10.10.10.5/32"})])
        r = self.table(policy(1, da='"h"', svc='"RDP"', action="deny"), policy(2), extra=extra)
        self.assertFalse(rules(r) & {"REL-SHADOW", "REL-PARTIAL", "REL-REDUNDANT"})

    def test_schedule_restriction_prevents_cover(self):
        r = self.table(policy(1, schedule='"business-hours"'), policy(2, svc='"HTTPS"', action="deny"))
        self.assertFalse(rules(r, "REL-SHADOW"))

    def test_fqdn_overlap_is_only_possible(self):
        extra = block("firewall address", [("f", {"type": "fqdn", "fqdn": "x.example"}),
                                           ("n", {"subnet": "10.10.10.0/24"})])
        r = self.table(policy(1, da='"f"', action="deny"), policy(2, da='"n"'), extra=extra)
        self.assertFalse(rules(r) & {"REL-SHADOW", "REL-PARTIAL"})
        self.assertEqual(r.vdoms[0]["relations"]["firewall policy"].get("possible"), 1)

    def test_downstream_redundancy(self):
        extra = block("firewall address", [("h", {"subnet": "10.10.10.5/32"})])
        r = self.table(policy(1, da='"h"', svc='"HTTPS"'), policy(2), extra=extra)
        f = rules(r, "REL-REDUNDANT-DOWNSTREAM")
        self.assertEqual(f[0].policies, ["1", "2"])

    def test_downstream_blocked_by_conflicting_rule_between(self):
        extra = block("firewall address", [("h", {"subnet": "10.10.10.5/32"})])
        r = self.table(policy(1, da='"h"', svc='"HTTPS"'), policy(2, svc='"HTTPS"', action="deny"),
                       policy(3), extra=extra)
        self.assertFalse(rules(r, "REL-REDUNDANT-DOWNSTREAM"))

    def test_near_duplicates(self):
        extra = block("firewall address", [("a", {"subnet": "10.10.10.1/32"}), ("b", {"subnet": "10.10.10.2/32"})])
        r = self.table(policy(1, da='"a"', svc='"HTTPS"'), policy(2, da='"b"', svc='"HTTPS"'), extra=extra)
        self.assertEqual(rules(r, "DUP-NEAR")[0].policies, ["1", "2"])

    def test_disabled_policies_do_not_shadow(self):
        r = self.table(policy(1, status="disable"), policy(2, svc='"HTTPS"', action="deny"))
        self.assertFalse(rules(r, "REL-SHADOW"))
        self.assertTrue(rules(r, "POL-DISABLED"))

    def test_sweep_matches_brute_force(self):
        """The fast pair search must find exactly what comparing every pair finds."""
        for seed in range(6):
            text = random_config(150, seed=seed, broad_every=37)
            scope = config.scopes(config.parse(text))[0]
            pols = polmod.build(scope, Resolver(scope), "firewall policy")
            graph = relations.analyse(pols)
            fast = {(r.upper, r.lower, r.kind) for r in graph.relations}
            slow = set()
            active = [p for p in pols if p.enabled]
            for i, a in enumerate(active):
                for b in active[i + 1:]:
                    kind = relations.classify(a, b)
                    if kind:
                        slow.add((a.position, b.position, kind))
            self.assertEqual(fast, slow, "seed {}".format(seed))
            self.assertTrue(slow)


class CheckTests(unittest.TestCase):
    def test_internet_inbound_and_risky_services(self):
        text = "\n".join([INTERFACES, block("firewall policy", [
            policy(1, src="wan1", dst="lan", svc='"RDP"'),
            policy(2, src="wan1", dst="lan", svc='"ALL"')])])
        r = run(text)
        self.assertEqual(rules(r, "SVC-RISKY")[0].severity, "CRITICAL")
        self.assertTrue(any(f.rule_id == "INET-INBOUND-OPEN" and f.severity == "CRITICAL" for f in r.findings))

    def test_vip_port_forward_limits_service(self):
        vip = block("firewall vip", [("web-vip", {"extip": "203.0.113.10", "mappedip": '"10.10.10.5"',
                                                  "extintf": '"wan1"', "portforward": "enable",
                                                  "extport": "443", "mappedport": "443"})])
        text = "\n".join([INTERFACES, vip, block("firewall policy", [
            policy(1, src="wan1", dst="dmz", da='"web-vip"', svc='"ALL"')])])
        r = run(text)
        self.assertFalse(rules(r) & {"SVC-ALL", "INET-INBOUND-OPEN"})

    def test_inspection_only_asks_for_relevant_profiles(self):
        text = "\n".join([INTERFACES, block("firewall policy", [
            policy(1, dst="wan1", svc='"HTTPS"', **{"utm-status": "enable", "ips-sensor": '"default"'})])])
        f = rules(run(text), "INSPECT-MISSING")[0]
        self.assertIn("web filter", f.evidence["missing"])
        self.assertNotIn("email filter", f.evidence["missing"])

    def test_profiles_ignored_without_utm_status(self):
        text = "\n".join([INTERFACES, block("firewall policy", [
            policy(1, dst="wan1", **{"av-profile": '"default"'})])])
        f = rules(run(text), "INSPECT-NONE")[0]
        self.assertIn("ignored", f.title)

    def test_missing_logtraffic_uses_fortios_default(self):
        pol = policy(1, dst="wan1", svc='"HTTPS"')
        del pol[1]["logtraffic"]
        r = run("\n".join([INTERFACES, block("firewall policy", [pol])]))
        self.assertFalse(rules(r, "LOG-NONE"))
        self.assertTrue(rules(r, "LOG-UTM-ONLY"))

    def test_wan_guessed_from_names_is_reported(self):
        intf = block("system interface", [("wan2", {"ip": "198.51.100.2/24"}), ("port1", {"ip": "10.0.0.1/24"})])
        r = run(intf + "\n" + block("firewall policy", [policy(1, src="port1", dst="wan2")]))
        self.assertTrue(rules(r, "INET-WAN-GUESSED"))
        self.assertTrue(rules(r, "INET-OUTBOUND-OPEN"))

    def test_trust_map_override(self):
        text = "\n".join([INTERFACES, block("firewall policy", [policy(1, src="lan", dst="dmz")])])
        self.assertFalse([f for f in run(text).findings if f.rule_id.startswith("TRUST-")])
        r = run(text, trust_map={"lan": "guest"})
        self.assertTrue(rules(r, "TRUST-GUEST-TO-DMZ"))

    def test_exposure_ranking_orders_internet_first(self):
        text = "\n".join([INTERFACES, block("firewall policy", [
            policy(1, src="lan", dst="dmz", svc='"HTTPS"'), policy(2, src="wan1", dst="lan")])])
        ranking = run(text).vdoms[0]["exposure_ranking"]
        self.assertEqual(ranking[0]["policy"], "2")
        self.assertGreater(ranking[0]["score"], 80)

    def test_never_matching_policy(self):
        grp = block("firewall addrgrp", [("empty", {"member": ""})])
        r = run("\n".join([INTERFACES, grp, block("firewall policy", [policy(1, da='"empty"')])]))
        self.assertTrue(rules(r, "POL-NEVER-MATCHES"))

    def test_multi_vdom_policies_audited_separately(self):
        text = ("config vdom\nedit root\nnext\nedit second\nnext\nend\nconfig global\n" + INTERFACES +
                "\nend\nconfig vdom\nedit root\n" + block("firewall policy", [policy(1, svc='"HTTPS"')]) +
                "\nnext\nedit second\n" + block("firewall policy", [policy(1, src="wan1", dst="lan")]) +
                "\nnext\nend\n")
        r = run(text)
        self.assertEqual({v["vdom"] for v in r.vdoms}, {"root", "second"})
        self.assertTrue(any(f.vdom == "second" and f.rule_id == "INET-INBOUND-OPEN" for f in r.findings))


class HitCountTests(unittest.TestCase):
    CFG = "\n".join([INTERFACES, block("firewall address", [("h", {"subnet": "10.10.10.5/32"})]),
                     block("firewall policy", [policy(1, da='"h"', svc='"HTTPS"'), policy(2),
                                               policy(3, svc='"SSH"', da='"h"', dst="lan")])])

    def test_rest_json_import(self):
        doc = [{"vdom": "root", "results": [{"policyid": 1, "hit_count": 0},
                                            {"policyid": 2, "hit_count": 500, "last_used": 1700000000}]}]
        data = hits.loads(json.dumps(doc))
        self.assertEqual(data.records[("root", "2")].hits, 500)

    def test_csv_import_flexible_headers(self):
        data = hits.loads("Policy ID,Hit Count,Last Used\n1,0,\n2,1234,2026-11-01 10:00\n")
        self.assertEqual(data.records[(None, "2")].hits, 1234)
        self.assertIsNotNone(data.records[(None, "2")].last_used)

    def test_csv_without_required_columns(self):
        with self.assertRaises(ValueError):
            hits.loads("name,bytes\nx,1\n")

    def test_removal_validated_only_with_long_zero_window(self):
        data = hits.loads("policyid,hits\n1,0\n2,900\n3,0\n")
        r = run(self.CFG, hits=data, hit_window_days=90)
        down = rules(r, "REL-REDUNDANT-DOWNSTREAM")[0]
        self.assertEqual(down.validation, VALIDATED)
        r = run(self.CFG, hits=data, hit_window_days=7)
        self.assertEqual(rules(r, "REL-REDUNDANT-DOWNSTREAM")[0].validation, UNVALIDATED)
        r = run(self.CFG, hits=hits.loads("policyid,hits\n1,5\n2,900\n"), hit_window_days=90)
        self.assertEqual(rules(r, "REL-REDUNDANT-DOWNSTREAM")[0].validation, BLOCKED)

    def test_unused_policy(self):
        r = run(self.CFG, hits=hits.loads("policyid,hits\n1,0\n2,900\n3,0\n"), hit_window_days=60)
        self.assertEqual(sorted(f.policies[0] for f in rules(r, "POL-UNUSED")), ["1", "3"])
        self.assertFalse(rules(r, "USAGE-NEEDS-HITS"))

    def test_busy_rule_ordering(self):
        addrs = [("a{}".format(i), {"subnet": "10.10.{}.1/32".format(i)}) for i in range(10)]
        pols = [policy(i + 1, da='"a{}"'.format(i), svc='"HTTPS"') for i in range(10)]
        text = "\n".join([INTERFACES, block("firewall address", addrs), block("firewall policy", pols)])
        data = hits.loads("policyid,hits\n" + "\n".join("{},{}".format(i, 10) for i in range(1, 10)) + "\n10,50000\n")
        r = run(text, hits=data, hit_window_days=30)
        f = rules(r, "ORDER-BUSY-FIRST")
        self.assertEqual(f[0].policies, ["10", "1"])
        self.assertIn("move 10 before 1", f[0].cli)


class CliTests(unittest.TestCase):
    def cli(self, *args, cwd):
        return subprocess.run([sys.executable, "-m", "policyaudit", *args], cwd=str(cwd),
                              capture_output=True, text=True, env={"PYTHONPATH": str(ROOT)})

    def test_standalone_cli_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self.cli("-c", str(FIXTURES / "relationships.conf"), "--out-dir", tmp, cwd=tmp)
            self.assertEqual(r.returncode, 0, r.stderr)
            data = json.loads((Path(tmp) / "relationships.conf_policy_analysis.json").read_text())
            self.assertTrue(data["complete"])
            r = self.cli("-c", str(FIXTURES / "relationships.conf"), "--out-dir", tmp, "--fail-on", "high", cwd=tmp)
            self.assertEqual(r.returncode, 1)
            r = self.cli("-c", str(Path(tmp) / "missing.conf"), cwd=tmp)
            self.assertEqual(r.returncode, 2)
            self.assertNotIn("Traceback", r.stderr)

    def test_truncated_config_refused_unless_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cut.conf"
            cfg.write_text("config firewall policy\n    edit 1\n        set action accept\n")
            r = self.cli("-c", str(cfg), "--out-dir", tmp, cwd=tmp)
            self.assertEqual(r.returncode, 2)
            r = self.cli("-c", str(cfg), "--out-dir", tmp, "--allow-incomplete", cwd=tmp)
            self.assertEqual(r.returncode, 0)
            self.assertIn("INCOMPLETE", (Path(tmp) / "cut.conf_policy_analysis_report.txt").read_text())


class ScaleTests(unittest.TestCase):
    def test_large_rule_base_is_fast(self):
        text = random_config(5000, seed=7, broad_every=500)
        start = time.time()
        r = run(text)
        elapsed = time.time() - start
        self.assertLess(elapsed, 30, "5,000 overlapping policies took {:.1f}s".format(elapsed))
        self.assertTrue(r.findings)


if __name__ == "__main__":
    unittest.main()
