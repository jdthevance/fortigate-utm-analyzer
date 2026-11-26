"""Tests for the FortiWeb audit and the FortiGate + FortiWeb cross-check (fwbaudit/)."""

import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from policyaudit import config as cfgmod  # noqa: E402
from fwbaudit import certs, crosscheck, engine  # noqa: E402
from fwbaudit.checks.common import Options  # noqa: E402
from fwbaudit.checks.system import _trusted_hosts  # noqa: E402
from fwbaudit.inventory import Inventory, ip_text  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "fortiweb"
NOW = datetime(2026, 11, 26, tzinfo=timezone.utc).timestamp()


def read(name):
    return (FIX / name).read_text(encoding="utf-8")


def audit(text, **opts):
    opts.setdefault("now", NOW)
    return engine.run(text, Options(**opts))


def ids(findings):
    return {f.rule_id for f in findings}


def by_id(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


def inventory(text):
    return Inventory(cfgmod.scopes(cfgmod.parse(text))[0])


def wrap(*blocks):
    return "\n".join(blocks)


POLICY = """config server-policy vserver
    edit "vs"
        config vip-list
            edit 1
                set interface "port1"
                set vip "10.0.0.10"
            next
        end
    next
end
config server-policy policy
    edit "p"
        set vserver "vs"
        set HTTPS-service HTTPS
        set certificate "c"
        set web-protection-profile "prof"
{extra}
    next
end"""


class CertificateTests(unittest.TestCase):
    def test_reads_legacy_certificate(self):
        inv = inventory(read("fwb_weak.conf"))
        node = inv.table("system certificate local")["portal-legacy"]
        info = certs.parse_pem(node.get("certificate"))
        self.assertEqual(info.key_bits, 1024)
        self.assertEqual(info.signature, "sha1WithRSA")
        self.assertTrue(info.self_signed)
        self.assertEqual(info.not_after.year, 2024)
        self.assertEqual(info.subject_cn, "portal.example.com")

    def test_reads_modern_certificate(self):
        inv = inventory(read("fwb_hardened.conf"))
        info = certs.parse_pem(inv.table("system certificate local")["www-cert"].get("certificate"))
        self.assertEqual((info.key_type, info.key_bits, info.signature), ("RSA", 2048, "sha256WithRSA"))
        self.assertFalse(info.self_signed)
        self.assertEqual(info.issuer_cn, "Example Issuing CA")

    def test_garbage_is_unreadable_not_a_crash(self):
        self.assertIsNone(certs.parse_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"))
        self.assertIsNone(certs.parse_pem(""))


class InventoryTests(unittest.TestCase):
    def test_weak_fixture_model(self):
        inv = inventory(read("fwb_weak.conf"))
        self.assertEqual({ip_text(v.host) for v in inv.vips}, {"10.10.10.10", "10.10.10.11"})
        shop = next(p for p in inv.policies if p.name == "shop-https")
        self.assertEqual((shop.http_ports, shop.https_ports), ([80], [443]))
        self.assertEqual([ip_text(s.host) for s in inv.backends_of(shop)], ["10.20.20.21", "10.20.20.22"])
        self.assertEqual(inv.data_interfaces(), {"port1"})
        self.assertEqual([ip_text(g) for g in inv.gateways()], ["10.10.10.254"])

    def test_literal_vip_address(self):
        inv = inventory(POLICY.format(extra=""))
        self.assertEqual(ip_text(inv.vips[0].host), "10.0.0.10")

    def test_trusted_host_formats(self):
        t = cfgmod.parse('config system admin\n edit "a"\n  set trusthosts 10.0.0.0/24 192.168.1.0 255.255.255.0\n'
                         ' next\n edit "b"\n  set trusthost1 10.1.0.0 255.255.0.0\n next\nend')
        a, b = t.root.objects("system admin")
        self.assertEqual([str(n) for n in _trusted_hosts(a)], ["10.0.0.0/24", "192.168.1.0/24"])
        self.assertEqual([str(n) for n in _trusted_hosts(b)], ["10.1.0.0/16"])


class FortiWebRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.weak = audit(read("fwb_weak.conf"))
        cls.good = audit(read("fwb_hardened.conf"))

    def test_weak_fixture_finds_the_planted_mistakes(self):
        expected = {
            "POL-MONITOR-MODE", "POL-NO-PROFILE", "POL-HTTP-ONLY", "POL-NO-REDIRECT", "POL-NO-HSTS",
            "SIG-ALERT-ONLY", "SIG-CLASS-ALERT", "SIG-CLASS-DISABLED", "SIG-EXCEPTION-BROAD",
            "TLS-OLD-CLIENT", "TLS-CIPHER-MEDIUM", "TLS-BACKEND-CLEAR", "TLS-BACKEND-NOVERIFY",
            "CERT-EXPIRED", "CERT-WEAK-KEY", "CERT-WEAK-SIG", "CERT-SELF-SIGNED",
            "ADMIN-NO-TRUSTHOST", "IFACE-ADMIN-ON-DATA", "IFACE-HTTP-ADMIN", "SNMP-DEFAULT-COMMUNITY",
            "SYS-SHELL", "SYS-ADMIN-TLS-OLD", "SYS-NTP", "SYS-PASSWORD-POLICY",
            "XFF-SPOOFABLE", "IPLIST-TRUST-BROAD", "METH-RISKY", "COOKIE-NO-PROTECTION", "UPLOAD-NO-SCAN",
            "DOS-ALERT-ONLY", "COV-CORE-MISSING", "HLTH-NONE", "LOG-SYSLOG-UDP", "INT-FGT-HTTP",
            "AUTH-LDAP-CLEAR", "BKP-FTP", "UPD-WEEKLY",
        }
        self.assertEqual(expected - ids(self.weak.findings), set())

    def test_hardened_fixture_is_clean(self):
        serious = [f for f in self.good.findings if f.severity in ("CRITICAL", "HIGH", "MEDIUM")]
        self.assertEqual(serious, [], [f.title for f in serious])

    def test_tls_10_and_11_are_on_by_default(self):
        r = audit(POLICY.format(extra=""), domains=["tls"])
        f = by_id(r.findings, "TLS-OLD-CLIENT")
        self.assertEqual(len(f), 1)
        self.assertIn("FortiWeb default", f[0].title)
        r = audit(POLICY.format(extra="        set tls-v10 disable\n        set tls-v11 disable"), domains=["tls"])
        self.assertNotIn("TLS-OLD-CLIENT", ids(r.findings))

    def test_signature_class_defaults_to_alert(self):
        sig = ('config waf signature\n edit "s"\n  config main_class_list\n   edit "010000000"\n'
               '   next\n  end\n next\nend\nconfig waf web-protection-profile inline-protection\n'
               ' edit "prof"\n  set signature-rule "s"\n next\nend\n')
        r = audit(sig + POLICY.format(extra=""), domains=["sig"])
        f = by_id(r.findings, "SIG-CLASS-ALERT")
        self.assertEqual(len(f), 1)
        self.assertIn("Cross Site Scripting", f[0].title)

    def test_repeated_settings_are_grouped(self):
        self.assertEqual(len(by_id(self.weak.findings, "POL-NO-SYNCOOKIE")), 1)
        self.assertIn("3 server policies", by_id(self.weak.findings, "POL-NO-SYNCOOKIE")[0].title)

    def test_coverage_table_lists_every_profile_feature(self):
        from fwbaudit.catalog import PROFILE_FEATURES
        cov = self.weak.devices[0]["coverage"]
        self.assertEqual(set(cov), {"shop-profile", "portal-profile"})
        for feat in PROFILE_FEATURES:
            self.assertIn(feat.name, cov["shop-profile"])
        self.assertTrue(cov["shop-profile"]["Attack signatures"])
        self.assertFalse(cov["shop-profile"]["HTTP protocol constraints"])

    def test_domain_selection(self):
        r = audit(read("fwb_weak.conf"), domains=["log"])
        self.assertEqual({f.category for f in r.findings}, {"Logging"})


class CrossCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        weak = audit(read("fwb_weak.conf"))
        cls.weak = crosscheck.run(read("fgt_weak.conf"), weak.inventories)
        good = audit(read("fwb_hardened.conf"))
        cls.good = crosscheck.run(read("fgt_hardened.conf"), good.inventories)

    def test_bypass_and_exposure(self):
        f = by_id(self.weak.findings, "XC-BYPASS-VIP")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "CRITICAL")
        self.assertIn("VIP-Legacy-API", f[0].title)
        internal = by_id(self.weak.findings, "XC-BYPASS-POLICY")
        self.assertEqual([x.severity for x in internal], ["MEDIUM"])
        self.assertEqual(by_id(self.weak.findings, "XC-WAF-ADMIN-EXPOSED")[0].severity, "CRITICAL")
        self.assertIn("XC-VIP-ALL-PORTS", ids(self.weak.findings))

    def test_published_app_without_blocking(self):
        titles = " ".join(f.title for f in by_id(self.weak.findings, "XC-UNPROTECTED-APP"))
        self.assertIn("monitor mode", titles)
        self.assertIn("no protection profile", titles)

    def test_nat_and_trust(self):
        found = ids(self.weak.findings)
        self.assertTrue({"XC-SNAT-HIDES-CLIENT", "XC-FWB-TRUSTS-FGT", "XC-XFF-SPOOFABLE"} <= found)
        self.assertEqual(by_id(self.weak.findings, "XC-FWB-TRUSTS-FGT")[0].severity, "CRITICAL")

    def test_routing_logging_and_integration(self):
        found = ids(self.weak.findings)
        self.assertTrue({"XC-RETURN-PATH", "XC-LOG-NO-COMMON", "XC-LOG-FGT-OFF", "XC-NTP",
                         "XC-QUARANTINE-HTTP", "XC-INSPECT-NO-IPS"} <= found)

    def test_one_finding_per_policy_not_per_vip(self):
        self.assertEqual(len(by_id(self.weak.findings, "XC-SNAT-HIDES-CLIENT")), 1)

    def test_hardened_pair_is_clean(self):
        serious = [f for f in self.good.findings if f.severity in ("CRITICAL", "HIGH", "MEDIUM")]
        self.assertEqual(serious, [], [f.title for f in serious])
        kinds = {r["kind"] for p in self.good.pairs for r in p["paths"]}
        self.assertEqual(kinds, {"waf"})

    def test_routed_policy_only_counts_where_it_can_deliver(self):
        # Hardened policy 20 has dstaddr "all" on waf-dmz: it reaches the FortiWeb VIP,
        # but not the servers (10.30.30.0/24) or the management port (192.168.100.0/24).
        rows = [r for p in self.good.pairs for r in p["paths"] if r["fortigate_policy"] == "20"]
        self.assertEqual([r["target"] for r in rows], ["10.10.10.20"])

    def test_unrelated_configs_say_so(self):
        fgt = 'config system interface\n edit "wan1"\n  set ip 198.51.100.1 255.255.255.0\n  set role wan\n next\nend\n' \
              'config firewall policy\n edit 1\n  set srcintf "wan1"\n  set dstintf "wan1"\n  set srcaddr "all"\n' \
              '  set dstaddr "all"\n  set action accept\n  set service "ALL"\n next\nend'
        r = crosscheck.run(fgt, audit(read("fwb_hardened.conf")).inventories)
        self.assertIn("XC-NO-LINK", ids(r.findings))


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "fwb.py")] + list(args),
                              capture_output=True, text=True, cwd=str(ROOT))

    def test_full_run_writes_reports(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.run_cli("-c", str(FIX / "fwb_weak.conf"), "-fg", str(FIX / "fgt_weak.conf"),
                             "--all", "--out-dir", d, "--fail-on", "high")
            self.assertEqual(r.returncode, 1, r.stderr)
            names = sorted(p.name for p in Path(d).iterdir())
            self.assertEqual(names, ["fwb_weak.conf_crosscheck_report.txt", "fwb_weak.conf_fortiweb_audit.json",
                                     "fwb_weak.conf_fortiweb_audit_report.txt", "fwb_weak.conf_fortiweb_summary.txt"])
            text = (Path(d) / "fwb_weak.conf_crosscheck_report.txt").read_text()
            self.assertIn("PATH MAP", text)
            self.assertIn("XC-BYPASS-VIP", text)

    def test_hardened_passes_fail_on_high(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.run_cli("-c", str(FIX / "fwb_hardened.conf"), "-fg", str(FIX / "fgt_hardened.conf"),
                             "--out-dir", d, "--fail-on", "high")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_input_problems_exit_2(self):
        self.assertEqual(self.run_cli("-c", "missing.conf").returncode, 2)
        with tempfile.TemporaryDirectory() as d:
            broken = Path(d) / "broken.conf"
            broken.write_text("config server-policy policy\n edit \"p\"\n  set status enable\n")
            r = self.run_cli("-c", str(broken), "--out-dir", d)
            self.assertEqual(r.returncode, 2)
            self.assertIn("incomplete", r.stderr)
            r = self.run_cli("-c", str(broken), "--out-dir", d, "--allow-incomplete")
            self.assertEqual(r.returncode, 0)
            self.assertIn("INCOMPLETE", (Path(d) / "broken.conf_fortiweb_audit_report.txt").read_text())


if __name__ == "__main__":
    unittest.main()
