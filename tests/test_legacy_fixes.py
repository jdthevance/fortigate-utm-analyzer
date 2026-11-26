"""Regression tests for the utm.py fixes from the 2026-11 review."""

import json
import random
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import utm  # noqa: E402
from utm import H, _addr_is_any, _svc_is_any, f, nv  # noqa: E402


def old_check_shadowed_policies(policies):
    """The original quadratic implementation, kept to prove the new one is identical."""
    findings = []
    enabled = [p for p in policies if nv(p.get("status", "enable")) != "disable"]
    for i, p_b in enumerate(enabled):
        pid_b, name_b = nv(p_b.get("policyid", p_b.get("_id", ""))), nv(p_b.get("name", ""))
        si_b, di_b, act_b = nv(p_b.get("srcintf", "")), nv(p_b.get("dstintf", "")), nv(p_b.get("action", ""))
        if _addr_is_any(nv(p_b.get("srcaddr", ""))) and _addr_is_any(nv(p_b.get("dstaddr", ""))) \
                and _svc_is_any(nv(p_b.get("service", ""))):
            continue
        for p_a in enabled[:i]:
            pid_a, name_a = nv(p_a.get("policyid", p_a.get("_id", ""))), nv(p_a.get("name", ""))
            si_a, di_a, act_a = nv(p_a.get("srcintf", "")), nv(p_a.get("dstintf", "")), nv(p_a.get("action", ""))
            if act_a != act_b:
                continue
            if si_a and si_b and si_a != si_b:
                continue
            if di_a and di_b and di_a != di_b:
                continue
            if _addr_is_any(nv(p_a.get("srcaddr", ""))) and _addr_is_any(nv(p_a.get("dstaddr", ""))) \
                    and _svc_is_any(nv(p_a.get("service", ""))):
                findings.append(f(H, f"Shadowed Policy: Policy #{pid_b} ('{name_b}') is COMPLETELY SHADOWED "
                                     f"by Policy #{pid_a} ('{name_a}'). "
                                     f"Policy #{pid_a} has action={act_a} with any-any-any src/dst/service "
                                     f"on the same interface pair — Policy #{pid_b} will NEVER be evaluated. "
                                     f"Review policy ordering or merge rules."))
                break
    return findings


def random_policies(rnd, n):
    out = []
    for i in range(n):
        p = {"_id": str(i), "policyid": str(i), "name": "p%d" % i,
             "srcintf": rnd.choice(['"port1"', '"port2"', "", '"any"']),
             "dstintf": rnd.choice(['"wan1"', '"port2"', ""]),
             "srcaddr": rnd.choice(['"all"', '"a"', '"a" "b"', ""]),
             "dstaddr": rnd.choice(['"all"', '"x"', ""]),
             "service": rnd.choice(['"ALL"', '"HTTPS"', ""]),
             "action": rnd.choice(["accept", "deny"])}
        if rnd.random() < 0.1:
            p["status"] = "disable"
        out.append(p)
    return out


class ShadowCheckTests(unittest.TestCase):
    def test_identical_to_original_on_random_sets(self):
        rnd = random.Random(42)
        for _ in range(300):
            pols = random_policies(rnd, rnd.randint(0, 40))
            self.assertEqual(utm.check_shadowed_policies(pols), old_check_shadowed_policies(pols))

    def test_5000_policies_under_one_second(self):
        pols = [{"_id": str(i), "srcintf": '"port1"', "dstintf": '"port2"', "srcaddr": '"a%d"' % i,
                 "dstaddr": '"b"', "service": '"HTTPS"', "action": "accept"} for i in range(5000)]
        start = time.time()
        utm.check_shadowed_policies(pols)
        self.assertLess(time.time() - start, 1.0)


class MultiValueTests(unittest.TestCase):
    def test_nv_list(self):
        self.assertEqual(utm.nv_list('"addr1" "Web Servers"'), ["addr1", "Web Servers"])
        self.assertEqual(utm.nv_list("accept"), ["accept"])
        self.assertEqual(utm.nv_list(""), [])

    def test_objects_in_multi_value_fields_are_used(self):
        cfg = "\n".join([
            "config firewall address", ' edit "a"', "  set subnet 10.0.0.1 255.255.255.255", " next",
            ' edit "b"', "  set subnet 10.0.0.2 255.255.255.255", " next",
            ' edit "spare"', "  set subnet 10.0.0.3 255.255.255.255", " next", "end",
            "config firewall policy", " edit 1", '  set srcaddr "a" "b"', '  set dstaddr "all"', " next", "end"])
        refs = utm.build_object_reference_map(utm.parse_firewall_policies(cfg), [], [], [], [], [])
        finds = utm.check_unused_objects(utm.parse_address_objects(cfg), [], [], [], [], [], [], [], [], refs)
        text = "\n".join(finds)
        self.assertNotIn("'a'", text)
        self.assertNotIn("'b'", text)
        self.assertIn("'spare'", text)

    def test_duplicate_detection_ignores_member_order_quotes(self):
        p1 = {"policyid": "1", "srcaddr": '"a" "b"', "dstaddr": '"all"', "service": '"HTTPS"'}
        p2 = {"policyid": "2", "srcaddr": '"b" "a"', "dstaddr": '"all"', "service": '"HTTPS"'}
        self.assertEqual(len(utm.check_duplicate_policies([p1, p2])), 1)


class CliSafetyTests(unittest.TestCase):
    def run_cli(self, tmp, *args):
        return subprocess.run([sys.executable, str(ROOT / "utm.py"), *args], cwd=tmp,
                              capture_output=True, text=True)

    def test_missing_file_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self.run_cli(tmp, "-c", "nope.conf", "-f")
            self.assertEqual(r.returncode, 2)
            self.assertNotIn("Traceback", r.stderr)

    def test_truncated_config_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cut.conf"
            cfg.write_text("config system global\n    set hostname fw\nconfig firewall policy\n    edit 1\n")
            r = self.run_cli(tmp, "-c", str(cfg), "--all")
            self.assertEqual(r.returncode, 2)
            self.assertIn("incomplete", r.stderr)
            self.assertFalse((Path(tmp) / "cut").exists())

    def test_truncated_config_allowed_is_marked(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cut.conf"
            cfg.write_text("config system global\n    set hostname fw\nconfig firewall policy\n    edit 1\n")
            r = self.run_cli(tmp, "-c", str(cfg), "-f", "--summary", "--allow-incomplete")
            self.assertEqual(r.returncode, 0, r.stderr)
            summary = (Path(tmp) / "cut" / "cut.conf_SUMMARY.txt").read_text()
            self.assertIn("INCOMPLETE CONFIGURATION", summary)
            data = json.loads((Path(tmp) / "cut" / "cut.conf_SUMMARY.json").read_text())
            self.assertTrue(data["summary"]["coverage_notes"])

    def test_multi_vdom_warning(self):
        pol = "config firewall policy\n    edit 1\n        set action accept\n    next\nend\n"
        cfg_text = ("config vdom\nedit root\nnext\nedit two\nnext\nend\nconfig vdom\nedit root\n" + pol +
                    "next\nedit two\n" + pol + "next\nend\n")
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "vd.conf"
            cfg.write_text(cfg_text)
            r = self.run_cli(tmp, "-c", str(cfg), "-f", "--summary")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("Multi-VDOM", r.stderr)
            self.assertIn("Multi-VDOM", (Path(tmp) / "vd" / "vd.conf_SUMMARY.txt").read_text())

    def test_policy_analysis_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self.run_cli(tmp, "-c", str(ROOT / "tests" / "fixtures" / "relationships.conf"),
                             "-pa", "--summary", "--html")
            self.assertEqual(r.returncode, 0, r.stderr)
            out = Path(tmp) / "relationships"
            self.assertTrue((out / "relationships.conf_policy_analysis_report.txt").exists())
            pa = json.loads((out / "relationships.conf_policy_analysis.json").read_text())
            self.assertTrue(any(fd["rule_id"] == "REL-SHADOW" for fd in pa["findings"]))
            summary = json.loads((out / "relationships.conf_SUMMARY.json").read_text())
            self.assertIn("Policy Analysis", summary["findings"])
            self.assertTrue((out / "relationships.conf_REPORT.html").exists())

    def test_policy_analysis_with_hitcounts(self):
        with tempfile.TemporaryDirectory() as tmp:
            hc = Path(tmp) / "hits.csv"
            hc.write_text("policyid,hits\n10,5000\n20,0\n30,12\n40,0\n50,0\n60,9000\n")
            r = self.run_cli(tmp, "-c", str(ROOT / "tests" / "fixtures" / "relationships.conf"),
                             "-pa", "--hitcounts", str(hc), "--hit-window-days", "90")
            self.assertEqual(r.returncode, 0, r.stderr)
            pa = json.loads((Path(tmp) / "relationships" / "relationships.conf_policy_analysis.json").read_text())
            unused = {fd["policies"][0] for fd in pa["findings"] if fd["rule_id"] == "POL-UNUSED"}
            self.assertEqual(unused, {"20", "40", "50"})
            self.assertEqual(pa["hit_counts"]["window_days"], 90)


if __name__ == "__main__":
    unittest.main()
