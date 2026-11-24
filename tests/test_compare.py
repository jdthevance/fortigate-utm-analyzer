"""Guards for the Go-port comparison baseline (standard library only)."""

from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import compare  # noqa: E402


class ComparisonBaselineTests(unittest.TestCase):
    def test_python_still_matches_recorded_baseline(self):
        # If this fails after an intentional change to utm.py, re-record with:
        #   python3 scripts/compare.py --update-golden
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "compare.py"),
             "--reference", "golden", "--candidate", "python"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout[-4000:] + proc.stderr)

    def test_every_case_has_a_recorded_baseline(self):
        for fixture in sorted(compare.FIXTURES.glob("*.conf")):
            for name, _ in compare.CASES:
                self.assertIsNotNone(compare.read_golden(fixture, name),
                                     f"{fixture.stem}/{name} has no baseline")

    def test_normalize_hides_run_specific_values(self):
        out = Path("/tmp/x/out")
        text = ('-> /tmp/x/out/a.txt and out/b.txt '
                '{"generated_at": "2026-11-24T22:24:55+00:00"}')
        self.assertEqual(
            compare.normalize(text, out),
            '-> <OUT_DIR>/a.txt and <OUT_DIR>/b.txt {"generated_at": "<TIMESTAMP>"}')

    def test_diff_reports_changed_missing_and_extra_files(self):
        expected = {"a.txt": "one\n", "b.txt": "same\n", "c.txt": "gone\n"}
        actual = {"a.txt": "two\n", "b.txt": "same\n", "d.txt": "new\n"}
        report = "\n".join(compare.diff_snapshots(expected, actual, 40))
        self.assertIn("-one", report)
        self.assertIn("+two", report)
        self.assertIn("missing file: c.txt", report)
        self.assertIn("unexpected file: d.txt", report)
        self.assertNotIn("b.txt", report)

    def test_cases_cover_every_cli_option(self):
        help_text = subprocess.run(
            [sys.executable, str(ROOT / "utm.py"), "--help"],
            capture_output=True, text=True).stdout
        covered = {arg for _, args in compare.CASES for arg in args}
        for flag in compare.DOMAIN_FLAGS:
            self.assertIn(flag, help_text)
        self.assertTrue(set(compare.DOMAIN_FLAGS) <= covered)
        self.assertIn("--all", covered)
        self.assertIn("--html", covered)


if __name__ == "__main__":
    unittest.main()
