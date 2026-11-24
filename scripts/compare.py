#!/usr/bin/env python3
"""Compare analyzer implementations on every fixture and CLI case.

The Python analyzer (utm.py) is the behavioral reference for the Go port.
This script runs a *candidate* implementation and a *reference* on the same
inputs, normalizes values that legitimately change between runs, and prints
any differences. Standard library only.

Typical use:

    # Go port vs Python, run live side by side (the main check)
    python3 scripts/compare.py

    # Only some cases, e.g. while porting one domain
    python3 scripts/compare.py --case vpn,sslvpn

    # Has the Python reference drifted from the recorded baseline?
    python3 scripts/compare.py --reference golden --candidate python

    # Re-record the baseline after an intentional Python change
    python3 scripts/compare.py --update-golden

Exit status: 0 when every case matches, 1 when any case differs or the Go
build fails, 2 on usage errors.
"""

import argparse
import difflib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "testdata" / "fixtures"
GOLDEN = ROOT / "testdata" / "golden"
PYTHON_SCRIPT = ROOT / "utm.py"
GO_PACKAGE = "./cmd/forti-analyzer"

OUT_PLACEHOLDER = "<OUT_DIR>"

# Each case is (name, extra CLI arguments). "-c <fixture>" and
# "--out-dir <dir>" are added by the runner.
DOMAIN_FLAGS = [
    "-f", "-i", "-av", "-ips", "-wf", "-app", "-dns", "-waf", "-email",
    "-video", "-file", "-vpatch", "-llm", "-utm", "-vpn", "-sslvpn", "-ha",
    "-log", "-dos", "-antidos", "-intel", "-unused", "-vip", "-sdwan",
    "-iface", "-cert", "-fabric", "-ai", "-s", "--summary", "-bgp", "-auth",
    "--radius", "--ldap", "--saml", "--mfa",
]
CASES = [(flag.lstrip("-"), [flag]) for flag in DOMAIN_FLAGS] + [
    # Combinations shown in the README.
    ("readme-s-vpn-cert-summary", ["-s", "-vpn", "-cert", "--summary"]),
    ("readme-intel-unused-vip-summary", ["-intel", "-unused", "-vip", "--summary"]),
    ("readme-sdwan-iface-summary", ["-sdwan", "-iface", "--summary"]),
    # Long-option spellings must keep working.
    ("long-bgp-auth", ["--bgp", "--auth"]),
    # HTML with no audit selected produces an explicitly empty assessment.
    ("html-only", ["--html"]),
    # Everything, including the HTML dashboard.
    ("all", ["--all", "--summary", "--html"]),
]

# Values that change between runs and are not behavior.
NORMALIZERS = [
    (re.compile(r'("generated_at":\s*")[^"]*(")'), r"\1<TIMESTAMP>\2"),
]


def normalize(text, out_dir):
    text = text.replace(str(out_dir), OUT_PLACEHOLDER)
    text = re.sub(r"(?<![\w/.-])out/", OUT_PLACEHOLDER + "/", text)
    for pattern, replacement in NORMALIZERS:
        text = pattern.sub(replacement, text)
    return text


def snapshot(fixture, args, command, work):
    """Run one implementation once and return {relative name: normalized text}."""
    out_dir = work / "out"
    out_dir.mkdir(parents=True)
    # Run from a scratch directory with a local copy of the fixture and
    # relative paths, so outputs do not depend on where the repo lives.
    shutil.copyfile(fixture, work / fixture.name)
    proc = subprocess.run(
        [*command, "-c", fixture.name, *args, "--out-dir", "out"],
        cwd=work, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    result = {
        "_exit_code": f"{proc.returncode}\n",
        "_stdout.txt": normalize(proc.stdout, out_dir),
    }
    for path in sorted(out_dir.rglob("*")):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            result[path.relative_to(out_dir).as_posix()] = normalize(text, out_dir)
    return result


def read_golden(fixture, case):
    directory = GOLDEN / fixture.stem / case
    if not directory.is_dir():
        return None
    return {
        p.relative_to(directory).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(directory.rglob("*")) if p.is_file()
    }


def write_golden(fixture, case, files):
    directory = GOLDEN / fixture.stem / case
    if directory.exists():
        shutil.rmtree(directory)
    for name, text in files.items():
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)


def diff_snapshots(expected, actual, max_lines):
    lines = []
    for name in sorted(set(expected) | set(actual)):
        if name not in actual:
            lines.append(f"  missing file: {name}")
        elif name not in expected:
            lines.append(f"  unexpected file: {name}")
        elif expected[name] != actual[name]:
            body = list(difflib.unified_diff(
                expected[name].splitlines(), actual[name].splitlines(),
                f"reference/{name}", f"candidate/{name}", lineterm="", n=1))
            if len(body) > max_lines:
                body = body[:max_lines] + [f"... ({len(body) - max_lines} more diff lines)"]
            lines.extend("  " + line for line in body)
    return lines


def build_go(work):
    if shutil.which("go") is None:
        sys.exit("error: 'go' is not installed or not on PATH")
    if not (ROOT / "go.mod").exists():
        sys.exit("error: no go.mod yet; the Go port has not been started")
    binary = work / ("forti-analyzer.exe" if os.name == "nt" else "forti-analyzer")
    proc = subprocess.run(["go", "build", "-o", str(binary), GO_PACKAGE],
                          cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit("error: go build failed\n" + proc.stderr)
    return [str(binary)]


def main():
    parser = argparse.ArgumentParser(
        description="Compare the Go port against the Python reference.")
    parser.add_argument("--candidate", choices=["go", "python"], default="go",
                        help="implementation under test (default: go)")
    parser.add_argument("--reference", choices=["python", "golden"], default="python",
                        help="what to compare against: a live Python run "
                             "(default) or the recorded files in testdata/golden")
    parser.add_argument("--case", default="",
                        help="comma-separated case names to run (default: all); "
                             "use --list to see them")
    parser.add_argument("--fixture", default="",
                        help="comma-separated fixture names without .conf (default: all)")
    parser.add_argument("--update-golden", action="store_true",
                        help="re-record testdata/golden from the Python reference and exit")
    parser.add_argument("--list", action="store_true", help="list cases and fixtures")
    parser.add_argument("--max-diff-lines", type=int, default=40,
                        help="diff lines shown per file (default: 40)")
    opts = parser.parse_args()

    fixtures = sorted(FIXTURES.glob("*.conf"))
    if opts.fixture:
        wanted = set(opts.fixture.split(","))
        fixtures = [f for f in fixtures if f.stem in wanted]
    cases = CASES
    if opts.case:
        wanted = set(opts.case.split(","))
        unknown = wanted - {name for name, _ in CASES}
        if unknown:
            parser.error(f"unknown case(s): {', '.join(sorted(unknown))}")
        cases = [c for c in CASES if c[0] in wanted]

    if opts.list:
        print("Fixtures:", ", ".join(f.stem for f in fixtures) or "(none)")
        for name, args in cases:
            print(f"  {name:34} {' '.join(args)}")
        return 0
    if not fixtures:
        parser.error(f"no fixtures found in {FIXTURES}")

    python_cmd = [sys.executable, str(PYTHON_SCRIPT)]
    with tempfile.TemporaryDirectory(prefix="forti-compare-") as temp:
        temp = Path(temp)

        if opts.update_golden:
            for fixture in fixtures:
                for name, args in cases:
                    files = snapshot(fixture, args, python_cmd, temp / fixture.stem / name)
                    write_golden(fixture, name, files)
            print(f"Recorded {len(fixtures) * len(cases)} cases in "
                  f"{GOLDEN.relative_to(ROOT)}")
            return 0

        if opts.candidate == "python" and opts.reference == "python":
            parser.error("candidate and reference are both a live Python run; "
                         "use --reference golden")
        candidate_cmd = build_go(temp) if opts.candidate == "go" else python_cmd

        failures = 0
        for fixture in fixtures:
            for name, args in cases:
                label = f"{fixture.stem}/{name}"
                if opts.reference == "golden":
                    expected = read_golden(fixture, name)
                    if expected is None:
                        print(f"FAIL {label}: no recorded baseline (run --update-golden)")
                        failures += 1
                        continue
                else:
                    expected = snapshot(fixture, args, python_cmd, temp / "ref" / label)
                actual = snapshot(fixture, args, candidate_cmd, temp / "cand" / label)
                problems = diff_snapshots(expected, actual, opts.max_diff_lines)
                if problems:
                    failures += 1
                    print(f"FAIL {label}  ({' '.join(args)})")
                    print("\n".join(problems))
                else:
                    print(f"ok   {label}")

    total = len(fixtures) * len(cases)
    print(f"\n{total - failures}/{total} cases match "
          f"({opts.candidate} vs {opts.reference}).")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
