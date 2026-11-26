"""Command line: ``python3 -m policyaudit -c fw.conf [options]``.

Exit codes: 0 = finished, 1 = findings at or above ``--fail-on``,
2 = input problem (missing file, incomplete config without
``--allow-incomplete``, unreadable hit-count file).

Go mapping: ``cmd/policyaudit``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__, hits as hitmod, report, trust
from .config import read_text
from .engine import Options, run
from .model import SEVERITY_ORDER


def add_arguments(parser: argparse.ArgumentParser, standalone: bool = True) -> None:
    """Options shared with ``utm.py -pa``."""
    if standalone:
        parser.add_argument("-c", "--config", required=True, help="FortiGate config backup")
        parser.add_argument("--out-dir", "--output-dir", default=None, metavar="DIRECTORY",
                            help="Where to write reports (default: input filename without extension)")
        parser.add_argument("--allow-incomplete", action="store_true",
                            help="Analyse a truncated or broken config anyway (reports are marked INCOMPLETE)")
    parser.add_argument("--hitcounts", metavar="FILE",
                        help="Policy hit counts (FortiGate REST JSON or CSV); enables unused-policy, "
                             "busy-rule ordering and activity-based exposure")
    parser.add_argument("--hit-window-days", type=float, metavar="DAYS",
                        help="How many days the hit counters cover (time since reboot/reset)")
    parser.add_argument("--min-unused-days", type=float, default=30.0, metavar="DAYS",
                        help="Counter period needed before removal advice is VALIDATED (default 30)")
    parser.add_argument("--trust-map", metavar="FILE",
                        help='JSON mapping interface/zone names to trust levels, e.g. {"Guest-WiFi": "guest"}')


def options_from(args) -> Options:
    return Options(hit_window_days=args.hit_window_days, min_unused_days=args.min_unused_days,
                   trust_map=trust.load_map(args.trust_map))


def load_hits(args):
    if not args.hitcounts:
        return None
    return hitmod.load(args.hitcounts, args.hit_window_days)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="policyaudit",
        description="FortiGate firewall policy analysis v{}: relationships (shadowing, overlap, "
                    "redundancy), trust, exposure, inspection, logging, usage.".format(__version__))
    add_arguments(parser)
    parser.add_argument("--fail-on", choices=["critical", "high", "medium"],
                        help="Exit with code 1 when a finding at or above this severity exists")
    args = parser.parse_args(argv)

    try:
        text = read_text(args.config)
    except OSError as exc:
        print("error: cannot read config '{}': {}".format(args.config, exc.strerror or exc), file=sys.stderr)
        return 2
    try:
        hits = load_hits(args)
        options = options_from(args)
    except (OSError, ValueError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    result = run(text, options, hits)
    if result.errors and not args.allow_incomplete:
        print("error: the configuration is incomplete or malformed, so it was not analysed:", file=sys.stderr)
        for e in result.errors[:10]:
            print("  " + e, file=sys.stderr)
        print("Use --allow-incomplete to analyse it anyway (reports will be marked INCOMPLETE).", file=sys.stderr)
        return 2

    base = Path(args.config).name
    out_dir = Path(args.out_dir).expanduser() if args.out_dir else Path(base).with_suffix("")
    out_dir.mkdir(parents=True, exist_ok=True)
    txt = out_dir / "{}_policy_analysis_report.txt".format(base)
    js = out_dir / "{}_policy_analysis.json".format(base)
    report.write_text(result, args.config, txt)
    report.write_json(result, args.config, js)
    counts = {s: sum(1 for f in result.findings if f.severity == s) for s in SEVERITY_ORDER}
    print("[+] Policy analysis report -> {}".format(txt))
    print("[+] Policy analysis JSON   -> {}".format(js))
    print("    " + "  ".join("{}: {}".format(k, v) for k, v in counts.items()) +
          "   ({:.2f} s)".format(result.elapsed))
    for w in result.warnings[:5]:
        print("[!] " + w, file=sys.stderr)

    if args.fail_on:
        limit = SEVERITY_ORDER[args.fail_on.upper()]
        if any(SEVERITY_ORDER[f.severity] <= limit for f in result.findings):
            return 1
    return 0
