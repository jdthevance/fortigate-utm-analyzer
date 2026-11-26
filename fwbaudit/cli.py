"""Command line for ``fwb.py`` / ``python3 -m fwbaudit``.

Exit codes (same as ``python3 -m policyaudit``): 0 finished, 1 a finding at or
above ``--fail-on`` exists, 2 input problem (missing file, incomplete config
without ``--allow-incomplete``, bad ``--trust-map``).

Go mapping: ``cmd/fwbaudit``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from policyaudit import trust
from policyaudit.config import read_text
from policyaudit.model import SEVERITY_ORDER

from . import __version__, crosscheck, engine, report
from .checks import DOMAINS
from .checks.common import Options

EPILOG = """
Examples:
  python3 fwb.py -c fortiweb.conf                         # every FortiWeb domain
  python3 fwb.py -c fortiweb.conf -tls -sig               # TLS and signatures only
  python3 fwb.py -c fortiweb.conf -fg fortigate.conf --all  # audit + cross-check + summary
  python3 fwb.py -c fortiweb.conf -fg fortigate.conf --fortigate-vdom dmz --fail-on high
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fwb.py", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG,
        description="FortiWeb Security Analyzer v{} - FortiWeb 8.0 config audit, and FortiGate + FortiWeb "
                    "cross-checks.".format(__version__))
    parser.add_argument("-c", "--config", required=True, help="FortiWeb config backup (show full-configuration)")
    for key, (help_text, _) in DOMAINS.items():
        parser.add_argument("-" + key, dest="dom_" + key, action="store_true", help=help_text)
    parser.add_argument("-fg", "--fortigate", metavar="FILE",
                        help="FortiGate config backup: also check how the two appliances are connected")
    parser.add_argument("--fortigate-vdom", metavar="NAME", help="Only cross-check this FortiGate VDOM")
    parser.add_argument("--trust-map", metavar="FILE",
                        help='JSON mapping FortiGate interfaces/zones to trust levels, e.g. {"port5": "dmz"}')
    parser.add_argument("--summary", action="store_true", help="Executive summary (scored, utm.py style)")
    parser.add_argument("--all", action="store_true", help="Every domain, plus the summary")
    parser.add_argument("--out-dir", "--output-dir", metavar="DIRECTORY",
                        help="Where to write reports (default: FortiWeb file name without extension)")
    parser.add_argument("--allow-incomplete", action="store_true",
                        help="Audit a truncated or malformed config anyway (reports are marked INCOMPLETE)")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium"],
                        help="Exit with code 1 when a finding at or above this severity exists")
    parser.add_argument("--cert-warn-days", type=int, default=30, metavar="DAYS",
                        help="Warn about certificates expiring within DAYS (default 30)")
    return parser


def _read(path: str, what: str) -> Optional[str]:
    try:
        return read_text(path)
    except OSError as exc:
        print("error: cannot read {} config '{}': {}".format(what, path, exc.strerror or exc), file=sys.stderr)
        return None


def _refuse(errors: List[str], what: str) -> None:
    print("error: the {} configuration is incomplete or malformed, so it was not audited:".format(what),
          file=sys.stderr)
    for e in errors[:10]:
        print("  " + e, file=sys.stderr)
    print("Use --allow-incomplete to audit it anyway (reports will be marked INCOMPLETE).", file=sys.stderr)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    chosen = [k for k in DOMAINS if getattr(args, "dom_" + k)]
    if args.all or not chosen:
        chosen = list(DOMAINS)
    if args.all:
        args.summary = True

    text = _read(args.config, "FortiWeb")
    if text is None:
        return 2
    fg_text = None
    if args.fortigate:
        fg_text = _read(args.fortigate, "FortiGate")
        if fg_text is None:
            return 2
    try:
        trust_map = trust.load_map(args.trust_map)
    except (OSError, ValueError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    result = engine.run(text, Options(domains=chosen, cert_warn_days=args.cert_warn_days))
    if result.errors and not args.allow_incomplete:
        _refuse(result.errors, "FortiWeb")
        return 2
    cross = None
    if fg_text is not None:
        cross = crosscheck.run(fg_text, result.inventories, args.fortigate_vdom, trust_map)
        if cross.errors and not args.allow_incomplete:
            _refuse(cross.errors, "FortiGate")
            return 2

    base = Path(args.config).name
    out_dir = Path(args.out_dir).expanduser() if args.out_dir else Path(base).with_suffix("")
    out_dir.mkdir(parents=True, exist_ok=True)
    txt = out_dir / "{}_fortiweb_audit_report.txt".format(base)
    js = out_dir / "{}_fortiweb_audit.json".format(base)
    report.write(txt, report.render_fortiweb(result, args.config))
    print("[+] FortiWeb audit report -> {}".format(txt))
    sections = {"FortiWeb": result.findings}
    if cross is not None:
        xtxt = out_dir / "{}_crosscheck_report.txt".format(base)
        report.write(xtxt, report.render_cross(cross, args.config, args.fortigate))
        print("[+] Cross-check report    -> {}".format(xtxt))
        sections["Cross-check"] = cross.findings
        for w in cross.warnings:
            print("[!] " + w, file=sys.stderr)
    report.write_json(js, report.to_json(result, args.config, cross, args.fortigate or ""))
    print("[+] JSON                  -> {}".format(js))
    if args.summary:
        stxt = out_dir / "{}_fortiweb_summary.txt".format(base)
        paths = {"FortiWeb": args.config}
        if args.fortigate:
            paths["FortiGate"] = args.fortigate
        report.write(stxt, report.render_summary(sections, paths))
        print("[+] Executive summary     -> {}".format(stxt))
    allf = [f for fs in sections.values() for f in fs]
    s = report.score(allf)
    print("    Risk {} (score {})  ".format(s["risk"], s["score"]) +
          "  ".join("{}: {}".format(k, v) for k, v in s["counts"].items()))
    for w in result.warnings[:5]:
        print("[!] " + w, file=sys.stderr)

    if args.fail_on:
        limit = SEVERITY_ORDER[args.fail_on.upper()]
        if any(SEVERITY_ORDER[f.severity] <= limit for f in allf):
            return 1
    return 0
