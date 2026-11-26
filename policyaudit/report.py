"""Text and JSON reports for policy analysis results.

Go mapping: ``internal/report``.
"""

from __future__ import annotations

import json
import textwrap
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List

from . import __version__
from .engine import Result
from .model import BLOCKED, SEVERITY_ORDER, UNVALIDATED, VALIDATED

W = 80
ICON = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED] ", "INFO": "[INFO]"}
CATEGORY_ORDER = (
    "Policy relationships", "Trust relationships", "Permissive objects", "Service exposure",
    "Internet access", "UTM inspection", "Logging", "Unused policies", "Policy ordering",
    "Exposure risk", "Engine",
)
VALIDATION_TEXT = {
    VALIDATED: "VALIDATED - hit counts and dependency checks support removal",
    UNVALIDATED: "UNVALIDATED - do not remove on this evidence alone",
    BLOCKED: "BLOCKED - evidence says keep it",
}


def to_dict(result: Result, config_path: str) -> Dict[str, Any]:
    counts = Counter(f.severity for f in result.findings)
    return {
        "tool": "policyaudit", "version": __version__,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "config": config_path,
        "complete": result.complete,
        "parse_errors": result.errors,
        "parse_warnings": result.warnings,
        "hit_counts": {"source": result.hit_source, "window_days": result.hit_window_days},
        "elapsed_seconds": result.elapsed,
        "counts": {s: counts.get(s, 0) for s in SEVERITY_ORDER},
        "vdoms": result.vdoms,
        "findings": [f.to_dict() for f in result.findings],
    }


def write_json(result: Result, config_path: str, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_dict(result, config_path), fh, indent=2, ensure_ascii=False)


def _wrap(text: str, indent: str) -> List[str]:
    out = []
    for para in text.split("\n"):
        out.extend(textwrap.wrap(para, W - len(indent), initial_indent=indent,
                                 subsequent_indent=indent) or [indent])
    return out


def render_text(result: Result, config_path: str) -> str:
    L: List[str] = []
    L.append("=" * W)
    L.append(" FIREWALL POLICY ANALYSIS ".center(W, "="))
    L.append("=" * W)
    if not result.complete:
        L.append("")
        L.append("!" * W)
        L.append("  INCOMPLETE CONFIGURATION - results below may be wrong or missing.")
        for e in result.errors[:10]:
            L.append("  " + e)
        L.append("!" * W)
    L.append("")
    L.append("  Config        : {}".format(config_path))
    L.append("  Generated     : {}".format(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")))
    if result.hit_source:
        win = "{:g} days".format(result.hit_window_days) if result.hit_window_days else "unknown period"
        L.append("  Hit counts    : {} ({})".format(result.hit_source, win))
    else:
        L.append("  Hit counts    : not imported (unused-policy and traffic checks limited)")
    counts = Counter(f.severity for f in result.findings)
    L.append("  Findings      : " + "  ".join("{} {}".format(s, counts.get(s, 0)) for s in SEVERITY_ORDER))
    L.append("")
    for v in result.vdoms:
        rel = v["relations"]
        L.append("  VDOM {}: {} policies ({} enabled)".format(
            v["vdom"], sum(v["policies"].values()), v["enabled"]))
        for table, c in rel.items():
            L.append("    {}: {} covers, {} exact duplicates, {} partial overlaps, {} possible "
                     "(FQDN/unknown objects), {} pairs compared".format(
                         table, c.get("covers", 0), c.get("equal", 0), c.get("partial", 0),
                         c.get("possible", 0), c.get("pairs_compared", 0)))
        if v["internet_interfaces"]:
            L.append("    Internet-facing: {}{}".format(", ".join(v["internet_interfaces"]),
                                                      " (guessed from names)" if v["internet_guessed_from_names"] else ""))
        if v["unresolved_names"]:
            L.append("    Names not found in the config (treated as unknown): {}".format(
                ", ".join(v["unresolved_names"][:10])))
    L.append("")
    L.append("  How to read this report")
    L.extend(_wrap("Exact shadowing means a later rule can never be reached. Partial overlap means "
                   "only some of its traffic is decided by an earlier rule. Removal advice is "
                   "marked VALIDATED, UNVALIDATED or BLOCKED: only VALIDATED advice is backed by "
                   "hit counts and a dependency check. All CLI shown is a review example; this "
                   "tool never changes the firewall.", "    "))

    by_cat = defaultdict(list)
    for f in result.findings:
        by_cat[f.category].append(f)
    cats = [c for c in CATEGORY_ORDER if c in by_cat] + sorted(c for c in by_cat if c not in CATEGORY_ORDER)
    for cat in cats:
        items = sorted(by_cat[cat], key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.vdom))
        L.append("")
        L.append("-" * W)
        L.append("  {} ({})".format(cat.upper(), len(items)))
        L.append("-" * W)
        for f in items:
            L.append("")
            L.extend(_wrap("{} {} [{} / {}]".format(ICON.get(f.severity, ""), f.title, f.vdom, f.rule_id), "  "))
            if f.detail:
                L.extend(_wrap(f.detail, "         "))
            if f.validation:
                L.append("         Removal: " + VALIDATION_TEXT.get(f.validation, f.validation))
            if f.recommendation:
                L.extend(_wrap("Action: " + f.recommendation, "         "))
            if f.cli:
                for line in f.cli.splitlines():
                    L.append("           " + line)

    for v in result.vdoms:
        if v["exposure_ranking"]:
            L.append("")
            L.append("-" * W)
            L.append("  EXPOSURE RANKING - VDOM {} (top 15, score 0-100)".format(v["vdom"]))
            L.append("-" * W)
            L.append("  {:>5}  {:<10} {:<22} {:<22} {}".format("Score", "Policy", "From", "To", "Activity"))
            for r in v["exposure_ranking"][:15]:
                L.append("  {:>5.0f}  #{:<9} {:<22} {:<22} {}".format(
                    r["score"], str(r["policy"])[:9],
                    "{} {:,}".format(r["source"]["trust"], r["source"]["addresses"])[:22],
                    "{} {:,}".format(r["destination"]["trust"], r["destination"]["addresses"])[:22],
                    r["activity"]))
    L.append("")
    L.append("=" * W)
    L.append("  Finished in {:.2f} s".format(result.elapsed))
    return "\n".join(L) + "\n"


def write_text(result: Result, config_path: str, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_text(result, config_path))
