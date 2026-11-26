"""Optional policy hit-count import.

A config backup says what the rules *allow*; hit counts say what traffic
actually *uses*. They unlock three things: unused-policy detection,
busy-rules-first ordering advice, and exposure risk based on real use.

Supported files (pick whichever is easiest to export):

1. FortiGate REST API JSON, saved as-is from
   ``GET /api/v2/monitor/firewall/policy?vdom=*``
   (a dict with ``results``, or a list of those, one per VDOM).
2. CSV with a header row. Column names are matched loosely
   (case, spaces and underscores ignored):

   ==============  ======================================================
   Meaning         Accepted header names
   ==============  ======================================================
   policy id       ``policyid``, ``policy id``, ``id``, ``seq``
   hit count       ``hit_count``, ``hits``, ``hit count``, ``count``
   last used       ``last_used``, ``last hit``, ``last used`` (unix time
                   or ``YYYY-MM-DD[ HH:MM[:SS]]``)
   bytes           ``bytes``, ``total bytes``
   VDOM            ``vdom``, ``virtual domain`` (optional)
   ==============  ======================================================

Hit counters reset when the firewall reboots or counters are cleared, so
the tool also needs to know **how many days the counters cover**
(``--hit-window-days``). Without it, zero-hit policies are reported but
any removal advice stays "unvalidated".

Go mapping: ``internal/hits`` with ``func Load(path string) (*Data, error)``.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .model import HitRecord

ALIASES = {
    "policyid": ("policyid", "policy id", "id", "seq", "seqnum", "policy"),
    "hits": ("hitcount", "hits", "hit count", "count", "hit_count"),
    "last_used": ("lastused", "last used", "last hit", "lasthit", "last_used", "last_hit"),
    "bytes": ("bytes", "total bytes", "totalbytes"),
    "vdom": ("vdom", "virtual domain", "virtualdomain"),
}


def _norm(h: str) -> str:
    return re.sub(r"[\s_\-]+", "", h.strip().lower())


_ALIAS_LOOKUP = {_norm(a): k for k, names in ALIASES.items() for a in names}


@dataclass
class HitData:
    source: str
    records: Dict[Tuple[Optional[str], str], HitRecord] = field(default_factory=dict)
    window_days: Optional[float] = None
    warnings: List[str] = field(default_factory=list)

    def lookup(self, vdom: str, policyid: str, single_vdom: bool) -> Optional[HitRecord]:
        rec = self.records.get((vdom, policyid))
        if rec is not None:
            return rec
        if single_vdom or not self.has_vdoms:
            return self.records.get((None, policyid))
        return None

    @property
    def has_vdoms(self) -> bool:
        return any(v is not None for v, _ in self.records)


def _int(value) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(float(str(value).replace(",", "")))
    except ValueError:
        return None


def _time(value) -> Optional[int]:
    if value in (None, "", 0, "0", "never", "Never", "-"):
        return None
    n = _int(value)
    if n is not None and n > 100000:
        return n
    text = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d"):
        try:
            return int(datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            continue
    return None


def load(path: str, window_days: Optional[float] = None) -> HitData:
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        text = fh.read()
    data = loads(text, source=path)
    if window_days is not None:
        data.window_days = window_days
    return data


def loads(text: str, source: str = "<text>") -> HitData:
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return _from_json(json.loads(text), source)
    return _from_csv(text, source)


def _from_json(doc, source: str) -> HitData:
    data = HitData(source)
    if isinstance(doc, dict) and "window_days" in doc:
        data.window_days = float(doc["window_days"])
    chunks = doc if isinstance(doc, list) else [doc]
    for chunk in chunks:
        if not isinstance(chunk, dict):
            continue
        if "results" in chunk and isinstance(chunk["results"], list):
            vdom = chunk.get("vdom")
            rows = chunk["results"]
        else:
            vdom, rows = None, [chunk]
        for row in rows:
            if not isinstance(row, dict):
                continue
            _add(data, row.get("vdom", vdom), row.get("policyid", row.get("id")),
                 row.get("hit_count", row.get("hits")), row.get("last_used", row.get("last_hit")),
                 row.get("bytes"))
    if not data.records:
        data.warnings.append("No policy rows found in {}".format(source))
    return data


def _from_csv(text: str, source: str) -> HitData:
    data = HitData(source)
    reader = csv.reader(io.StringIO(text))
    header = None
    for row in reader:
        if not row or all(not c.strip() for c in row):
            continue
        if header is None:
            header = [_ALIAS_LOOKUP.get(_norm(c)) for c in row]
            if "policyid" not in header or "hits" not in header:
                raise ValueError("{}: CSV needs a policy id column and a hit count column "
                                 "(found: {})".format(source, ", ".join(row)))
            continue
        values = {k: row[i] for i, k in enumerate(header) if k and i < len(row)}
        _add(data, values.get("vdom") or None, values.get("policyid"), values.get("hits"),
             values.get("last_used"), values.get("bytes"))
    if not data.records:
        data.warnings.append("No policy rows found in {}".format(source))
    return data


def _add(data: HitData, vdom, policyid, hits, last_used, nbytes) -> None:
    pid = str(policyid).strip() if policyid is not None else ""
    count = _int(hits)
    if not pid or count is None:
        return
    key = (str(vdom) if vdom else None, pid)
    rec = data.records.get(key)
    if rec is None:
        data.records[key] = HitRecord(count, _time(last_used), _int(nbytes))
    else:   # the same policy listed twice (IPv4 and IPv6 rows): add them up
        rec.hits += count
        lu = _time(last_used)
        if lu and (rec.last_used is None or lu > rec.last_used):
            rec.last_used = lu
