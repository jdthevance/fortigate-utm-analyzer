"""Interval sets: the maths behind "does rule A cover rule B".

Every address, address group, service and service group is turned into an
:class:`IntervalSet`, a sorted list of non-overlapping inclusive ranges of
integers. Comparing two rules then becomes simple range arithmetic, which is
exact and fast.

To compare everything on one number line, each kind of value gets its own
region:

* Addresses: IPv4 at 0..2^32-1, then a region for IPv4 objects that have no
  fixed IP (FQDN, geography, dynamic). IPv6 and its non-IP objects follow.
  "all" covers both the IPs and the non-IP objects of its family, so
  ``all`` contains an FQDN object, but ``10.0.0.0/8`` does not.
* Services: TCP ports, UDP ports, SCTP ports, ICMP types, ICMPv6 types,
  other IP protocol numbers, then a region for services the resolver cannot
  express as ports (for example ones restricted by source port).

Go mapping: ``internal/netset`` with ``type Set []Range``; Go will need
``math/big`` or two uint64 words for the IPv6 region.
"""

from __future__ import annotations

import bisect
import ipaddress
from typing import Iterable, List, Optional, Sequence, Tuple

Range = Tuple[int, int]

# ── Address number line ──────────────────────────────────────────────────────
TOKEN_SPAN = 1 << 24
V4_LO, V4_HI = 0, (1 << 32) - 1
V4_TOK_LO = 1 << 32
V4_TOK_HI = V4_TOK_LO + TOKEN_SPAN - 1
V6_LO = 1 << 33
V6_HI = V6_LO + (1 << 128) - 1
V6_TOK_LO = V6_HI + 1
V6_TOK_HI = V6_TOK_LO + TOKEN_SPAN - 1

# ── Service number line ──────────────────────────────────────────────────────
PORTS = 1 << 16
TCP_BASE, UDP_BASE, SCTP_BASE = 0, PORTS, 2 * PORTS
ICMP_BASE = 3 * PORTS
ICMP6_BASE = ICMP_BASE + 256
PROTO_BASE = ICMP_BASE + 512            # other IP protocol numbers 0..255
SVC_TOK_LO = 4 * PORTS
SVC_TOK_HI = SVC_TOK_LO + TOKEN_SPAN - 1
SVC_ALL: Range = (0, SVC_TOK_HI)


class IntervalSet:
    """An immutable set of integers stored as merged inclusive ranges."""

    __slots__ = ("ranges", "_lo", "_hi")

    def __init__(self, ranges: Iterable[Range] = ()):
        self.ranges: Tuple[Range, ...] = _normalise(ranges)
        self._lo = self.ranges[0][0] if self.ranges else None
        self._hi = self.ranges[-1][1] if self.ranges else None

    # basic properties
    def __bool__(self) -> bool:
        return bool(self.ranges)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, IntervalSet) and self.ranges == other.ranges

    def __hash__(self) -> int:
        return hash(self.ranges)

    def __repr__(self) -> str:
        return "IntervalSet({!r})".format(list(self.ranges))

    @property
    def bounds(self) -> Optional[Range]:
        if not self.ranges:
            return None
        return (self._lo, self._hi)

    def size(self) -> int:
        return sum(hi - lo + 1 for lo, hi in self.ranges)

    def size_within(self, lo: int, hi: int) -> int:
        total = 0
        for a, b in self.ranges:
            a2, b2 = max(a, lo), min(b, hi)
            if a2 <= b2:
                total += b2 - a2 + 1
        return total

    # set algebra
    def union(self, other: "IntervalSet") -> "IntervalSet":
        return IntervalSet(self.ranges + other.ranges)

    def intersect(self, other: "IntervalSet") -> "IntervalSet":
        out: List[Range] = []
        a, b = self.ranges, other.ranges
        i = j = 0
        while i < len(a) and j < len(b):
            lo = max(a[i][0], b[j][0])
            hi = min(a[i][1], b[j][1])
            if lo <= hi:
                out.append((lo, hi))
            if a[i][1] < b[j][1]:
                i += 1
            else:
                j += 1
        return IntervalSet(out)

    def overlaps(self, other: "IntervalSet") -> bool:
        if not self.ranges or not other.ranges:
            return False
        if self._hi < other._lo or other._hi < self._lo:
            return False
        a, b = self.ranges, other.ranges
        i = j = 0
        while i < len(a) and j < len(b):
            if a[i][0] <= b[j][1] and b[j][0] <= a[i][1]:
                return True
            if a[i][1] < b[j][1]:
                i += 1
            else:
                j += 1
        return False

    def contains(self, other: "IntervalSet") -> bool:
        """True if every value of ``other`` is in this set."""
        if not other.ranges:
            return True
        if not self.ranges:
            return False
        if other._lo < self._lo or other._hi > self._hi:
            return False
        starts = [r[0] for r in self.ranges]
        for lo, hi in other.ranges:
            k = bisect.bisect_right(starts, lo) - 1
            if k < 0 or self.ranges[k][1] < hi:
                return False
        return True

    def complement(self, lo: int, hi: int) -> "IntervalSet":
        out: List[Range] = []
        cur = lo
        for a, b in self.ranges:
            if b < lo or a > hi:
                continue
            if a > cur:
                out.append((cur, a - 1))
            cur = max(cur, b + 1)
        if cur <= hi:
            out.append((cur, hi))
        return IntervalSet(out)


def _normalise(ranges: Iterable[Range]) -> Tuple[Range, ...]:
    items = sorted((int(lo), int(hi)) for lo, hi in ranges if lo <= hi)
    if not items:
        return ()
    merged = [list(items[0])]
    for lo, hi in items[1:]:
        last = merged[-1]
        if lo <= last[1] + 1:
            if hi > last[1]:
                last[1] = hi
        else:
            merged.append([lo, hi])
    return tuple((lo, hi) for lo, hi in merged)


EMPTY = IntervalSet()


# ── Address helpers ──────────────────────────────────────────────────────────

def v4_range(first: str, last: str) -> Range:
    return (int(ipaddress.IPv4Address(first)), int(ipaddress.IPv4Address(last)))


def v4_network(addr: str, mask: str = "") -> Range:
    """``10.0.0.0 255.0.0.0`` or ``10.0.0.0/8`` -> range of integers."""
    text = addr if not mask else "{}/{}".format(addr, mask)
    net = ipaddress.IPv4Network(text, strict=False)
    return (int(net.network_address), int(net.broadcast_address))


def v6_network(text: str) -> Range:
    net = ipaddress.IPv6Network(text, strict=False)
    return (V6_LO + int(net.network_address), V6_LO + int(net.broadcast_address))


def v6_range(first: str, last: str) -> Range:
    return (V6_LO + int(ipaddress.IPv6Address(first)), V6_LO + int(ipaddress.IPv6Address(last)))


V4_ALL = IntervalSet([(V4_LO, V4_TOK_HI)])
V6_ALL = IntervalSet([(V6_LO, V6_TOK_HI)])


def v4_count(s: IntervalSet) -> int:
    """Number of real IPv4 addresses in the set (non-IP objects excluded)."""
    return s.size_within(V4_LO, V4_HI)


def v6_count(s: IntervalSet) -> int:
    return s.size_within(V6_LO, V6_HI)


def has_tokens(s: IntervalSet) -> bool:
    return bool(s.size_within(V4_TOK_LO, V4_TOK_HI) or s.size_within(V6_TOK_LO, V6_TOK_HI))


def describe_v4(s: IntervalSet, limit: int = 4) -> str:
    """Short human text for the IPv4 part, e.g. ``10.0.0.0/8, 192.168.1.5``."""
    parts: List[str] = []
    for lo, hi in s.ranges:
        if lo > V4_HI:
            break
        hi = min(hi, V4_HI)
        nets = list(ipaddress.summarize_address_range(
            ipaddress.IPv4Address(lo), ipaddress.IPv4Address(hi)))
        for n in nets:
            parts.append(str(n.network_address) if n.prefixlen == 32 else str(n))
            if len(parts) > limit:
                return ", ".join(parts[:limit]) + ", ..."
    return ", ".join(parts)


def prefix_equivalent(count: int, bits: int = 32) -> int:
    """Smallest prefix length whose network holds ``count`` addresses."""
    if count <= 0:
        return bits
    return max(0, bits - (count - 1).bit_length())


# ── Service helpers ──────────────────────────────────────────────────────────

PROTO_REGIONS: Sequence[Tuple[str, int, int]] = (
    ("TCP", TCP_BASE + 1, TCP_BASE + 65535),
    ("UDP", UDP_BASE + 1, UDP_BASE + 65535),
    ("SCTP", SCTP_BASE + 1, SCTP_BASE + 65535),
)


def port_count(s: IntervalSet) -> int:
    """Total TCP + UDP + SCTP destination ports in a service set."""
    return sum(s.size_within(lo, hi) for _, lo, hi in PROTO_REGIONS)


def ports_of(s: IntervalSet, proto: str) -> IntervalSet:
    for name, lo, hi in PROTO_REGIONS:
        if name == proto:
            base = lo - 1
            return IntervalSet((max(a, lo) - base, min(b, hi) - base)
                               for a, b in s.ranges if b >= lo and a <= hi)
    return EMPTY


def describe_service(s: IntervalSet, limit: int = 6) -> str:
    if s.contains(IntervalSet([SVC_ALL])):
        return "all protocols"
    parts: List[str] = []
    for name, lo, hi in PROTO_REGIONS:
        p = ports_of(s, name)
        for a, b in p.ranges:
            parts.append("{}/{}".format(name.lower(), a if a == b else "{}-{}".format(a, b)))
    if s.size_within(ICMP_BASE, ICMP6_BASE + 255):
        parts.append("icmp")
    if s.size_within(PROTO_BASE, PROTO_BASE + 255):
        parts.append("other IP protocols")
    if s.size_within(SVC_TOK_LO, SVC_TOK_HI):
        parts.append("services with source-port or other limits")
    if len(parts) > limit:
        return ", ".join(parts[:limit]) + ", ..."
    return ", ".join(parts) or "nothing"
