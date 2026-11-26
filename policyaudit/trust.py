"""Trust levels for interfaces and zones.

To judge whether a policy creates an inappropriate trust relationship
(for example Guest Wi-Fi reaching the internal network), every interface
and zone gets a trust level:

==========  =====  =========================================================
Level       Rank   How it is recognised
==========  =====  =========================================================
internet    0      WAN role, default route, SD-WAN member, PPPoE
guest       1      name or alias contains guest / visitor / public / byod /
                   hotspot, or an open (no password) Wi-Fi SSID
dmz         2      DMZ role, or "dmz" in the name
remote      3      SSL-VPN (``ssl.*``) and IPsec tunnel interfaces
internal    4      LAN role, or anything not matched above
management  5      "mgmt" / "management" / "oob" / "ha" in the name, or the
                   dedicated management interface
==========  =====  =========================================================

The guesses can be overridden with a small JSON file passed as
``--trust-map``::

    {"Guest-WiFi": "guest", "port5": "dmz", "OT-Zone": "management"}

Go mapping: ``internal/trust``.
"""

from __future__ import annotations

import json
from typing import Dict, Optional, Tuple

from .objects import Resolver

LEVELS = ("internet", "guest", "dmz", "remote", "internal", "management")
RANK = {name: i for i, name in enumerate(LEVELS)}

GUEST_HINTS = ("guest", "visitor", "public", "byod", "hotspot", "captive", "iot-guest")
MGMT_HINTS = ("mgmt", "management", "oob", "out-of-band")
DMZ_HINTS = ("dmz",)


def load_map(path: Optional[str]) -> Dict[str, str]:
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    out = {}
    for name, level in raw.items():
        level = str(level).lower()
        if level not in RANK:
            raise ValueError("--trust-map: '{}' has unknown level '{}' (use one of: {})".format(
                name, level, ", ".join(LEVELS)))
        out[str(name)] = level
    return out


class TrustModel:
    def __init__(self, resolver: Resolver, overrides: Optional[Dict[str, str]] = None):
        self.r = resolver
        self.overrides = overrides or {}
        self._cache: Dict[str, Tuple[str, str]] = {}
        self._open_ssids = set()
        for scope_obj in resolver.scope.objects("wireless-controller vap"):
            if scope_obj.get("security") == "open":
                self._open_ssids.add(scope_obj.name)

    def level(self, name: str) -> Tuple[str, str]:
        """(level, reason) for an interface or zone name."""
        if name in self._cache:
            return self._cache[name]
        result = self._level(name)
        self._cache[name] = result
        return result

    def _level(self, name: str) -> Tuple[str, str]:
        if name in self.overrides:
            return self.overrides[name], "set in --trust-map"
        if name.lower() == "any":
            return "internet", "'any' includes internet-facing interfaces"
        info = self.r.interfaces.get(name)
        text = name.lower() + " " + (info.alias.lower() if info else "")
        if info and info.wan_reason:
            return "internet", info.wan_reason
        if any(h in text for h in GUEST_HINTS) or name in self._open_ssids:
            return "guest", "guest network (name or open SSID)"
        if any(h in text for h in MGMT_HINTS) or (info and info.itype == "physical" and name in ("mgmt", "ha")):
            return "management", "management network (name)"
        if (info and info.role == "dmz") or any(h in text for h in DMZ_HINTS):
            return "dmz", "DMZ (role or name)"
        if name.startswith("ssl.") or (info and info.itype == "tunnel"):
            return "remote", "VPN / remote access interface"
        if info and info.is_zone and info.members:
            levels = [self.level(m) for m in info.members]
            worst = min(levels, key=lambda lv: RANK[lv[0]])
            if worst[0] != "internal":
                return worst[0], "zone member: " + worst[1]
            return "internal", "all zone members are internal"
        if info and info.role == "lan":
            return "internal", "interface role is lan"
        return "internal", "no other evidence (assumed internal)"

    def lowest(self, names) -> Tuple[str, str, str]:
        """Least trusted of a list: (level, interface, reason)."""
        best = ("management", "", "")
        for n in names or ["any"]:
            lv, why = self.level(n)
            if RANK[lv] < RANK[best[0]] or not best[1]:
                best = (lv, n, why)
        return best

    def highest(self, names) -> Tuple[str, str, str]:
        best = ("internet", "", "")
        for n in names or ["any"]:
            if n.lower() == "any":
                return "management", n, "'any' includes every internal network"
            lv, why = self.level(n)
            if RANK[lv] > RANK[best[0]] or not best[1]:
                best = (lv, n, why)
        return best
