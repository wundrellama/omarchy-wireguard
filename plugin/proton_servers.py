"""Print a compact, read-only index of available Proton VPN servers.

The official client caches its server list in
$XDG_CACHE_HOME/Proton/VPN/serverlist.json (about 24 MB). QML must not parse
that file, so this helper reads it once and prints only what the panel search
needs: name, exit country, city, features, load and tier. It keeps servers
with Status == 1 and a tier the account can use (Tier <= MaxTier). Every
value is checked with the same rules as Proton.js; anything else is dropped.
It never writes a file and never runs a command. Any problem prints ok:false.
"""
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_BYTES = 64 * 1024 * 1024
MAX_SERVERS = 30000
FIELDS = ["name", "country", "city", "features", "load", "tier"]
# proton/vpn/session/servers/types.py ServerFeatureEnum (IntFlag).
FEATURES = (("securecore", 1), ("tor", 2), ("p2p", 4), ("streaming", 8), ("ipv6", 16))
SERVER = re.compile(r"[A-Z]{2}(-[A-Z]{2,4})?#[0-9]{1,5}(-TOR)?")
COUNTRY = re.compile(r"[A-Z]{2}")
CITY = re.compile(r"[A-Za-z0-9\u00c0-\u024f\u1e00-\u1eff][A-Za-z0-9\u00c0-\u024f\u1e00-\u1eff .,'()-]{0,63}")


def default_path():
    cache = os.environ.get("XDG_CACHE_HOME", "")
    base = Path(cache) if cache and os.path.isabs(cache) else Path.home() / ".cache"
    return base / "Proton" / "VPN" / "serverlist.json"


def number(value):
    return isinstance(value, int) and not isinstance(value, bool)


def row(item, max_tier):
    if not isinstance(item, dict) or item.get("Status") != 1:
        return None
    name, country, city = item.get("Name"), item.get("ExitCountry"), item.get("City")
    features, load, tier = item.get("Features"), item.get("Load"), item.get("Tier")
    if not isinstance(name, str) or not SERVER.fullmatch(name):
        return None
    if not isinstance(country, str) or not COUNTRY.fullmatch(country):
        return None
    if not number(features) or not number(load) or not 0 <= load <= 100:
        return None
    if not number(tier) or tier < 0 or (max_tier is not None and tier > max_tier):
        return None
    if not isinstance(city, str) or not CITY.fullmatch(city) or city != city.rstrip():
        city = ""
    return [name, country, city, [label for label, bit in FEATURES if features & bit], load, tier]


def index(path):
    try:
        # O_NONBLOCK: a FIFO at the path must not block the helper.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return {"ok": False, "error": "Proton server list not found"}
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            return {"ok": False, "error": "Proton server list is not a regular file"}
        size = info.st_size
        if size <= 0 or size > MAX_BYTES:
            return {"ok": False, "error": "Proton server list has an unexpected size"}
        raw = handle.read(MAX_BYTES + 1)
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return {"ok": False, "error": "Proton server list is not valid JSON"}
    if not isinstance(data, dict) or not isinstance(data.get("LogicalServers"), list):
        return {"ok": False, "error": "Proton server list has an unexpected format"}
    max_tier = data.get("MaxTier") if number(data.get("MaxTier")) else None
    servers, seen = [], set()
    for item in data["LogicalServers"]:
        entry = row(item, max_tier)
        if entry is None or entry[0] in seen:
            continue
        seen.add(entry[0])
        servers.append(entry)
        if len(servers) >= MAX_SERVERS:
            break
    return {"ok": True, "maxTier": max_tier, "fields": FIELDS, "count": len(servers), "servers": servers}


def main(argv):
    path = Path(argv[1]) if len(argv) > 1 else default_path()
    try:
        result = index(path)
    except (OSError, MemoryError):
        result = {"ok": False, "error": "Could not read the Proton server list"}
    sys.stdout.write(json.dumps(result, separators=(",", ":"), ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
