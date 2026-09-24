"""Read or write the panel's last VPN choice.

File: $XDG_STATE_HOME/wundrellama-wireguard/last-connection.json (default
~/.local/state). The directory is 0700 and the file is 0600. A write goes to
a temporary file in the same directory and then replaces the file, so a
reader never sees half a record. The record is only a choice descriptor:
{"version": 1, "kind": ..., "value": ..., "label": ...}. It never holds
account data. QuickConnect.js checks the record again before it is used.

Usage: last_connection.py read | last_connection.py write '<json>'
Output: one JSON line, {"ok": true, ...} or {"ok": false, "error": ...}.
"""
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

MAX_BYTES = 4096
KEYS = {"version", "kind", "value", "label"}
QUICK = {"fastest", "random", "p2p", "securecore", "tor"}
CONTROL = re.compile(r"[\u0000-\u001f\u007f-\u009f]")
SERVER = re.compile(r"[A-Z]{2}(-[A-Z]{2,4})?#[0-9]{1,5}(-TOR)?")
COUNTRY = re.compile(r"[A-Z]{2}")
CITY = re.compile(r"[A-Za-z0-9\u00c0-\u024f\u1e00-\u1eff][A-Za-z0-9\u00c0-\u024f\u1e00-\u1eff .,'()-]{0,63}")


def state_dir():
    state = os.environ.get("XDG_STATE_HOME", "")
    base = Path(state) if state and os.path.isabs(state) else Path.home() / ".local" / "state"
    return base / "wundrellama-wireguard"


def text(value, limit=128):
    return isinstance(value, str) and 0 < len(value) <= limit and not CONTROL.search(value)


def valid(record):
    if not isinstance(record, dict) or set(record) != KEYS:
        return False
    version, kind, value = record.get("version"), record.get("kind"), record.get("value")
    # type() rejects True and 1.0; kind must be a string before any set lookup.
    if type(version) is not int or version != 1 or not isinstance(kind, str):
        return False
    if not text(record.get("label")) or not isinstance(value, str):
        return False
    if kind in QUICK:
        return value == ""
    if kind == "server":
        return bool(SERVER.fullmatch(value))
    if kind == "country":
        return bool(COUNTRY.fullmatch(value))
    if kind == "city":
        return bool(CITY.fullmatch(value)) and value == value.rstrip()
    if kind == "wireguard":
        return text(value)
    return False


def parse(raw):
    try:
        return json.loads(raw)
    except (ValueError, TypeError, RecursionError):
        return None


def read():
    # O_NONBLOCK: a FIFO at the path must not block the panel's reader.
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(state_dir() / "last-connection.json", flags)
    except OSError:
        return {"ok": False, "error": "no last connection"}
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            return {"ok": False, "error": "last connection is not a private regular file"}
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        return {"ok": False, "error": "last connection file is too large"}
    record = parse(raw)
    if record is None:
        return {"ok": False, "error": "last connection file is not valid JSON"}
    return {"ok": True, "connection": record} if valid(record) else {"ok": False, "error": "invalid last connection"}


def write(raw):
    record = parse(raw)
    if record is None or not valid(record):
        return {"ok": False, "error": "invalid last connection"}
    directory = state_dir()
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        return {"ok": False, "error": "state path is not a directory"}
    os.chmod(directory, 0o700)
    fd, temporary = tempfile.mkstemp(prefix=".last-connection.", dir=directory)
    try:
        with os.fdopen(fd, "w") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, directory / "last-connection.json")
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return {"ok": True}


def main(argv):
    try:
        if len(argv) == 2 and argv[1] == "read":
            result = read()
            code = 0
        elif len(argv) == 3 and argv[1] == "write":
            result = write(argv[2])
            code = 0 if result["ok"] else 1
        else:
            result, code = {"ok": False, "error": "usage: read | write JSON"}, 2
    except OSError as error:
        result, code = {"ok": False, "error": error.strerror or "file error"}, 1
    except (ValueError, TypeError, RecursionError):
        result, code = {"ok": False, "error": "invalid last connection"}, 1
    sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
