#!/usr/bin/env python3
"""Unprivileged, bounded interface counters; never reads connection secrets."""
import json
import re
import subprocess
import sys
import time
from pathlib import Path


def parse_mapping(text, profile):
    if not re.fullmatch(r'[a-z0-9-]+', profile):
        return None
    matches = []
    for line in text.splitlines():
        # Managed IDs contain no colons/backslashes. Unrelated escaped names
        # cannot accidentally match this exact ID; no broad owg-* fallback.
        fields = line.split(':')
        if len(fields) != 4:
            continue
        name, uuid, kind, interface = fields
        if (name == 'omarchy-wireguard-' + profile and kind == 'wireguard'
                and re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', uuid)
                and re.fullmatch(r'owg-[a-zA-Z0-9_-]{1,11}', interface)):
            matches.append((uuid, interface))
    return matches[0] if len(matches) == 1 else None


def active_connections():
    return subprocess.run(['nmcli', '-t', '-f', 'NAME,UUID,TYPE,DEVICE',
                           'connection', 'show', '--active'], check=True,
                          capture_output=True, text=True, timeout=0.7).stdout


def sample(profile, query=active_connections, root=Path('/sys/class/net')):
    try:
        mapping = parse_mapping(query(), profile)
        if mapping is None:
            return {'ok': False}
        uuid, interface = mapping
        base = root / interface
        index = int((base / 'ifindex').read_text())
        rx = int((base / 'statistics/rx_bytes').read_text())
        tx = int((base / 'statistics/tx_bytes').read_text())
        timestamp = time.monotonic()
        # Reject interfaces recreated or re-assigned during the read.
        if (index <= 0 or rx < 0 or tx < 0
                or int((base / 'ifindex').read_text()) != index
                or parse_mapping(query(), profile) != mapping):
            return {'ok': False}
        return {'ok': True, 'profile': profile, 'uuid': uuid,
                'interface': interface, 'ifindex': index,
                'rx': rx, 'tx': tx, 'time': timestamp}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {'ok': False}


if __name__ == '__main__':
    print(json.dumps(sample(sys.argv[1]) if len(sys.argv) == 2 else {'ok': False}))
