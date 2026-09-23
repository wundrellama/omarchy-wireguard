#!/usr/bin/env python3
"""Host-side READ-ONLY supervisor. Only unshare children may mutate networking."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile

TIMEOUT = 60
HERE = Path(__file__).resolve().parent


def read_host():
    """No nft/NM/systemd commands run in the host namespace, including reads."""
    result = {}
    for name, args in (
        ("links", ["-j", "link", "show"]),
        ("routes4", ["-j", "-4", "route", "show", "table", "all"]),
        ("routes6", ["-j", "-6", "route", "show", "table", "all"]),
    ):
        proc = subprocess.run(["ip", *args], check=True, capture_output=True, text=True, timeout=5)
        result[name] = json.loads(proc.stdout)
    return result


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def kill_group(proc):
    # Our own start_new_session process group, never an inherited host group.
    assert proc.pid != os.getpgrp()
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait(timeout=5)
    try:
        os.killpg(proc.pid, 0)
    except ProcessLookupError:
        return True
    return False


def main():
    missing = [name for name in ("ip", "wg", "nft", "unshare") if not shutil.which(name)]
    if missing:
        print(json.dumps({"status": "blocked", "missing_commands": missing}))
        return 2
    scratch = Path(os.environ.get("TMPDIR", str(Path.home() / ".hermes/cache/scratch"))).resolve()
    if scratch == Path("/tmp") or Path("/tmp") in scratch.parents:
        raise RuntimeError("Refusing /tmp; set TMPDIR to a private scratch directory")
    scratch.mkdir(parents=True, exist_ok=True)
    artifact = Path(tempfile.mkdtemp(prefix="wireguard-netns-", dir=scratch))
    host_net = os.readlink("/proc/self/ns/net")
    host_user = os.readlink("/proc/self/ns/user")
    before = read_host()
    save(artifact / "host-before.json", before)
    refused = subprocess.run(
        [sys.executable, "-B", str(HERE / "namespace_harness.py"),
         "--host-net", host_net, "--host-user", host_user],
        capture_output=True, text=True, timeout=5)
    guard_refused = refused.returncode != 0 and "REFUSED: not in the verified isolated" in refused.stderr
    report = {"host_netns": host_net, "host_before_sha256": digest(before),
              "kernel_release": os.uname().release,
              "backend_sha256": {name: hashlib.sha256(
                  (HERE.parents[1] / "backend" / "omarchy_wireguard" / name).read_bytes()).hexdigest()
                  for name in ("nftables.py", "system.py", "constants.py")},
              "host_direct_invocation_refused": guard_refused,
              "timeout_seconds_per_scenario": TIMEOUT, "artifact_directory": str(artifact), "scenarios": []}
    if not guard_refused:
        raise RuntimeError("Isolation guard self-test failed; refusing namespace scenarios")
    for name, flags in (("packet_tests", []), ("injected_failure", ["--inject-failure"])):
        proc = None
        entry: dict = {"name": name}
        try:
            proc = subprocess.Popen(
                ["unshare", "-Urn", sys.executable, "-B", str(HERE / "namespace_harness.py"),
                 "--host-net", host_net, "--host-user", host_user, *flags],
                start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = proc.communicate(timeout=TIMEOUT)
            entry["exit_code"] = proc.returncode
            entry["stderr"] = stderr.strip()
            try:
                entry["result"] = json.loads(stdout)
            except json.JSONDecodeError:
                entry["result"] = {"status": "blocked", "output": stdout}
        except subprocess.TimeoutExpired:
            entry["result"] = {"status": "blocked", "error": f"scenario exceeded {TIMEOUT}s bound"}
        finally:
            if proc is not None:
                entry["process_group_gone"] = kill_group(proc)
            after = read_host()
            save(artifact / f"host-after-{name}.json", after)
            entry["host_after_sha256"] = digest(after)
            entry["host_links_routes_unchanged"] = before == after
            entry["host_netns_unchanged"] = os.readlink("/proc/self/ns/net") == host_net
        report["scenarios"].append(entry)
        save(artifact / "results.json", report)
        if not entry["host_links_routes_unchanged"] or not entry["host_netns_unchanged"]:
            break
        # Kernel/tool failures are bounded: don't repeat an unavailable topology.
        if entry["result"]["status"] != "passed":
            break
    report["status"] = "passed" if (
        len(report["scenarios"]) == 2
        and report["scenarios"][0]["result"]["status"] == "passed"
        and report["scenarios"][1]["result"]["status"] == "expected_abort"
        and all(item["host_links_routes_unchanged"] and item["host_netns_unchanged"]
                and item.get("process_group_gone")
                and item["result"].get("peer_process_reaped") for item in report["scenarios"])
    ) else "failed_or_blocked"
    save(artifact / "results.json", report)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
