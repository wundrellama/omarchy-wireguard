"""Emergency rollback checks with real scratch files and inert OS boundaries."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader("wireguard_emergency_cli", str(ROOT / "bin/omarchy-wireguard"))
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
cli = importlib.util.module_from_spec(spec)
loader.exec_module(cli)


class EmergencyRollbackTests(unittest.TestCase):
    def test_catalog_failure_stops_daemon_but_retains_firewall(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory(prefix="wireguard-emergency-") as temporary:
            state = Path(temporary) / "state"
            def safe_path(value):
                return state if str(value) == "/var/lib/omarchy-wireguard" else Path(value)
            with patch.object(cli.os, "geteuid", return_value=0), \
                    patch.object(cli, "Path", side_effect=safe_path), \
                    patch.object(cli, "load_owned_profiles", side_effect=cli.CliError("bad catalog")), \
                    patch.object(cli.subprocess, "run", side_effect=run), \
                    self.assertRaisesRegex(cli.CliError, "firewall retained"):
                cli.emergency_disable()
        self.assertIn(["systemctl", "disable", "--now", "omarchy-wireguard.service"], calls)
        self.assertFalse(any(call[:2] == ["nft", "delete"] for call in calls))

    def invoke(self, *, nft_returncode=0, nft_output=None):
        if nft_output is None:
            nft_output = json.dumps({"nftables": [{"metainfo": {"json_schema_version": 1}}]})
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            rc, output = 0, ""
            if argv == ["systemctl", "disable", "--now", "omarchy-wireguard.service"]:
                pass
            elif argv == ["systemctl", "is-active", "--quiet", "omarchy-wireguard.service"]:
                rc = 3
            elif argv[:2] == ["nmcli", "-t"]:
                output = ""  # no active managed profiles in this rollback fixture
            elif argv == ["ip", "-json", "link", "show"]:
                output = "[]"
            elif argv == ["nft", "delete", "table", "inet", "omarchy_wireguard"]:
                pass
            elif argv == ["nft", "list", "table", "inet", "omarchy_wireguard"]:
                rc = 1  # legacy check: ambiguous absence OR inability to inspect
            elif argv == ["nft", "-j", "list", "tables"]:
                rc, output = nft_returncode, nft_output
            else:
                raise AssertionError("Unexpected OS command: " + repr(argv))
            if kwargs.get("check") and rc:
                raise subprocess.CalledProcessError(rc, argv)
            return subprocess.CompletedProcess(argv, rc, stdout=output, stderr="")

        with tempfile.TemporaryDirectory(prefix="wireguard-emergency-") as temporary:
            state = Path(temporary) / "state"
            def safe_path(value):
                if str(value) == "/var/lib/omarchy-wireguard":
                    return state
                return Path(value)
            with patch.object(cli.os, "geteuid", return_value=0), \
                    patch.object(cli, "Path", side_effect=safe_path), \
                    patch.object(cli, "load_owned_profiles", return_value=()), \
                    patch.object(cli.subprocess, "run", side_effect=run):
                result = cli.emergency_disable()
            self.assertFalse(json.loads((state / "state.json").read_text())["enabled"])
        return result, calls

    def test_unreadable_firewall_does_not_report_success(self):
        with self.assertRaisesRegex(cli.CliError, "verify.*firewall"):
            self.invoke(nft_returncode=1)

    def test_verified_absence_reports_success(self):
        observations = (
            {"nftables": [{"metainfo": {"json_schema_version": 1}}]},
            {"nftables": []},
            {"nftables": [{"table": {"family": "inet", "name": "unrelated"}},
                          {"table": {"family": "ip", "name": "omarchy_wireguard"}}]},
        )
        for observation in observations:
            with self.subTest(observation=observation):
                result, calls = self.invoke(nft_output=json.dumps(observation))
                self.assertTrue(result["ok"])
                self.assertIn(["nft", "-j", "list", "tables"], calls)

    def test_remaining_firewall_does_not_report_success(self):
        with self.assertRaisesRegex(cli.CliError, "still active"):
            self.invoke(nft_output=json.dumps({"nftables": [{"table": {"family": "inet", "name": "omarchy_wireguard"}}]}))

    def test_malformed_firewall_observation_does_not_report_success(self):
        for output in ("not json", "[]", "{}", '{"nftables":null}', '{"nftables":[null]}',
                       '{"nftables":[{"table":null}]}', '{"nftables":[{"table":{}}]}',
                       '{"nftables":[{"table":{"family":"inet","name":null}}]}',
                       '{"nftables":[{"unexpected":{}}]}'):
            with self.subTest(output=output), self.assertRaisesRegex(cli.CliError, "verify.*firewall"):
                self.invoke(nft_output=output)


if __name__ == "__main__":
    unittest.main()
