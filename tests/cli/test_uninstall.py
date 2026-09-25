import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader("wireguard_uninstall_cli", str(ROOT / "bin/omarchy-wireguard"))
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
cli = importlib.util.module_from_spec(spec)
loader.exec_module(cli)

UUID = "00000000-0000-0000-0000-000000000001"
ORPHAN = "00000000-0000-0000-0000-000000000099"


class CatalogCleanupTests(unittest.TestCase):
    def catalog(self, root, value):
        state = Path(root) / "state"
        state.mkdir(mode=0o700)
        path = state / "profiles.json"
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return state

    def test_catalog_reader_validates_exact_owned_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = self.catalog(temporary, [{"id": "home-1", "uuid": UUID, "label": "Home"}])
            self.assertEqual(cli.load_owned_profiles(state, os.getuid()),
                             ((UUID, "omarchy-wireguard-home-1"),))
            (state / "profiles.json").write_text("{broken")
            with self.assertRaises(cli.CliError):
                cli.load_owned_profiles(state, os.getuid())

    def test_uninstall_deletes_only_exact_catalog_profiles(self):
        records = ((UUID, "omarchy-wireguard-home-1"),)
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            output = ""
            if argv == ["nmcli", "-t", "-f", "UUID", "connection", "show"]:
                output = UUID + "\n" + ORPHAN + "\n"
            elif argv == ["nmcli", "-t", "-f", "UUID", "connection", "show", "--active"]:
                output = ""
            elif argv == ["nmcli", "--escape", "no", "-g", "connection.id,connection.uuid,connection.type",
                          "connection", "show", "uuid", UUID]:
                output = "omarchy-wireguard-home-1\n" + UUID + "\nwireguard\n"
            elif argv == ["nmcli", "-t", "-f", "NAME,UUID,TYPE", "connection", "show"]:
                output = ("omarchy-wireguard-home-1:" + UUID + ":wireguard\n"
                          "omarchy-wireguard-collision:" + ORPHAN + ":wireguard\n")
            elif argv == ["nmcli", "connection", "delete", "uuid", UUID]:
                pass
            else:
                raise AssertionError("unexpected command: " + repr(argv))
            return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

        with patch.object(cli, "load_owned_profiles", return_value=records), \
                patch.object(cli.subprocess, "run", side_effect=run), \
                patch.object(cli.os, "geteuid", return_value=0):
            result = cli.uninstall_profiles()
        self.assertEqual(result["deleted"], [UUID])
        self.assertEqual(result["retained_orphans"], [ORPHAN])
        self.assertNotIn(["nmcli", "connection", "delete", "uuid", ORPHAN], calls)

    def test_identity_mismatch_aborts_before_any_delete(self):
        records = ((UUID, "omarchy-wireguard-home-1"),)
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            if argv == ["nmcli", "-t", "-f", "UUID", "connection", "show"]:
                return subprocess.CompletedProcess(argv, 0, stdout=UUID + "\n", stderr="")
            if argv[0:3] == ["nmcli", "--escape", "no"]:
                return subprocess.CompletedProcess(argv, 0, stdout="wrong-name\n" + UUID + "\nwireguard\n", stderr="")
            raise AssertionError("unexpected command: " + repr(argv))

        with patch.object(cli, "load_owned_profiles", return_value=records), \
                patch.object(cli.subprocess, "run", side_effect=run), \
                patch.object(cli.os, "geteuid", return_value=0), \
                self.assertRaisesRegex(cli.CliError, "identity"):
            cli.uninstall_profiles()
        self.assertFalse(any(call[:3] == ["nmcli", "connection", "delete"] for call in calls))

    def test_active_orphan_blocks_uninstall_without_deletion(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            if argv == ["nmcli", "-t", "-f", "UUID", "connection", "show"]:
                output = ORPHAN + "\n"
            elif argv == ["nmcli", "-t", "-f", "UUID", "connection", "show", "--active"]:
                output = ORPHAN + "\n"
            elif argv == ["nmcli", "-t", "-f", "NAME,UUID,TYPE", "connection", "show"]:
                output = "omarchy-wireguard-orphan:" + ORPHAN + ":wireguard\n"
            else:
                raise AssertionError("unexpected command: " + repr(argv))
            return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

        with patch.object(cli, "load_owned_profiles", return_value=()), \
                patch.object(cli.subprocess, "run", side_effect=run), \
                patch.object(cli.os, "geteuid", return_value=0), \
                self.assertRaisesRegex(cli.CliError, "active uncataloged"):
            cli.uninstall_profiles()
        self.assertFalse(any(call[:3] == ["nmcli", "connection", "delete"] for call in calls))


if __name__ == "__main__":
    unittest.main()
