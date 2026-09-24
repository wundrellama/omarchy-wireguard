"""Last-connection state helper: atomic, private, validated, never a shell."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[2] / "plugin" / "last_connection.py"


class LastConnectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "state"
        self.env = dict(os.environ, XDG_STATE_HOME=str(self.state), HOME=str(Path(self.tmp.name) / "home"))
        self.directory = self.state / "wundrellama-wireguard"
        self.file = self.directory / "last-connection.json"

    def tearDown(self):
        self.tmp.cleanup()

    def run_helper(self, *args, env=None):
        result = subprocess.run([sys.executable, "-B", str(HELPER), *args], capture_output=True, text=True,
                                timeout=10, env=env or self.env)
        return result.returncode, json.loads(result.stdout)

    def test_round_trip_is_private_and_atomic(self):
        record = {"version": 1, "kind": "server", "value": "US-CA#370", "label": "US-CA#370"}
        code, out = self.run_helper("write", json.dumps(record))
        self.assertEqual((code, out["ok"]), (0, True))
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o600)
        self.assertEqual(os.listdir(self.directory), ["last-connection.json"], "no temporary files remain")
        code, out = self.run_helper("read")
        self.assertEqual(out, {"ok": True, "connection": record})
        # A second write replaces the file and keeps its private mode.
        other = {"version": 1, "kind": "wireguard", "value": "home", "label": "Home"}
        self.run_helper("write", json.dumps(other))
        self.assertEqual(self.run_helper("read")[1]["connection"], other)
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o600)

    def test_existing_directory_is_tightened(self):
        self.directory.mkdir(parents=True, mode=0o755)
        os.chmod(self.directory, 0o755)
        self.run_helper("write", json.dumps({"version": 1, "kind": "fastest", "value": "", "label": "Fastest"}))
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)

    def test_write_rejects_anything_but_a_choice_descriptor(self):
        for bad in ("{", "[]", json.dumps({"version": 1, "kind": "shell", "value": "x", "label": "x"}),
                    json.dumps({"version": 1, "kind": "server", "value": "x", "label": "x", "account": "a@b"}),
                    json.dumps({"version": 2, "kind": "fastest", "value": "", "label": "Fastest"}),
                    json.dumps({"version": 1, "kind": "city", "value": "a\nb", "label": "x"}),
                    json.dumps({"version": 1, "kind": "city", "value": "x" * 200, "label": "x"})):
            code, out = self.run_helper("write", bad)
            self.assertNotEqual(code, 0, bad)
            self.assertFalse(out["ok"])
        self.assertFalse(self.file.exists())

    def test_read_fails_closed(self):
        self.assertEqual(self.run_helper("read")[1]["ok"], False, "missing file")
        self.directory.mkdir(parents=True)
        self.file.write_text("{broken")
        self.assertEqual(self.run_helper("read")[1]["ok"], False)
        self.file.write_text(json.dumps({"version": 1, "kind": "server", "value": "x", "label": "x", "extra": 1}))
        self.assertEqual(self.run_helper("read")[1]["ok"], False)
        self.file.write_text(" " * 70000)
        self.assertEqual(self.run_helper("read")[1]["ok"], False, "oversized file")
        self.file.unlink()
        target = Path(self.tmp.name) / "elsewhere.json"
        target.write_text(json.dumps({"version": 1, "kind": "fastest", "value": "", "label": "Fastest"}))
        self.file.symlink_to(target)
        self.assertEqual(self.run_helper("read")[1]["ok"], False, "symlinks are not followed")

    def test_malformed_kinds_and_versions_never_traceback(self):
        base = {"version": 1, "value": "", "label": "x"}
        bad = [dict(base, kind=[]), dict(base, kind={}), dict(base, kind=None), dict(base, kind=1),
               {"version": True, "kind": "fastest", "value": "", "label": "Fastest"},
               {"version": 1.0, "kind": "fastest", "value": "", "label": "Fastest"}]
        for record in bad:
            code, out = self.run_helper("write", json.dumps(record))
            self.assertNotEqual(code, 0, record)
            self.assertEqual(out["ok"], False, record)
        self.assertFalse(self.file.exists())
        self.directory.mkdir(parents=True)
        for record in bad:
            self.file.write_text(json.dumps(record))
            self.assertEqual(self.run_helper("read")[1]["ok"], False, record)

    def test_deeply_nested_json_fails_closed(self):
        nested = "[" * 4000
        code, out = self.run_helper("write", nested)
        self.assertNotEqual(code, 0)
        self.assertEqual(out["ok"], False)
        self.directory.mkdir(parents=True)
        self.file.write_text(nested)
        self.assertEqual(self.run_helper("read")[1]["ok"], False)

    def test_read_refuses_fifo_and_directory_promptly(self):
        self.directory.mkdir(parents=True)
        os.mkfifo(self.file)
        self.assertEqual(self.run_helper("read")[1]["ok"], False, "a FIFO must not block the reader")
        self.file.unlink()
        self.file.mkdir()
        self.assertEqual(self.run_helper("read")[1]["ok"], False, "a directory is not a record")

    def test_read_refuses_a_file_owned_by_someone_else(self):
        self.directory.mkdir(parents=True)
        self.file.write_text(json.dumps({"version": 1, "kind": "tor", "value": "", "label": "Tor"}))
        sys.path.insert(0, str(HELPER.parent))
        try:
            import last_connection
        finally:
            sys.path.pop(0)
        saved = dict(os.environ)
        os.environ["XDG_STATE_HOME"] = str(self.state)
        real = os.getuid
        try:
            self.assertEqual(last_connection.read()["ok"], True)
            last_connection.os.getuid = lambda: real() + 1
            self.assertEqual(last_connection.read()["ok"], False)
        finally:
            last_connection.os.getuid = real
            os.environ.clear()
            os.environ.update(saved)

    def test_relative_xdg_state_home_falls_back_to_home(self):
        env = dict(self.env, XDG_STATE_HOME="relative/state")
        self.run_helper("write", json.dumps({"version": 1, "kind": "tor", "value": "", "label": "Tor"}), env=env)
        self.assertTrue((Path(self.tmp.name) / "home/.local/state/wundrellama-wireguard/last-connection.json").is_file())

    def test_unknown_command_is_refused(self):
        code, out = self.run_helper("delete")
        self.assertNotEqual(code, 0)
        self.assertFalse(out["ok"])


if __name__ == "__main__":
    unittest.main()
