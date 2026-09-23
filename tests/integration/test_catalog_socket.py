"""Offline integration: real CLI/socket/authorization/parser/state, simulated host IO.

Never starts the root daemon or changes networking. These tests do not prove
that NetworkManager, DNS, the firewall, or actual VPN traffic work on a host.
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

from omarchy_wireguard.controller import Controller
from omarchy_wireguard.daemon import _handle_connection
from omarchy_wireguard.nftables import FirewallContext
from omarchy_wireguard.storage import StateStore


ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader("socket_cli", str(ROOT / "bin/omarchy-wireguard"))
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
cli = importlib.util.module_from_spec(spec)
loader.exec_module(cli)

# Deliberately synthetic fixture, never a user's VPN configuration.
CONFIG = """[Interface]
PrivateKey = TEST_ONLY_NOT_A_REAL_PRIVATE_KEY
Address = 10.55.0.2/32
DNS = 10.55.0.1
[Peer]
PublicKey = TEST_ONLY_NOT_A_REAL_PUBLIC_KEY
AllowedIPs = 0.0.0.0/0
Endpoint = 192.0.2.8:51820
"""


class CatalogHost:
    """Only the explicit import and connection-scheduling boundaries exist."""
    def __init__(self):
        self.profiles = {}
        self.deactivations = 0
        self.firewalls = []

    def managed_profiles(self):
        return dict(self.profiles)

    def import_profile(self, profile, name):
        identifier = str(uuid.uuid4())
        self.profiles[identifier] = name
        return identifier

    def delete_profile(self, identifier):
        del self.profiles[identifier]

    def deactivate_managed(self):
        self.deactivations += 1

    def inspect_firewall_context(self):
        return FirewallContext()

    def apply_firewall(self, context):
        self.firewalls.append(context)


class CatalogSocketTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = StateStore(self.root / "state", owner_uid=os.getuid())
        self.host = CatalogHost()
        self.controller = Controller(self.store, self.host, controller_uid=os.getuid())
        self.socket_path = str(self.root / "s")
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self.server.close)
        self.server.bind(self.socket_path)
        self.server.listen(1)
        self.server.settimeout(3)
        no_host_commands = patch.object(cli.subprocess, "run", side_effect=AssertionError("host IO escaped test"))
        no_host_commands.start()
        self.addCleanup(no_host_commands.stop)

    def invoke(self, *arguments):
        errors = []

        def serve_once():
            try:
                connection, _ = self.server.accept()
                with connection:
                    _handle_connection(connection, self.controller, os.getuid())
            except BaseException as exc:
                errors.append(exc)

        worker = threading.Thread(target=serve_once, daemon=True)
        worker.start()
        output = io.StringIO()
        try:
            with patch.object(cli, "SOCKET_PATH", self.socket_path), \
                    patch.object(cli.sys, "argv", ["omarchy-wireguard", *arguments]), \
                    contextlib.redirect_stdout(output):
                cli.main()
        finally:
            worker.join(timeout=4)
            self.assertFalse(worker.is_alive(), "test socket handler did not exit")
            self.assertEqual(errors, [])
        return json.loads(output.getvalue())["result"]

    def config(self, name):
        path = self.root / name
        path.write_text(CONFIG)
        path.chmod(0o600)
        return str(path)

    def test_labeled_multifile_import_preserves_source_names_and_cleans_staging(self):
        paths = [self.config("first.conf"), self.config("second.conf")]
        labels = {"first.conf": "Primary exit", "second.conf": "Secondary exit"}
        with patch.dict(cli.os.environ, {"XDG_RUNTIME_DIR": str(self.root)}):
            result = self.invoke("import", *paths, "--labels", json.dumps(labels))
            self.assertTrue(result["imported"])
            self.assertEqual(result["profiles"], 2)
            self.assertEqual(list(self.root.glob("omarchy-wireguard-*.zip")), [])
            profiles = self.invoke("list")["profiles"]
            self.assertEqual({item["source_name"]: item["label"] for item in profiles}, labels)
            self.assertEqual(len({item["id"] for item in profiles}), 2)
            self.assertEqual(len(self.host.profiles), 2)
            self.assertEqual(self.host.deactivations, 0)
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
                self.invoke("import", *paths, "--labels", json.dumps(labels))
            self.assertEqual(raised.exception.code, 1)
            self.assertIn("duplicate source_name", errors.getvalue())
            self.assertEqual(list(self.root.glob("omarchy-wireguard-*.zip")), [])
            self.assertEqual(self.invoke("list")["profiles"], profiles)
            self.assertEqual(len(self.host.profiles), 2)

    def test_add_list_select_and_reload_named_profile(self):
        first_path = self.config("first.conf")
        second_path = self.config("second.conf")
        self.assertTrue(self.invoke("import", first_path, "--label", "Personal exit")["imported"])
        first = self.invoke("list")["profiles"][0]
        before = self.store.read("profiles.json", [])
        self.assertTrue(self.invoke("import", second_path, "--label", "Backup exit")["imported"])
        profiles = self.invoke("list")["profiles"]
        self.assertEqual({item["label"] for item in profiles}, {"Personal exit", "Backup exit"})
        self.assertEqual(self.store.read("profiles.json", [])[0], before[0])
        self.assertEqual(self.host.deactivations, 0)
        self.assertEqual(len(self.host.profiles), 2)
        selected = self.invoke("connect", "--profile", first["id"])
        self.assertEqual(selected["target_profile"]["id"], first["id"])
        self.assertEqual(selected["mode"], "connecting")
        self.assertEqual(self.host.deactivations, 1)
        self.controller = Controller(self.store, self.host, controller_uid=os.getuid())
        self.assertEqual(self.invoke("status")["target_profile"]["id"], first["id"])
        for path in (self.root / "state").glob("*.json"):
            self.assertNotIn("TEST_ONLY_NOT_A_REAL_PRIVATE_KEY", path.read_text())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
