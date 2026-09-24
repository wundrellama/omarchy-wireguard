"""Read-only Proton server index helper, against synthetic serverlist.json files."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[2] / "plugin" / "proton_servers.py"


def server(name, exit_country="CH", city="Zurich", features=0, status=1, load=30, tier=2, entry=None):
    return {"Name": name, "EntryCountry": entry or exit_country, "ExitCountry": exit_country, "City": city,
            "Features": features, "Status": status, "Load": load, "Tier": tier, "Region": None,
            "Servers": [{"Status": status}], "ID": "synthetic"}


class ProtonServersTest(unittest.TestCase):
    def run_helper(self, payload=None, raw=None, size=None, env=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "serverlist.json"
            if raw is not None:
                path.write_bytes(raw)
            elif payload is not None:
                path.write_text(json.dumps(payload))
            if size is not None:
                with open(path, "wb") as handle:
                    handle.truncate(size)
            args = [sys.executable, "-B", str(HELPER)]
            if env is None:
                args.append(str(path))
            full_env = dict(os.environ, **(env or {}))
            if env is not None and "XDG_CACHE_HOME" in env:
                target = Path(env["XDG_CACHE_HOME"]) / "Proton" / "VPN"
                target.mkdir(parents=True, exist_ok=True)
                (target / "serverlist.json").write_text(json.dumps(payload))
            result = subprocess.run(args, capture_output=True, text=True, timeout=30, env=full_env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertLess(len(result.stdout), 4 * 1024 * 1024)
            return json.loads(result.stdout)

    def test_feature_bits_match_installed_proton_enum(self):
        # proton/vpn/session/servers/types.py ServerFeatureEnum (proton-vpn-session).
        sys.path.insert(0, str(HELPER.parent))
        try:
            import proton_servers
        finally:
            sys.path.pop(0)
        self.assertEqual(proton_servers.FEATURES, (("securecore", 1), ("tor", 2), ("p2p", 4), ("streaming", 8), ("ipv6", 16)))

    def test_index_keeps_only_available_valid_servers(self):
        payload = {"MaxTier": 2, "LogicalServers": [
            server("CH#12", features=4 | 8),
            server("US-CA#370", "US", "Los Angeles", features=16 | 8 | 4, load=41),
            server("CH-US#1", "US", "New York", features=1, entry="CH"),
            server("FR#13-TOR", "FR", "Paris", features=2),
            server("DE#9", "DE", "Berlin", status=0),
            server("--help", "DE", "Berlin"),
            server("de#1", "DE", "Berlin"),
            server("JP#1", "jp", "Tokyo"),
            server("NL#5", "NL", "-rf"),
            server("SE#1", "SE", "Stockholm", tier=3),
            server("NO#1", "NO", "Oslo", load=500),
            "not-an-object",
        ]}
        result = self.run_helper(payload)
        self.assertTrue(result["ok"])
        self.assertEqual(result["fields"], ["name", "country", "city", "features", "load", "tier"])
        by_name = {row[0]: row for row in result["servers"]}
        self.assertEqual(sorted(by_name), ["CH#12", "CH-US#1", "FR#13-TOR", "NL#5", "US-CA#370"])
        self.assertEqual(by_name["US-CA#370"], ["US-CA#370", "US", "Los Angeles", ["p2p", "streaming", "ipv6"], 41, 2])
        self.assertEqual(by_name["CH-US#1"][3], ["securecore"])
        self.assertEqual(by_name["FR#13-TOR"][3], ["tor"])
        self.assertEqual(by_name["NL#5"][2], "", "an invalid city is dropped, not the server")
        self.assertEqual(result["count"], 5)

    def test_missing_malformed_and_huge_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, "-B", str(HELPER), str(Path(directory) / "absent.json")],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(json.loads(result.stdout)["ok"], False)
        self.assertEqual(self.run_helper(raw=b"{not json")["ok"], False)
        self.assertEqual(self.run_helper(payload=[1, 2])["ok"], False)
        self.assertEqual(self.run_helper(payload={"LogicalServers": "x"})["ok"], False)
        self.assertEqual(self.run_helper(size=65 * 1024 * 1024)["ok"], False)

    def test_fifo_and_directory_fail_closed_promptly(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "serverlist.json"
            os.mkfifo(fifo)
            result = subprocess.run([sys.executable, "-B", str(HELPER), str(fifo)], capture_output=True, text=True, timeout=10)
            self.assertEqual(json.loads(result.stdout)["ok"], False, "a FIFO must not block the helper")
            result = subprocess.run([sys.executable, "-B", str(HELPER), directory], capture_output=True, text=True, timeout=10)
            self.assertEqual(json.loads(result.stdout)["ok"], False)

    def test_default_path_uses_xdg_cache_home(self):
        with tempfile.TemporaryDirectory() as cache:
            result = self.run_helper({"MaxTier": 2, "LogicalServers": [server("IT#23", "IT", "Milan")]},
                                     env={"XDG_CACHE_HOME": cache})
            self.assertEqual([row[0] for row in result["servers"]], ["IT#23"])


if __name__ == "__main__":
    unittest.main()
