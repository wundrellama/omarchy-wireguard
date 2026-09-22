import io
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from omarchy_wireguard.importer import ImportFailure, expand_archives, parse_config, parse_profiles, read_path


CONFIG = """[Interface]
PrivateKey = secret-value
Address = 10.0.0.2/32
DNS = 10.8.0.1

[Peer]
PublicKey = public-value
Endpoint = 192.0.2.10:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 4
"""


class ImporterTests(unittest.TestCase):
    def test_parses_endpoint_location_and_forces_keepalive(self):
        profile = parse_config("us-new-york-12.conf", CONFIG)
        self.assertEqual((profile.country, profile.city), ("United States", "New York"))
        self.assertEqual((profile.endpoint_host, profile.endpoint_port), ("192.0.2.10", 51820))
        self.assertIn("PersistentKeepalive = 25", profile.config)
        self.assertIn("PrivateKey = secret-value", profile.config)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", profile.config)
        self.assertNotIn("privatekey", profile.config)
        self.assertNotIn("secret-value", repr(profile))

    def test_ambiguous_location_requires_review(self):
        profiles, ambiguous = parse_profiles([("unknown.conf", CONFIG.encode())])
        self.assertEqual(ambiguous, ["unknown.conf"])
        reviewed, ambiguous = parse_profiles(
            [("unknown.conf", CONFIG.encode())],
            {"unknown.conf": {"country": "Japan", "city": "Tokyo"}},
        )
        self.assertFalse(ambiguous)
        self.assertEqual(reviewed[0].city_key, "Japan/Tokyo")

    def test_rejects_traversal_and_zip_symlink(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("../escape.conf", CONFIG)
        with self.assertRaises(ImportFailure):
            expand_archives([("bad.zip", archive.getvalue())])

        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zipped:
            info = zipfile.ZipInfo("link.conf")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zipped.writestr(info, "target")
        with self.assertRaises(ImportFailure):
            expand_archives([("bad.zip", archive.getvalue())])

    def test_directory_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "real.conf").write_text(CONFIG)
            (root / "link.conf").symlink_to(root / "real.conf")
            with self.assertRaises(ImportFailure):
                read_path(str(root))

    def test_directory_recurses_without_following_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            nested = Path(temporary) / "region"
            nested.mkdir()
            (nested / "jp-tokyo.conf").write_text(CONFIG)
            files = read_path(temporary)
            self.assertEqual(files[0][0], "region/jp-tokyo.conf")

    def test_rejects_bad_endpoint_without_exposing_secret(self):
        with self.assertRaisesRegex(ImportFailure, "invalid endpoint") as raised:
            parse_config("test.conf", CONFIG.replace("192.0.2.10:51820", "bad endpoint"))
        self.assertNotIn("secret-value", str(raised.exception))

    def test_rejects_multiple_peers_unsupported_keys_and_non_default_route(self):
        with self.assertRaises(ImportFailure):
            parse_config("multi.conf", CONFIG + "\n[Peer]\nPublicKey = another\n")
        with self.assertRaisesRegex(ImportFailure, "unsupported"):
            parse_config("script.conf", CONFIG.replace("Address =", "PreUp = evil\nAddress ="))
        with self.assertRaisesRegex(ImportFailure, "IPv4 default"):
            parse_config("split.conf", CONFIG.replace("0.0.0.0/0", "10.0.0.0/8"))

    def test_canonicalizes_mixed_case_without_losing_values(self):
        mixed = CONFIG.replace("PrivateKey", "privatekey").replace("AllowedIPs", "allowedips")
        profile = parse_config("jp-tokyo.conf", mixed)
        self.assertIn("PrivateKey = secret-value", profile.config)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", profile.config)


if __name__ == "__main__":
    unittest.main()
