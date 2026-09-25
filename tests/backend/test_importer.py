import io
import multiprocessing
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import omarchy_wireguard.importer as importer
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
    def test_source_descriptor_reads_the_opened_regular_file(self):
        self.assertTrue(hasattr(importer, "read_source_fd"))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "home.conf"
            path.write_text(CONFIG)
            path.chmod(0o600)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                path.rename(path.with_suffix(".old"))
                path.write_text("replacement")
                files = importer.read_source_fd(descriptor, "home.conf", os.getuid())
            finally:
                os.close(descriptor)
            self.assertEqual(files, [("home.conf", CONFIG.encode())])

    def test_source_descriptor_rejects_fifo_before_reading(self):
        self.assertTrue(hasattr(importer, "read_source_fd"))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pipe.conf"
            os.mkfifo(path, 0o600)
            descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                with self.assertRaisesRegex(ImportFailure, "regular"):
                    importer.read_source_fd(descriptor, "pipe.conf", os.getuid())
            finally:
                os.close(descriptor)

    def test_fifo_path_rejection_never_blocks(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pipe.conf"
            os.mkfifo(path, 0o600)
            queue = multiprocessing.Queue()

            def read_fifo():
                try:
                    read_path(str(path))
                except Exception as exc:
                    queue.put(type(exc).__name__)

            process = multiprocessing.Process(target=read_fifo)
            process.start()
            process.join(0.5)
            try:
                self.assertFalse(process.is_alive(), "FIFO open blocked before type validation")
                self.assertEqual(queue.get(timeout=1), "ImportFailure")
            finally:
                if process.is_alive():
                    process.terminate()
                process.join()

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

    def test_labels_require_exact_names_and_bounded_printable_text(self):
        files = [("nested/home.conf", CONFIG.encode())]
        for labels in ([], "Home", {"home.conf": "Home"}, {"nested/home.conf": None},
                       {"nested/home.conf": ""}, {"nested/home.conf": "   "},
                       {"nested/home.conf": "x" * 129}, {"nested/home.conf": "Home\nexit"},
                       {"nested/home.conf": "Home\x00exit"}):
            with self.subTest(labels=labels), self.assertRaisesRegex(ImportFailure, "label"):
                parse_profiles(files, labels=labels)
        profiles, ambiguous = parse_profiles(files, labels={"nested/home.conf": "x" * 128})
        self.assertFalse(ambiguous)
        self.assertEqual(profiles[0].label, "x" * 128)

    def test_named_profiles_allow_explicit_empty_geography(self):
        files = [("us-seattle.conf", CONFIG.encode())]
        profiles, ambiguous = parse_profiles(files,
            locations={"us-seattle.conf": {"country": "", "city": ""}},
            labels={"us-seattle.conf": "Home"})
        self.assertFalse(ambiguous)
        self.assertEqual((profiles[0].country, profiles[0].city), ("", ""))
        with self.assertRaisesRegex(ImportFailure, "location"):
            parse_profiles(files, locations={"us-seattle.conf": {"country": "", "city": ""}})

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

    def test_directory_budget_counts_every_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(3):
                (root / f"ignored-{index}.txt").write_text("ignored")
            (root / "profile.conf").write_text(CONFIG)
            with patch.object(importer, "MAX_TRAVERSAL", 3, create=True), \
                    self.assertRaisesRegex(ImportFailure, "too many"):
                read_path(temporary)

    def test_zip_entry_limit_is_checked_before_zipfile_construction(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zipped:
            for index in range(4):
                zipped.writestr(f"ignored-{index}.txt", b"")
        with patch.object(importer, "MAX_FILES", 3), \
                patch.object(importer.zipfile, "ZipFile", side_effect=AssertionError("parser reached")), \
                self.assertRaisesRegex(ImportFailure, "too many"):
            expand_archives([("many.zip", archive.getvalue())])

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
