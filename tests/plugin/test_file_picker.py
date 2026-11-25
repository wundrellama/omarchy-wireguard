import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

HELPER = Path(__file__).resolve().parents[2] / "plugin" / "file_picker.py"


class FilePickerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("wireguard_file_picker", HELPER)
        if spec is None or spec.loader is None:
            raise RuntimeError("picker helper cannot be loaded")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_paths_are_json_framed_and_absolute(self):
        paths = self.module.validate_paths(["/home/me/a.conf", "/tmp/--labels"], False)
        self.assertEqual(json.loads(self.module.encode_paths(paths)), paths)

    def test_control_relative_and_excess_paths_are_rejected(self):
        for paths in (["relative.conf"], ["/tmp/a\n--labels"], ["/tmp/a\r.conf"],
                      ["/tmp/a\x00.conf"], ["/a"] * 513, ["/a", 7]):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                self.module.validate_paths(paths, False)

    def test_directory_mode_accepts_exactly_one_path(self):
        self.assertEqual(self.module.validate_paths(["/home/me/configs"], True),
                         ["/home/me/configs"])
        with self.assertRaises(ValueError):
            self.module.validate_paths(["/one", "/two"], True)

    def test_gio_and_glib_load_as_lazy_submodules(self):
        # PyGObject's gi.repository has no Gio/GLib attributes until the
        # submodules are imported; the stub package mirrors that.
        versions = []
        gi = types.ModuleType("gi")
        gi.require_version = lambda name, version: versions.append((name, version))
        repository = types.ModuleType("gi.repository")
        repository.__path__ = []
        gio, glib = types.ModuleType("gi.repository.Gio"), types.ModuleType("gi.repository.GLib")
        stubs = {"gi": gi, "gi.repository": repository,
                 "gi.repository.Gio": gio, "gi.repository.GLib": glib}
        with mock.patch.dict(sys.modules, stubs):
            self.assertEqual(self.module.load_gio(), (gio, glib))
        self.assertEqual(versions, [("Gio", "2.0")])

    def test_remote_file_uri_is_rejected(self):
        with self.assertRaises(ValueError):
            self.module.local_path(("/etc/passwd", "evil.example"))
        self.assertEqual(self.module.local_path(("/home/me/a.conf", None)),
                         "/home/me/a.conf")


if __name__ == "__main__":
    unittest.main()
