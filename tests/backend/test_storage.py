import json
import os
import tempfile
import unittest
from pathlib import Path

from omarchy_torguard.storage import StateStore


class StorageTests(unittest.TestCase):
    def test_atomic_private_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            store = StateStore(root, owner_uid=os.getuid())
            store.write("state.json", {"enabled": True})
            self.assertEqual(store.read("state.json", {}), {"enabled": True})
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / "state.json").stat().st_mode & 0o777, 0o600)

    def test_rejects_symlink_and_bad_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_text("{}")
            (root / "state.json").symlink_to(target)
            store = StateStore(root, owner_uid=os.getuid())
            with self.assertRaises(OSError):
                store.read("state.json", {})
            with self.assertRaises(ValueError):
                store.write("../escape", {})


if __name__ == "__main__":
    unittest.main()
