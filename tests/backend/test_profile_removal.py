import unittest

from omarchy_wireguard.controller import Controller, RequestFailure
from omarchy_wireguard.storage import StateCommitError
from omarchy_wireguard.system import SystemFailure

from test_controller import FakeSystem, MemoryStore, PROFILE, PROFILE_2

PERSONAL = {**PROFILE, "id": "profile-profile-1", "uuid": "uuid-3", "source_name": "home.conf",
            "label": "Home", "country": "", "city": "", "city_key": "/"}


class FailingStore(MemoryStore):
    def __init__(self, values, error):
        super().__init__(values)
        self.error = error

    def write(self, name, value):
        if name == "profiles.json":
            raise self.error
        super().write(name, value)


class ProfileRemovalTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.store = MemoryStore({"profiles.json": [dict(PROFILE), dict(PROFILE_2), dict(PERSONAL)],
                                  "state.json": {"enabled": False, "target": None,
                                                 "mru": ["profile-profile-1", "japan-tokyo-1"]}})
        self.system = FakeSystem()
        self.system.managed_profiles = lambda: {
            "uuid-1": "omarchy-wireguard-japan-tokyo-1",
            "uuid-2": "omarchy-wireguard-japan-tokyo-2",
            "uuid-3": "omarchy-wireguard-profile-profile-1",
        }
        self.controller = self.make_controller(self.store)

    def make_controller(self, store):
        return Controller(store, self.system, clock=lambda: self.now,
                          monotonic=lambda: self.now, sleeper=lambda _seconds: None)

    def ids(self):
        return [item["id"] for item in self.controller.catalog]

    def test_remove_deletes_connection_catalog_entry_and_history(self):
        result = self.controller.handle("remove", {"profile": "profile-profile-1"})
        self.assertEqual((result["removed"], result["profile"]), (True, "profile-profile-1"))
        self.assertEqual(result["status"]["mode"], "disabled")
        self.assertEqual(self.system.deleted, ["uuid-3"])
        self.assertEqual(self.ids(), ["japan-tokyo-1", "japan-tokyo-2"])
        self.assertEqual([item["id"] for item in self.store.values["profiles.json"]], self.ids())
        self.assertEqual(self.store.values["state.json"]["mru"], ["japan-tokyo-1"])
        self.assertNotIn("profile-profile-1",
                         [item["id"] for item in self.controller.list_profiles({})["profiles"]])

    def test_arguments_must_name_exactly_one_known_profile(self):
        for args in ({}, {"profile": ""}, {"profile": 7}, {"profile": "japan-tokyo-1", "city": "x"},
                     {"city": "Japan/Tokyo"}):
            with self.subTest(args=args), self.assertRaisesRegex(RequestFailure, "exactly one profile"):
                self.controller.handle("remove", args)
        with self.assertRaisesRegex(RequestFailure, "unknown profile"):
            self.controller.handle("remove", {"profile": "missing"})
        self.assertEqual(self.system.deleted, [])

    def test_current_and_target_profiles_are_refused(self):
        self.controller.connect({"profile": "japan-tokyo-1"})
        self.controller.tick()
        self.assertEqual(self.controller.current["id"], "japan-tokyo-1")
        with self.assertRaisesRegex(RequestFailure, "disconnect first"):
            self.controller.handle("remove", {"profile": "japan-tokyo-1"})
        # Failed and paused targets are still enabled intent.
        self.controller.current = None
        with self.assertRaisesRegex(RequestFailure, "disconnect first"):
            self.controller.handle("remove", {"profile": "japan-tokyo-1"})
        self.assertEqual(self.system.deleted, [])
        self.controller.handle("remove", {"profile": "profile-profile-1"})
        self.assertEqual(self.system.deleted, ["uuid-3"])

    def test_city_target_protects_its_profiles(self):
        self.controller.connect({"city": "Japan/Tokyo"})
        for identifier in ("japan-tokyo-1", "japan-tokyo-2"):
            with self.subTest(identifier=identifier), self.assertRaisesRegex(RequestFailure, "disconnect first"):
                self.controller.handle("remove", {"profile": identifier})
        self.assertEqual(self.system.deleted, [])

    def test_mismatched_connection_identity_is_never_deleted(self):
        self.system.managed_profiles = lambda: {"uuid-3": "omarchy-wireguard-someone-else-1"}
        with self.assertRaisesRegex(RequestFailure, "identity"):
            self.controller.handle("remove", {"profile": "profile-profile-1"})
        self.assertEqual(self.system.deleted, [])
        self.assertIn("profile-profile-1", self.ids())

    def test_absent_connection_is_dropped_from_the_catalog(self):
        self.system.managed_profiles = lambda: {}
        self.controller.handle("remove", {"profile": "profile-profile-1"})
        self.assertEqual(self.system.deleted, [])
        self.assertNotIn("profile-profile-1", self.ids())

    def test_failed_delete_keeps_the_catalog(self):
        def fail(_uuid):
            raise SystemFailure("nmcli failed with status 10")
        self.system.delete_profile = fail
        with self.assertRaisesRegex(RequestFailure, "could not delete"):
            self.controller.handle("remove", {"profile": "profile-profile-1"})
        self.assertIn("profile-profile-1", self.ids())
        self.assertEqual(self.controller.mru, ["profile-profile-1", "japan-tokyo-1"])

    def test_failed_catalog_write_is_a_request_failure_and_retryable(self):
        values = {"profiles.json": [dict(PROFILE), dict(PERSONAL)]}
        controller = self.make_controller(FailingStore(values, OSError("disk full")))
        with self.assertRaisesRegex(RequestFailure, "retry remove"):
            controller.handle("remove", {"profile": "profile-profile-1"})
        self.assertEqual(self.system.deleted, ["uuid-3"])
        self.assertIn("profile-profile-1", [item["id"] for item in controller.catalog])
        # The retry skips the now-absent connection and only commits the catalog.
        self.system.managed_profiles = lambda: {"uuid-1": "omarchy-wireguard-japan-tokyo-1"}
        retry = self.make_controller(MemoryStore(values))
        retry.handle("remove", {"profile": "profile-profile-1"})
        self.assertEqual(self.system.deleted, ["uuid-3"])
        self.assertEqual([item["id"] for item in retry.catalog], ["japan-tokyo-1"])

    def test_committed_but_unconfirmed_catalog_write_completes(self):
        controller = self.make_controller(
            FailingStore({"profiles.json": [dict(PROFILE), dict(PERSONAL)]}, StateCommitError("fsync")))
        result = controller.handle("remove", {"profile": "profile-profile-1"})
        self.assertTrue(result["removed"])
        self.assertEqual([item["id"] for item in controller.catalog], ["japan-tokyo-1"])


if __name__ == "__main__":
    unittest.main()
