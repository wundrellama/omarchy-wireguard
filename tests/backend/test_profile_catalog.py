"""Regression coverage for the additive catalog's full-tunnel safety boundary."""
import base64
import io
import unittest
import zipfile

from omarchy_wireguard.controller import Controller, RequestFailure
from omarchy_wireguard.system import SystemFailure
from test_controller import FakeSystem, IMPORT_CONFIG, MemoryStore, PROFILE, PROFILE_2


def batch_args(files, **metadata):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        for name, config in files:
            zipped.writestr(name, config)
    return {"name": "profiles.zip", "data": base64.b64encode(archive.getvalue()).decode(), **metadata}


class CatalogSafetyTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.system = FakeSystem()
        self.controller = Controller(self.store, self.system, clock=lambda: 1000,
                                     monotonic=lambda: 1000)

    def test_complete_batch_is_validated_before_importing_any_profile(self):
        args = batch_args([
            ("us-seattle.conf", IMPORT_CONFIG),
            ("home.conf", IMPORT_CONFIG.replace("0.0.0.0/0", "10.0.0.0/8")),
        ], labels={"home.conf": "Home exit"})
        with self.assertRaisesRegex(RequestFailure, "IPv4 default route"):
            self.controller.handle("import", args)
        self.assertEqual(self.system.imported, [])
        self.assertEqual(self.system.deleted, [])
        self.assertEqual(self.system.deactivations, 0)
        self.assertEqual(self.store.values["profiles.json"], [PROFILE])

    def test_review_required_does_not_import_the_unambiguous_subset(self):
        result = self.controller.handle("import", batch_args([
            ("us-seattle.conf", IMPORT_CONFIG), ("home.conf", IMPORT_CONFIG),
        ]))
        self.assertFalse(result["imported"])
        self.assertEqual(result["review_required"], ["home.conf"])
        self.assertEqual(self.system.imported, [])

    def test_mid_batch_nm_failure_rolls_back_only_new_profiles(self):
        importer = self.system.import_profile
        def fail_third(profile, name):
            if len(self.system.imported) == 2:
                raise SystemFailure("NM import failed")
            return importer(profile, name)
        self.system.import_profile = fail_third
        with self.assertRaises(RequestFailure):
            self.controller.handle("import", batch_args([
                ("us-seattle.conf", IMPORT_CONFIG), ("gb-london.conf", IMPORT_CONFIG),
                ("de-berlin.conf", IMPORT_CONFIG),
            ]))
        self.assertEqual(self.system.deleted, ["new-0", "new-1"])
        self.assertEqual(len(self.controller.catalog), 1)
        self.assertEqual(self.store.values["profiles.json"], [PROFILE])
        self.assertEqual(self.system.deactivations, 0)

    def test_rollback_continues_after_nm_delete_failure_and_reports_incomplete(self):
        def fail_persistence(name, value):
            raise OSError("disk full")
        self.store.write = fail_persistence
        delete = self.system.delete_profile
        def fail_first_delete(uuid):
            delete(uuid)
            if uuid == "new-0":
                raise SystemFailure("NM unavailable")
        self.system.delete_profile = fail_first_delete
        with self.assertRaisesRegex(RequestFailure, "rollback incomplete"):
            self.controller.handle("import", batch_args([
                ("us-seattle.conf", IMPORT_CONFIG), ("gb-london.conf", IMPORT_CONFIG),
            ]))
        self.assertEqual(self.system.deleted, ["new-0", "new-1"])
        self.assertEqual(self.store.values["profiles.json"], [PROFILE])
        self.assertEqual(len(self.controller.catalog), 1)

    def test_post_commit_response_failure_never_deletes_committed_profiles(self):
        def fail_status(args):
            raise RuntimeError("response formatting failed")
        self.controller.status = fail_status
        with self.assertRaises(RuntimeError):
            self.controller.import_profiles(batch_args([("us-seattle.conf", IMPORT_CONFIG)]))
        self.assertEqual(len(self.store.values["profiles.json"]), 2)
        self.assertEqual(self.controller.catalog, self.store.values["profiles.json"])
        self.assertEqual(self.system.deleted, [])

    def test_profile_failure_never_falls_back_to_another_profile_in_the_city(self):
        self.controller.catalog.append(dict(PROFILE_2))
        self.system.fail_uuids = {PROFILE_2["uuid"]}
        self.controller.connect({"profile": PROFILE_2["id"]})
        self.controller.tick()
        self.assertEqual(self.system.activations, [PROFILE_2["uuid"]])
        self.assertEqual(self.controller.mode, "failed")
        self.assertIsNone(self.system.firewalls[-1].tunnel_interface)
        self.controller.retry({})
        self.controller.tick()
        self.assertEqual(self.system.activations, [PROFILE_2["uuid"], PROFILE_2["uuid"]])

    def test_persisted_exact_profile_target_survives_restart_and_pause(self):
        self.store.write("profiles.json", [dict(PROFILE), dict(PROFILE_2)])
        self.store.write("state.json", {"enabled": True, "target": "profile:" + PROFILE_2["id"],
                                        "mru": [PROFILE["id"]]})
        controller = Controller(self.store, self.system, clock=lambda: 1000, monotonic=lambda: 1000)
        controller.boot()
        self.assertEqual(self.system.activations, [PROFILE_2["uuid"]])
        controller.pause({"seconds": 10})
        restarted_system = FakeSystem()
        restarted = Controller(self.store, restarted_system, clock=lambda: 1000, monotonic=lambda: 1000)
        restarted.boot()
        self.assertEqual(restarted_system.activations, [PROFILE_2["uuid"]])
        self.assertEqual(restarted.status({})["target_profile"]["id"], PROFILE_2["id"])

    def test_connect_rejects_all_nonexclusive_or_unknown_selectors_without_side_effects(self):
        for args in ({}, {"city": "Japan/Tokyo", "profile": PROFILE["id"]},
                     {"profile": PROFILE["id"], "extra": True}, {"profile": ""},
                     {"profile": None}, {"profile": 1}, {"profile": "missing"},
                     {"profile": "profile:" + PROFILE["id"]}, {"city": PROFILE["id"]}):
            with self.subTest(args=args), self.assertRaises(RequestFailure):
                self.controller.connect(args)
        self.assertEqual(self.system.deactivations, 0)
        self.assertFalse(self.controller.enabled)
        self.assertNotIn("state.json", self.store.values)

    def test_labels_do_not_allow_split_tunnel_roles_or_replace_flags(self):
        for extra in ({"role": "lan-access"}, {"replace": True}, {"labels": {"home.conf": ""}}):
            with self.subTest(extra=extra), self.assertRaises(RequestFailure):
                self.controller.handle("import", batch_args([("home.conf", IMPORT_CONFIG)], **extra))
        self.assertEqual(self.system.imported, [])

    def test_personal_list_uses_label_and_never_exposes_credentials_or_endpoints(self):
        self.controller.handle("import", batch_args([("home.conf", IMPORT_CONFIG)],
                                                     labels={"home.conf": "Personal exit"}))
        profile = self.controller.list_profiles({})["profiles"][-1]
        self.assertEqual(profile, {"id": self.controller.catalog[-1]["id"], "label": "Personal exit",
                                  "role": "internet-exit", "source_name": "home.conf",
                                  "country": "", "city": ""})


if __name__ == "__main__":
    unittest.main()
