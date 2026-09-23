import contextlib
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader("wireguard_cli", str(ROOT / "bin/omarchy-wireguard"))
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
cli = importlib.util.module_from_spec(spec)
loader.exec_module(cli)


class CliTests(unittest.TestCase):
    def run_cli(self, *arguments):
        output = io.StringIO()
        with patch.object(cli.sys, "argv", ["omarchy-wireguard", *arguments]), \
                patch.object(cli, "call", return_value={"ok": True, "result": {}}) as call, \
                patch.object(cli.subprocess, "run", side_effect=AssertionError("unexpected host command")), \
                contextlib.redirect_stdout(output):
            cli.main()
        self.assertTrue(json.loads(output.getvalue())["ok"])
        return call

    def test_connect_selects_exact_profile(self):
        call = self.run_cli("connect", "--profile", "stable-personal-id")
        call.assert_called_once_with("connect", {"profile": "stable-personal-id"})

    def test_connect_legacy_city(self):
        call = self.run_cli("connect", "Japan/Tokyo")
        call.assert_called_once_with("connect", {"city": "Japan/Tokyo"})

    def test_connect_requires_one_target(self):
        for arguments in (("connect",), ("connect", "Japan/Tokyo", "--profile", "one")):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    cli.parser().parse_args(arguments)
                self.assertEqual(raised.exception.code, 2)

    def test_import_personal_label_without_overwriting_network_policy(self):
        call = self.run_cli("import", "/example/personal.conf", "--label", "Personal exit")
        call.assert_called_once_with("import", {
            "path": "/example/personal.conf", "labels": {"personal.conf": "Personal exit"},
        })

    def test_label_rejects_ambiguous_input_before_staging_or_contacting_daemon(self):
        for paths in (["one.conf", "two.conf"], ["bundle.zip"], ["directory"]):
            with self.subTest(paths=paths), patch.object(cli, "call") as call, \
                    patch.object(cli, "stage_files") as stage:
                with self.assertRaisesRegex(cli.CliError, "one .conf"):
                    cli.import_profiles(paths, None, "Personal")
                stage.assert_not_called()
                call.assert_not_called()

    def test_batch_labels_are_forwarded_as_a_json_object(self):
        call = self.run_cli("import", "/example/bundle.zip", "--labels", '{"personal.conf":"Personal"}')
        call.assert_called_once_with("import", {
            "path": "/example/bundle.zip", "labels": {"personal.conf": "Personal"},
        })

    def test_invalid_metadata_is_rejected_before_contacting_daemon(self):
        for option in ("labels", "locations"):
            for value in ("[", "[]", "null", '"text"', ""):
                with self.subTest(option=option, value=value), patch.object(cli, "call") as call:
                    kwargs = {"locations": None, option: value}
                    with self.assertRaisesRegex(cli.CliError, "JSON object"):
                        cli.import_profiles(["one.conf"], **kwargs)
                    call.assert_not_called()

    def test_label_and_labels_are_mutually_exclusive(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            cli.parser().parse_args(["import", "one.conf", "--label", "One", "--labels", "{}"])
        self.assertEqual(raised.exception.code, 2)

    def test_single_import_does_not_resolve_symlink_past_backend_safety_check(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original.conf"
            original.write_text("test fixture\n")
            link = Path(directory) / "link.conf"
            link.symlink_to(original)
            call = self.run_cli("import", str(link), "--label", "Personal")
            self.assertEqual(call.call_args.args[1]["path"], str(link))

    def test_duplicate_basenames_are_rejected_not_silently_renamed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = []
            for parent in ("first", "second"):
                folder = root / parent
                folder.mkdir()
                config = folder / "personal.conf"
                config.write_text("test fixture\n")
                files.append(str(config))
            with patch.dict(cli.os.environ, {"XDG_RUNTIME_DIR": directory}):
                with self.assertRaisesRegex(cli.CliError, "duplicate source filename"):
                    cli.stage_files(files)
            self.assertEqual(list(root.glob("omarchy-wireguard-*")), [])


if __name__ == "__main__":
    unittest.main()
