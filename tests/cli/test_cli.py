import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
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
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "personal.conf"
            path.write_text("test fixture\n")
            path.chmod(0o600)
            call = self.run_cli("import", str(path), "--label", "Personal exit")
        call.assert_called_once_with("import", {
            "data": cli.base64.b64encode(b"test fixture\n").decode("ascii"), "name": "personal.conf",
            "labels": {"personal.conf": "Personal exit"},
        }, source_fd=None)

    def test_label_rejects_ambiguous_input_before_staging_or_contacting_daemon(self):
        for paths in (["one.conf", "two.conf"], ["bundle.zip"], ["directory"]):
            with self.subTest(paths=paths), patch.object(cli, "call") as call, \
                    patch.object(cli, "stage_files") as stage:
                with self.assertRaisesRegex(cli.CliError, "one .conf"):
                    cli.import_profiles(paths, None, "Personal")
                stage.assert_not_called()
                call.assert_not_called()

    def test_batch_labels_are_forwarded_as_a_json_object(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.zip"
            with cli.zipfile.ZipFile(path, "w") as archive:
                archive.writestr("personal.conf", "test fixture\n")
            path.chmod(0o600)
            call = self.run_cli("import", str(path), "--labels", '{"personal.conf":"Personal"}')
        operation, arguments = call.call_args.args
        self.assertEqual(operation, "import")
        self.assertEqual(arguments["name"], "bundle.zip")
        self.assertEqual(arguments["labels"], {"personal.conf": "Personal"})
        self.assertIn("data", arguments)
        self.assertEqual(call.call_args.kwargs, {"source_fd": None})
        with cli.zipfile.ZipFile(io.BytesIO(cli.base64.b64decode(arguments["data"]))) as archive:
            self.assertEqual(archive.read("personal.conf"), b"test fixture\n")

    def test_large_import_uses_descriptor_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.conf"
            path.write_bytes(b"x" * (cli.MAX_INLINE_SOURCE + 1))
            path.chmod(0o600)
            call = self.run_cli("import", str(path))
        operation, arguments = call.call_args.args
        self.assertEqual(operation, "import")
        self.assertEqual(arguments, {"source": "fd", "name": "large.conf"})
        self.assertIsInstance(call.call_args.kwargs["source_fd"], int)

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

    def test_single_import_rejects_symlink_before_contacting_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original.conf"
            original.write_text("test fixture\n")
            link = Path(directory) / "link.conf"
            link.symlink_to(original)
            with patch.object(cli, "call") as call, self.assertRaisesRegex(cli.CliError, "opened safely"):
                cli.import_profiles([str(link)], None, "Personal")
            call.assert_not_called()

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

    def test_multifile_staging_reads_held_descriptors_not_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "one.conf"
            second = root / "two.conf"
            first.write_text("one\n")
            second.write_text("two\n")
            first.chmod(0o600)
            second.chmod(0o600)
            with patch.object(cli.zipfile.ZipFile, "write",
                              side_effect=AssertionError("pathname reopened")):
                staged, name = cli.stage_files([str(first), str(second)])
            try:
                self.assertEqual(name, "upload.zip")
                staged.seek(0)
                with cli.zipfile.ZipFile(staged) as archive:
                    self.assertEqual(archive.read("one.conf"), b"one\n")
                    self.assertEqual(archive.read("two.conf"), b"two\n")
            finally:
                staged.close()


if __name__ == "__main__":
    unittest.main()
