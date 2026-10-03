"""Run integrate-user against inert command stubs; never touch the real desktop."""
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/integrate-user"


class IntegrateUserTests(unittest.TestCase):
    def run_integration(self, session_path=None, bar_exit=0):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        stubs = root / "stubs"
        stubs.mkdir()
        log = root / "omarchy.log"
        session_line = f"OMARCHY_PATH={session_path}" if session_path else ""
        (stubs / "systemctl").write_text(f"#!/bin/bash\necho '{session_line}'\n")
        omarchy = (
            "#!/bin/bash\n"
            f"echo \"$OMARCHY_PATH $0 $*\" >>'{log}'\n"
            f"[[ $1 != bar ]] || exit {bar_exit}\n"
        )
        packaged = root / "packaged"
        (packaged / "bin").mkdir(parents=True)
        for directory in (stubs, packaged / "bin"):
            (directory / "omarchy").write_text(omarchy)
        if session_path:
            (pathlib.Path(session_path) / "shell").mkdir(parents=True)
            (pathlib.Path(session_path) / "shell/shell.qml").write_text("")
            (pathlib.Path(session_path) / "bin").mkdir()
            (pathlib.Path(session_path) / "bin/omarchy").write_text(omarchy)
            (pathlib.Path(session_path) / "bin/omarchy").chmod(0o755)
        for path in root.rglob("*"):
            if path.is_file():
                path.chmod(0o755)
        home = root / "home"
        home.mkdir()
        env = {
            "HOME": str(home),
            "PATH": f"{stubs}:/usr/bin:/bin",
            "OMARCHY_PATH": str(packaged),
        }
        result = subprocess.run([str(SCRIPT), "install"], env=env, capture_output=True, text=True)
        calls = log.read_text().splitlines() if log.exists() else []
        menu = (home / ".config/omarchy/extensions/omarchy-menu.jsonc").read_text()
        return result, calls, menu

    def test_uses_the_session_omarchy_checkout(self):
        with tempfile.TemporaryDirectory() as session:
            result, calls, menu = self.run_integration(session_path=session)
        self.assertEqual(result.returncode, 0, result.stderr)
        bar = next(call for call in calls if " bar move " in call)
        self.assertTrue(bar.startswith(f"{session} {session}/bin/omarchy "), bar)
        self.assertIn("setup.network.wireguard", menu)

    def test_keeps_the_packaged_checkout_without_a_session(self):
        result, calls, _ = self.run_integration()
        self.assertEqual(result.returncode, 0, result.stderr)
        bar = next(call for call in calls if " bar move " in call)
        self.assertIn("/packaged /", bar)
        self.assertIn("/packaged/bin/omarchy ", bar)

    def test_bar_placement_failure_is_a_warning(self):
        result, _, menu = self.run_integration(bar_exit=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("could not place the bar widget", result.stderr)
        self.assertIn("setup.network.wireguard", menu)

    def test_installer_does_not_fail_after_commit_on_integration_error(self):
        source = (ROOT / "scripts/install-backend").read_text()
        integration = source.split("trap - HUP INT TERM", 1)[1]
        self.assertIn("if ! runuser", integration)
        self.assertIn("integrate-user install; then", integration)


if __name__ == "__main__":
    unittest.main()
