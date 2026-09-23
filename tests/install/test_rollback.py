"""Execute installer rollback with inert commands; never run the installer itself."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class InstallRollbackTests(unittest.TestCase):
    def run_cleanup(self, reload_succeeds=True):
        source = (ROOT / "scripts/install-backend").read_text()
        cleanup = "cleanup() {" + source.split("cleanup() {", 1)[1].split("\ntrap cleanup ERR", 1)[0]
        # No external commands can resolve. Model systemd's cached Requires edge:
        # deleting a drop-in does not detach it until daemon-reload completes.
        harness = r'''
set -eu
PATH=/no-external-commands
stage=""
backup=""
had_networkmanager_dropin=false
cached_dependency=true
networkmanager_active=true
firewall_stopped=false
firewall_removed=false
rm() { printf 'remove %s\n' "$*"; }
nft() { firewall_removed=true; }
systemctl() {
  if [[ $* == "daemon-reload" ]]; then
    [[ $reload_succeeds == true ]] || return 1
    cached_dependency=false
  elif [[ $* == *"disable --now"* && $* == *"omarchy-wireguard-firewall.service"* ]]; then
    firewall_stopped=true
    if [[ $cached_dependency == true ]]; then
      networkmanager_active=false
    fi
  fi
}
'''
        script = ('reload_succeeds=' + str(reload_succeeds).lower() + '\n' + harness + cleanup
                  + '\ncleanup\nprintf "NM active: %s; firewall stopped: %s; removed: %s\\n" "$networkmanager_active" "$firewall_stopped" "$firewall_removed"\n')
        result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", script],
                                env={"PATH": "/no-external-commands"}, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NM active: true", result.stdout)
        self.assertIn("50-omarchy-wireguard.conf", result.stdout)
        return result

    def test_detach_networkmanager_dependency_before_stopping_firewall(self):
        result = self.run_cleanup()
        self.assertIn("firewall stopped: true; removed: true", result.stdout)

    def test_failed_reload_preserves_firewall_service(self):
        result = self.run_cleanup(reload_succeeds=False)
        self.assertIn("firewall stopped: false; removed: false", result.stdout)


if __name__ == "__main__":
    unittest.main()
