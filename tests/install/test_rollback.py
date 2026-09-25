"""Execute installer rollback with inert commands; never run the installer itself."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class InstallRollbackTests(unittest.TestCase):
    def run_cleanup(self, reload_succeeds=True, inject_signal=False):
        source = (ROOT / "scripts/install-backend").read_text()
        cleanup = "cleanup() {" + source.split("cleanup() {", 1)[1].split("\ntrap cleanup ERR", 1)[0]
        # No external commands can resolve. Model systemd's cached Requires edge:
        # deleting a drop-in does not detach it until daemon-reload completes.
        harness = r'''
set -eu
PATH=/no-external-commands
stage=""
backup=""
backup_cli=""
backup_integrate=""
backup_uninstall=""
backup_service=""
backup_firewall_service=""
backup_config=""
backup_networkmanager_dropin=""
transaction_started=true
backend_replaced=true
daemon_was_enabled=disabled
daemon_was_active=inactive
firewall_was_enabled=disabled
firewall_was_active=inactive
cached_dependency=true
networkmanager_active=true
firewall_stopped=false
firewall_removed=false
signal_sent=false
rm() {
  if [[ $inject_signal == true && $signal_sent == false && $* == *"/usr/lib/omarchy-wireguard/backend"* ]]; then
    signal_sent=true
    kill -TERM $$
  fi
  printf 'remove %s\n' "$*"
}
mv() { printf 'restore %s\n' "$*"; }
nft() { firewall_removed=true; }
systemctl() {
  if [[ $* == "daemon-reload" ]]; then
    [[ $reload_succeeds == true ]] || return 1
    cached_dependency=false
  elif [[ $* == "stop omarchy-wireguard-firewall.service" ]]; then
    firewall_stopped=true
    if [[ $cached_dependency == true ]]; then
      networkmanager_active=false
    fi
  fi
}
'''
        script = ('reload_succeeds=' + str(reload_succeeds).lower() + '\ninject_signal=' + str(inject_signal).lower() + '\n' + harness + cleanup
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

    def test_signal_during_cleanup_is_ignored_until_rollback_finishes(self):
        result = self.run_cleanup(inject_signal=True)
        self.assertIn("NM active: true; firewall stopped: true; removed: true", result.stdout)

    def test_uninstaller_uses_catalog_ownership_without_prefix_delete_fallback(self):
        source = (ROOT / "scripts/uninstall-backend").read_text()
        self.assertIn("omarchy-wireguard uninstall-profiles", source)
        self.assertNotIn("nmcli connection delete", source)
        self.assertNotIn("omarchy-wireguard-*", source)

    def test_daemon_no_longer_has_home_or_dac_import_authority(self):
        unit = (ROOT / "packaging/systemd/omarchy-wireguard.service").read_text()
        self.assertIn("ProtectHome=yes", unit)
        capability_line = next(line for line in unit.splitlines()
                               if line.startswith("CapabilityBoundingSet="))
        self.assertNotIn("CAP_DAC_OVERRIDE", capability_line)
        self.assertNotIn("CAP_FOWNER", capability_line)

    def test_upgrade_publishes_backend_last_and_restores_all_coupled_artifacts(self):
        source = (ROOT / "scripts/install-backend").read_text()
        backend_publish = source.index('mv "$stage" /usr/lib/omarchy-wireguard/backend')
        for install in (
            'install -m 0755 "$repo_dir/bin/omarchy-wireguard"',
            'install -m 0755 "$repo_dir/scripts/integrate-user"',
            'install -m 0755 "$repo_dir/scripts/uninstall-backend"',
            'install -m 0644 "$repo_dir/packaging/systemd/omarchy-wireguard.service"',
            'install -m 0644 "$repo_dir/packaging/systemd/omarchy-wireguard-firewall.service"',
            'install -m 0600 "$config" /etc/omarchy-wireguard/backend.conf',
        ):
            self.assertLess(source.index(install), backend_publish, install)
        for backup in (
            "backup_cli", "backup_integrate", "backup_uninstall", "backup_service",
            "backup_firewall_service", "backup_config", "backup_networkmanager_dropin",
        ):
            self.assertIn(f'[[ -z ${backup} ]] || mv "${backup}"', source)
        cleanup = "cleanup() {" + source.split("cleanup() {", 1)[1].split("\ntrap cleanup ERR", 1)[0]
        self.assertLess(cleanup.index("systemctl daemon-reload"),
                        cleanup.index("systemctl restart omarchy-wireguard.service"))
        self.assertIn("daemon_was_enabled", cleanup)
        self.assertIn("daemon_was_active", cleanup)
        self.assertIn("firewall_was_enabled", cleanup)
        self.assertIn("firewall_was_active", cleanup)
        self.assertLess(source.index("backend_replaced=true"),
                        source.index("rm -rf /usr/lib/omarchy-wireguard/backend", backend_publish - 200))
        success = source.index("systemctl daemon-reload", backend_publish)
        self.assertLess(source.index("transaction_started=false", success),
                        source.index('rm -rf "$backup"', success))


if __name__ == "__main__":
    unittest.main()
