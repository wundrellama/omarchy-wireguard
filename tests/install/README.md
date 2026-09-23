# Installer rollback checks

Run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/install -v` from the repository root.

These tests extract and execute the production installer's `cleanup()` function with shell-function replacements for every external operation and a PATH that cannot resolve external commands. They do not execute the installer, elevate privileges, delete files, run host systemd, or change host networking.

The modeled systemd dependency is deliberately cached: deleting `50-omarchy-wireguard.conf` does not detach NetworkManager's `Requires=omarchy-wireguard-firewall.service` edge until a successful `daemon-reload`. Tests assert that the firewall stops only after that barrier and remains running when the reload fails. This is executable command-order regression coverage, not a live systemd installation/rollback test.

Emergency-disable checks are in `tests/cli/test_emergency.py`. They use scratch state files and inert subprocess boundaries to require a successful, well-formed nftables table listing before claiming firewall removal. An unreadable table is not proof of absence. Actual service/DNS rollback still needs separate isolated lifecycle verification.
