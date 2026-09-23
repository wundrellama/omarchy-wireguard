# Disposable actual-systemd VM lifecycle harness

## Status: 36 checks passed

The completed run (`observed-passed.json`) booted systemd 261.3 as PID1 with real D-Bus, NetworkManager, systemd-resolved, nftables and WireGuard kernel modules. The unmodified production installer, emergency-disable command and uninstaller executed successfully. An explicitly injected installer failure exercised rollback through real systemd dependency handling.

NetworkManager kept the same PID and InvocationID throughout installation, emergency-disable, uninstall and rollback. An unrelated NM profile's configuration and an unrelated nft table remained intact. The installed daemon answered an unprivileged controller's socket request. The runner verified 36 assertion markers, a matching structured success result, guest exit zero and QEMU exit zero; it does not accept QEMU exit alone. The parent verified every recorded production source hash against the current checkout.

## Reproduce

Prerequisites: Arch x86-64 host with readable matching kernel/module tree, unprivileged `/dev/kvm` access, installed public `/usr` systemd, Python, NetworkManager, nftables, WireGuard tools, D-Bus, PAM, cpio, man-db/groff and a trusted extracted Arch QEMU package tree. No host package installation or privileged operation is performed. The existing QEMU extraction was obtained from signature-verified Arch packages; replace the path below with your own trusted extraction if the scratch copy has expired.

From the project root:

```bash
image=$(mktemp -d "$HOME/.hermes/cache/scratch/wg-vm.XXXXXX")
/usr/bin/python3 tests/vm/build.py --output "$image"
/usr/bin/python3 tests/vm/run.py --image "$image" \
  --qemu-root /home/michael/.hermes/cache/scratch/systemd-vm.TFMS0A/qemu \
  --timeout 180
```

The builder refuses to overwrite an existing `root/`. It writes a project snapshot, per-source SHA-256 manifest, guest tree and compressed initramfs to scratch. The runner saves `serial.log` and `result.json`. QEMU has no disks, NICs, shared host trees, guest agent, monitor or graphics. Root inside this RAM-only guest is not host privilege escalation. Runtime is bounded to 180 seconds by default (maximum 240), with terminate/kill and process reaping; individual guest commands have a 40-second limit and the proof unit a 150-second limit.

Only public installed `/usr` dependencies are copied. Host `/etc`, homes, network settings, private keys and secrets are not read into the image. Guest accounts, PAM, NetworkManager and resolver configuration are synthetic. Project inputs are allowlisted to backend source, bin, scripts, packaging/systemd and manifest. The host kernel and QEMU binary are launch inputs, not mounted into the guest.

## Verified behavior and boundaries

- Install uses the unmodified production `scripts/install-backend`, units, backend and CLI. Query the daemon as UID 1000 and inspect the actual NM `Requires` edge.
- Apply production-rendered nft policy, run actual emergency-disable, verify firewall table absence and that the early-firewall service stays active while the daemon stops.
- Run unmodified uninstall, requiring dependency and backend removal without stopping/restarting NM or changing unrelated NM/nft state.
- Inject an installer failure through a guest-only `ExecStartPost=+/bin/bash /vm-fault.sh`. It attaches the actual NM dependency, reloads PID1, records its cached `Requires`, then exits 23. The `+` prefix exempts only this artificial injection process from daemon sandboxing; the production daemon remains hardened. The unmodified installer detaches the edge before stopping the firewall, and NM remains active with unchanged identity. No command wrapper substitutes for systemd, NM or nft.
- Sole inert production boundary: the copied `scripts/integrate-user` is replaced **only in the guest snapshot** by a labeled print-and-exit stub because the guest has no Omarchy desktop/bar/menu. Its original source hash is recorded, not claimed to match the stub.
- D-Bus uses its real implementation with a synthetic `Type=notify` launcher and the stock `dbus.socket`, passing `--systemd-activation --address=systemd:`. NetworkManager and resolved use stock units.
- Synthetic PAM permits guest `runuser`; this does not test host login/PAM security. There is no Internet or provider connection. A real WireGuard interface is created, but handshake/traffic testing belongs to the separate namespace harness.
- This is install/emergency/uninstall/rollback coverage, not installed-state reboot ordering, suspend/resume, physical-device behavior, every rollback failure mode or graphical integration coverage.

## Evidence

Passing artifacts live at `/home/michael/.hermes/cache/scratch/wg-vm.APpt69/` (`serial.log`, `result.json`, `snapshot-sha256.json`, guest tree and initramfs), subject to scratch retention. `observed-passed.json` and `observed-passed-sha256.json` preserve the result and production source hashes in this test directory.

The first attempt's `observed-blocked.json` and `observed-snapshot-sha256.json` remain historical evidence, not the current outcome. Subsequent fixes supplied the missing D-Bus socket and activation settings, `resolvectl`, and real man-db/groff dependencies needed by the installer's `systemd-analyze verify`. Guest subprocess stdout and stderr are captured separately so systemctl diagnostics do not corrupt JSON parsing. The initial rollback injector correctly encountered the daemon's read-only sandbox; only the injected process was exempted for the deliberate failure test.
