# Unified VPN adaptation

## Goal

Replace the separate WireGuard TUI widget and Omaproton widget with one native Omarchy panel. Keep the official Proton client for Proton authentication and provider features. Keep private-network reachability distinct from internet-exit protection.

This is a development branch, not a deployment. Do not install its privileged backend onto the active desktop until the migration and network-verification gates below are met. Existing WireGuard profiles, Proton state, bar configuration, and running services remain untouched during development.

## Milestone 1 — Personal WireGuard

### First slice: safe catalog and CLI

- [x] Named full-tunnel profiles without mandatory geographic metadata.
- [x] Additive imports with stable profile identity; importing another profile must not delete or disconnect an existing one.
- [x] Duplicate source names rejected before mutations, rather than silently replacing profiles.
- [x] Newly created NetworkManager profiles cleaned up if the import cannot be committed; incomplete cleanup and committed-but-durability-unconfirmed states are reported explicitly.
- [x] Select an exact profile by ID while retaining legacy country/city selection and persisted state compatibility.
- [x] Ordinary imports preserve existing network policy instead of rediscovering or overwriting it.
- [x] Explicit policy changes are rejected before import effects while VPN intent is enabled, so saved policy cannot silently diverge from active firewall exceptions.
- [x] Backend, CLI, and real Unix socket/state-file integration tests with simulated host operations.
- [x] Independent code review, blocker correction, and passing independent re-review.

This slice deliberately retains the IPv4-default-route requirement and existing full-tunnel protection semantics. It is not split-tunnel support. Profile update/removal and crash recovery for orphaned staged NetworkManager profiles remain follow-ups. The subsequent panel slice is described below.

Verification: 83 backend tests, 10 CLI tests and 2 socket/persistence integration tests pass on Python 3.11 and the system Python 3.14. JavaScript model tests, Omarchy plugin validation and `git diff --check` pass. Integration tests cover successful labeled multi-file staging and cleanup after duplicate rejection, using real socket authorization and state files but simulated NetworkManager/firewall operations. The independent review's policy-change blocker was reproduced and corrected; independent re-review passed with no remaining findings in scope. No UI, packet-level networking, reboot or live migration verification is claimed.

### Second slice: named full-tunnel panel and isolated packets

- [x] Named profile catalog, optional geography, source/name/location search, exact profile selection and additive import label review.
- [x] Conservative unknown status on failed, invalid or stale observations; stale/pre-action successful polls cannot restore a green state.
- [x] Removed timed-pause control rather than promising unverified protection after expiry.
- [x] Corrected exact activation-state and interface matching in backend verification, with regression tests.
- [x] Real kernel WireGuard and backend-generated nftables packet tests in disposable network namespaces; host links/routes unchanged after normal completion and deliberate failure.
- [x] Rendered the production panel with a non-networking fixture in the running Omarchy shell, including long labels, failed/unknown states, filtered selection and actual keyboard selection.
- [x] Corrected review findings with failing-then-passing regressions: explicit first-install bootstrap under unknown status, label isolation across sequential import batches, contradictory disabled/enabled status, and boolean review visibility. Rechecked final bootstrap and labeled import rendering; bootstrap actions wrap rather than overflow.
- [x] Independent re-review passed after bootstrap/import corrections, with no remaining security or logic findings in scope. The subsequent bootstrap Row-to-Flow layout correction passed its regression check and actual-shell visual verification.
- [x] Real NetworkManager/systemd-resolved adapter and controller lifecycle exercised in isolated namespaces: 41 checks passed, including DNS answers with ingress evidence, controller reconstruction, tunnel-loss blocking, retry, unrelated-profile retention, persisted-import rollback, and foreground service restarts.
- [x] Final-revision atomic-import lifecycle reruns: 45 normal, 47 inactive-import and 14 pre-abort assertions passed; all recorded backend hashes match the final files, and host networking fingerprints were unchanged.
- [x] Independent atomic-import review and numeric-validation re-review passed after correcting libnm's silent-default behavior; no remaining findings in scope.
- [x] Real systemd install, emergency-disable, uninstall and injected installer rollback passed 36 assertions in an isolated booted guest, retaining the same NetworkManager PID/InvocationID and unrelated NM/nft settings. Graphical integration is explicitly stubbed in the guest; installed-state reboot ordering remains untested.

Panel-checkpoint automated evidence: 87 backend tests, 10 CLI tests, 2 socket/persistence tests, three Node test files, and 5 Qt Model cases pass. The network harness passes 39 checks and 10 setup checks before its intentional failure/cleanup case. That harness covers selected UDP OUTPUT flows, IPv4/IPv6 fallback, intended LAN exceptions, marked WireGuard endpoints and nft transaction failure; it does not prove TCP, forwarding, full controller operation, DNS, reboot, or suspend/resume. Stock qmltestrunner cannot load the Quickshell plugin needed by the real Service test; actual panel rendering uses the running shell and an injected inactive live service instead. No live VPN backend was installed.

### Remaining personal-tunnel work

- Introduce explicit `internet-exit` and `private-network` roles, with validated route and DNS policy for each.
- Permit private-network tunnels alongside one internet exit only when their routing policies are compatible; reject ambiguous overlap before changing anything.
- Replace the literal `alfred-vpn` exception with validated, per-tunnel routes and endpoint exceptions.
- Replace the hardcoded `.lan` DNS assumption with explicit split-DNS domains.
- Keep per-tunnel intent and health separate from global internet-protection state, including boot, reconnect, and failure handling.
- Extend the named full-tunnel panel with role-specific private-network reachability states once that backend exists.

### Safety prerequisites before private-tunnel activation

These are follow-up requirements identified by source review, not claims of reproduced packet leaks or fixes already shipped:

- **Guard private destinations when their tunnel fails.** Allow each protected prefix only on its assigned tunnel, then drop other egress for that prefix before general exit/LAN accepts. Keep these destination guards even when no internet exit is enabled. An allowlist alone does not prevent fallback traffic.
- **Separate ownership.** The current `HostSystem.import_profile()` and `activate()` apply exit defaults and catch-all DNS; `deactivate_managed()` affects all prefixed profiles. Add role-specific configuration and UUID-scoped lifecycle operations before mixing private tunnels with an exit.
- **Quarantine before disruption.** `Controller._emergency_disconnect()` currently clears DNS/deactivates before rebuilding the firewall. Add a transition barrier and a minimal quarantine that can be installed without successful link discovery. Never use direct-disconnect as a protected handoff.
- **Verify exact observations.** Exact activation state/device matching is now tested, but `HostSystem.verify()` still uses a single IPv4 route probe and partial firewall text checks. Strengthen those checks before making broader protection claims. Private-tunnel status must not reuse the exit's fresh-handshake/green-shield semantics blindly.
- **Handle DNS separately.** Begin private-tunnel runtime with IP routes only. Private DNS needs suffix-to-resolver/link ownership and proven no-fallback behavior when the link disappears; do not simply replace `~lan` with another fixed suffix.
- **Do not promise independent pause expiry yet.** The existing timeout is enforced by the controller's `tick()`. A paused controller leaves that timer unenforced. Resolve or clearly constrain this before deployment.
- **Treat status loss as unknown.** The panel now expires stale status and rejects invalid/contradictory observations. A fresh `connected` mode from the current backend is accepted because the controller gates that mode on verification; this is not independent traffic verification.

Reject ambiguous private-route overlap initially, including overlaps with other private tunnels, connected LANs, tunnel endpoints, infrastructure DNS, and default-equivalent prefix collections. Reboot reconciliation must restore private destination guards independently of exit enablement.

## Milestone 2 — Proton adapter

Use the installed official `protonvpn` client in the user session. Do not copy its account credentials into the root WireGuard service. Start with status, disconnect, fastest, country, and exact server selection. Retain existing Proton account/session storage.

Define one internet-exit owner before enabling provider switching. Explicitly coordinate DNS and firewall ownership; never assume two independent kill switches compose safely. Do not promise a leak-free handoff until tested. Unsupported handoffs must be refused rather than silently falling back to direct traffic.

## Milestone 3 — Feature parity and hardening

Add the Proton features actually needed: Secure Core, NetShield, port forwarding, and client-supported split tunneling. Preserve provider constraints, particularly conflicts between kill-switch and split-tunneling modes. Exercise suspend/resume, Wi-Fi changes, captive-portal pause, daemon crashes, reboot, stale handshakes, DNS restoration, IPv6, and conventional Docker/VM bridges.

## Migration and verification gate

1. Inventory profile names, route prefixes, DNS servers/domains, backend ownership, and autoconnect settings without displaying private or preshared keys. Never assume an old remembered NetworkManager profile is still present.
2. Prepare root-only backups of existing WireGuard configuration and relevant NetworkManager state, plus user-owned backups of shell/menu configuration. Keep backups outside Git; do not expose credentials to chat or logs.
3. Keep the old plugins and original VPN profiles available until the new paths are proven. Do not activate two managers against the same tunnel.
4. Exercise privileged networking in a disposable VM or explicitly approved isolated harness before installing on the active desktop. Mocked command tests are not packet-level leak tests.
5. Verify interface, route, DNS, IPv6, firewall and handshake behavior, then independently exercise actual traffic. Test failure paths, not only successful connects.
6. Verify the native panel in the running UI, including failed/unknown states, keyboard handling and long labels.
7. Only then switch bar entries. Removing a widget does not remove persistent root services, a NetworkManager dependency drop-in, or firewall state.

## Rollback requirements

Have recovery instructions available outside the GUI before deployment. The upstream emergency-disable command is intended to stop the managed exit and restore direct networking, but it must be retested as ownership and tunnel roles evolve. Re-enabling old widgets alone is not network rollback. Backend removal must preserve unrelated profiles and restore original DNS policy; validate that NetworkManager stays active. No live deployment, commits, or publication are implied by local development completion.

Independently reviewed rollback hardening: installer cleanup now reloads systemd after removing the NetworkManager dependency drop-in and before stopping the firewall service; if reload fails it retains services/firewall rather than risking NetworkManager shutdown through a cached dependency. Emergency-disable now requires a successful, well-formed `nft -j list tables` observation before claiming firewall removal. Two inert installer tests and four additional CLI rollback tests reproduce the old behaviors and pass with these corrections. The CLI suite now has 14 tests. These are command-order/error-path tests, not proof of live installation, uninstall or DNS restoration.

## Atomic import verification

The old `nmcli connection import` followed by `connection modify ... autoconnect no` race was reproduced with real NM. The new implementation validates the complete settings offline through libnm and publishes them with one `AddConnection2(TO_DISK | BLOCK_AUTOCONNECT)` request carrying `autoconnect=false`; keys are not put in subprocess arguments or temporary files. UUID collision checks and exact identity verification constrain rollback to the newly published profile.

Saved `tests/lifecycle/observed-final-{normal,inactive,abort}.json` reports show 45, 47 and 14 successful assertions respectively, unchanged host namespace/link/route fingerprints and cleanup. Their recorded backend hashes all match the current files, including the final GLib ownership correction in `nm_import.py`. Original failing evidence is retained as `observed-import-race-red.json`, and the earlier `observed-atomic-*.json` reports remain historical. The parent reran 100 backend tests, 14 CLI tests, 2 installer tests, 2 socket integration tests, three Node suites and 5 Qt Model cases successfully. The final lifecycle runs include explicit numeric range checks for ListenPort, MTU and PersistentKeepalive before publication; negative and overflowing values can no longer be silently dropped by libnm in favor of defaults. An offline real-libnm test verifies accepted boundary values under fatal-warning handling. Independent atomic-import review and numeric-validation re-review passed with no remaining findings in scope.

A disposable no-NIC QEMU/KVM guest initially established real systemd PID 1 capability in scratch `systemd-vm.TFMS0A`. The completed [project VM harness](../tests/vm/README.md) subsequently passed all 36 checks for actual installation, emergency-disable, uninstall and injected installer rollback. `tests/vm/observed-passed.json` and `observed-passed-sha256.json` preserve evidence; the parent verified source hashes against the current checkout. No production scripts were modified to make this test pass, except the documented guest-only inert graphical integration boundary.

The first project VM attempt (`tests/vm/observed-blocked.json`) remains historical failure evidence. Completing real D-Bus socket activation and the minimal userspace dependencies removed that infrastructure blocker. The rollback injector uses a guest-only `ExecStartPost=+` exemption so its artificial dependency mutation is not blocked by production daemon hardening. Production daemon sandboxing remains enabled. Successful guest shutdown and QEMU exit accompany the 36 checks; exit zero alone is insufficient. Installed-state reboot ordering, physical networking, provider connectivity and broader feature work remain separate requirements. No live deployment, commit or push is implied.
