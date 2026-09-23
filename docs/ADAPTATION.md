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

This slice deliberately retains the IPv4-default-route requirement and existing full-tunnel protection semantics. It is not split-tunnel support. Profile update/removal, crash recovery for orphaned staged NetworkManager profiles, and the named-profile panel are separate follow-ups. The legacy panel remains location-oriented until its adaptation is visually verified; use the CLI for named-profile development tests.

Verification: 83 backend tests, 10 CLI tests and 2 socket/persistence integration tests pass on Python 3.11 and the system Python 3.14. JavaScript model tests, Omarchy plugin validation and `git diff --check` pass. Integration tests cover successful labeled multi-file staging and cleanup after duplicate rejection, using real socket authorization and state files but simulated NetworkManager/firewall operations. The independent review's policy-change blocker was reproduced and corrected; independent re-review passed with no remaining findings in scope. No UI, packet-level networking, reboot or live migration verification is claimed.

### Remaining personal-tunnel work

- Introduce explicit `internet-exit` and `private-network` roles, with validated route and DNS policy for each.
- Permit private-network tunnels alongside one internet exit only when their routing policies are compatible; reject ambiguous overlap before changing anything.
- Replace the literal `alfred-vpn` exception with validated, per-tunnel routes and endpoint exceptions.
- Replace the hardcoded `.lan` DNS assumption with explicit split-DNS domains.
- Keep per-tunnel intent and health separate from global internet-protection state, including boot, reconnect, and failure handling.
- Adapt the native panel for named profiles, incremental imports, and truthful reachability/protection states.

### Safety prerequisites before private-tunnel activation

These are follow-up requirements identified by source review, not claims of reproduced packet leaks or fixes already shipped:

- **Guard private destinations when their tunnel fails.** Allow each protected prefix only on its assigned tunnel, then drop other egress for that prefix before general exit/LAN accepts. Keep these destination guards even when no internet exit is enabled. An allowlist alone does not prevent fallback traffic.
- **Separate ownership.** The current `HostSystem.import_profile()` and `activate()` apply exit defaults and catch-all DNS; `deactivate_managed()` affects all prefixed profiles. Add role-specific configuration and UUID-scoped lifecycle operations before mixing private tunnels with an exit.
- **Quarantine before disruption.** `Controller._emergency_disconnect()` currently clears DNS/deactivates before rebuilding the firewall. Add a transition barrier and a minimal quarantine that can be installed without successful link discovery. Never use direct-disconnect as a protected handoff.
- **Verify exact observations.** `HostSystem.verify()` uses substring matching for activation state, a single IPv4 route probe, and partial firewall text checks. Strengthen those checks before making broader protection claims. Private-tunnel status must not reuse the exit's fresh-handshake/green-shield semantics blindly.
- **Handle DNS separately.** Begin private-tunnel runtime with IP routes only. Private DNS needs suffix-to-resolver/link ownership and proven no-fallback behavior when the link disappears; do not simply replace `~lan` with another fixed suffix.
- **Do not promise independent pause expiry yet.** The existing timeout is enforced by the controller's `tick()`. A paused controller leaves that timer unenforced. Resolve or clearly constrain this before deployment.
- **Treat status loss as unknown.** The unchanged QML model/service can retain old connected state or default missing verification to true. The new panel must age verification and stop presenting stale status as protection.

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
