# Isolated real NetworkManager / resolved lifecycle tests

**Final-revision execution passed:** `observed-final-{normal,inactive,abort}.json` contains 45 normal checks, 47 inactive-import checks and 14 pre-abort checks. The parent reran these after the final GLib ownership cleanup and verified every recorded backend hash matches the current code. Host namespace/link/route fingerprints stayed unchanged and children were reaped. Earlier `observed-atomic-*.json` reports predate the final cleanup and remain historical. Independent review of the atomic import and real systemd install/uninstall tests are separate gates.

Run from the repository as an ordinary user, without sudo:

```sh
python -B tests/lifecycle/run.py
python -B tests/lifecycle/run.py --inject-failure
python -B tests/lifecycle/run.py --assert-import-inactive
```

The first command exercises real production `Controller`, `HostSystem`, `CommandRunner`, `StateStore`, importer and nft renderer against real NetworkManager, systemd-resolved, WireGuard and nftables. No service command is mocked or redirected to a fake executable. `GuardedRunner` checks isolation then delegates to the actual production runner, including its fixed environment and `/run/omarchy-wireguard` import path.

## Safety boundary

- Bubblewrap creates independent user, mount, PID, network, IPC and UTS namespaces with mapped root. The child verifies every namespace differs from the host before starting services and rechecks identity before tool execution. Direct host invocation is a mandatory refusal self-test.
- Only `/usr`, the repository's `backend/`, and `tests/lifecycle/` are mounted read-only. No host home, `/etc`, `/run`, `/var`, service bus, credentials, or network is mounted. Writable `/etc`, `/run`, `/var`, `/sys` are private tmpfs; `/proc` is namespace-local and `/dev` is bubblewrap's minimal device filesystem. No host systemctl, nmcli, nft, install/uninstall or emergency-disable command is executed.
- D-Bus uses a newly created `/run/dbus/system_bus_socket` with a synthetic policy. All resolver sockets and NM state/keyfiles live in the private filesystem. Synthetic accounts, machine ID, DNS configuration and freshly generated WireGuard keys are created only inside it. Keys travel through private stdin pipes/files, never results.
- A second isolated network namespace contains the synthetic WireGuard peer, UDP DNS authorities and echo listener. The two test networks have no connection to host devices or the Internet.
- Every run has a 120-second outer timeout; readiness, commands, peer RPC and cleanup have shorter bounds. Children are terminated/reaped in `finally`; namespace teardown destroys remaining resources. A separate post-activation abort exercises cleanup.
- Host reads are limited to read-only `ip -j` link/route snapshots and namespace IDs. Before/after JSON snapshots and hashes are saved under `$TMPDIR/wireguard-lifecycle-*`; host nft/NM state is deliberately not read. Matching network fingerprints are useful evidence, not a claim to fingerprint every possible host property.

## What is exercised

- Actual NM import, profile hardening, activation, deactivation and full production seven-check connection verification.
- Genuine kernel WireGuard handshake and encrypted traffic to a synthetic peer. Public DNS reaches `10.77.0.1` over `wgpeer`, `.lan` DNS reaches `192.0.2.2` over `ethpeer`; real A answers differ. Packet records prove ingress paths, not just successful queries.
- `resolvectl` tunnel set/revert/reconfigure; nonempty original LAN search/routing domains and default-route state restored after disconnect. A post-disconnect DNS answer proves the restored route works.
- Fresh Controller reconstruction from its real state store while connected; DNS snapshot retained across boot/reconnect.
- Real tunnel interface deletion causes failed/fail-closed state. A public UDP probe is blocked, increments the production nft drop counter, and is absent at the peer. Reconnect succeeds. A direct underlay echo after disconnect is the positive control.
- An unrelated active NM dummy profile survives connect, controller restart, tunnel failure, disconnect and failed-import rollback.
- A deliberately injected StateStore catalog-write error causes the production rollback path to delete newly imported **real NM profiles** without changing the existing profile set. This is persistence fault injection, not a fabricated NM result.
- Real foreground NM termination/restart retains keyfiles and permits reconnection. Real resolved termination/restart permits reconnection and fresh DNS answers after the synthetic underlay baseline is republished.

## Explicit limits

This is **not systemd PID 1/unit lifecycle or installation rollback proof**. There is no systemd manager, cgroup delegation, udev, Polkit, host dispatcher configuration, DHCP, production credentials or physical NIC. Services are real foreground daemon processes supervised by the harness. Production install/uninstall and emergency-disable are not run, even inside this sandbox. `Requires=` ordering, `daemon-reload`, boot enablement, service hardening and installation rollback still require a disposable VM or independently booted system container.

A fresh sysfs mount was attempted safely inside the sandbox and rejected by this kernel with `VFS: Mount too revealing`. The harness uses an **empty private `/sys` tmpfs**, never host sysfs. NM and resolved work for these netlink-created devices without it.

The underlay is a manually configured veth named `eth0`, discovered by the real adapter's current `ip -json link` path, not a physical/DHCP integration test. The unrelated connection is a dummy profile, not an existing real VPN. A single user mapping means resolved runs as mapped UID 0 with a synthetic `systemd-resolve` passwd entry; these tests do not establish distinct-UID DNS firewall isolation. DNS testing is IPv4 UDP A-query routing, not DNSSEC, encrypted DNS, TCP fallback or IPv6 DNS. The IPv6 production verification check passes through the firewall-blocked alternative, not an IPv6 tunnel. Resolved restart explicitly republishes the synthetic underlay DNS baseline; automatic DHCP/NM physical DNS recovery is not claimed. Controller reconstruction is not a daemon/socket-service restart.

## Recorded execution

Observed on Linux `7.2.5-4-omarchy`, NetworkManager `1.58.1-1`, systemd `261.3-1-arch`, bubblewrap `0.13.0`:

- `observed-lifecycle.json`: **41/41 assertions passed**, supervisor exit 0.
- `observed-abort.json`: **10/10 assertions before the intentional abort passed**, `expected_abort`, children reaped, supervisor exit 0.
- `observed-import-race.json`: regression probe **fails** `import_must_not_activate_before_connect`; this is a real discovered behavior, not a blocked prerequisite.
- Every recorded run refused direct host invocation, reaped children, removed its supervisor process group, and reported unchanged host namespaces/link/route fingerprints. Each JSON embeds exact backend hashes and scratch artifact paths.

### Original import autoconnect race — historical failing baseline

`--assert-import-inactive` widens the actual interval **after** `nmcli connection import` returns and **before** the production `nmcli connection modify ... connection.autoconnect no` by 300 ms. It never requests activation and fabricates no responses. Real NM nevertheless reports `import-<random>:wireguard` active and resolved exposes its `10.77.0.1` DNS while the Controller is still `disabled`. A real `ip -j route get 1.1.1.1` also selects that temporary import interface and the only nft table observed is NM's own `ip nm-wg-import-*`, not the backend fail-closed table. Profile modification subsequently deactivates it, so looking only after `import_profile()` returns misses this transient behavior. Ordinary non-delayed run logs also showed the temporary import link publishing DNS.

This probe is separate so the remaining lifecycle checks still execute and provide useful evidence. Passing the normal command **does not mean the import race is fixed**. The regression command must become green against a production fix before claiming safe inactive import.

The production fix replaces the import-then-modify sequence with offline libnm validation and a single `AddConnection2` publication containing all settings and both `autoconnect=false` and `BLOCK_AUTOCONNECT`. The current regression delays the actual publication return and verifies that the observation ran; it checks all WireGuard connections/interfaces, routes and DNS rather than matching only temporary import names. `observed-import-race-red.json` preserves the original failure. The newer tests also check real NM settings persistence (including secrets without logging their values), restrictive keyfile permissions and cleanup after an injected lost reply. The final-revision reruns passed as documented above.
