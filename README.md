# omarchy-wireguard

omarchy-wireguard adds a status-bar control panel and a fail-closed backend for full-tunnel WireGuard profiles on Omarchy 4.x. The panel imports named profiles, verifies local protection state, shows traffic, and coordinates switches to Proton VPN.

Maintained by **wundrellama**, based on Nicolas Dorier's original omarchy-wireguard. The original MIT copyright and license are retained in [LICENSE](LICENSE).

> **Development fork.** This plugin supports named full-tunnel WireGuard profiles. It does not support private-network split tunnels. Proton VPN support is a first version; see [Proton VPN](docs/PROTON.md). Keep your existing VPN plugins until you test the replacement. See the [roadmap and deployment limits](docs/ADAPTATION.md). The [panel preview](tests/preview/README.md) uses synthetic profiles and does not change networking.

## Panel and status shield

The bar shows a shield. Click the shield to open the profile panel.

| Icon | State |
| --- | --- |
| Green check-shield | Connected. The checks for the active VPN pass. |
| Amber shield | Connecting. |
| Red shield | Failed or unverified, a Proton VPN error, or a conflict: WireGuard and Proton VPN both report active. |
| Muted shield | Disabled, paused, or unknown. Read the panel for the exact state. |

The shield shows the active VPN: WireGuard or Proton VPN. The tooltip names the active VPN and its server, and warns when the connection is operational but protection has not yet been verified.

For WireGuard, the backend checks the tunnel interface, firewall policy, default route, Domain Name System (DNS), IPv6 policy, and recent handshake. Missing, stale, or contradictory WireGuard status appears as unknown.

For Proton VPN, the plugin compares fresh NetworkManager and Proton CLI reports. An operational connection stays red until the reports match and NetworkManager confirms that WireGuard is absent. A green icon reports these local checks. It does not prove every possible traffic path.

The panel supports these actions:

- Search profiles by name, source file, city, or country.
- Connect a selected profile or disconnect the current profile.
- Import individual files, a directory, or a ZIP archive.
- Review display labels before an ambiguous import.
- Retry a failed connection.
- Use one button at the top to connect the last connection again (WireGuard or Proton VPN), or to disconnect the active VPN.
- Copy diagnostics from **BACKEND MAINTENANCE** at the bottom of the panel.

Imports add profiles without replacing existing profiles. The file chooser returns to the panel for label review when required. The panel does not offer timed pause.

## Proton VPN

The panel has a Proton VPN section. It uses the official `protonvpn` command in your user session. The plugin does not read or store your Proton password.

- Sign in: the panel opens Proton's own sign-in prompt in a terminal.
- Connect: Fastest, Random, Fastest P2P, Secure Core, Tor, a country, a city, or a server.
- Search: one field finds countries, cities, and servers (for example `US-CA#3`, `los angeles`, or `tor`) while you type.
- Disconnect, and show the server, location, load, protocol, and traffic.

To change from one VPN to the other, select the new connection and confirm the switch. The panel disconnects the active VPN first. During the switch, traffic uses your regular connection. A complete switch can take up to 150 seconds. If the Proton kill switch is not `off`, the panel does not switch to WireGuard. See [Proton VPN](docs/PROTON.md).

## Traffic display

While connected, the panel and shield tooltip show:

| Measurement | Meaning |
| --- | --- |
| Download / upload | Current receive and transmit rates, in B/s, KiB/s, or MiB/s. |
| Received / sent | Total bytes through the current tunnel interface. |

The sampler reads counters once per second. Totals start when the tunnel interface is created. They do not reset when you close the panel. Recreating the interface resets its totals. The plugin does not store lifetime totals across connections.

The first sample shows `—/s` until a second sample establishes a rate. Missing or stale samples show unavailable values, not zero traffic. A real idle sample shows `0 B/s`. Disconnecting hides the traffic section.

The bar remains shield-only. The sampler needs no root access and does not change the connection. Traffic counters do not prove VPN protection. See [traffic behavior and tests](docs/TRAFFIC.md).

## Install

```bash
omarchy plugin add https://github.com/wundrellama/omarchy-wireguard.git --enable
```

1. Click the bar shield.
2. If the backend is not installed, choose **Install backend**.
3. If the status is unknown, choose **Install / repair backend**.
4. If the panel shows **Setup required**, choose **Repair backend**.
5. Authorize the Polkit prompt.

The installer adds `wireguard-tools`, a root service, and a dedicated nftables kill-switch table. It does not change Uncomplicated Firewall (UFW) rules.

Import compatible `.conf` files, a directory, or a ZIP. The panel shows each named profile with optional location data. **Open TorGuard generator** opens that provider's public generator for TorGuard customers.

Installation requires an explicit user action. An unavailable status response never starts installation automatically. An unreachable backend appears as unknown, not as proof that VPN protection is disabled. An ambiguous profile needs a display label before import.

Accepted profiles must contain exactly one `Interface` followed by one `Peer`,
include DNS and the IPv4 default route in `AllowedIPs`, use only the supported
standard keys, and contain no hooks. Profiles from every provider are not
guaranteed to meet these constraints.

The panel is also available at **SUPER+SPACE → Setup → Network → WireGuard VPN**
and through the `torguard`, `vpn`, and `wireguard` search aliases.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the component boundaries, privileged
control flow, state machine, DNS and firewall design, boot behavior, and
security invariants.

## CLI

```bash
omarchy-wireguard status
omarchy-wireguard list
omarchy-wireguard connect 'Japan/Tokyo'
omarchy-wireguard disconnect
omarchy-wireguard retry
omarchy-wireguard pause 600
omarchy-wireguard import ~/Downloads/tokyo.conf ~/Downloads/singapore.conf
omarchy-wireguard diagnostics
```

### Named profiles

Import a full-tunnel profile with a display name instead of assigning it a country/city, then use the stable ID returned by `list`:

```bash
omarchy-wireguard import ~/Downloads/personal.conf --label 'Personal exit'
omarchy-wireguard list
omarchy-wireguard connect --profile '<id-from-list>'
```

For a directory or ZIP, `--labels '{"personal.conf":"Personal exit"}'` maps exact source names (including archive-relative directories) to labels. Labels must be nonempty printable text of at most 128 characters. They do not relax the full-tunnel configuration requirements.

Imports add to the catalog; they never replace old profiles. Duplicate source names are rejected, and duplicate basenames in a multi-file CLI import must be renamed explicitly. Profile replacement, update and removal are not implemented in this slice. Existing connections and IDs survive an import. CLI imports no longer discover `alfred-vpn` or overwrite saved network policy.

The panel lists named profiles without requiring location data. It searches labels, source names, cities, and countries. It connects the exact selected ID. Ambiguous imports request display labels and add profiles without replacing existing profiles. Missing, stale, or contradictory WireGuard status appears as unknown. An operational Proton connection with incomplete evidence appears as unverified. Timed pause and private or split tunnels remain unsupported. The panel supports Proton VPN when its official CLI is installed. It coordinates VPN transitions but does not enable the Proton kill switch.

If a backend failure leaves traffic blocked:

```bash
sudo omarchy-wireguard emergency-disable
```

## Remove

```bash
sudo /usr/lib/omarchy-wireguard/uninstall-backend "$USER"
omarchy plugin remove wundrellama.wireguard
```

The uninstaller removes profiles that the plugin catalog owns. It also removes the services, firewall state, and menu integration. It leaves uncataloged profiles unchanged. If an uncataloged managed profile is active, the uninstaller stops and keeps the firewall for manual recovery. It does not modify unrelated VPNs such as `alfred-vpn`.

## Security

The backend accepts requests only from root and the user selected at install.
WireGuard private keys remain in root-owned NetworkManager profiles. The kill
switch covers host, Docker, and VM traffic while allowing directly connected
LAN traffic, `.lan` split DNS, local discovery, WireGuard endpoints, and the
explicitly allowlisted `alfred-vpn` private route.

No telemetry is collected. Diagnostics omit keys, imported configurations,
DNS queries, and browsing destinations.

## Development

Run the fast checks with the same command as GitHub Actions:

```bash
./tests/fast
```

See [fast CI checks](docs/CI.md) for dependencies, logs, and coverage limits. The fast workflow excludes real networking, systemd VM, and Quickshell tests.

Run individual suites or additional desktop checks as needed:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend python3 -m unittest discover -s tests/backend -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/cli -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/install -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend python3 -m unittest discover -s tests/integration -v
node --test tests/plugin/*.test.js
omarchy plugin validate .
qmllint -I /usr/share/omarchy/shell plugin/BarWidget.qml plugin/Service.qml
```

The integration suite exercises the actual CLI, Unix socket authorization/protocol, parser, controller and private state files with simulated host operations. It never activates NetworkManager profiles or changes firewall/DNS settings. Passing it is not live-network or leak-test evidence.

The separate [network namespace harness](tests/network/README.md) exercises actual backend-generated nftables rules and real WireGuard packets inside disposable, unprivileged namespaces. Run `python3 -B tests/network/run.py`. This is bounded packet-level evidence, not verification of the real NetworkManager/systemd-resolved lifecycle, reboot, or comprehensive leak protection. See [plugin checks](tests/plugin/README.md) for Qt test coverage and limitations.

The [real-service lifecycle harness](tests/lifecycle/README.md) adds isolated NetworkManager, systemd-resolved, actual DNS answers and controller transitions. Run `python3 -B tests/lifecycle/run.py` and its documented failure/regression scenarios. These are real foreground daemons in private namespaces, not systemd-managed services or an installation test; the harness documents synthetic-network, UID and DNS limits. Its normal passing run does not excuse a failing inactive-import regression.

The [disposable systemd VM harness](tests/vm/README.md) covers actual installation, emergency-disable, uninstall and injected installer rollback with real systemd, NetworkManager and nftables. Its retained 36-check result is historical and its source hashes do not cover this revision; rerun it before treating it as current release evidence. The guest has no host network or filesystem shares; graphical user integration is explicitly stubbed, and installed-state reboot ordering and provider connectivity are not covered.
