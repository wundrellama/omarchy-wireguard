# omarchy-wireguard

A WireGuard integration for Omarchy 4.x.

> **Development fork — not ready to replace the installed VPN plugins.** This branch adds safe additive imports and a named full-tunnel profile panel with conservative unknown-status handling. Split/private-network tunnels and Proton integration are not implemented yet. See [the adaptation roadmap and deployment gates](docs/ADAPTATION.md). The install command below targets this fork's default branch; it does not select `feature/personal-vpn-profiles` or imply deployment approval for this development branch. Use the [non-networking preview](tests/preview/README.md) to evaluate the panel without installing the backend.

It adds a status dot beside the Network widget and a searchable location panel.
Green means the tunnel, default route, DNS, IPv6 policy, and recent WireGuard
handshake are verified. Amber means connecting, red means enabled but failed,
and a muted hollow dot means disabled or temporarily paused.

## Install

```bash
omarchy plugin add https://github.com/wundrellama/omarchy-wireguard.git --enable
```

Click the new bar dot, choose **Install backend** (or **Install / repair backend** when status is unknown), and authorize the Polkit
prompt. The installer adds `wireguard-tools`, a narrowly scoped root service,
and a dedicated nftables kill-switch table without changing UFW rules.

Import compatible `.conf` files, a directory, or a ZIP; the development panel displays each named profile, with optional geography. **Open TorGuard generator** is an optional convenience for TorGuard customers and opens that provider's public generator.

On this development branch, installation remains an explicit user action; an unavailable status response never triggers installation automatically. A disconnected backend is shown as unknown, not as proof that VPN protection is disabled. The named panel lists profile labels rather than requiring a city.

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

### Named profiles (development branch)

Import a full-tunnel profile with a display name instead of assigning it a country/city, then use the stable ID returned by `list`:

```bash
omarchy-wireguard import ~/Downloads/personal.conf --label 'Personal exit'
omarchy-wireguard list
omarchy-wireguard connect --profile '<id-from-list>'
```

For a directory or ZIP, `--labels '{"personal.conf":"Personal exit"}'` maps exact source names (including archive-relative directories) to labels. Labels must be nonempty printable text of at most 128 characters. They do not relax the full-tunnel configuration requirements.

Imports add to the catalog; they never replace old profiles. Duplicate source names are rejected, and duplicate basenames in a multi-file CLI import must be renamed explicitly. Profile replacement, update and removal are not implemented in this slice. Existing connections and IDs survive an import. CLI imports no longer discover `alfred-vpn` or overwrite saved network policy.

The development panel lists named profiles without requiring geography, searches labels/source names/locations, and connects the exact selected ID. Ambiguous imports request display labels and add profiles without replacing existing ones. Missing, stale or contradictory status is shown as unknown rather than protected or disconnected. Timed pause is not exposed in this panel. Private/split tunnels and Proton remain unsupported; do not deploy it as a replacement for both installed plugins.

If a backend failure leaves traffic blocked:

```bash
sudo omarchy-wireguard emergency-disable
```

## Remove

```bash
sudo /usr/lib/omarchy-wireguard/uninstall-backend "$USER"
omarchy plugin remove nicolasdorier.wireguard
```

This removes plugin-owned profiles, services, firewall state, and menu
integration. It does not modify unrelated VPNs such as `alfred-vpn`.

## Security

The backend accepts requests only from root and the user selected at install.
WireGuard private keys remain in root-owned NetworkManager profiles. The kill
switch covers host, Docker, and VM traffic while allowing directly connected
LAN traffic, `.lan` split DNS, local discovery, WireGuard endpoints, and the
explicitly allowlisted `alfred-vpn` private route.

No telemetry is collected. Diagnostics omit keys, imported configurations,
DNS queries, and browsing destinations.

## Development

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

The [disposable systemd VM harness](tests/vm/README.md) covers actual installation, emergency-disable, uninstall and injected installer rollback with real systemd, NetworkManager and nftables. Its 36 passing checks preserve NetworkManager's running identity and unrelated NM/nft settings. The guest has no host network or filesystem shares; graphical user integration is explicitly stubbed, and installed-state reboot ordering and provider connectivity are not covered.
