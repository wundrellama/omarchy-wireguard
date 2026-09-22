# omarchy-wireguard

A WireGuard integration for Omarchy 4.x.

It adds a status dot beside the Network widget and a searchable location panel.
Green means the tunnel, default route, DNS, IPv6 policy, and recent WireGuard
handshake are verified. Amber means connecting, red means enabled but failed,
and a muted hollow dot means disabled or temporarily paused.

## Install

```bash
omarchy plugin add https://github.com/nicolasdorier/omarchy-wireguard.git --enable
```

Click the new bar dot, choose **Install backend**, and authorize the Polkit
prompt. The installer adds `wireguard-tools`, a narrowly scoped root service,
and a dedicated nftables kill-switch table without changing UFW rules.

Import any number of compatible `.conf` files, a directory, or a ZIP; the panel
displays every imported city. **Open TorGuard generator** is an optional
convenience for TorGuard customers and opens that provider's public generator.

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
node --test tests/plugin/model.test.js
omarchy plugin validate .
qmllint -I /usr/share/omarchy/shell plugin/BarWidget.qml plugin/Service.qml
```
