# omarchy-torguard

An unofficial TorGuard WireGuard integration for Omarchy 4.x.

It adds a status dot beside the Network widget and a searchable location panel.
Green means the tunnel, default route, DNS, IPv6 policy, and recent WireGuard
handshake are verified. Amber means connecting, red means enabled but failed,
and a muted hollow dot means disabled or temporarily paused.

## Install

```bash
omarchy plugin add https://github.com/nicolasdorier/omarchy-torguard.git --enable
```

Click the new bar dot, choose **Install backend**, and authorize the Polkit
prompt. The installer adds `wireguard-tools`, a narrowly scoped root service,
and a dedicated nftables kill-switch table without changing UFW rules.

Use **Open generator** to sign in to TorGuard and create WireGuard profiles.
TorGuard's public generator is only confirmed to generate one location at a
time. Import any number of downloaded `.conf` files, a directory, or a ZIP;
the panel displays every imported city.

The panel is also available at **SUPER+SPACE → Setup → Network → TorGuard VPN**
and through the `torguard`, `vpn`, and `wireguard` search aliases.

## CLI

```bash
omarchy-torguard status
omarchy-torguard list
omarchy-torguard connect 'Japan/Tokyo'
omarchy-torguard disconnect
omarchy-torguard retry
omarchy-torguard pause 600
omarchy-torguard import ~/Downloads/tokyo.conf ~/Downloads/singapore.conf
omarchy-torguard diagnostics
```

If a backend failure leaves traffic blocked:

```bash
sudo omarchy-torguard emergency-disable
```

## Remove

```bash
sudo /usr/lib/omarchy-torguard/uninstall-backend "$USER"
omarchy plugin remove nicolasdorier.torguard
```

This removes plugin-owned profiles, services, firewall state, and menu
integration. It does not modify unrelated VPNs such as `alfred-vpn`.

## Security

The backend accepts requests only from root and the user selected at install.
WireGuard private keys remain in root-owned NetworkManager profiles. The kill
switch covers host, Docker, and VM traffic while allowing directly connected
LAN traffic, `.lan` split DNS, local discovery, TorGuard endpoints, and the
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

## Trademarks

This project is not affiliated with, sponsored by, or endorsed by TorGuard or
Omarchy. TorGuard and related marks belong to their respective owner.
"WireGuard" and the "WireGuard" logo are registered trademarks of Jason A.
Donenfeld.
