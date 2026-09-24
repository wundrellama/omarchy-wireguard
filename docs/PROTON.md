# Proton VPN

This is the first version of the Proton VPN adapter. It uses the official Proton VPN command-line client (`protonvpn`, proton-vpn-cli 1.0.3) in your user session. The root WireGuard backend does not change.

## What the first version does

- Shows the Proton sign-in state: signed in, signed out, unknown, or command not installed.
- Opens Proton's own interactive sign-in in a floating terminal. You type your user name, password, and two-factor code into Proton's client. The plugin does not receive them, and the root backend does not receive them.
- Connects with these options:
  - Fastest, Random, Fastest P2P, Secure Core, and Tor.
  - The fastest server in a country. The country list comes from `protonvpn countries list`. The panel keeps the list until the shell restarts. Select **Refresh** to load it again.
  - The fastest server in a city. The panel loads the cities for a country when you expand it.
  - A server name, such as `IT#23` or `CH-US#1`.
- Disconnects.
- Shows the server, location, load, protocol, and traffic rates for the Proton tunnel.

The panel checks each value before it runs a command:

| Value | Rule |
| --- | --- |
| Country code | Two capital letters. |
| Server name | The Proton name format, for example `IT#23`, `CH-US#1`, `US-CA#148`, or `FR#13-TOR`. |
| City | Letters, digits, spaces, and `. , ' ( ) -`. It must not start with `-`. The maximum is 64 characters. |

The panel sends each value as a separate command argument. It does not use a shell. If `protonvpn` fails, the panel shows the error message from Proton.

## Status and shield

A NetworkManager check runs every few seconds. It finds the Proton tunnel: exactly one active `wireguard` connection named `ProtonVPN <server>` on the device `proton0`. The slower `protonvpn status` command runs every 5 seconds while the panel is open, and every 60 seconds when it is closed. It adds the location, load, and protocol.

- A Proton connection shows a green check-shield. The WireGuard backend must report disabled or not installed. If the WireGuard status is unknown, the shield stays muted.
- A Proton connection or disconnection in progress shows an amber shield.
- A Proton error shows a red shield.
- If WireGuard and Proton VPN both report active, the shield is red and the panel reports a conflict. This can occur if you connect Proton VPN outside the panel.
- A missing, failed, stale, or contradictory observation is unknown. Unknown is never shown as protected.
- If `protonvpn` cannot start, the panel shows "Could not run protonvpn" and the status becomes unknown.

The traffic sampler has a separate Proton mode. It reads only the `proton0` counters, and only when exactly one active connection matches the name, type, and device. It never uses other tunnels as a fallback.

## Switching between VPNs

The panel runs one VPN at a time. It does not start two connections at the same time. When you select an option for the other VPN, the panel asks you to confirm. During the switch, **traffic uses your regular connection** for a few seconds, and possibly up to about a minute.

WireGuard to Proton VPN:

1. The panel runs `omarchy-wireguard disconnect`. This also removes the WireGuard firewall, which blocks Proton traffic.
2. The panel waits until a new WireGuard status reports disabled.
3. The panel runs `protonvpn connect` with your choice.

If the WireGuard disconnect fails, or WireGuard does not report disabled within 30 seconds, the panel stops. It does not start Proton VPN.

Proton VPN to WireGuard:

1. The panel reads `protonvpn config list`. If the Proton kill switch is not `off`, the panel stops and tells you to disconnect Proton VPN or set its kill switch to `off`.
2. The panel runs `protonvpn disconnect`.
3. The panel waits until new checks show that the Proton tunnel is gone and `protonvpn status` reports `Disconnected`.
4. The panel connects the WireGuard profile.

Each switch has a limit of 150 seconds. After this limit, the panel stops the switch and shows an error. A late result from a stopped switch does not start a VPN. Each `omarchy-wireguard` command has a limit of 120 seconds.

## Troubleshooting

If a Proton connect fails, look in the NetworkManager journal:

```bash
journalctl -u NetworkManager --since -10min | grep -i proton
```

The message `Activation failed because the device is unmanaged` means that a local NetworkManager rule ignores WireGuard devices. The plugin does not install this rule. Add an exception for `proton0` to the `unmanaged-devices` setting, for example:

```ini
[keyfile]
unmanaged-devices=type:wireguard;except:interface-name:owg-*;except:interface-name:proton0
```

Then reload NetworkManager with `sudo systemctl reload NetworkManager`. A reload does not stop your active connections.

## Limits

- The first version does not coordinate the Proton kill switch with the WireGuard firewall. It does not change Proton settings.
- The switch is not leak-free. It has the unprotected period described above.
- Automated tests use synthetic commands. They do not test a real Proton connection.

## Deferred

These features are not in the first version:

- Profiles and recent connections.
- Proton settings changes, port forwarding, split tunneling, and Always On.
- The world map and the traffic graph.

Keep the omaproton-vpn plugin installed until this plugin has the features that you need.

## Tests

- `tests/plugin/proton.test.js`: output parsers, value checks, command arguments, status, and shield states.
- `tests/plugin/service-switch.test.js`: switching in both directions, failure stops, and stale results.
- `tests/plugin/proton-panel.test.js`: panel bindings, confirmation, and fixtures without Proton fields.
- `tests/plugin/test_traffic.py`: the Proton traffic mode.
- `tests/plugin/proton-offscreen.py`: the real service in offscreen Quickshell with synthetic `omarchy-wireguard`, `protonvpn`, and `nmcli` commands.
