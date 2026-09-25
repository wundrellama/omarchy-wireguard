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
- Has one search field. The results change while you type. They show the countries (name or code), the cities, and the servers that match, for example `US-CA#3`, `los angeles`, or `tor`. Select a result to connect, or press Enter to connect the first result. A search shows a maximum of 30 results.
- Shows one button near the top of the panel for the last connection. See [Quick connect button](#quick-connect-button).
- Shows **Copy diagnostics** in **BACKEND MAINTENANCE**, at the bottom of the panel.
- Shows the server, location, load, protocol, and traffic rates for the Proton tunnel.

The panel checks each value before it runs a command:

| Value | Rule |
| --- | --- |
| Country code | Two capital letters. |
| Server name | The Proton name format, for example `IT#23`, `CH-US#1`, `US-CA#148`, or `FR#13-TOR`. |
| City | Letters, digits, spaces, and `. , ' ( ) -`. It must not start with `-`. The maximum is 64 characters. |

The panel sends each value as a separate command argument. It does not use a shell. If `protonvpn` fails, the panel shows the error message from Proton.

## Server search data

The official client keeps its server list in `~/.cache/Proton/VPN/serverlist.json` (or `$XDG_CACHE_HOME/Proton/VPN/serverlist.json`). This file is large, about 24 MB. The panel does not read it. The helper `plugin/proton_servers.py` reads it one time for each session, and again when you select **Refresh**. The helper only reads the file. It does not run `protonvpn`, and it does not write files.

The helper keeps a server only if all of these are true:

- `Status` is 1 (the server is available).
- `Tier` is not more than the `MaxTier` value in the file.
- The name, country code, and load are correct.

For each server, the helper gives the name, exit country, city, features, load, and tier. The feature names come from the `Features` bit field. The bit values are the same as `ServerFeatureEnum` in the installed Proton library: 1 is Secure Core, 2 is Tor, 4 is P2P, 8 is streaming, and 16 is IPv6.

If the file is missing, too large (more than 64 MB), or not in the correct format, the helper gives an error. Then the search shows only countries and the cities that the panel loaded. The panel checks each server name again before it can connect.

## Quick connect button

The panel shows one large button near the top.

| VPN status | Button |
| --- | --- |
| No VPN is active. | **Connect: <last>**, for example **Connect: Home**, **Connect: Proton US-CA#370**, **Connect: Proton Fastest**, **Connect: Proton Switzerland**, or **Connect: Proton Los Angeles**. |
| WireGuard is active, connecting, or failed. | **Disconnect <profile>**, for example **Disconnect Home**. |
| Proton VPN is connected or connecting. This includes a connection that you started outside the panel. | **Disconnect Proton VPN**. |
| Both VPNs are active. | **Conflict: both VPNs are active**. The button is disabled. Use the separate disconnect controls. |
| A status is unknown. | **VPN status unknown**. The button is disabled. |
| A switch is in progress. | **Switching VPN**. The button is disabled. |

The button uses the usual connect and disconnect paths. If the other VPN is active, you must confirm the switch.

The panel records a connection only after it is successful:

- WireGuard: when a status check shows that the profile is connected.
- Proton VPN: when `protonvpn connect` completes without an error.

The record is in `$XDG_STATE_HOME/wundrellama-wireguard/last-connection.json` (default `~/.local/state`). The directory mode is 0700 and the file mode is 0600. The helper `plugin/last_connection.py` writes a temporary file and then renames it. The record has only the kind, the value, and the display name, for example `{"version": 1, "kind": "server", "value": "US-CA#370", "label": "US-CA#370"}`. It has no account data.

The panel checks the record with the same rules that it uses to connect. A WireGuard profile must be in the current profile list. If the record is missing or not correct, the button uses:

1. The most recent WireGuard profile from the backend.
2. Proton Fastest, if Proton VPN is installed and you are signed in.

If none of these is available, the panel does not show the button.

## Status and shield

A NetworkManager check runs every few seconds. It finds the Proton tunnel: exactly one active `wireguard` connection named `ProtonVPN <server>` on the device `proton0`. The slower `protonvpn status` command runs every 5 seconds while the panel is open, and every 10 seconds when it is closed. It adds the location, load, and protocol.

- A Proton connection shows a green check-shield only after NetworkManager and `protonvpn status` independently report the same connection and WireGuard is freshly observed absent. An operational connection without those checks stays red and is labeled **protection not verified**.
- A Proton connection or disconnection in progress shows an amber shield.
- A Proton error shows a red shield.
- If WireGuard and Proton VPN both report active, the shield is red and the panel reports a conflict. This can occur if you connect Proton VPN outside the panel.
- Missing, failed, stale, or contradictory evidence is never shown as protected. If NetworkManager still proves that a Proton tunnel is operational, the shield is red and labeled **protection not verified**; otherwise status is unknown and muted.
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

- Profiles and a list of recent connections. (The panel keeps only the last connection.)
- Proton settings changes, port forwarding, split tunneling, and Always On.
- The world map and the traffic graph.

Keep the omaproton-vpn plugin installed until this plugin has the features that you need.

## Tests

- `tests/plugin/proton.test.js`: output parsers, value checks, command arguments, status, and shield states.
- `tests/plugin/service-switch.test.js`: switching in both directions, failure stops, and stale results.
- `tests/plugin/proton-panel.test.js`: panel bindings, confirmation, and fixtures without Proton fields.
- `tests/plugin/quick-connect.test.js`: the quick connect button in each state, the last connection record, the search, and the panel order.
- `tests/plugin/test_proton_servers.py`: the server list helper with synthetic files, including files that are not correct.
- `tests/plugin/test_last_connection.py`: the last connection helper, file modes, and records that are not correct.
- `tests/plugin/test_traffic.py`: the Proton traffic mode.
- `tests/plugin/proton-offscreen.py`: the real service in offscreen Quickshell with synthetic `omarchy-wireguard`, `protonvpn`, and `nmcli` commands.
