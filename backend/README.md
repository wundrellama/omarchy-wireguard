# Privileged backend

See [../ARCHITECTURE.md](../ARCHITECTURE.md) for the complete runtime topology,
trust boundaries, state machine, networking policy, and failure behavior.

Install this directory at `/usr/lib/omarchy-wireguard/backend`, install the two
systemd units, and create `/etc/omarchy-wireguard/backend.conf` from the example.
Enable both units. The firewall unit must start before networking; the daemon
will refuse to run without an explicit numeric controller UID.

The control socket accepts one newline-terminated JSON object per connection:

```json
{"op":"status","args":{},"request_id":"opaque"}
```

Import accepts either a controller-owned, non-group/world-writable `path`, or
base64 `data` plus `name`.
Profiles must have one `Interface`, one `Peer`, DNS, an IPv4 default
`AllowedIPs` route, only supported keys, and no hooks. This does not guarantee
compatibility with profiles from every provider.
Ambiguous locations return `review_required`; resubmit with a `locations`
object keyed by source filename. Secrets are passed directly to NetworkManager
through mode-0600 temporary files and are not retained in backend metadata.

The optional import `network` object configures exact `lan_resolvers` and an
`alfred` object containing the literal `alfred-vpn` interface, IP/UDP endpoint
pairs, and routed prefixes. Hostnames and implicit routes are rejected. This
policy is persisted for the early-boot firewall; omitting it preserves the
existing policy.

Disabled and paused modes remove only the backend's nftables table. Enabled
connecting or failed modes retain fail-closed filtering. At boot, missing or
valid disabled state leaves direct networking available; malformed or unsafe
state is treated as enabled for safety.

Desktop notifications are exposed as a privacy-safe notification object in
`status` and `/var/lib/omarchy-wireguard/notification.json`. A user-session
client can translate it to the desktop's notification protocol without giving
the root service access to the user's session bus.
