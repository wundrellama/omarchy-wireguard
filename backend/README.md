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

Import accepts either one open regular-file descriptor passed with `SCM_RIGHTS`
using `{"source":"fd","name":"..."}`, or base64 `data` plus `name`. Pathname
imports are rejected so the privileged backend never resolves an untrusted path.
Profiles must have one `Interface`, one `Peer`, DNS, an IPv4 default
`AllowedIPs` route, only supported keys, and no hooks. This does not guarantee
compatibility with profiles from every provider.
Ambiguous locations return `review_required`; resubmit with a `locations` object keyed by source filename, or supply a `labels` object for named personal profiles. A label permits missing geography but does not permit split-tunnel routes. Labels must be nonempty printable text of at most 128 characters.

Imports are additive. Duplicate source names within a batch or against the catalog are rejected before any NetworkManager changes. Existing profiles and active connections are preserved. New profiles are staged, then the combined catalog is persisted before publication in memory. Pre-commit failure cleans up only the new profiles; incomplete cleanup is reported. A post-rename durability error is reported as committed-but-unconfirmed and does not delete profiles referenced by the catalog. NetworkManager and filesystem changes are not crash-atomic; orphan reconciliation is a follow-up.

`list` includes a flat `profiles` array with stable IDs, labels and the `internet-exit` role, alongside legacy `cities`. `connect` accepts exactly one of `{"profile":"<id>"}` or `{"city":"Country/City"}`. Exact-profile selection persists as `profile:<id>` and never falls back to another profile in that city. `status.target_profile` describes an exact-profile target. Update, replacement, removal and private-network roles are not supported yet.

Secrets are passed directly to NetworkManager through mode-0600 temporary files and are not retained in backend metadata.

The optional import `network` object configures exact `lan_resolvers` and an
`alfred` object containing the literal `alfred-vpn` interface, IP/UDP endpoint
pairs, and routed prefixes. Hostnames and implicit routes are rejected. This
policy is persisted for the early-boot firewall; omitting it preserves the existing policy. A differing policy is rejected before import effects whenever VPN intent is enabled (including connecting, failed and paused states). Disconnect first to change network policy; additive imports must not acknowledge a policy that the active firewall has not adopted.

Disabled and paused modes remove only the backend's nftables table. Enabled
connecting or failed modes retain fail-closed filtering. At boot, missing or
valid disabled state leaves direct networking available; malformed or unsafe
state is treated as enabled for safety.

Desktop notifications are exposed as a privacy-safe notification object in
`status` and `/var/lib/omarchy-wireguard/notification.json`. A user-session
client can translate it to the desktop's notification protocol without giving
the root service access to the user's session bus.
