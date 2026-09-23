# Bounded real-network namespace evidence

Run as the ordinary user, **without sudo**:

```sh
cd /home/michael/Projects/omarchy-wireguard
python -B tests/network/run.py
```

Requires Python 3 stdlib, Linux user/network namespaces, `unshare`, `ip`, `wg`,
`nft`, and kernel veth/WireGuard/nftables support. No installs or elevation are
attempted. Each scenario has a 60-second supervisor deadline; commands have
5-second deadlines and peer RPCs have 6-second deadlines. Missing capabilities,
command errors, assertion failures, or a timeout return nonzero with evidence;
there is no mock fallback.

## Isolation and cleanup

`run.py` is a read-only host supervisor. It fingerprints `ip -j link show` and
IPv4/IPv6 routes in **all** tables before testing and after each scenario. It
never runs host `nft`, NetworkManager, resolved, or systemd commands. It first
checks that direct invocation of the harness in the host namespace is refused.

Each scenario starts with `unshare -Urn`. Before **every** `ip`/`wg`/`nft` command,
including commands made through the real backend adapter, the harness checks
that its netns differs from the recorded host netns, still matches its initially
verified netns, and its user namespace differs from the host with mapped UID 0.
It also requires that the initial top-level netns contains only `lo`.

One peer is created using a further `unshare -n`. Both ends of the veth start in
the isolated top-level namespace; only the peer end is moved to the descendant
peer. No host link is moved and there is no uplink to the actual network. No
named namespaces, bind mounts, or `/run/netns` entries are created. The peer is
terminated and reaped in `finally`; the supervisor also kills its own separately
created process group and verifies that the group no longer exists. Once these
processes exit, there are no harness-held references keeping the namespaces or
links alive. Normal exit and intentional failure are both exercised.

Synthetic WireGuard keys are generated in memory, transmitted only over private
process pipes, and never saved or printed. WireGuard command errors redact their
arguments/configuration. No real VPN profile or secret is opened. Python bytecode
writes are disabled. Evidence goes into a unique directory under `$TMPDIR`
(default `~/.hermes/cache/scratch`); `/tmp` is refused. Host snapshot files can
contain local network addressing; they stay in the private scratch directory.

## Actual topology

```text
isolated client namespace                  descendant peer namespace
  physical 192.0.2.1/24  ------ veth ------  wire 192.0.2.2/24
           2001:db8:1::1/64                      2001:db8:1::2/64
  wgtest   10.77.0.1/24 ===== WireGuard ===  wgpeer 10.77.0.2/24
                                           lo 198.51.100.80/32
                                              2001:db8:2::80/128
```

The peer serves real UDP echoes. Documentation-only addresses represent public
IPv4/IPv6 destinations: they are not in the client's connected LAN prefixes and
initially use its physical default routes. They never reach the real Internet.
Echoes return the actual receiving interface obtained with `IP_PKTINFO` or
`IPV6_PKTINFO`, and the peer separately records the unique payload token.

The selected IPv4 WireGuard default has a lower metric than the physical default.
The IPv6 physical default deliberately remains usable, representing an IPv4-only
VPN with potential IPv6 fallback. Removing the tunnel restores the IPv4 physical
default, so negative checks cannot succeed merely because there is no route.

The harness supplies a synthetic `FirewallContext`, imports the repository's
**actual `nftables.render()`**, validates it with `nft -c -f -`, and executes the
real `HostSystem.apply_firewall()` / `remove_firewall()` methods with a guarded
real-command runner. It does not reproduce the firewall rules in test code.

## Proven by the recorded execution

`observed-results.json` is a retained actual run against the working tree based on
commit `1995fce713c26b17ee61393e95eccc5c0f580cf5`, kernel `7.2.5-4-omarchy`.
The record includes exact backend source hashes; concurrent work on
`HostSystem.verify()` is separate from this harness and that method is not used:

- **39/39 checks passed** in the normal packet scenario.
- **10/10 setup checks passed**, followed by the expected injected exception
  after a live isolated firewall was installed.
- The direct host invocation was refused; both peer processes were reaped and
  both process groups were gone.
- Initial and post-scenario host link/route fingerprints were identical:
  `e19fc2e8ca30e3a058b3103216a7d04706ae016f72f1774df6621eee71481ed4`.

The packet assertions show:

1. IPv4/IPv6 default-path traffic really reaches the peer over `wire` before
   firewall application and again after firewall removal (positive controls).
2. Backend rules parse, install on first creation, replace successfully, and
   remove successfully. Replacement resets the installed output drop counter.
3. Enabling the firewall while the selected tunnel is absent blocks the same
   already-used IPv4/IPv6 UDP sockets/5-tuples. Each blocked probe must have no
   echo, no matching token at the peer, **and an increased backend drop counter**.
4. Explicit connected IPv4/IPv6 LAN exceptions intentionally remain reachable.
5. With the tunnel up, a payload reaches **`wgpeer`**, with a real nonzero
   WireGuard handshake timestamp and bidirectional kernel transfer counters.
6. Working physical IPv6 fallback is blocked while that IPv4-only VPN is up.
7. Removing LAN exemptions and recreating both WG devices/keys forces a fresh
   handshake; traffic still passes through WG using the backend's marked
   endpoint exception. Unmarked ordinary underlay traffic is blocked.
8. Deleting the client tunnel restores its physical IPv4 default but both
   IPv4/IPv6 public fallback probes are blocked; the LAN exception still works.
9. An invalid nft input containing a delete followed by a syntax error leaves
   the installed table unchanged and traffic remains blocked. This tests failed
   parsing, not a simulated arbitrary kernel/netlink transaction failure.
10. An intentional exception with the isolated firewall still installed does not
    change host links/routes and leaves no test process group behind.

The first development run exposed a **harness** assumption: Linux reports local
nft OUTPUT drops to UDP `send()` synchronously as `EPERM`, rather than always
silently timing out. The harness now accepts EPERM/EACCES as a candidate drop
only when its independent peer/counter checks also pass. No backend fix was
needed or made. The final execution completed with exit status 0.

## Deliberately NOT proven

This is **packet-level evidence for a subset, not full leak certification**.

- No actual NetworkManager activation/import/deactivation, systemd-resolved or
  DNS routing, controller state machine, daemon IPC, reboot, boot ordering,
  suspend/resume, reconnect races, or real provider connectivity is exercised.
- A veth represents the underlay; the context is explicitly supplied. Real
  `inspect_firewall_context()` discovery, physical interfaces, LAN-prefix
  validation, and actual IPv6 LAN discovery are **not** verified here.
- The tests exercise selected host OUTPUT UDP flows, not all ports/protocols,
  TCP, conntrack state assertions, forwarded Docker/VM traffic, bridges, NAT,
  policy-routing rules used by NetworkManager, or alfred-vpn coexistence.
- DNS/UID exceptions, DHCP/mDNS/SSDP/NDP exception semantics, malicious root
  marking packets, other firewall managers and competing nft tables are not
  comprehensively tested. Successful WG transfer without LAN exemptions proves
  the marked endpoint path, not every possible wrong-mark/wrong-port bypass.
- IPv6 underlay is tested, but IPv6-in-WireGuard and IPv6 WG endpoints are not.
- Tunnel absence/deletion is exercised; an interface remaining up with a dead
  remote peer, arbitrary packet loss, MTU issues and sustained leak/race testing
  are not.
- Host link/route identity and process cleanup are checked; the harness never
  reads the host firewall and does not claim a full host-state audit. Unrelated
  host route/link changes during a run cause a reported fingerprint failure.

Files: `run.py` (supervisor), `namespace_harness.py` (topology/probes),
`observed-results.json` (actual result, including backend source hashes), and this
README. No backend or QML source is changed, no deployment is performed, and no
commits are created.
