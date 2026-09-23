import json
import hashlib
import ipaddress
import os
import pwd
import re
import subprocess
import base64
import configparser
import uuid as uuid_module

from .nm_import import publish_keyfile
import time
from dataclasses import dataclass, replace

from .constants import (NFT_TABLE, PROFILE_PREFIX, STALE_HANDSHAKE,
                         WIREGUARD_DNS_PRIORITY, WIREGUARD_FWMARK, WIREGUARD_FWMARK_TEXT)
from .importer import Profile
from .nftables import FirewallContext, FirewallError, render


class SystemFailure(RuntimeError):
    pass


@dataclass(frozen=True)
class Verification:
    ok: bool
    checks: dict[str, bool]
    detail: str


DnsRestoreState = tuple[tuple[str, tuple[str, ...], bool], ...]


def bootstrap_hostname(host: str | None) -> str | None:
    """Return a safe full DNS hostname, never an input routing-domain expression.

    resolved routes suffixes: descendants of this hostname also match. This is
    deliberately not a QNAME firewall. Numeric endpoints need no DNS exception.
    """
    if host is None:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if (not isinstance(host, str) or len(host) > 253 or '.' not in host or
            not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                    for label in host.split('.'))):
        raise SystemFailure("invalid endpoint bootstrap hostname")
    return host


class CommandRunner:
    def run(self, argv: list[str], *, stdin: str | None = None, timeout: float = 10) -> str:
        try:
            result = subprocess.run(
                argv, input=stdin, text=True, capture_output=True, timeout=timeout,
                check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SystemFailure(f"command unavailable or timed out: {argv[0]}") from exc
        if result.returncode:
            # stderr may contain configuration or endpoint details; never copy it to logs/API.
            raise SystemFailure(f"{argv[0]} failed with status {result.returncode}")
        return result.stdout


class HostSystem:
    def __init__(self, runner: CommandRunner | None = None, controller_uid: int | None = None):
        self.runner = runner or CommandRunner()
        self.controller_uid = controller_uid

    def import_profile(self, profile: Profile, connection_name: str) -> str:
        if not re.fullmatch(rf"{PROFILE_PREFIX}[a-z0-9-]+", connection_name):
            raise SystemFailure("invalid managed profile name")
        uuid = str(uuid_module.uuid4())
        # Refuse collisions before either publication or rollback. AddConnection2
        # adds, never updates: a catalog identity must never be reused/deleted.
        existing = self.runner.run(["nmcli", "-t", "-f", "UUID", "connection", "show"])
        if uuid in existing.splitlines():
            raise SystemFailure("NetworkManager profile UUID already exists")
        text = _profile_keyfile(profile, connection_name, uuid, self.controller_uid)
        try:
            publish_keyfile(text)
            actual = self.runner.run(["nmcli", "-g", "connection.id", "connection", "show", "uuid", uuid]).strip()
            if actual != connection_name:
                raise SystemFailure("NetworkManager profile identity verification failed")
            return uuid
        except Exception as exc:
            # A timed-out reply may follow a successful add. Delete only this
            # previously absent UUID, and only if its exact identity still matches.
            try:
                actual = self.runner.run(["nmcli", "-g", "connection.id", "connection", "show", "uuid", uuid]).strip()
                if actual == connection_name:
                    self.delete_profile(uuid)
            except SystemFailure:
                pass
            raise SystemFailure("NetworkManager profile import failed") from exc

    def managed_profiles(self) -> dict[str, str]:
        output = self.runner.run(["nmcli", "-t", "-f", "NAME,UUID", "connection", "show"])
        result = {}
        for line in output.splitlines():
            name, separator, uuid = line.rpartition(":")
            if separator and name.startswith(PROFILE_PREFIX):
                result[uuid] = name
        return result

    def delete_profile(self, uuid: str) -> None:
        self.runner.run(["nmcli", "connection", "delete", "uuid", uuid])

    def activate(self, uuid: str, timeout: float) -> str:
        deadline = time.monotonic() + timeout

        def remaining() -> float:
            value = deadline - time.monotonic()
            if value <= 0:
                raise SystemFailure("activation budget exhausted")
            return value

        # Reassert this on activation so profiles imported by an older backend cannot
        # retain negative priorities that suppress the physical split-DNS link.
        self.runner.run(["nmcli", "connection", "modify", "uuid", uuid,
                          "wireguard.fwmark", WIREGUARD_FWMARK_TEXT,
                          "ipv4.dns-priority", str(WIREGUARD_DNS_PRIORITY),
                         "ipv4.dns-search", "~."],
                        timeout=min(2, remaining()))
        activation_timeout = remaining()
        self.runner.run(["nmcli", "--wait", str(max(1, int(activation_timeout))),
                         "connection", "up", "uuid", uuid], timeout=activation_timeout)
        output = self.runner.run(["nmcli", "-g", "GENERAL.DEVICES", "connection", "show", "uuid", uuid],
                                 timeout=remaining())
        interface = output.strip().split(",", 1)[0]
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface):
            raise SystemFailure("NetworkManager returned no safe interface")
        return interface

    def deactivate_managed(self) -> None:
        output = self.runner.run(["nmcli", "-t", "-f", "NAME,UUID,TYPE", "connection", "show", "--active"])
        for line in output.splitlines():
            fields = line.rsplit(":", 2)
            if len(fields) == 3 and fields[0].startswith(PROFILE_PREFIX):
                self.runner.run(["nmcli", "connection", "down", "uuid", fields[1]])

    def resolve_endpoint(self, host: str, port: int, timeout: float = 10) -> tuple[tuple[str, int], ...]:
        try:
            return ((str(ipaddress.ip_address(host)), port),)
        except ValueError:
            pass
        try:
            output = self.runner.run(["getent", "ahosts", host], timeout=timeout)
            addresses = {line.split()[0] for line in output.splitlines() if line.split()}
            values = tuple(sorted((str(ipaddress.ip_address(item)), port) for item in addresses))
            if not values:
                raise ValueError
            return values
        except (OSError, ValueError, SystemFailure) as exc:
            raise SystemFailure("endpoint resolution failed") from exc

    def apply_firewall(self, context: FirewallContext, timeout: float = 10) -> None:
        try:
            rules = render(context)
        except FirewallError as exc:
            raise SystemFailure(str(exc)) from exc
        # A single nft input is one netlink transaction. Only our dedicated table is replaced.
        script = f"delete table inet {NFT_TABLE}\n" + rules
        try:
            self.runner.run(["nft", "-f", "-"], stdin=script, timeout=timeout)
        except SystemFailure:
            # First boot has no table to delete. The second transaction only creates our table.
            self.runner.run(["nft", "-f", "-"], stdin=rules, timeout=timeout)

    def remove_firewall(self, timeout: float = 10) -> None:
        tables = self.runner.run(["nft", "list", "tables"], timeout=timeout)
        if re.search(rf"^table inet {re.escape(NFT_TABLE)}$", tables, re.MULTILINE):
            self.runner.run(["nft", "delete", "table", "inet", NFT_TABLE], timeout=timeout)

    def inspect_firewall_context(self, timeout: float = 10) -> FirewallContext:
        each = max(0.1, timeout / 3)
        routes = json.loads(self.runner.run(["ip", "-json", "route", "show", "table", "main"], timeout=each))
        routes += json.loads(self.runner.run(["ip", "-6", "-json", "route", "show", "table", "main"], timeout=each))
        links = json.loads(self.runner.run(["ip", "-json", "link", "show"], timeout=each))
        bridges = {item.get("ifname") for item in links
                   if item.get("linkinfo", {}).get("info_kind") == "bridge" and item.get("ifname")}
        bridge_indexes = {item.get("ifindex") for item in links if item.get("ifname") in bridges}
        local = tuple(sorted({item["ifname"] for item in links if item.get("ifname") and
                              (item.get("ifname") in bridges or item.get("master") in bridges or
                               item.get("master") in bridge_indexes)}))
        link_by_name = {item.get("ifname"): item for item in links if item.get("ifname")}
        default_devices = {route.get("dev") for route in routes
                           if route.get("dst") == "default" and route.get("dev")}
        physical = {dev for dev in default_devices
                    if dev in link_by_name and _is_underlay(dev, link_by_name[dev], set(local))}
        lan = {route["dst"] for route in routes
               if route.get("dev") in physical and route.get("scope") == "link" and
               route.get("dst") not in (None, "default")}
        # DNS is intentionally empty until discovered from these verified underlays.
        try:
            resolver_uid = pwd.getpwnam("systemd-resolve").pw_uid
        except KeyError:
            resolver_uid = None
        return FirewallContext(lan_prefixes=tuple(sorted(lan)), physical_interfaces=tuple(sorted(physical)),
                               local_interfaces=local, resolver_uid=resolver_uid)

    def capture_lan_dns(self, interfaces: tuple[str, ...], timeout: float = 10) -> DnsRestoreState:
        if not interfaces:
            return ()
        if len(interfaces) > 16:
            raise SystemFailure("too many physical DNS links")
        each = max(0.1, timeout / (len(interfaces) * 2))
        state = []
        for interface in interfaces:
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface):
                raise SystemFailure("invalid physical interface")
            domains = _resolved_values(
                self.runner.run(["resolvectl", "domain", interface], timeout=each))
            if len(domains) > 32 or any(len(domain) > 255 for domain in domains):
                raise SystemFailure("physical DNS domain state is too large")
            default_route = _resolved_default_route(
                self.runner.run(["resolvectl", "default-route", interface], timeout=each))
            if default_route is None:
                raise SystemFailure("resolved returned invalid default-route state")
            state.append((interface, domains, default_route))
        return tuple(state)

    def configure_lan_dns(self, context: FirewallContext, timeout: float = 10,
                          *, endpoint_host: str | None = None) -> FirewallContext:
        hostname = bootstrap_hostname(endpoint_host)
        domains = ("~lan",) + (("~" + hostname,) if hostname else ())
        if not context.physical_interfaces:
            return context
        each = max(0.1, timeout / (len(context.physical_interfaces) * 3))
        resolvers = set(context.lan_resolvers)
        dns_links = []
        for interface in context.physical_interfaces:
            self.runner.run(["resolvectl", "domain", interface, *domains], timeout=each)
            self.runner.run(["resolvectl", "default-route", interface, "no"], timeout=each)
            addresses = _resolved_addresses(self.runner.run(["resolvectl", "dns", interface], timeout=each))
            resolvers.update(addresses)
            dns_links.append((interface, addresses))
        if hostname and not any(addresses for _interface, addresses in dns_links):
            raise SystemFailure("no physical DNS for endpoint bootstrap")
        return replace(context, lan_resolvers=tuple(sorted(resolvers)), lan_dns_links=tuple(dns_links))

    def configure_tunnel_dns(self, uuid: str, interface: str,
                             timeout: float = 10) -> tuple[str, ...]:
        if not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", uuid):
            raise SystemFailure("invalid NetworkManager profile UUID")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface):
            raise SystemFailure("invalid tunnel interface")
        each = max(0.1, timeout / 5)
        outputs = [
            self.runner.run(["nmcli", "--escape", "no", "-g", "ipv4.dns", "connection", "show", "uuid", uuid], timeout=each),
            self.runner.run(["nmcli", "--escape", "no", "-g", "ipv6.dns", "connection", "show", "uuid", uuid], timeout=each),
        ]
        servers = []
        for output in outputs:
            for token in re.split(r"[,\s]+", output.strip()):
                if not token or token == "--":
                    continue
                try:
                    servers.append(str(ipaddress.ip_address(token)))
                except ValueError as exc:
                    raise SystemFailure("NetworkManager profile contains invalid DNS") from exc
        servers = sorted(set(servers))
        if not servers:
            raise SystemFailure("NetworkManager profile has no tunnel DNS")
        self.runner.run(["resolvectl", "dns", interface, *servers], timeout=each)
        self.runner.run(["resolvectl", "domain", interface, "~."], timeout=each)
        self.runner.run(["resolvectl", "default-route", interface, "yes"], timeout=each)
        return tuple(servers)

    def clear_tunnel_dns(self, interface: str, timeout: float = 10) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface):
            raise SystemFailure("invalid tunnel interface")
        self.runner.run(["resolvectl", "revert", interface], timeout=timeout)

    def restore_lan_dns(self, state: DnsRestoreState, timeout: float = 10) -> None:
        if not state:
            return
        links = json.loads(self.runner.run(["ip", "-json", "link", "show"], timeout=timeout))
        existing = {link.get("ifname") for link in links}
        active = [item for item in state if item[0] in existing]
        if not active:
            return
        each = max(0.1, timeout / (len(active) * 2))
        failed = False
        for interface, domains, default_route in active:
            for command in (
                    ["resolvectl", "domain", interface, *(domains or ("",))],
                    ["resolvectl", "default-route", interface,
                     "yes" if default_route else "no"]):
                try:
                    self.runner.run(command, timeout=each)
                except SystemFailure:
                    failed = True
        if failed:
            raise SystemFailure("could not restore physical DNS settings")

    def verify(self, uuid: str, interface: str, now: float | None = None, timeout: float = 10,
               firewall_context: FirewallContext | None = None) -> Verification:
        now = now if now is not None else time.time()
        expected_dns = dict(firewall_context.lan_dns_links) if firewall_context else {}
        expected_tunnel_dns = firewall_context.tunnel_dns if firewall_context else ()
        each = max(0.1, timeout / (9 + len(expected_dns) * 3))
        active = self.runner.run(["nmcli", "-g", "GENERAL.STATE,GENERAL.DEVICES", "connection", "show", "uuid", uuid], timeout=each)
        active_fields = active.strip().splitlines()
        profile_ok = (len(active_fields) == 2 and active_fields[0].strip() == "activated"
                      and active_fields[1].strip() == interface)
        mark_text = self.runner.run(["wg", "show", interface, "fwmark"], timeout=each).strip()
        try:
            fwmark_ok = int(mark_text, 0) == WIREGUARD_FWMARK
        except ValueError:
            fwmark_ok = False
        route4 = json.loads(self.runner.run(["ip", "-json", "route", "get", "1.1.1.1"], timeout=each))
        ipv4_ok = bool(route4) and route4[0].get("dev") == interface
        try:
            route6 = json.loads(self.runner.run(
                ["ip", "-6", "-json", "route", "get", "2606:4700:4700::1111"], timeout=each))
        except SystemFailure:
            route6 = []
        ipv6_tunnel = bool(route6) and route6[0].get("dev") == interface
        firewall = self.runner.run(["nft", "list", "table", "inet", NFT_TABLE], timeout=each)
        output_drop = re.search(r"chain output\s*\{.*?hook output.*?policy drop", firewall,
                                re.DOTALL) is not None
        mark_match = re.search(r"meta mark (0x[0-9a-fA-F]+|[0-9]+)", firewall)
        firewall_ok = (f"table inet {NFT_TABLE}" in firewall and
                       "WireGuard fail closed" in firewall and output_drop and mark_match is not None and
                       int(mark_match.group(1), 0) == WIREGUARD_FWMARK)
        ipv6_blocked = firewall_ok
        tunnel_servers = set(_resolved_addresses(
            self.runner.run(["resolvectl", "dns", interface], timeout=each)))
        tunnel_domains = _resolved_values(
            self.runner.run(["resolvectl", "domain", interface], timeout=each))
        tunnel_dns = bool(expected_tunnel_dns) and set(expected_tunnel_dns) <= tunnel_servers and "~." in tunnel_domains
        lan_split = bool(expected_dns)
        for physical, expected_resolvers in expected_dns.items():
            domains = _resolved_values(self.runner.run(["resolvectl", "domain", physical], timeout=each))
            resolvers = set(_resolved_addresses(
                self.runner.run(["resolvectl", "dns", physical], timeout=each)))
            default_route = _resolved_default_route(
                self.runner.run(["resolvectl", "default-route", physical], timeout=each))
            lan_split = (lan_split and domains == ("~lan",) and default_route is False and
                         bool(expected_resolvers) and set(expected_resolvers) == resolvers)
        if firewall_context:
            discovered = {resolver for _physical, resolvers in expected_dns.items() for resolver in resolvers}
            lan_split = lan_split and set(firewall_context.lan_resolvers) <= discovered
        dns_ok = tunnel_dns and lan_split
        handshakes = self.runner.run(["wg", "show", interface, "latest-handshakes"], timeout=each)
        timestamps = [int(line.rsplit("\t", 1)[-1]) for line in handshakes.splitlines() if line.rsplit("\t", 1)[-1].isdigit()]
        handshake_ok = bool(timestamps) and max(timestamps) > 0 and 0 <= now - max(timestamps) <= STALE_HANDSHAKE
        checks = {"profile_interface": profile_ok, "wireguard_fwmark": fwmark_ok,
                  "firewall_policy": firewall_ok, "ipv4_default": ipv4_ok,
                  "ipv6_tunneled_or_blocked": ipv6_tunnel or ipv6_blocked,
                  "split_dns": dns_ok, "handshake_fresh": handshake_ok}
        failed = [name for name, passed in checks.items() if not passed]
        return Verification(not failed, checks, "ok" if not failed else "failed: " + ", ".join(failed))


def _profile_keyfile(profile: Profile, name: str, uuid: str, uid: int | None) -> str:
    """Translate the validated WG subset, keeping secrets off argv and disk."""
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(profile.config)
        wg, peer = parser["Interface"], parser["Peer"]
        # Validate base64 before using a public key as a keyfile section name.
        for key in (wg["PrivateKey"], peer["PublicKey"], peer.get("PresharedKey")):
            if key is not None and len(base64.b64decode(key, validate=True)) != 32:
                raise ValueError("invalid key length")
        addresses = [ipaddress.ip_interface(v.strip()) for v in wg["Address"].split(",")]
        dns = [ipaddress.ip_address(v.strip()) for v in wg["DNS"].split(",")]
        allowed = [str(ipaddress.ip_network(v.strip(), strict=False))
                   for v in peer["AllowedIPs"].split(",") if v.strip()]
        permissions = ""
        if uid is not None:
            user = pwd.getpwuid(uid).pw_name
            if not re.fullmatch(r"[A-Za-z0-9_.@$-]+", user):
                raise ValueError("unsafe account name")
            permissions = "user:" + user + ":;"
        interface = "owg-" + hashlib.sha256(name.encode("ascii")).hexdigest()[:10]
        lines = ["[connection]", f"id={name}", f"uuid={uuid}", "type=wireguard",
                 "autoconnect=false", f"interface-name={interface}", f"permissions={permissions}",
                 "", "[wireguard]", f"private-key={wg['PrivateKey']}", "private-key-flags=0",
                 f"fwmark={WIREGUARD_FWMARK}", "peer-routes=true"]
        # libnm's keyfile reader can silently discard out-of-range values.
        # MTU is a guint32 (zero selects the default); listen-port is uint16.
        for source, target, maximum in (("ListenPort", "listen-port", 65535),
                                        ("MTU", "mtu", 4294967295)):
            if source in wg:
                value = int(wg[source])
                if not 0 <= value <= maximum:
                    raise ValueError("numeric setting out of range")
                lines.append(f"{target}={value}")
        keepalive = int(peer.get('PersistentKeepalive', '0'))
        if not 0 <= keepalive <= 65535:
            raise ValueError("persistent keepalive out of range")
        lines += ["", f"[wireguard-peer.{peer['PublicKey']}]",
                  f"endpoint={peer['Endpoint']}",
                  f"persistent-keepalive={keepalive}",
                  "allowed-ips=" + ";".join(allowed) + ";"]
        if "PresharedKey" in peer:
            lines += [f"preshared-key={peer['PresharedKey']}", "preshared-key-flags=0"]
        for version in (4, 6):
            family_addresses = [str(v) for v in addresses if v.version == version]
            family_dns = [str(v) for v in dns if v.version == version]
            method = "manual" if family_addresses else ("auto" if family_dns else "disabled")
            lines += ["", f"[ipv{version}]", f"method={method}", "never-default=false",
                      "ignore-auto-dns=true", f"dns-priority={WIREGUARD_DNS_PRIORITY}"]
            if method != "disabled":
                lines.append("dns-search=~.;")
            lines += [f"address{i}={v}" for i, v in enumerate(family_addresses, 1)]
            if family_dns:
                lines.append("dns=" + ";".join(family_dns) + ";")
        return "\n".join(lines) + "\n"
    except (KeyError, ValueError, configparser.Error) as exc:
        raise SystemFailure("invalid WireGuard profile settings") from exc


def _is_underlay(name: str, link: dict, local: set[str]) -> bool:
    kind = link.get("linkinfo", {}).get("info_kind", "")
    if kind in {"wireguard", "tun", "tap", "veth", "bridge", "vxlan", "gre", "gretap",
                "ipip", "sit", "xfrm", "macvlan", "macvtap"} or name in local:
        return False
    return re.match(r"^(?:wg|tun|tap|ppp|veth|docker|br-|virbr|tailscale|zt|zerotier|proton|nord|vpn|alfred|owg-)",
                    name, re.IGNORECASE) is None


def _resolved_values(output: str) -> tuple[str, ...]:
    _prefix, separator, values = output.partition(":")
    if not separator:
        return ()
    return tuple(value for value in values.split() if value.lower() not in {"none", "n/a"})


def _resolved_addresses(output: str) -> tuple[str, ...]:
    result = []
    for token in _resolved_values(output):
        try:
            result.append(str(ipaddress.ip_address(token.split("%", 1)[0])))
        except ValueError:
            continue
    return tuple(sorted(set(result)))


def _resolved_default_route(output: str) -> bool | None:
    values = _resolved_values(output)
    if len(values) != 1 or values[0].lower() not in {"yes", "no"}:
        return None
    return values[0].lower() == "yes"
