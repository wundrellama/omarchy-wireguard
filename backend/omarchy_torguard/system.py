import json
import hashlib
import ipaddress
import os
import pwd
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, replace

from .constants import (NFT_TABLE, PROFILE_PREFIX, STALE_HANDSHAKE,
                        TORGUARD_DNS_PRIORITY, TORGUARD_FWMARK, TORGUARD_FWMARK_TEXT)
from .importer import Profile
from .nftables import FirewallContext, FirewallError, render


class SystemFailure(RuntimeError):
    pass


@dataclass(frozen=True)
class Verification:
    ok: bool
    checks: dict[str, bool]
    detail: str


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
        fd, path = tempfile.mkstemp(prefix="import-", suffix=".conf", dir="/run/omarchy-torguard")
        uuid = None
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                fd = -1
                stream.write(profile.config)
                stream.flush()
                os.fsync(stream.fileno())
            output = self.runner.run(["nmcli", "connection", "import", "type", "wireguard", "file", path])
            match = re.search(r"\(([0-9a-fA-F-]{36})\)", output)
            if not match:
                raise SystemFailure("NetworkManager did not return an imported UUID")
            uuid = match.group(1)
            interface = "otg-" + hashlib.sha256(connection_name.encode("ascii")).hexdigest()[:10]
            permissions = ""
            if self.controller_uid is not None:
                try:
                    permissions = "user:" + pwd.getpwuid(self.controller_uid).pw_name
                except KeyError as exc:
                    raise SystemFailure("controller UID has no account") from exc
            self.runner.run(["nmcli", "connection", "modify", "uuid", uuid,
                             "connection.id", connection_name,
                             "connection.interface-name", interface,
                             "connection.autoconnect", "no",
                             "connection.permissions", permissions,
                             "wireguard.fwmark", TORGUARD_FWMARK_TEXT,
                             "ipv4.never-default", "no",
                             "ipv4.dns-priority", str(TORGUARD_DNS_PRIORITY),
                             "ipv4.dns-search", "~."])
            return uuid
        except Exception:
            if uuid is not None:
                try:
                    self.delete_profile(uuid)
                except SystemFailure:
                    pass
            raise
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

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
                         "wireguard.fwmark", TORGUARD_FWMARK_TEXT,
                         "ipv4.dns-priority", str(TORGUARD_DNS_PRIORITY),
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

    def configure_lan_dns(self, context: FirewallContext, timeout: float = 10) -> FirewallContext:
        if not context.physical_interfaces:
            return context
        each = max(0.1, timeout / (len(context.physical_interfaces) * 3))
        resolvers = set(context.lan_resolvers)
        dns_links = []
        for interface in context.physical_interfaces:
            domains = _resolved_values(self.runner.run(["resolvectl", "domain", interface], timeout=each))
            updated = tuple(dict.fromkeys((*domains, "~lan")))
            self.runner.run(["resolvectl", "domain", interface, *updated], timeout=each)
            addresses = _resolved_addresses(self.runner.run(["resolvectl", "dns", interface], timeout=each))
            resolvers.update(addresses)
            dns_links.append((interface, addresses))
        return replace(context, lan_resolvers=tuple(sorted(resolvers)), lan_dns_links=tuple(dns_links))

    def configure_tunnel_dns(self, uuid: str, interface: str,
                             timeout: float = 10) -> tuple[str, ...]:
        if not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", uuid):
            raise SystemFailure("invalid NetworkManager profile UUID")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface):
            raise SystemFailure("invalid tunnel interface")
        each = max(0.1, timeout / 5)
        outputs = [
            self.runner.run(["nmcli", "-g", "ipv4.dns", "connection", "show", "uuid", uuid], timeout=each),
            self.runner.run(["nmcli", "-g", "ipv6.dns", "connection", "show", "uuid", uuid], timeout=each),
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

    def restore_lan_dns(self, timeout: float = 10) -> None:
        context = self.inspect_firewall_context(timeout)
        if not context.physical_interfaces:
            return
        each = max(0.1, timeout / (len(context.physical_interfaces) * 2))
        for interface in context.physical_interfaces:
            domains = tuple(value for value in _resolved_values(
                self.runner.run(["resolvectl", "domain", interface], timeout=each)) if value != "~lan")
            self.runner.run(["resolvectl", "domain", interface, *(domains or ("",))], timeout=each)

    def verify(self, uuid: str, interface: str, now: float | None = None, timeout: float = 10,
               firewall_context: FirewallContext | None = None) -> Verification:
        now = now if now is not None else time.time()
        expected_dns = dict(firewall_context.lan_dns_links) if firewall_context else {}
        expected_tunnel_dns = firewall_context.tunnel_dns if firewall_context else ()
        each = max(0.1, timeout / (9 + len(expected_dns) * 2))
        active = self.runner.run(["nmcli", "-g", "GENERAL.STATE,GENERAL.DEVICES", "connection", "show", "uuid", uuid], timeout=each)
        profile_ok = "activated" in active.lower() and interface in active
        mark_text = self.runner.run(["wg", "show", interface, "fwmark"], timeout=each).strip()
        try:
            fwmark_ok = int(mark_text, 0) == TORGUARD_FWMARK
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
                       "TorGuard fail closed" in firewall and output_drop and mark_match is not None and
                       int(mark_match.group(1), 0) == TORGUARD_FWMARK)
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
            lan_split = lan_split and "~lan" in domains and bool(expected_resolvers) and set(expected_resolvers) <= resolvers
        if firewall_context:
            discovered = {resolver for _physical, resolvers in expected_dns.items() for resolver in resolvers}
            lan_split = lan_split and set(firewall_context.lan_resolvers) <= discovered
        dns_ok = tunnel_dns and lan_split
        handshakes = self.runner.run(["wg", "show", interface, "latest-handshakes"], timeout=each)
        timestamps = [int(line.rsplit("\t", 1)[-1]) for line in handshakes.splitlines() if line.rsplit("\t", 1)[-1].isdigit()]
        handshake_ok = bool(timestamps) and max(timestamps) > 0 and now - max(timestamps) <= STALE_HANDSHAKE
        checks = {"profile_interface": profile_ok, "wireguard_fwmark": fwmark_ok,
                  "firewall_policy": firewall_ok, "ipv4_default": ipv4_ok,
                  "ipv6_tunneled_or_blocked": ipv6_tunnel or ipv6_blocked,
                  "split_dns": dns_ok, "handshake_fresh": handshake_ok}
        failed = [name for name, passed in checks.items() if not passed]
        return Verification(not failed, checks, "ok" if not failed else "failed: " + ", ".join(failed))


def _is_underlay(name: str, link: dict, local: set[str]) -> bool:
    kind = link.get("linkinfo", {}).get("info_kind", "")
    if kind in {"wireguard", "tun", "tap", "veth", "bridge", "vxlan", "gre", "gretap",
                "ipip", "sit", "xfrm", "macvlan", "macvtap"} or name in local:
        return False
    return re.match(r"^(?:wg|tun|tap|ppp|veth|docker|br-|virbr|tailscale|zt|zerotier|proton|nord|vpn|alfred|otg-)",
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
