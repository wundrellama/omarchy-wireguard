import ipaddress
import re
from dataclasses import dataclass

from .constants import NFT_TABLE


class FirewallError(ValueError):
    pass


@dataclass(frozen=True)
class FirewallContext:
    tunnel_interface: str | None = None
    endpoints: tuple[tuple[str, int], ...] = ()
    torguard_fwmark: int | None = None
    lan_prefixes: tuple[str, ...] = ()
    lan_resolvers: tuple[str, ...] = ()
    resolver_uid: int | None = None
    alfred_interface: str | None = None
    alfred_endpoints: tuple[tuple[str, int], ...] = ()
    alfred_routes: tuple[str, ...] = ()
    physical_interfaces: tuple[str, ...] = ()
    local_interfaces: tuple[str, ...] = ()
    lan_dns_links: tuple[tuple[str, tuple[str, ...]], ...] = ()


def _interface(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", value):
        raise FirewallError("invalid interface")
    return value


def _addresses(values: tuple[str, ...], version: int | None = None) -> list[str]:
    result = []
    for value in values:
        address = ipaddress.ip_address(value)
        if version is None or address.version == version:
            result.append(str(address))
    return sorted(set(result))


def _networks(values: tuple[str, ...], version: int) -> list[str]:
    result = []
    for value in values:
        network = ipaddress.ip_network(value, strict=False)
        if network.version == version:
            result.append(str(network))
    return sorted(set(result))


def _set(values: list[str]) -> str:
    return "{ " + ", ".join(values) + " }"


def _endpoint(value: tuple[str, int]) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    host, port = value
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise FirewallError("invalid endpoint port")
    return ipaddress.ip_address(host), port


def render(context: FirewallContext) -> str:
    tunnel = _interface(context.tunnel_interface) if context.tunnel_interface else None
    alfred = _interface(context.alfred_interface) if context.alfred_interface else None
    physical = [_interface(item) for item in context.physical_interfaces]
    local = [_interface(item) for item in context.local_interfaces]
    endpoint4, endpoint6 = [], []
    alfred4, alfred6 = [], []
    for value in context.endpoints:
        address, port = _endpoint(value)
        (endpoint4 if address.version == 4 else endpoint6).append(f"{address} . {port}")
    for value in context.alfred_endpoints:
        address, port = _endpoint(value)
        (alfred4 if address.version == 4 else alfred6).append(f"{address} . {port}")
    if endpoint4 or endpoint6:
        if not physical:
            raise FirewallError("TorGuard endpoints require a verified physical interface")
        if (not isinstance(context.torguard_fwmark, int) or isinstance(context.torguard_fwmark, bool) or
                not 1 <= context.torguard_fwmark <= 0xFFFFFFFF):
            raise FirewallError("TorGuard endpoints require a dedicated fwmark")
    if (alfred4 or alfred6) and not physical:
        raise FirewallError("alfred-vpn endpoints require a verified physical interface")
    lan4 = _networks(context.lan_prefixes, 4)
    lan6 = _networks(context.lan_prefixes, 6)
    routes4 = _networks(context.alfred_routes, 4)
    routes6 = _networks(context.alfred_routes, 6)
    dns4 = _addresses(context.lan_resolvers, 4)
    dns6 = _addresses(context.lan_resolvers, 6)
    if (dns4 or dns6) and (not isinstance(context.resolver_uid, int) or context.resolver_uid < 0):
        raise FirewallError("LAN DNS requires an explicit resolver service UID")
    lines = [
        f"table inet {NFT_TABLE} {{",
        "  chain output {",
        "    type filter hook output priority -10; policy drop;",
        "    oifname \"lo\" accept",
    ]
    if tunnel:
        lines.append(f'    oifname "{tunnel}" accept comment "selected TorGuard tunnel"')
    lines += _output_underlay(physical, endpoint4, endpoint6, alfred4, alfred6, lan4, lan6,
                              dns4, dns6, context.resolver_uid, context.torguard_fwmark)
    if routes4 and alfred:
        lines.append(f'    oifname "{alfred}" ip daddr {_set(routes4)} accept')
    if routes6 and alfred:
        lines.append(f'    oifname "{alfred}" ip6 daddr {_set(routes6)} accept')
    lines += [
        "    counter drop comment \"TorGuard fail closed\"",
        "  }",
        "  chain forward {",
        "    type filter hook forward priority -10; policy drop;",
    ]
    if local:
        local_set = _set([f'"{item}"' for item in local])
        lines.append(f"    iifname {local_set} oifname {local_set} accept comment \"local bridge traffic\"")
        if lan4:
            lines += [
                f"    iifname {local_set} ip daddr {_set(lan4)} accept comment \"local guests to LAN\"",
                f"    oifname {local_set} ip saddr {_set(lan4)} ct state established,related accept",
            ]
        if lan6:
            lines += [
                f"    iifname {local_set} ip6 daddr {_set(lan6)} accept comment \"local guests to LAN\"",
                f"    oifname {local_set} ip6 saddr {_set(lan6)} ct state established,related accept",
            ]
    if tunnel:
        if local:
            local_set = _set([f'"{item}"' for item in local])
            lines += [f'    iifname {local_set} oifname "{tunnel}" accept',
                      f'    iifname "{tunnel}" oifname {local_set} ct state established,related accept']
    if alfred:
        if routes4:
            if local:
                lines += [f'    iifname {local_set} oifname "{alfred}" ip daddr {_set(routes4)} accept',
                          f'    iifname "{alfred}" oifname {local_set} ip saddr {_set(routes4)} ct state established,related accept']
        if routes6:
            if local:
                lines += [f'    iifname {local_set} oifname "{alfred}" ip6 daddr {_set(routes6)} accept',
                          f'    iifname "{alfred}" oifname {local_set} ip6 saddr {_set(routes6)} ct state established,related accept']
    lines += ["    counter drop comment \"protect Docker and VM forwarding\"", "  }", "}"]
    return "\n".join(lines) + "\n"


def _output_underlay(physical, endpoint4, endpoint6, alfred4, alfred6, lan4, lan6, dns4, dns6,
                     resolver_uid, torguard_fwmark):
    lines: list[str] = []
    quoted_physical = [f'"{item}"' for item in physical]
    devices = f"oifname {_set(quoted_physical)} " if physical else ""
    if endpoint4:
        lines.append(f"    meta mark {torguard_fwmark:#x} {devices}ip daddr . udp dport {_set(sorted(set(endpoint4)))} accept comment \"TorGuard endpoints\"")
    if endpoint6:
        lines.append(f"    meta mark {torguard_fwmark:#x} {devices}ip6 daddr . udp dport {_set(sorted(set(endpoint6)))} accept comment \"TorGuard endpoints\"")
    if alfred4:
        lines.append(f"    meta skuid 0 {devices}ip daddr . udp dport {_set(sorted(set(alfred4)))} accept comment \"alfred-vpn endpoints\"")
    if alfred6:
        lines.append(f"    meta skuid 0 {devices}ip6 daddr . udp dport {_set(sorted(set(alfred6)))} accept comment \"alfred-vpn endpoints\"")
    if lan4:
        lines.append(f"    {devices}ip daddr {_set(lan4)} accept comment \"directly connected LAN\"")
    if lan6:
        lines.append(f"    {devices}ip6 daddr {_set(lan6)} accept comment \"directly connected LAN\"")
    lines += [
        f"    {devices}udp sport 68 udp dport 67 accept comment \"DHCPv4\"",
        f"    {devices}udp sport 546 udp dport 547 accept comment \"DHCPv6\"",
        f"    {devices}ip daddr 224.0.0.251 udp dport 5353 accept comment \"mDNS\"",
        f"    {devices}ip6 daddr ff02::fb udp dport 5353 accept comment \"mDNS\"",
        f"    {devices}ip daddr 239.255.255.250 udp dport 1900 accept comment \"SSDP\"",
    ]
    if physical:
        lines.append(f"    {devices}ip6 daddr {{ fe80::/10, ff02::/16 }} icmpv6 type {{ nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }} accept comment \"IPv6 neighbor discovery\"")
    if dns4:
        lines.append(f"    meta skuid {resolver_uid} {devices}ip daddr {_set(dns4)} meta l4proto {{ tcp, udp }} th dport 53 accept comment \"resolved split .lan DNS\"")
    if dns6:
        lines.append(f"    meta skuid {resolver_uid} {devices}ip6 daddr {_set(dns6)} meta l4proto {{ tcp, udp }} th dport 53 accept comment \"resolved split .lan DNS\"")
    return lines
