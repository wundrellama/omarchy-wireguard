import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass

from .constants import NFT_TABLE


class FirewallError(ValueError):
    pass


@dataclass(frozen=True)
class FirewallContext:
    tunnel_interface: str | None = None
    endpoints: tuple[tuple[str, int], ...] = ()
    wireguard_fwmark: int | None = None
    lan_prefixes: tuple[str, ...] = ()
    lan_resolvers: tuple[str, ...] = ()
    resolver_uid: int | None = None
    alfred_interface: str | None = None
    alfred_endpoints: tuple[tuple[str, int], ...] = ()
    alfred_routes: tuple[str, ...] = ()
    physical_interfaces: tuple[str, ...] = ()
    local_interfaces: tuple[str, ...] = ()
    lan_dns_links: tuple[tuple[str, tuple[str, ...]], ...] = ()
    tunnel_dns: tuple[str, ...] = ()


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


def _trusted_networks(values: tuple[str, ...], version: int, *, lan: bool) -> list[str]:
    if version == 4:
        allowed = [
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
        ]
        if lan:
            allowed.append(ipaddress.IPv4Network("169.254.0.0/16"))
        networks = [ipaddress.IPv4Network(value, strict=False) for value in values
                    if ipaddress.ip_network(value, strict=False).version == 4]
    else:
        allowed = [ipaddress.IPv6Network("fc00::/7")]
        if lan:
            allowed.append(ipaddress.IPv6Network("fe80::/10"))
        networks = [ipaddress.IPv6Network(value, strict=False) for value in values
                    if ipaddress.ip_network(value, strict=False).version == 6]
    result = []
    for network in networks:
        if not any(network.subnet_of(item) for item in allowed):
            raise FirewallError("LAN prefix is not a trusted private or link-local network"
                                if lan else "alfred-vpn route is not private")
        result.append(str(network))
    return sorted(set(result))


def _set(values: list[str]) -> str:
    return "{ " + ", ".join(values) + " }"


def _endpoint(value: tuple[str, int]) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    host, port = value
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise FirewallError("invalid endpoint port")
    return ipaddress.ip_address(host), port


def _sign_rules(lines: list[str]) -> str:
    chain = ""
    signed = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("chain ") and stripped.endswith("{"):
            chain = stripped.split()[1]
        if line.startswith("    ") and not stripped.startswith("type filter"):
            match = re.search(r' comment "([^"]*)"$', line)
            description = match.group(1) if match else "rule"
            body = line[:match.start()] if match else line
            digest = hashlib.sha256(f"{chain}:{body.strip()}".encode()).hexdigest()[:16]
            line = f'{body} comment "owg:{digest}:{description}"'
        signed.append(line)
    return "\n".join(signed) + "\n"


def _signed_rules(rules: str) -> list[tuple[str, str]]:
    result = []
    chain = ""
    for line in rules.splitlines():
        stripped = line.strip()
        if stripped.startswith("chain ") and stripped.endswith("{"):
            chain = stripped.split()[1]
        match = re.search(r'comment "(owg:[^"]+)"', line)
        if match:
            result.append((chain, match.group(1)))
    return result


def _normalize_policy_item(kind: str, item: object) -> tuple[str, object]:
    if not isinstance(item, dict):
        raise ValueError("policy item must be an object")
    value = json.loads(json.dumps(item))
    value.pop("handle", None)
    value.pop("index", None)
    if kind == "rule":
        expressions = value.get("expr")
        if not isinstance(expressions, list) or not expressions:
            raise ValueError("rule expressions are required")
        for expression in expressions:
            if isinstance(expression, dict) and isinstance(expression.get("counter"), dict):
                expression["counter"]["packets"] = 0
                expression["counter"]["bytes"] = 0
    return kind, value


def expected_policy_from_echo(echoed: str) -> tuple[tuple[str, object], ...]:
    """Normalize nft --json --echo output from the rules actually applied."""
    value = json.loads(echoed)
    entries = value.get("nftables")
    if not isinstance(entries, list):
        raise ValueError("invalid nft echo")
    result = []
    for entry in entries:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise ValueError("invalid nft echo entry")
        command, payload = next(iter(entry.items()))
        if command != "add":
            continue
        if not isinstance(payload, dict) or len(payload) != 1:
            raise ValueError("invalid nft add entry")
        kind, item = next(iter(payload.items()))
        if kind in {"table", "chain", "rule"}:
            result.append(_normalize_policy_item(kind, item))
    if not result:
        raise ValueError("nft echo contained no policy")
    return tuple(result)


def expected_policy_comments(expected: tuple[tuple[str, object], ...]) -> list[tuple[str, str]]:
    result = []
    for kind, item in expected:
        if kind == "rule" and isinstance(item, dict):
            chain, comment = item.get("chain"), item.get("comment")
            if isinstance(chain, str) and isinstance(comment, str):
                result.append((chain, comment))
    return result


def observed_policy_matches(observed: str, expected: tuple[tuple[str, object], ...]) -> bool:
    """Compare complete normalized nft JSON semantics, ignoring only volatile fields."""
    try:
        value = json.loads(observed)
        entries = value["nftables"]
        if not isinstance(entries, list):
            return False
        actual = []
        for entry in entries:
            if not isinstance(entry, dict) or len(entry) != 1:
                return False
            kind, item = next(iter(entry.items()))
            if kind == "metainfo":
                if not isinstance(item, dict):
                    return False
            elif kind in {"table", "chain", "rule"}:
                actual.append(_normalize_policy_item(kind, item))
            else:
                return False
        return tuple(actual) == expected
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False


def render_quarantine() -> str:
    """Render a discovery-independent barrier used before any protected transition."""
    return _sign_rules([
        f"table inet {NFT_TABLE} {{",
        "  chain output {",
        "    type filter hook output priority -10; policy drop;",
        '    oifname "lo" accept',
        '    counter drop comment "WireGuard transition quarantine"',
        "  }",
        "  chain forward {",
        "    type filter hook forward priority -10; policy drop;",
        '    counter drop comment "protect Docker and VM forwarding"',
        "  }",
        "}",
    ])


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
            raise FirewallError("WireGuard endpoints require a verified physical interface")
        if (not isinstance(context.wireguard_fwmark, int) or isinstance(context.wireguard_fwmark, bool) or
                not 1 <= context.wireguard_fwmark <= 0xFFFFFFFF):
            raise FirewallError("WireGuard endpoints require a dedicated fwmark")
    if (alfred4 or alfred6) and not physical:
        raise FirewallError("alfred-vpn endpoints require a verified physical interface")
    lan4 = _trusted_networks(context.lan_prefixes, 4, lan=True)
    lan6 = _trusted_networks(context.lan_prefixes, 6, lan=True)
    routes4 = _trusted_networks(context.alfred_routes, 4, lan=False)
    routes6 = _trusted_networks(context.alfred_routes, 6, lan=False)
    dns4 = _addresses(context.lan_resolvers, 4)
    dns6 = _addresses(context.lan_resolvers, 6)
    if (dns4 or dns6) and (not isinstance(context.resolver_uid, int) or context.resolver_uid < 0):
        raise FirewallError("LAN DNS requires an explicit resolver service UID")
    if (lan4 or lan6) and not physical:
        raise FirewallError("LAN prefixes require a verified physical interface")
    lines = [
        f"table inet {NFT_TABLE} {{",
        "  chain output {",
        "    type filter hook output priority -10; policy drop;",
        "    oifname \"lo\" accept",
    ]
    if tunnel:
        lines.append(f'    oifname "{tunnel}" accept comment "selected WireGuard tunnel"')
    lines += _output_underlay(physical, endpoint4, endpoint6, alfred4, alfred6, lan4, lan6,
                               dns4, dns6, context.resolver_uid, context.wireguard_fwmark)
    if routes4 and alfred:
        lines.append(f'    oifname "{alfred}" ip daddr {_set(routes4)} accept')
    if routes6 and alfred:
        lines.append(f'    oifname "{alfred}" ip6 daddr {_set(routes6)} accept')
    lines += [
        "    counter drop comment \"WireGuard fail closed\"",
        "  }",
        "  chain forward {",
        "    type filter hook forward priority -10; policy drop;",
    ]
    if local:
        local_set = _set([f'"{item}"' for item in local])
        physical_set = _set([f'"{item}"' for item in physical])
        lines.append(f"    iifname {local_set} oifname {local_set} accept comment \"local bridge traffic\"")
        if lan4:
            lines += [
                f"    iifname {local_set} oifname {physical_set} ip daddr {_set(lan4)} meta l4proto {{ tcp, udp }} th dport 53 drop comment \"block guest direct LAN DNS\"",
                f"    iifname {local_set} oifname {physical_set} ip daddr {_set(lan4)} accept comment \"local guests to LAN\"",
                f"    iifname {physical_set} oifname {local_set} ip saddr {_set(lan4)} ct state established,related accept",
            ]
        if lan6:
            lines += [
                f"    iifname {local_set} oifname {physical_set} ip6 daddr {_set(lan6)} meta l4proto {{ tcp, udp }} th dport 53 drop comment \"block guest direct LAN DNS\"",
                f"    iifname {local_set} oifname {physical_set} ip6 daddr {_set(lan6)} accept comment \"local guests to LAN\"",
                f"    iifname {physical_set} oifname {local_set} ip6 saddr {_set(lan6)} ct state established,related accept",
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
    return _sign_rules(lines)


def _output_underlay(physical, endpoint4, endpoint6, alfred4, alfred6, lan4, lan6, dns4, dns6,
                     resolver_uid, wireguard_fwmark):
    lines: list[str] = []
    quoted_physical = [f'"{item}"' for item in physical]
    devices = f"oifname {_set(quoted_physical)} " if physical else ""
    if endpoint4:
        lines.append(f"    meta mark {wireguard_fwmark:#x} {devices}ip daddr . udp dport {_set(sorted(set(endpoint4)))} accept comment \"WireGuard endpoints\"")
    if endpoint6:
        lines.append(f"    meta mark {wireguard_fwmark:#x} {devices}ip6 daddr . udp dport {_set(sorted(set(endpoint6)))} accept comment \"WireGuard endpoints\"")
    if alfred4:
        lines.append(f"    meta skuid 0 {devices}ip daddr . udp dport {_set(sorted(set(alfred4)))} accept comment \"alfred-vpn endpoints\"")
    if alfred6:
        lines.append(f"    meta skuid 0 {devices}ip6 daddr . udp dport {_set(sorted(set(alfred6)))} accept comment \"alfred-vpn endpoints\"")
    if dns4:
        lines.append(f"    meta skuid {resolver_uid} {devices}ip daddr {_set(dns4)} meta l4proto {{ tcp, udp }} th dport 53 accept comment \"resolved split .lan DNS\"")
    if dns6:
        lines.append(f"    meta skuid {resolver_uid} {devices}ip6 daddr {_set(dns6)} meta l4proto {{ tcp, udp }} th dport 53 accept comment \"resolved split .lan DNS\"")
    if lan4:
        lines.append(f"    {devices}ip daddr {_set(lan4)} meta l4proto {{ tcp, udp }} th dport 53 drop comment \"block direct LAN DNS\"")
    if lan6:
        lines.append(f"    {devices}ip6 daddr {_set(lan6)} meta l4proto {{ tcp, udp }} th dport 53 drop comment \"block direct LAN DNS\"")
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
    return lines
