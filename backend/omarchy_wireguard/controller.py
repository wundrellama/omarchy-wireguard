import re
import time
import ipaddress
from dataclasses import replace
from pathlib import PurePosixPath
from typing import Any, Callable

from .constants import CITY_BUDGET, MAX_RETRY, PAUSE_SECONDS, PROFILE_PREFIX, WIREGUARD_FWMARK
from .importer import ImportFailure, decode_payload, parse_profiles
from .nftables import FirewallContext
from .storage import StateCommitError, StateStore
from .system import DnsRestoreState, HostSystem, SystemFailure


class RequestFailure(ValueError):
    pass


def _slug(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return value[:32] or "profile"


def _dns_restore_state(value: object) -> DnsRestoreState:
    if not isinstance(value, (list, tuple)) or len(value) > 16:
        raise RequestFailure("invalid persisted DNS restore state")
    state = []
    for item in value:
        if (not isinstance(item, (list, tuple)) or len(item) != 3 or
                not isinstance(item[0], str) or
                not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", item[0]) or
                not isinstance(item[1], (list, tuple)) or len(item[1]) > 32 or
                not all(isinstance(domain, str) and 0 < len(domain) <= 255 and
                        "\n" not in domain and "\r" not in domain for domain in item[1]) or
                not isinstance(item[2], bool)):
            raise RequestFailure("invalid persisted DNS restore state")
        state.append((item[0], tuple(item[1]), item[2]))
    return tuple(state)


def network_context(policy: object, base: FirewallContext) -> FirewallContext:
    if policy is None:
        policy = {}
    if not isinstance(policy, dict) or set(policy) - {"lan_resolvers", "alfred"}:
        raise RequestFailure("invalid network policy")
    resolvers = policy.get("lan_resolvers", [])
    if not isinstance(resolvers, list) or len(resolvers) > 8:
        raise RequestFailure("invalid LAN resolvers")
    try:
        resolver_values = tuple(sorted(set(base.lan_resolvers) |
                                       {str(ipaddress.ip_address(item)) for item in resolvers}))
    except (TypeError, ValueError) as exc:
        raise RequestFailure("LAN resolvers must be IP addresses") from exc
    alfred = policy.get("alfred")
    if alfred is None:
        return FirewallContext(lan_prefixes=base.lan_prefixes, lan_resolvers=resolver_values,
                               resolver_uid=base.resolver_uid, physical_interfaces=base.physical_interfaces,
                               local_interfaces=base.local_interfaces, lan_dns_links=base.lan_dns_links)
    if not isinstance(alfred, dict) or set(alfred) != {"interface", "endpoints", "routes"}:
        raise RequestFailure("invalid alfred-vpn policy")
    if alfred["interface"] != "alfred-vpn" or not isinstance(alfred["endpoints"], list) or not isinstance(alfred["routes"], list):
        raise RequestFailure("alfred-vpn policy must use the explicit alfred-vpn interface")
    if len(alfred["endpoints"]) > 16 or len(alfred["routes"]) > 64:
        raise RequestFailure("alfred-vpn policy is too large")
    endpoints = []
    try:
        for endpoint in alfred["endpoints"]:
            if not isinstance(endpoint, list) or len(endpoint) != 2:
                raise ValueError
            address, port = str(ipaddress.ip_address(endpoint[0])), endpoint[1]
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise ValueError
            endpoints.append((address, port))
        routes = tuple(str(ipaddress.ip_network(route, strict=False)) for route in alfred["routes"])
    except (TypeError, ValueError) as exc:
        raise RequestFailure("alfred-vpn endpoints/routes must be exact IP values") from exc
    return FirewallContext(lan_prefixes=base.lan_prefixes, lan_resolvers=resolver_values,
                           resolver_uid=base.resolver_uid,
                           alfred_interface="alfred-vpn", alfred_endpoints=tuple(endpoints),
                           alfred_routes=routes, physical_interfaces=base.physical_interfaces,
                           local_interfaces=base.local_interfaces, lan_dns_links=base.lan_dns_links)


class Controller:
    MODES = {"disabled", "paused", "connecting", "connected", "failed"}

    def __init__(self, store: StateStore, system: HostSystem, *, controller_uid: int | None = None,
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 sleeper: Callable[[float], None] = time.sleep):
        self.store = store
        self.system = system
        self.clock = clock
        self.monotonic = monotonic
        self.sleeper = sleeper
        self.controller_uid = controller_uid
        self.network_policy = store.read("network.json", {})
        # Validate persisted policy before any firewall is generated.
        network_context(self.network_policy, FirewallContext())
        self.catalog: list[dict[str, Any]] = [
            {**item, "label": item.get("label", PurePosixPath(item["source_name"]).stem),
             "role": "internet-exit"} for item in store.read("profiles.json", [])]
        self.dns_restore = _dns_restore_state(store.read("dns.json", []))
        persisted = store.read("state.json", None)
        if persisted is None:
            persisted = {"enabled": False, "target": None, "mru": []}
        if (not isinstance(persisted, dict) or "enabled" not in persisted or
                not isinstance(persisted["enabled"], bool)):
            raise RequestFailure("invalid persisted state")
        if persisted.get("enabled") and not isinstance(persisted.get("target"), str):
            raise RequestFailure("enabled persisted state requires a target")
        if not isinstance(persisted.get("mru", []), list):
            raise RequestFailure("invalid persisted MRU")
        self.enabled = persisted.get("enabled", False)
        self.target = persisted.get("target") if isinstance(persisted.get("target"), str) else None
        self.mru = [item for item in persisted.get("mru", []) if isinstance(item, str)][:20]
        # Pauses are deliberately not restored after boot. Fail closed and reconnect if enabled.
        self.mode = "connecting" if self.enabled and self.target else "disabled"
        self.current: dict[str, Any] | None = None
        self.interface: str | None = None
        self.firewall_context: FirewallContext | None = None
        self.retry_count = 0
        self.retry_at: float | None = self.clock() if self.mode == "connecting" else None
        self.pause_until: float | None = None
        self.last_error: str | None = None
        self.last_checks: dict[str, bool] = {}
        self.notification: dict[str, Any] | None = None

    def boot(self) -> None:
        if self.mode == "connecting":
            self._fail_closed()
            self._attempt()
        else:
            self._direct_disconnect()
            self._clear_dns_restore()

    def handle(self, operation: str, args: dict[str, Any]) -> dict[str, Any]:
        handlers = {
            "status": self.status, "list": self.list_profiles, "import": self.import_profiles,
            "connect": self.connect, "disconnect": self.disconnect, "retry": self.retry,
            "pause": self.pause, "diagnostics": self.diagnostics,
        }
        try:
            return handlers[operation](args)
        except (ImportFailure, SystemFailure) as exc:
            raise RequestFailure(str(exc)) from exc

    def status(self, args: dict) -> dict:
        self._none(args)
        target_profile = self._target_profile()
        target = self._city(target_profile["city_key"] if target_profile else self.target)
        current = self._profile_summary(self.current) if self.current else None
        return {"mode": self.mode, "enabled": self.enabled, "target": self.target,
                "current_profile": self.current["id"] if self.current else None,
                "target_city": target, "current": current,
                "target_profile": self._profile_summary(target_profile) if target_profile else None,
                "retry_at": self.retry_at, "pause_until": self.pause_until,
                "last_error": self.last_error, "notification": self.notification}

    def list_profiles(self, args: dict) -> dict:
        self._none(args)
        cities: dict[str, list[dict]] = {}
        for profile in self.catalog:
            if not profile["country"] or not profile["city"]:
                continue
            cities.setdefault(profile["city_key"], []).append({
                "id": profile["id"], "source_name": profile["source_name"],
                "country": profile["country"], "city": profile["city"],
            })
        return {"cities": [{"id": key, "country": value[0]["country"], "city": value[0]["city"],
                            "profiles": value} for key, value in sorted(cities.items())],
                "profiles": [{key: value for key, value in self._profile_summary(item).items()
                              if key != "city_key"} for item in self.catalog],
                "mru": list(self.mru)}

    def import_profiles(self, args: dict) -> dict:
        proposed_network = args.get("network", self.network_policy)
        network_context(proposed_network, FirewallContext())
        if self.enabled and proposed_network != self.network_policy:
            raise RequestFailure("cannot change network policy while enabled; disconnect first")
        files = decode_payload(args, self.controller_uid)
        sources = {item["source_name"] for item in self.catalog}
        for name, _raw in files:
            if name in sources:
                raise ImportFailure(f"duplicate source_name: {name}; imports are additive only")
            sources.add(name)
        profiles, ambiguous = parse_profiles(files, args.get("locations"), args.get("labels"))
        if ambiguous:
            return {"imported": False, "review_required": ambiguous,
                    "message": "country/city inference was ambiguous; resubmit with locations"}
        imported: list[dict] = []
        created: list[str] = []
        identifiers = {item["id"] for item in self.catalog}
        identifiers.update(name[len(PROFILE_PREFIX):] for name in self.system.managed_profiles().values()
                           if name.startswith(PROFILE_PREFIX))
        network_written = False
        durability_error = None
        try:
            for profile in profiles:
                stem = f"{_slug(profile.country)}-{_slug(profile.city)}"
                index = 1
                while f"{stem}-{index}" in identifiers:
                    index += 1
                identifier = f"{stem}-{index}"
                identifiers.add(identifier)
                name = PROFILE_PREFIX + identifier
                uuid = self.system.import_profile(profile, name)
                created.append(uuid)
                imported.append({"id": identifier, "uuid": uuid, "source_name": profile.source_name,
                                 "label": profile.label, "role": profile.role,
                                 "country": profile.country, "city": profile.city,
                                 "city_key": profile.city_key, "endpoint_host": profile.endpoint_host,
                                 "endpoint_port": profile.endpoint_port})
            catalog = self.catalog + imported
            if proposed_network != self.network_policy:
                try:
                    self.store.write("network.json", proposed_network)
                except StateCommitError:
                    network_written = True
                    raise
                network_written = True
            try:
                self.store.write("profiles.json", catalog)
            except StateCommitError as exc:
                # The catalog already references these UUIDs. Never delete them after commit.
                durability_error = exc
        except Exception as exc:
            rollback_failed = False
            if network_written:
                try:
                    self.store.write("network.json", self.network_policy)
                except OSError:
                    rollback_failed = True
            for uuid in created:
                try:
                    self.system.delete_profile(uuid)
                except SystemFailure:
                    rollback_failed = True
            message = "could not import or persist new profiles"
            if rollback_failed:
                message += "; rollback incomplete: network policy or new NM profiles require inspection"
            raise ImportFailure(message) from exc
        self.catalog = catalog
        self.network_policy = proposed_network
        if durability_error:
            raise ImportFailure("profiles committed but durability could not be confirmed; inspect list before retrying") from durability_error

        return {"imported": True, "profiles": len(imported),
                "cities": sorted({item["city_key"] for item in imported}),
                "status": self.status({})}

    def connect(self, args: dict) -> dict:
        if set(args) not in ({"city"}, {"profile"}):
            raise RequestFailure("connect requires exactly one city or profile string")
        kind = next(iter(args))
        value = args[kind]
        if not isinstance(value, str) or not value:
            raise RequestFailure("connect requires exactly one city or profile string")
        key = "city_key" if kind == "city" else "id"
        if value not in {item[key] for item in self.catalog
                         if kind == "profile" or (item["country"] and item["city"])}:
            raise RequestFailure(f"unknown {kind}")
        target = value if kind == "city" else "profile:" + value
        self.enabled, self.target, self.mode = True, target, "connecting"
        self.pause_until = None
        self.retry_count = 0
        self.retry_at = self.clock()
        self._persist()
        self._emergency_disconnect()
        return self.status({})

    def disconnect(self, args: dict) -> dict:
        self._none(args)
        try:
            self._direct_disconnect()
        except SystemFailure as exc:
            self.mode, self.last_error = "failed", str(exc)
            self.retry_at = None
            self._persist()
            raise
        self.enabled, self.target, self.mode = False, None, "disabled"
        self.retry_at = self.pause_until = None
        self._persist()
        self._clear_dns_restore()
        return self.status({})

    def retry(self, args: dict) -> dict:
        self._none(args)
        if not self.enabled or not self.target:
            raise RequestFailure("no enabled target to retry")
        self.retry_count = 0
        self._schedule_connecting()
        return self.status({})

    def pause(self, args: dict) -> dict:
        if set(args) - {"seconds"}:
            raise RequestFailure("unknown pause argument")
        seconds = args.get("seconds", PAUSE_SECONDS)
        if not isinstance(seconds, int) or isinstance(seconds, bool) or not 1 <= seconds <= PAUSE_SECONDS:
            raise RequestFailure("pause must be between 1 and 600 seconds")
        if not self.enabled:
            raise RequestFailure("cannot pause a disabled connection")
        try:
            self._direct_disconnect()
        except SystemFailure as exc:
            self.mode, self.last_error = "failed", str(exc)
            self.retry_at = None
            self._persist()
            raise
        self._clear_dns_restore()
        self.mode, self.pause_until, self.retry_at = "paused", self.clock() + seconds, None
        self._persist()
        return self.status({})

    def diagnostics(self, args: dict) -> dict:
        self._none(args)
        return {"mode": self.mode, "checks": dict(self.last_checks),
                "managed_profiles": len(self.catalog), "retry_count": self.retry_count,
                "guarantees": {"lan_dns": "requires resolved split-DNS verification",
                               "ipv6": "must be tunneled or have no default route"}}

    def tick(self) -> None:
        now = self.clock()
        if self.mode == "paused" and self.pause_until is not None and now >= self.pause_until:
            self.pause_until = None
            self._schedule_connecting()
        elif self.mode == "connecting" and self.retry_at is not None and now >= self.retry_at:
            self.retry_at = None
            self._attempt()
        elif self.mode == "failed" and self.retry_at is not None and now >= self.retry_at:
            self.mode = "connecting"
            self.retry_at = None
            self._attempt()
        elif self.mode == "connected" and self.current and self.interface:
            try:
                result = self.system.verify(self.current["uuid"], self.interface, now,
                                            firewall_context=self.firewall_context)
                self.last_checks = result.checks
                if not result.ok:
                    self._failure(result.detail)
            except SystemFailure as exc:
                self._failure(str(exc))

    def emergency(self) -> None:
        """Best-effort isolation used for unexpected internal failures."""
        if self.enabled:
            self._emergency_disconnect()
            self.mode = "failed"
        else:
            self._direct_disconnect()
            self.mode = "disabled"
        self.last_error = "internal safety failure"

    def _attempt(self) -> None:
        if self.target and self.target.startswith("profile:"):
            selected = self._target_profile()
            profiles = [selected] if selected else []
        else:
            profiles = [item for item in self.catalog if item["city_key"] == self.target]
        order = {identifier: index for index, identifier in enumerate(self.mru)}
        profiles.sort(key=lambda item: order.get(item["id"], len(order)))
        started = self.monotonic()
        self._emergency_disconnect()
        errors = []
        def remaining() -> float:
            value = CITY_BUDGET - (self.monotonic() - started)
            if value <= 0:
                raise SystemFailure("city connection budget exhausted")
            return value

        for profile in profiles:
            if CITY_BUDGET - (self.monotonic() - started) <= 0:
                errors.append("city connection budget exhausted")
                break
            try:
                base = network_context(self.network_policy, self.system.inspect_firewall_context(remaining()))
                base = self._configure_lan_dns(base, remaining)
                # Permit only resolved's physical-link DNS before resolving a hostname;
                # all application traffic remains blocked during this transition.
                self.system.apply_firewall(base, remaining())
                endpoints = self.system.resolve_endpoint(profile["endpoint_host"], profile["endpoint_port"], remaining())
                self.system.apply_firewall(FirewallContext(
                    endpoints=endpoints, wireguard_fwmark=WIREGUARD_FWMARK,
                    lan_prefixes=base.lan_prefixes,
                    lan_resolvers=base.lan_resolvers, resolver_uid=base.resolver_uid,
                    alfred_interface=base.alfred_interface,
                    alfred_endpoints=base.alfred_endpoints, alfred_routes=base.alfred_routes,
                    physical_interfaces=base.physical_interfaces,
                    local_interfaces=base.local_interfaces,
                    lan_dns_links=base.lan_dns_links), remaining())
                interface = self.system.activate(profile["uuid"], remaining())
                self.interface = interface
                # Activation can cause NetworkManager to republish physical-link DNS.
                # Reassert ~lan and rebuild the firewall from the refreshed resolvers.
                refreshed = network_context(
                    self.network_policy, self.system.inspect_firewall_context(remaining()))
                base = self._configure_lan_dns(refreshed, remaining)
                connected_context = FirewallContext(
                    tunnel_interface=interface, endpoints=endpoints,
                    wireguard_fwmark=WIREGUARD_FWMARK, lan_prefixes=base.lan_prefixes,
                    lan_resolvers=base.lan_resolvers, resolver_uid=base.resolver_uid,
                    alfred_interface=base.alfred_interface,
                    alfred_endpoints=base.alfred_endpoints, alfred_routes=base.alfred_routes,
                    physical_interfaces=base.physical_interfaces,
                    local_interfaces=base.local_interfaces,
                    lan_dns_links=base.lan_dns_links)
                self.system.apply_firewall(connected_context, remaining())
                tunnel_dns = self.system.configure_tunnel_dns(
                    profile["uuid"], interface, remaining())
                connected_context = replace(connected_context, tunnel_dns=tunnel_dns)
                self._wait_for_verification(profile["uuid"], interface, connected_context, remaining)
                self.mode, self.current, self.interface = "connected", profile, interface
                self.firewall_context = connected_context
                self.retry_count, self.retry_at, self.last_error = 0, None, None
                self.mru = [profile["id"]] + [item for item in self.mru if item != profile["id"]]
                self.mru = self.mru[:20]
                self._persist()
                self._notify("connected", f"Connected to {self.target}")
                return
            except SystemFailure as exc:
                errors.append(str(exc))
                self._emergency_disconnect()
        self._failure(errors[-1] if errors else "no profiles for target city")

    def _wait_for_verification(self, uuid: str, interface: str, context: FirewallContext,
                               remaining: Callable[[], float]):
        last_error = "connection verification did not complete"
        # The iteration cap protects tests/custom clocks that do not advance when sleeping;
        # the monotonic deadline remains authoritative in production.
        for _ in range(int(CITY_BUDGET / 0.5) + 1):
            try:
                budget = remaining()
            except SystemFailure:
                raise SystemFailure(last_error)
            try:
                result = self.system.verify(uuid, interface, self.clock(), budget, context)
                self.last_checks = result.checks
                if result.ok:
                    return result
                last_error = result.detail
            except SystemFailure as exc:
                last_error = str(exc)
            try:
                delay = min(0.5, remaining())
            except SystemFailure:
                raise SystemFailure(last_error)
            self.sleeper(delay)
        raise SystemFailure(last_error)

    def _schedule_connecting(self) -> None:
        self.mode = "connecting"
        self.retry_at = self.clock()
        self._persist()
        self._emergency_disconnect()

    def _failure(self, reason: str) -> None:
        self._emergency_disconnect()
        self.mode, self.last_error = "failed", reason
        self.retry_count += 1
        self.retry_at = self.clock() + min(MAX_RETRY, 2 ** min(self.retry_count, 9))
        self._notify("failed", "WireGuard connection failed; traffic remains blocked")

    def _emergency_disconnect(self) -> None:
        if self.interface:
            try:
                self.system.clear_tunnel_dns(self.interface)
            except SystemFailure:
                pass
        try:
            self.system.deactivate_managed()
        except SystemFailure:
            # Firewall isolation is authoritative even if NetworkManager is unavailable.
            pass
        self.current = None
        self.interface = None
        self.firewall_context = None
        self._fail_closed()

    def _direct_disconnect(self) -> None:
        if self.interface:
            try:
                self.system.clear_tunnel_dns(self.interface)
            except SystemFailure:
                pass
        self.system.deactivate_managed()
        self.current = None
        self.interface = None
        self.firewall_context = None
        self.system.restore_lan_dns(self.dns_restore)
        self.system.remove_firewall()

    def _configure_lan_dns(self, base: FirewallContext,
                           remaining: Callable[[], float]) -> FirewallContext:
        physical = set(base.physical_interfaces)
        stale = tuple(item for item in self.dns_restore if item[0] not in physical)
        if stale:
            self.system.restore_lan_dns(stale, remaining())
        retained = tuple(item for item in self.dns_restore if item[0] in physical)
        known = {interface for interface, _domains, _default in retained}
        missing = tuple(interface for interface in base.physical_interfaces if interface not in known)
        updated = retained + self.system.capture_lan_dns(missing, remaining())
        if len(updated) > 16:
            raise SystemFailure("too many physical DNS links")
        if updated != self.dns_restore:
            self.dns_restore = updated
            self.store.write("dns.json", self.dns_restore)
        return self.system.configure_lan_dns(base, remaining())

    def _clear_dns_restore(self) -> None:
        self.dns_restore = ()
        self.store.write("dns.json", [])

    def _fail_closed(self) -> None:
        base = self.system.inspect_firewall_context()
        self.system.apply_firewall(network_context(self.network_policy, base))

    def _persist(self) -> None:
        self.store.write("state.json", {"enabled": self.enabled, "target": self.target, "mru": self.mru})

    def _notify(self, kind: str, message: str) -> None:
        self.notification = {"kind": kind, "message": message, "at": self.clock()}
        self.store.write("notification.json", self.notification)

    def _target_profile(self) -> dict | None:
        if self.target and self.target.startswith("profile:"):
            identifier = self.target[len("profile:"):]
            return next((item for item in self.catalog if item["id"] == identifier), None)
        return None

    def _city(self, key: str | None) -> dict | None:
        for profile in self.catalog:
            if profile["city_key"] == key:
                if not profile["country"] or not profile["city"]:
                    return None
                return {"id": key, "country": profile["country"], "city": profile["city"]}
        if key and "/" in key:
            country, city = key.split("/", 1)
            return {"id": key, "country": country, "city": city}
        return None

    @staticmethod
    def _profile_summary(profile: dict) -> dict:
        return {**{key: profile[key] for key in ("id", "country", "city", "city_key", "source_name")},
                "label": profile.get("label", PurePosixPath(profile["source_name"]).stem),
                "role": "internet-exit"}

    @staticmethod
    def _none(args: dict) -> None:
        if args:
            raise RequestFailure("operation takes no arguments")
