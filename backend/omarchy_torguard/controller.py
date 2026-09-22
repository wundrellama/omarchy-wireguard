import re
import time
import ipaddress
from dataclasses import replace
from typing import Any, Callable

from .constants import CITY_BUDGET, MAX_RETRY, PAUSE_SECONDS, PROFILE_PREFIX, TORGUARD_FWMARK
from .importer import ImportFailure, decode_payload, parse_profiles
from .nftables import FirewallContext
from .storage import StateStore
from .system import HostSystem, SystemFailure


class RequestFailure(ValueError):
    pass


def _slug(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return value[:32] or "profile"


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
        self.catalog: list[dict[str, Any]] = store.read("profiles.json", [])
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
        target = self._city(self.target)
        current = self._profile_summary(self.current) if self.current else None
        return {"mode": self.mode, "enabled": self.enabled, "target": self.target,
                "current_profile": self.current["id"] if self.current else None,
                "target_city": target, "current": current,
                "retry_at": self.retry_at, "pause_until": self.pause_until,
                "last_error": self.last_error, "notification": self.notification}

    def list_profiles(self, args: dict) -> dict:
        self._none(args)
        cities: dict[str, list[dict]] = {}
        for profile in self.catalog:
            cities.setdefault(profile["city_key"], []).append({
                "id": profile["id"], "source_name": profile["source_name"],
                "country": profile["country"], "city": profile["city"],
            })
        return {"cities": [{"id": key, "country": value[0]["country"], "city": value[0]["city"],
                            "profiles": value} for key, value in sorted(cities.items())],
                "mru": list(self.mru)}

    def import_profiles(self, args: dict) -> dict:
        proposed_network = args.get("network", self.network_policy)
        network_context(proposed_network, FirewallContext())
        files = decode_payload(args, self.controller_uid)
        profiles, ambiguous = parse_profiles(files, args.get("locations"))
        if ambiguous:
            return {"imported": False, "review_required": ambiguous,
                    "message": "country/city inference was ambiguous; resubmit with locations"}
        old = self.system.managed_profiles()
        if self.current:
            self._emergency_disconnect()
        imported: list[dict] = []
        created: list[str] = []
        try:
            for index, profile in enumerate(profiles):
                identifier = f"{_slug(profile.country)}-{_slug(profile.city)}-{index + 1}"
                name = PROFILE_PREFIX + identifier
                uuid = self.system.import_profile(profile, name)
                created.append(uuid)
                imported.append({"id": identifier, "uuid": uuid, "source_name": profile.source_name,
                                 "country": profile.country, "city": profile.city,
                                 "city_key": profile.city_key, "endpoint_host": profile.endpoint_host,
                                 "endpoint_port": profile.endpoint_port})
        except Exception:
            for uuid in created:
                try:
                    self.system.delete_profile(uuid)
                except SystemFailure:
                    pass
            raise
        for uuid in old:
            try:
                self.system.delete_profile(uuid)
            except SystemFailure as exc:
                # New profiles are usable, but ownership would be ambiguous with stale profiles.
                for created_uuid in created:
                    try:
                        self.system.delete_profile(created_uuid)
                    except SystemFailure:
                        pass
                raise SystemFailure("could not retire old managed profiles safely") from exc
        self.catalog = imported
        self.store.write("profiles.json", imported)
        if proposed_network != self.network_policy:
            self.network_policy = proposed_network
            self.store.write("network.json", proposed_network)
        if self.target not in {item["city_key"] for item in imported}:
            if self.enabled and self.target:
                self.mode = "failed"
                self.retry_at = None
                self.last_error = "selected city is unavailable after import"
                self._fail_closed()
                self._persist()
                self._notify("failed", "Selected TorGuard city is no longer available; traffic remains blocked")
        elif self.enabled:
            self._schedule_connecting()
        return {"imported": True, "profiles": len(imported),
                "cities": sorted({item["city_key"] for item in imported}),
                "status": self.status({})}

    def connect(self, args: dict) -> dict:
        if set(args) != {"city"} or not isinstance(args["city"], str):
            raise RequestFailure("connect requires only a city string")
        if args["city"] not in {item["city_key"] for item in self.catalog}:
            raise RequestFailure("unknown city")
        self.enabled, self.target, self.mode = True, args["city"], "connecting"
        self.pause_until = None
        self.retry_count = 0
        self.retry_at = self.clock()
        self._persist()
        self._emergency_disconnect()
        return self.status({})

    def disconnect(self, args: dict) -> dict:
        self._none(args)
        self.enabled, self.target, self.mode = False, None, "disabled"
        self.retry_at = self.pause_until = None
        self._persist()
        self._direct_disconnect()
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
        self.mode, self.pause_until, self.retry_at = "paused", self.clock() + seconds, None
        self._persist()
        self._direct_disconnect()
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
                base = self.system.configure_lan_dns(base, remaining())
                # Permit only resolved's physical-link DNS before resolving a hostname;
                # all application traffic remains blocked during this transition.
                self.system.apply_firewall(base, remaining())
                endpoints = self.system.resolve_endpoint(profile["endpoint_host"], profile["endpoint_port"], remaining())
                self.system.apply_firewall(FirewallContext(
                    endpoints=endpoints, torguard_fwmark=TORGUARD_FWMARK,
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
                base = self.system.configure_lan_dns(base, remaining())
                connected_context = FirewallContext(
                    tunnel_interface=interface, endpoints=endpoints,
                    torguard_fwmark=TORGUARD_FWMARK, lan_prefixes=base.lan_prefixes,
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
        self._notify("failed", "TorGuard connection failed; traffic remains blocked")

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
        try:
            self.system.deactivate_managed()
        finally:
            self.current = None
            self.interface = None
            self.firewall_context = None
            try:
                self.system.restore_lan_dns()
            finally:
                self.system.remove_firewall()

    def _fail_closed(self) -> None:
        base = self.system.inspect_firewall_context()
        self.system.apply_firewall(network_context(self.network_policy, base))

    def _persist(self) -> None:
        self.store.write("state.json", {"enabled": self.enabled, "target": self.target, "mru": self.mru})

    def _notify(self, kind: str, message: str) -> None:
        self.notification = {"kind": kind, "message": message, "at": self.clock()}
        self.store.write("notification.json", self.notification)

    def _city(self, key: str | None) -> dict | None:
        for profile in self.catalog:
            if profile["city_key"] == key:
                return {"id": key, "country": profile["country"], "city": profile["city"]}
        if key and "/" in key:
            country, city = key.split("/", 1)
            return {"id": key, "country": country, "city": city}
        return None

    @staticmethod
    def _profile_summary(profile: dict) -> dict:
        return {key: profile[key] for key in ("id", "country", "city", "city_key", "source_name")}

    @staticmethod
    def _none(args: dict) -> None:
        if args:
            raise RequestFailure("operation takes no arguments")
