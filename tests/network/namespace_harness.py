#!/usr/bin/env python3
"""Real, bounded nft/WireGuard tests. Run via run.py; no host mutations."""
from __future__ import annotations

import argparse
import dataclasses
import errno
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import sys
import threading
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))
from omarchy_wireguard.constants import NFT_TABLE, WIREGUARD_FWMARK
from omarchy_wireguard.nftables import FirewallContext, render
from omarchy_wireguard.system import HostSystem, SystemFailure

PORT = 39071
PUBLIC4 = "198.51.100.80"
PUBLIC6 = "2001:db8:2::80"
LAN4 = "192.168.77.2"
LAN6 = "fd42:1::2"
HOST_NET = ""
HOST_USER = ""
CURRENT_NET = ""
CHECKS: list[dict] = []


def ns(kind="net"):
    return os.readlink(f"/proc/self/ns/{kind}")


def guard():
    # Rechecked before EVERY ip/wg/nft execution, including adapter calls.
    if not HOST_NET or ns() == HOST_NET or ns() != CURRENT_NET:
        raise RuntimeError("REFUSED: not in the verified isolated network namespace")
    if not HOST_USER or ns("user") == HOST_USER or os.geteuid() != 0:
        raise RuntimeError("REFUSED: not in the isolated mapped-root user namespace")


def command(argv, stdin=None, timeout=5):
    guard()
    if argv[0] not in {"ip", "wg", "nft"}:
        raise RuntimeError("command outside isolated allowlist")
    result = subprocess.run(argv, input=stdin, text=True, capture_output=True,
                            timeout=timeout, env={"PATH": "/usr/bin:/usr/sbin", "LANG": "C"})
    if result.returncode:
        # Never expose keys/configuration, even in a failing WireGuard command.
        detail = "WireGuard operation failed (configuration redacted)" if argv[0] == "wg" else (
            " ".join(argv) + ": " + result.stderr.strip())
        raise RuntimeError(detail)
    return result.stdout


def check(name, condition, **evidence):
    CHECKS.append({"name": name, "passed": bool(condition), **evidence})
    if not condition:
        raise AssertionError(name)


class GuardedRunner:
    """Real adapter command execution; not a fake. Forbids NM/resolved/systemd."""
    def run(self, argv, *, stdin=None, timeout=10):
        try:
            return command(argv, stdin, min(timeout, 5))
        except RuntimeError as exc:
            raise SystemFailure(str(exc)) from exc


class Peer:
    def __init__(self):
        guard()
        self.proc = subprocess.Popen(
            ["unshare", "-n", sys.executable, "-B", __file__, "--peer",
             "--host-net", HOST_NET, "--host-user", HOST_USER],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1)
        assert self.proc.stdin is not None and self.proc.stdout is not None and self.proc.stderr is not None
        self.identity = self.receive()
        check("peer_namespace_is_distinct", self.identity["netns"] not in {HOST_NET, CURRENT_NET},
              namespace=self.identity["netns"])

    def receive(self):
        assert self.proc.stdout is not None and self.proc.stderr is not None
        with selectors.DefaultSelector() as selector:
            selector.register(self.proc.stdout, selectors.EVENT_READ)
            if not selector.select(6):
                raise RuntimeError("peer RPC timed out")
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("peer exited: " + self.proc.stderr.read(4096))
        result = json.loads(line)
        if "error" in result:
            raise RuntimeError(result["error"])
        return result

    def call(self, op, **fields):
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps({"op": op, **fields}) + "\n")
        self.proc.stdin.flush()
        return self.receive()

    def ip(self, *args):
        return self.call("ip", args=list(args))

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=3)


def peer_main():
    guard()
    seen = []
    lock = threading.Lock()
    sockets = []

    def echo(sock):
        while True:
            data, ancillary, _flags, address = sock.recvmsg(4096, 256)
            interface = None
            for level, kind, value in ancillary:
                if level == socket.IPPROTO_IP and kind == 8:  # Linux IP_PKTINFO
                    interface = socket.if_indextoname(struct.unpack("I", value[:4])[0])
                elif level == socket.IPPROTO_IPV6 and kind == socket.IPV6_PKTINFO:
                    interface = socket.if_indextoname(struct.unpack("I", value[16:20])[0])
            item = {"token": data.decode("ascii"), "ingress": interface}
            with lock:
                seen.append(item)
            sock.sendto(json.dumps(item).encode(), address)

    print(json.dumps({"netns": ns(), "pid": os.getpid()}), flush=True)
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if request["op"] == "ip":
                result = {"output": command(["ip", *request["args"]])}
            elif request["op"] == "wg":
                command(["wg", "setconf", "wgpeer", "/dev/stdin"], request["config"])
                result = {"ok": True}
            elif request["op"] == "start":
                for address in (PUBLIC4, PUBLIC6, LAN4, LAN6):
                    family = socket.AF_INET6 if ":" in address else socket.AF_INET
                    sock = socket.socket(family, socket.SOCK_DGRAM)
                    if family == socket.AF_INET:
                        sock.setsockopt(socket.IPPROTO_IP, 8, 1)
                    else:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
                    sock.bind((address, PORT))
                    sockets.append(sock)
                    threading.Thread(target=echo, args=(sock,), daemon=True).start()
                result = {"ok": True}
            elif request["op"] == "seen":
                with lock:
                    result = {"packets": list(seen)}
            else:
                raise RuntimeError("unknown peer operation")
            print(json.dumps(result), flush=True)
        except Exception as exc:
            print(json.dumps({"error": str(exc)}), flush=True)


class Probe:
    def __init__(self, address):
        self.address = address
        self.sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET,
                                  socket.SOCK_DGRAM)
        self.sock.settimeout(0.7)
        self.sock.connect((address, PORT))
        self.tokens = []

    def send(self):
        token = uuid.uuid4().hex
        self.tokens.append(token)
        try:
            self.sock.send(token.encode())
        except OSError as exc:
            # Linux may report a local nft OUTPUT drop synchronously to UDP.
            # The caller still requires a drop-counter increment and no peer packet.
            if exc.errno in (errno.EPERM, errno.EACCES):
                return token, None
            raise
        try:
            item = json.loads(self.sock.recv(4096))
        except socket.timeout:
            return token, None
        if item["token"] != token:
            raise RuntimeError("stale/unexpected echo token")
        return token, item

    def close(self):
        self.sock.close()


def drops():
    output = json.loads(command(["nft", "-j", "list", "chain", "inet", NFT_TABLE, "output"]))
    for entry in output["nftables"]:
        rule = entry.get("rule", {})
        if str(rule.get("comment", "")).endswith(":WireGuard fail closed"):
            for expr in rule["expr"]:
                if "counter" in expr:
                    return expr["counter"]["packets"]
    raise RuntimeError("backend output drop counter missing")


def expect_echo(peer, probe, name, ingress):
    token, response = probe.send()
    check(name, response is not None and response["ingress"] == ingress,
          destination=probe.address, received=response)
    check(name + "_peer_observed", any(item["token"] == token and item["ingress"] == ingress
                                       for item in peer.call("seen")["packets"]))


def expect_block(peer, probe, name):
    before = drops()
    token, response = probe.send()
    after = drops()
    observed = any(item["token"] == token for item in peer.call("seen")["packets"])
    check(name, response is None and not observed and after > before,
          destination=probe.address, peer_observed=observed,
          drop_counter_before=before, drop_counter_after=after)


def route_device(address):
    return json.loads(command(["ip", "-j", "route", "get", address]))[0]["dev"]


def setup(peer):
    command(["ip", "link", "set", "lo", "up"])
    command(["ip", "link", "add", "physical", "type", "veth", "peer", "name", "wire"])
    command(["ip", "link", "set", "wire", "netns", str(peer.proc.pid)])
    command(["ip", "addr", "add", "192.168.77.1/24", "dev", "physical"])
    command(["ip", "-6", "addr", "add", "fd42:1::1/64", "dev", "physical", "nodad"])
    command(["ip", "link", "set", "physical", "up"])
    peer.ip("link", "set", "lo", "up")
    peer.ip("addr", "add", LAN4 + "/24", "dev", "wire")
    peer.ip("-6", "addr", "add", LAN6 + "/64", "dev", "wire", "nodad")
    peer.ip("addr", "add", PUBLIC4 + "/32", "dev", "lo")
    peer.ip("-6", "addr", "add", PUBLIC6 + "/128", "dev", "lo", "nodad")
    peer.ip("link", "set", "wire", "up")
    command(["ip", "route", "add", "default", "via", LAN4, "dev", "physical", "metric", "100"])
    command(["ip", "-6", "route", "add", "default", "via", LAN6, "dev", "physical", "metric", "100"])
    peer.call("start")


def setup_wireguard(peer):
    command(["ip", "link", "add", "wgtest", "type", "wireguard"])
    peer.ip("link", "add", "wgpeer", "type", "wireguard")
    private_client = command(["wg", "genkey"]).strip()
    private_peer = command(["wg", "genkey"]).strip()
    public_client = command(["wg", "pubkey"], private_client + "\n").strip()
    public_peer = command(["wg", "pubkey"], private_peer + "\n").strip()
    peer.call("wg", config=(f"[Interface]\nPrivateKey = {private_peer}\nListenPort = 51820\n"
                            f"[Peer]\nPublicKey = {public_client}\nAllowedIPs = 10.77.0.1/32\n"))
    command(["wg", "setconf", "wgtest", "/dev/stdin"],
            f"[Interface]\nPrivateKey = {private_client}\nFwMark = {WIREGUARD_FWMARK}\n"
            f"[Peer]\nPublicKey = {public_peer}\nEndpoint = {LAN4}:51820\nAllowedIPs = 0.0.0.0/0\n")
    command(["ip", "addr", "add", "10.77.0.1/24", "dev", "wgtest"])
    peer.ip("addr", "add", "10.77.0.2/24", "dev", "wgpeer")
    peer.ip("link", "set", "wgpeer", "up")
    command(["ip", "link", "set", "wgtest", "up"])
    command(["ip", "route", "add", "default", "dev", "wgtest", "metric", "5"])


def inner(inject_failure):
    peer = None
    probes = []
    report = {"namespace": ns(), "host_namespace": HOST_NET, "checks": CHECKS}
    try:
        guard()
        links = json.loads(command(["ip", "-j", "link", "show"]))
        check("fresh_isolated_namespace", [item["ifname"] for item in links] == ["lo"])
        peer = Peer()
        setup(peer)
        report["peer_namespace"] = peer.identity["netns"]
        system = HostSystem(runner=GuardedRunner())
        p4, p6, lan4, lan6 = [Probe(address) for address in (PUBLIC4, PUBLIC6, LAN4, LAN6)]
        probes.extend((p4, p6, lan4, lan6))
        expect_echo(peer, p4, "baseline_ipv4_default_reachable", "wire")
        expect_echo(peer, p6, "baseline_ipv6_default_reachable", "wire")
        expect_echo(peer, lan4, "baseline_lan_reachable", "wire")
        # This veth intentionally represents a physical uplink. We do NOT claim
        # inspect_firewall_context() validates real physical discovery here.
        context = FirewallContext(tunnel_interface="wgtest", endpoints=((LAN4, 51820),),
                                  wireguard_fwmark=WIREGUARD_FWMARK,
                                  physical_interfaces=("physical",),
                                  lan_prefixes=("192.168.77.0/24", "fd42:1::/64"))
        rules = render(context)
        command(["nft", "-c", "-f", "-"], rules)
        check("real_render_passes_nft_check", True)
        system.apply_firewall(context)
        check("adapter_first_creation_applied", NFT_TABLE in command(["nft", "list", "tables"]))
        if inject_failure:
            raise RuntimeError("intentional failure after live isolated firewall application")
        expect_block(peer, p4, "enabled_tunnel_absent_existing_ipv4_flow_blocked")
        expect_block(peer, p6, "enabled_tunnel_absent_existing_ipv6_flow_blocked")
        expect_echo(peer, lan4, "intentional_connected_ipv4_lan_exception", "wire")
        expect_echo(peer, lan6, "intentional_connected_ipv6_lan_exception", "wire")
        system.apply_firewall(context)
        check("adapter_atomic_replacement_applied", drops() == 0)
        setup_wireguard(peer)
        check("ipv4_default_route_uses_wireguard", route_device(PUBLIC4) == "wgtest")
        # An IPv4-only tunnel deliberately leaves a working IPv6 physical default.
        check("ipv6_default_still_physical", route_device(PUBLIC6) == "physical")
        tunnel_probe = Probe(PUBLIC4)
        probes.append(tunnel_probe)
        expect_echo(peer, tunnel_probe, "encrypted_wireguard_payload_reaches_peer", "wgpeer")
        handshakes = command(["wg", "show", "wgtest", "latest-handshakes"])
        check("real_wireguard_handshake", any(int(line.split()[-1]) > 0 for line in handshakes.splitlines()))
        transfer = command(["wg", "show", "wgtest", "transfer"])
        counts = [tuple(map(int, line.split()[1:])) for line in transfer.splitlines()]
        check("wireguard_transfer_counters_both_directions", any(rx > 0 and tx > 0 for rx, tx in counts),
              transfer_bytes=counts)
        expect_block(peer, p6, "ipv6_physical_fallback_blocked_while_vpn_up")
        # Remove LAN exemptions and force a new handshake, proving the marked
        # endpoint exemption, rather than the broad LAN exemption, carries WG.
        strict = dataclasses.replace(context, lan_prefixes=())
        system.apply_firewall(strict)
        command(["ip", "link", "del", "wgtest"])
        peer.ip("link", "del", "wgpeer")
        setup_wireguard(peer)
        strict_probe = Probe(PUBLIC4)
        probes.append(strict_probe)
        expect_echo(peer, strict_probe, "marked_endpoint_without_lan_exemption", "wgpeer")
        expect_block(peer, lan4, "unmarked_underlay_not_blanket_allowed")
        # Restore policy as the controller would, then destroy the selected device.
        system.apply_firewall(context)
        command(["ip", "link", "del", "wgtest"])
        check("tunnel_loss_restores_physical_default", route_device(PUBLIC4) == "physical")
        fresh4 = Probe(PUBLIC4)
        probes.append(fresh4)
        expect_block(peer, fresh4, "physical_ipv4_fallback_blocked_after_tunnel_loss")
        expect_block(peer, p6, "physical_ipv6_fallback_blocked_after_tunnel_loss")
        expect_echo(peer, lan4, "lan_exception_survives_tunnel_loss", "wire")
        # Invalid transaction must not remove the previously applied table.
        before = command(["nft", "list", "table", "inet", NFT_TABLE])
        try:
            command(["nft", "-f", "-"], f"delete table inet {NFT_TABLE}\nthis_is_invalid\n")
        except RuntimeError:
            pass
        else:
            raise AssertionError("invalid nft transaction unexpectedly succeeded")
        after = command(["nft", "list", "table", "inet", NFT_TABLE])
        check("failed_nft_transaction_preserves_installed_rules", before == after)
        expect_block(peer, fresh4, "failed_transaction_remains_fail_closed")
        system.remove_firewall()
        check("adapter_remove_verified", NFT_TABLE not in command(["nft", "list", "tables"]))
        expect_echo(peer, fresh4, "firewall_removed_ipv4_positive_control", "wire")
        expect_echo(peer, p6, "firewall_removed_ipv6_positive_control", "wire")
        report["status"] = "passed"
    except Exception as exc:
        report["error"] = str(exc)
        report["status"] = ("expected_abort" if inject_failure and str(exc) ==
                            "intentional failure after live isolated firewall application" else "failed")
    finally:
        for probe in probes:
            probe.close()
        if peer is not None:
            peer.close()
            report["peer_process_reaped"] = peer.proc.poll() is not None
    print(json.dumps(report, indent=2), flush=True)
    return 0 if report["status"] in {"passed", "expected_abort"} else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-net", required=True)
    parser.add_argument("--host-user", required=True)
    parser.add_argument("--peer", action="store_true")
    parser.add_argument("--inject-failure", action="store_true")
    args = parser.parse_args()
    HOST_NET, HOST_USER, CURRENT_NET = args.host_net, args.host_user, ns()
    guard()
    if args.peer:
        peer_main()
    else:
        sys.exit(inner(args.inject_failure))
