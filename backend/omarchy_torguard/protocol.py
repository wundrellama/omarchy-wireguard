import json
import socket
import struct
import time
from typing import Any

from .constants import MAX_REQUEST, MAX_RESPONSE, REQUEST_TIMEOUT


class ProtocolError(ValueError):
    pass


OPERATIONS = frozenset(
    {"status", "list", "import", "connect", "disconnect", "retry", "pause", "diagnostics"}
)


def peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise ProtocolError("SO_PEERCRED is unavailable")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def authorized(peer_uid: int, controller_uid: int) -> bool:
    return peer_uid in (0, controller_uid)


def read_request(connection: socket.socket) -> dict[str, Any]:
    deadline = time.monotonic() + REQUEST_TIMEOUT
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProtocolError("request timed out")
        connection.settimeout(remaining)
        try:
            chunk = connection.recv(min(65536, MAX_REQUEST + 1 - len(data)))
        except socket.timeout as exc:
            raise ProtocolError("request timed out") from exc
        if not chunk:
            raise ProtocolError("request ended before newline")
        data.extend(chunk)
        if len(data) > MAX_REQUEST:
            raise ProtocolError("request too large")
        newline = data.find(b"\n")
        if newline >= 0:
            if newline != len(data) - 1:
                raise ProtocolError("one request is allowed per connection")
            break
    try:
        request = json.loads(data[:-1].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid JSON") from exc
    if not isinstance(request, dict) or set(request) - {"op", "args", "request_id"}:
        raise ProtocolError("request must be an object with known fields")
    if request.get("op") not in OPERATIONS:
        raise ProtocolError("unknown operation")
    if "args" in request and not isinstance(request["args"], dict):
        raise ProtocolError("args must be an object")
    request.setdefault("args", {})
    return request


def send_response(connection: socket.socket, response: dict[str, Any]) -> None:
    encoded = json.dumps(response, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    if len(encoded) > MAX_RESPONSE:
        encoded = b'{"ok":false,"error":{"code":"response_too_large","message":"response too large"}}\n'
    connection.sendall(encoded)
