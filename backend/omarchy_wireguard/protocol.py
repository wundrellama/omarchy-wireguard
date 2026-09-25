import array
import json
import os
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


def read_request(connection: socket.socket) -> tuple[dict[str, Any], int | None]:
    deadline = time.monotonic() + REQUEST_TIMEOUT
    data = bytearray()
    descriptors: list[int] = []
    integer_size = array.array("i").itemsize
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProtocolError("request timed out")
            connection.settimeout(remaining)
            try:
                chunk, ancillary, flags, _address = connection.recvmsg(
                    min(65536, MAX_REQUEST + 1 - len(data)),
                    socket.CMSG_SPACE(integer_size * 2),
                    getattr(socket, "MSG_CMSG_CLOEXEC", 0),
                )
            except socket.timeout as exc:
                raise ProtocolError("request timed out") from exc
            invalid_ancillary = False
            for level, kind, raw in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    usable = len(raw) - (len(raw) % integer_size)
                    if usable:
                        received = array.array("i")
                        received.frombytes(raw[:usable])
                        descriptors.extend(received)
                    if usable != len(raw):
                        invalid_ancillary = True
                else:
                    invalid_ancillary = True
            if flags & getattr(socket, "MSG_CTRUNC", 0):
                raise ProtocolError("descriptor data was truncated")
            if invalid_ancillary:
                raise ProtocolError("invalid descriptor data")
            if len(descriptors) > 1:
                raise ProtocolError("one source descriptor is allowed")
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
        source_fd = descriptors[0] if descriptors else None
        expects_fd = request["op"] == "import" and request["args"].get("source") == "fd"
        if expects_fd != (source_fd is not None):
            raise ProtocolError("source descriptor does not match the import request")
        if source_fd is not None and ({"data", "path"} & set(request["args"])):
            raise ProtocolError("descriptor import cannot include data or path")
        if source_fd is not None:
            os.set_inheritable(source_fd, False)
        return request, source_fd
    except Exception:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def send_response(connection: socket.socket, response: dict[str, Any]) -> None:
    encoded = json.dumps(response, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    if len(encoded) > MAX_RESPONSE:
        encoded = b'{"ok":false,"error":{"code":"response_too_large","message":"response too large"}}\n'
    connection.sendall(encoded)
