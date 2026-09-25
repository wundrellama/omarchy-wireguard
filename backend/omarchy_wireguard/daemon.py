import argparse
import logging
import os
import pwd
import selectors
import signal
import socket
from pathlib import Path

from .constants import SOCKET_PATH, STATE_DIR
from .controller import Controller, RequestFailure, _dns_restore_state
from .protocol import ProtocolError, authorized, peer_credentials, read_request, send_response
from .storage import StateStore
from .system import HostSystem, SystemFailure

LOG = logging.getLogger("omarchy-wireguard")


def serve(controller_uid: int, socket_path: Path = SOCKET_PATH, state_dir: Path = STATE_DIR) -> None:
    if os.geteuid() != 0:
        raise SystemExit("daemon must run as root")
    store = StateStore(state_dir)
    store.prepare()
    controller = Controller(store, HostSystem(controller_uid=controller_uid), controller_uid=controller_uid)
    controller.boot()
    socket_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    group = pwd.getpwuid(controller_uid).pw_gid
    os.chown(socket_path, 0, group)
    os.chmod(socket_path, 0o660)
    server.listen(16)
    server.setblocking(False)
    selector = selectors.DefaultSelector()
    selector.register(server, selectors.EVENT_READ)
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    LOG.info("control service ready")
    try:
        while not stopping:
            for key, _ in selector.select(timeout=2):
                connection, _ = key.fileobj.accept()
                with connection:
                    _handle_connection(connection, controller, controller_uid)
            try:
                controller.tick()
            except SystemFailure:
                LOG.error("periodic safety check failed; emergency policy retained")
                controller.emergency()
    finally:
        selector.close()
        server.close()
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass


def _handle_connection(connection: socket.socket, controller: Controller, controller_uid: int) -> None:
    request_id = None
    source_fd = None
    try:
        # Only socket setup/read errors are transport failures. In particular,
        # an OSError raised by controller.handle must still fail closed below.
        try:
            _pid, uid, _gid = peer_credentials(connection)
            if not authorized(uid, controller_uid):
                raise ProtocolError("unauthorized peer")
            request, source_fd = read_request(connection)
        except OSError as exc:
            LOG.warning("request transport failed (%s)", type(exc).__name__)
            return
        request_id = request.get("request_id")
        if source_fd is None:
            result = controller.handle(request["op"], request["args"])
        else:
            result = controller.handle(request["op"], request["args"], source_fd=source_fd)
        response = {"ok": True, "request_id": request_id, "result": result}
    except (ProtocolError, RequestFailure) as exc:
        response = {"ok": False, "request_id": request_id,
                    "error": {"code": "rejected", "message": str(exc)}}
    except Exception as exc:
        # Inputs and subprocess output can contain secrets: log only the type,
        # without traceback, exception text, or client-supplied request ID.
        LOG.error("request failed internally (%s)", type(exc).__name__)
        controller.emergency()
        response = {"ok": False, "request_id": request_id,
                    "error": {"code": "internal", "message": "internal failure"}}
    finally:
        if source_fd is not None:
            try:
                os.close(source_fd)
            except OSError:
                pass
    try:
        send_response(connection, response)
    except OSError as exc:
        LOG.warning("response delivery failed (%s)", type(exc).__name__)


def fail_closed(state_dir: Path = STATE_DIR) -> None:
    if os.geteuid() != 0:
        raise SystemExit("fail-closed setup must run as root")
    system = HostSystem()
    store = StateStore(state_dir)
    reconcile_early_firewall(store, system)


def reconcile_early_firewall(store: StateStore, system: HostSystem) -> None:
    try:
        state = store.read("state.json", None)
        dns_restore = _dns_restore_state(store.read("dns.json", []))
        if state is None:
            if dns_restore:
                system.apply_quarantine()
            else:
                system.remove_firewall()
            return
        if (not isinstance(state, dict) or not isinstance(state.get("enabled"), bool) or
                (state["enabled"] and
                 (not isinstance(state.get("target"), str) or not state.get("target")))):
            raise ValueError("invalid state")
        if not state["enabled"]:
            if dns_restore:
                system.apply_quarantine()
            else:
                system.remove_firewall()
            return
        system.apply_quarantine()
    except Exception:
        # Missing state means first install; unreadable or malformed state is not equivalent
        # to an intentional disable and must remain conservative.
        system.apply_quarantine()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--controller-uid", type=int)
    parser.add_argument("--fail-closed", action="store_true")
    arguments = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(levelname)s: %(message)s")
    if arguments.fail_closed:
        fail_closed()
    elif arguments.controller_uid is None or arguments.controller_uid < 0:
        parser.error("--controller-uid is required and must be non-negative")
    else:
        serve(arguments.controller_uid)


if __name__ == "__main__":
    main()
