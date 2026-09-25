#!/usr/bin/python3
"""Portal file chooser with unambiguous, bounded JSON path framing."""
import argparse
import importlib
import json
import os
import sys

ANSWER_TIMEOUT_SEC = 600
EXIT_NOTHING_PICKED = 1
EXIT_CHOOSER_FAILED = 2
MAX_PATHS = 512
MAX_PATH_LENGTH = 4096


def validate_paths(paths, directory):
    if not isinstance(paths, list) or not paths or len(paths) > MAX_PATHS:
        raise ValueError("invalid path count")
    if directory and len(paths) != 1:
        raise ValueError("directory selection requires one path")
    result = []
    for path in paths:
        if (not isinstance(path, str) or not path.startswith("/") or
                len(path) > MAX_PATH_LENGTH or any(char in path for char in ("\x00", "\r", "\n"))):
            raise ValueError("unsafe selected path")
        result.append(path)
    return result


def encode_paths(paths):
    return json.dumps(paths, ensure_ascii=True, separators=(",", ":"))


def local_path(uri_result):
    path, hostname = uri_result
    if hostname:
        raise ValueError("remote file URI is not allowed")
    return path


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--title", default="Select file")
    parser.add_argument("--multiple", action="store_true")
    parser.add_argument("--directory", action="store_true")
    parser.add_argument("--extensions", default="")
    args, unknown = parser.parse_known_args()
    if unknown:
        print("wireguard-file-picker: unknown option %s" % unknown[0], file=sys.stderr)
        return EXIT_CHOOSER_FAILED

    gi = importlib.import_module("gi")
    gi.require_version("Gio", "2.0")
    repository = importlib.import_module("gi.repository")
    Gio, GLib = repository.Gio, repository.GLib

    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    loop = GLib.MainLoop()
    uris = []

    def on_response(connection, sender, path, interface, signal, params):
        code, results = params.unpack()
        if code == 0:
            uris.extend(results.get("uris", []))
        loop.quit()

    def subscribe(path):
        bus.signal_subscribe(
            "org.freedesktop.portal.Desktop",
            "org.freedesktop.portal.Request",
            "Response",
            path,
            None,
            Gio.DBusSignalFlags.NONE,
            on_response,
        )

    token = "omarchywireguard%d" % os.getpid()
    sender = bus.get_unique_name()[1:].replace(".", "_")
    predicted = "/org/freedesktop/portal/desktop/request/%s/%s" % (sender, token)
    subscribe(predicted)

    options = {
        "handle_token": GLib.Variant("s", token),
        "multiple": GLib.Variant("b", args.multiple),
    }
    if args.directory:
        options["directory"] = GLib.Variant("b", True)
    if args.extensions and not args.directory:
        extensions = [item.lstrip(".").lower() for item in args.extensions.split()]
        patterns = [(0, "*." + item) for item in extensions] + [(0, "*." + item.upper()) for item in extensions]
        label = " ".join("*." + item for item in extensions)
        options["filters"] = GLib.Variant("a(sa(us))", [(label, patterns)])
        options["current_filter"] = GLib.Variant("(sa(us))", (label, patterns))

    handle = bus.call_sync(
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.FileChooser",
        "OpenFile",
        GLib.Variant("(ssa{sv})", ("", args.title, options)),
        None,
        Gio.DBusCallFlags.NONE,
        -1,
        None,
    ).unpack()[0]
    if handle != predicted:
        subscribe(handle)

    GLib.timeout_add_seconds(ANSWER_TIMEOUT_SEC, loop.quit)
    loop.run()
    if not uris:
        return EXIT_NOTHING_PICKED
    try:
        paths = validate_paths([local_path(GLib.filename_from_uri(uri)) for uri in uris], args.directory)
    except (TypeError, ValueError, GLib.Error) as exc:
        print("wireguard-file-picker: %s" % exc, file=sys.stderr)
        return EXIT_CHOOSER_FAILED
    print(encode_paths(paths))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print("wireguard-file-picker: %s" % error, file=sys.stderr)
        sys.exit(EXIT_CHOOSER_FAILED)
