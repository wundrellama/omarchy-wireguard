"""Atomic NM publication using libnm's keyfile parser and the supported D-Bus API.

No PyGObject dependency, subprocess secrets, temporary files, or writable /etc.
ABI signatures come from nm-keyfile.h, nm-connection.h and gdbusconnection.h.
"""
import ctypes as C


def publish_keyfile(text: str) -> None:
    """Validate entirely offline, then AddConnection2(TO_DISK|BLOCK_AUTOCONNECT)."""
    p, s, i, u = C.c_void_p, C.c_char_p, C.c_int, C.c_uint
    glib = C.CDLL('libglib-2.0.so.0')
    gio = C.CDLL('libgio-2.0.so.0')
    obj = C.CDLL('libgobject-2.0.so.0')
    nm = C.CDLL('libnm.so.0')

    def bind(lib, name, result, *args):
        f = getattr(lib, name)
        f.restype, f.argtypes = result, args
        return f

    key_new = bind(glib, 'g_key_file_new', p)
    key_load = bind(glib, 'g_key_file_load_from_data', i, p, s, C.c_size_t, i, p)
    key_free = bind(glib, 'g_key_file_unref', None, p)
    read = bind(nm, 'nm_keyfile_read', p, p, s, u, p, p, p)
    verify = bind(nm, 'nm_connection_verify', i, p, p)
    verify_secrets = bind(nm, 'nm_connection_verify_secrets', i, p, p)
    serialize = bind(nm, 'nm_connection_to_dbus', p, p, u)
    parse = bind(glib, 'g_variant_parse', p, p, s, p, p, p)
    uint = bind(glib, 'g_variant_new_uint32', p, u)
    tuple_new = bind(glib, 'g_variant_new_tuple', p, C.POINTER(p), C.c_size_t)
    sink = bind(glib, 'g_variant_ref_sink', p, p)
    unref = bind(glib, 'g_variant_unref', None, p)
    object_unref = bind(obj, 'g_object_unref', None, p)
    bus_get = bind(gio, 'g_bus_get_sync', p, i, p, p)
    call = bind(gio, 'g_dbus_connection_call_sync', p, p, s, s, s, s, p, p, i, i, p, p)
    key = key_new()
    connection = settings = parameters = extra = bus = reply = None
    try:
        data = text.encode('utf-8')
        # Never surface GLib/NM errors: they may quote secret values.
        if not key_load(key, data, len(data), 0, None):
            raise ValueError('invalid NetworkManager keyfile')
        connection = read(key, b'/', 0, None, None, None)
        if not connection or not verify(connection, None) or not verify_secrets(connection, None):
            raise ValueError('invalid NetworkManager WireGuard settings')
        settings = sink(serialize(connection, 0))  # NM_CONNECTION_SERIALIZE_ALL, includes secrets
        extra = parse(None, b'@a{sv} {}', None, None, None)
        parameters = sink(tuple_new((p * 3)(settings, uint(0x1 | 0x20), extra), 3))
        bus = bus_get(1, None, None)  # G_BUS_TYPE_SYSTEM
        if not bus:
            raise ValueError('NetworkManager system bus unavailable')
        reply = call(bus, b'org.freedesktop.NetworkManager',
                     b'/org/freedesktop/NetworkManager/Settings',
                     b'org.freedesktop.NetworkManager.Settings', b'AddConnection2',
                     parameters, None, 0, 10000, None, None)
        if not reply:
            raise ValueError('NetworkManager atomic profile publication failed')
    finally:
        if reply:
            unref(reply)
        if bus:
            object_unref(bus)
        if parameters:
            unref(parameters)
        if settings:
            unref(settings)
        if extra:
            unref(extra)  # g_variant_parse returns a non-floating reference
        if connection:
            object_unref(connection)
        key_free(key)
