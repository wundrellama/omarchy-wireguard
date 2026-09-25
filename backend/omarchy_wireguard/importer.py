import base64
import configparser
import fcntl
import io
import ipaddress
import os
import re
import stat
import struct
import zipfile
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Iterable

from .constants import MAX_ARCHIVE, MAX_FILES, MAX_MEMBER

MAX_TRAVERSAL = 1024
MAX_ZIP_METADATA = 1024 * 1024


class ImportFailure(ValueError):
    pass


@dataclass(frozen=True)
class Profile:
    source_name: str
    country: str
    city: str
    endpoint_host: str
    endpoint_port: int
    config: str = field(repr=False)
    label: str = ""
    role: str = "internet-exit"

    @property
    def city_key(self) -> str:
        return f"{self.country}/{self.city}"


SECRET_KEYS = {"privatekey", "presharedkey"}
INTERFACE_KEYS = {
    "privatekey": "PrivateKey", "address": "Address", "dns": "DNS",
    "listenport": "ListenPort", "mtu": "MTU",
}
PEER_KEYS = {
    "publickey": "PublicKey", "presharedkey": "PresharedKey",
    "allowedips": "AllowedIPs", "endpoint": "Endpoint",
    "persistentkeepalive": "PersistentKeepalive",
}
COUNTRY_CODES = {
    "au": "Australia", "at": "Austria", "be": "Belgium", "br": "Brazil",
    "ca": "Canada", "ch": "Switzerland", "de": "Germany", "dk": "Denmark",
    "es": "Spain", "fi": "Finland", "fr": "France", "gb": "United Kingdom",
    "hk": "Hong Kong", "ie": "Ireland", "in": "India", "it": "Italy",
    "jp": "Japan", "mx": "Mexico", "nl": "Netherlands", "no": "Norway",
    "nz": "New Zealand", "pl": "Poland", "pt": "Portugal", "ro": "Romania",
    "se": "Sweden", "sg": "Singapore", "us": "United States",
}


def _safe_name(name: str) -> PurePosixPath:
    if len(name.encode("utf-8")) > 255:
        raise ImportFailure("archive path is too long")
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ImportFailure("archive contains an unsafe path")
    return path


def read_path(path_text: str, owner_uid: int | None = None) -> list[tuple[str, bytes]]:
    owner_uid = os.geteuid() if owner_uid is None else owner_uid
    path = Path(path_text)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise ImportFailure("source cannot be opened without following links") from exc
    try:
        info = os.fstat(descriptor)
        if info.st_uid != owner_uid or info.st_mode & 0o022:
            raise ImportFailure("source must be owned by the controller and not group/world writable")
        if stat.S_ISREG(info.st_mode):
            if info.st_size > MAX_ARCHIVE:
                raise ImportFailure("source is too large")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                return [(path.name, stream.read(MAX_ARCHIVE + 1))]
        if not stat.S_ISDIR(info.st_mode):
            raise ImportFailure("source must be a regular file or directory")
        return _read_directory(descriptor, owner_uid)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_source_fd(descriptor: int, name: str, owner_uid: int) -> list[tuple[str, bytes]]:
    if not isinstance(name, str) or not name or PurePosixPath(name).name != name:
        raise ImportFailure("source name must be one safe filename")
    try:
        info = os.fstat(descriptor)
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    except OSError as exc:
        raise ImportFailure("source descriptor cannot be inspected") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ImportFailure("source descriptor must reference a regular file")
    if info.st_uid != owner_uid or info.st_mode & 0o022:
        raise ImportFailure("source must be owned by the controller and not group/world writable")
    if flags & os.O_ACCMODE == os.O_WRONLY:
        raise ImportFailure("source descriptor must be readable")
    if info.st_size > MAX_ARCHIVE:
        raise ImportFailure("source is too large")
    try:
        data = os.pread(descriptor, MAX_ARCHIVE + 1, 0)
    except OSError as exc:
        raise ImportFailure("source descriptor cannot be read") from exc
    if len(data) > MAX_ARCHIVE:
        raise ImportFailure("source is too large")
    return [(name, data)]


def _read_directory(directory_fd: int, owner_uid: int) -> list[tuple[str, bytes]]:
    result: list[tuple[str, bytes]] = []
    total = [0]
    visited = [0]

    def walk(current_fd: int, prefix: str, depth: int) -> None:
        if depth > 8:
            raise ImportFailure("directory nesting is too deep")
        names = []
        with os.scandir(current_fd) as entries:
            for entry in entries:
                visited[0] += 1
                if visited[0] > MAX_TRAVERSAL:
                    raise ImportFailure("too many directory entries")
                names.append(entry.name)
        for name in sorted(names):
            try:
                info = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
            except OSError as exc:
                raise ImportFailure("directory entry cannot be inspected safely") from exc
            relative = f"{prefix}/{name}" if prefix else name
            if stat.S_ISLNK(info.st_mode):
                raise ImportFailure("directory contains a link")
            if stat.S_ISDIR(info.st_mode):
                if info.st_uid != owner_uid or info.st_mode & 0o022:
                    raise ImportFailure("nested directory has unsafe ownership or permissions")
                try:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=current_fd)
                except OSError as exc:
                    raise ImportFailure("nested directory cannot be opened safely") from exc
                try:
                    walk(child, relative, depth + 1)
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ImportFailure("directory contains a special file")
            if not name.lower().endswith(".conf"):
                continue
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current_fd)
            except OSError as exc:
                raise ImportFailure("directory contains an unsafe configuration") from exc
            try:
                opened = os.fstat(fd)
                if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != owner_uid or
                        opened.st_mode & 0o022 or opened.st_size > MAX_MEMBER):
                    raise ImportFailure("configuration is not a safe regular file")
                total[0] += opened.st_size
                if total[0] > MAX_ARCHIVE:
                    raise ImportFailure("directory payload is too large")
                with os.fdopen(fd, "rb") as stream:
                    fd = -1
                    if len(result) >= MAX_FILES:
                        raise ImportFailure("too many files")
                    result.append((relative, stream.read(MAX_MEMBER + 1)))
            finally:
                if fd >= 0:
                    os.close(fd)

    # Every child is opened relative to the held descriptor with O_NOFOLLOW.
    walk(directory_fd, "", 0)
    if not result:
        raise ImportFailure("no WireGuard configurations found")
    return result


def decode_payload(args: dict, owner_uid: int | None = None,
                   source_fd: int | None = None) -> list[tuple[str, bytes]]:
    allowed = {"source", "data", "name", "locations", "network", "labels"}
    if set(args) - allowed:
        raise ImportFailure("unknown import argument")
    owner_uid = os.geteuid() if owner_uid is None else owner_uid
    if source_fd is not None:
        if args.get("source") != "fd" or "data" in args:
            raise ImportFailure("descriptor import must use source=fd without data")
        name = args.get("name", "upload.conf")
        files = read_source_fd(source_fd, name, owner_uid)
    else:
        if args.get("source") == "fd" or "source" in args:
            raise ImportFailure("source descriptor is required")
        if (not isinstance(args.get("data"), str) or
                not isinstance(args.get("name", "upload.conf"), str)):
            raise ImportFailure("invalid payload")
        try:
            data = base64.b64decode(args["data"], validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ImportFailure("payload is not valid base64") from exc
        if len(data) > MAX_ARCHIVE:
            raise ImportFailure("payload is too large")
        files = [(args.get("name", "upload.conf"), data)]
    return expand_archives(files)


def _preflight_zip(data: bytes) -> int:
    minimum = 22
    start = max(0, len(data) - (65535 + minimum))
    index = data.rfind(b"PK\x05\x06", start)
    while index >= start:
        if index + minimum <= len(data):
            try:
                (_signature, disk, directory_disk, entries_disk, entries_total,
                 directory_size, directory_offset, comment_size) = struct.unpack_from(
                     "<4s4H2LH", data, index)
            except struct.error:
                pass
            else:
                if index + minimum + comment_size == len(data):
                    if (disk or directory_disk or entries_disk != entries_total or
                            entries_total == 0xFFFF or directory_size == 0xFFFFFFFF or
                            directory_offset == 0xFFFFFFFF):
                        raise ImportFailure("ZIP archive layout is unsupported")
                    if entries_total > MAX_FILES:
                        raise ImportFailure("archive has too many entries")
                    if directory_size > MAX_ZIP_METADATA:
                        raise ImportFailure("archive metadata is too large")
                    if directory_offset + directory_size > index:
                        raise ImportFailure("invalid ZIP archive")
                    return entries_total
        index = data.rfind(b"PK\x05\x06", start, index)
    raise ImportFailure("invalid ZIP archive")


def expand_archives(files: Iterable[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
    output: list[tuple[str, bytes]] = []
    for name, data in files:
        if name.lower().endswith(".zip") or data.startswith(b"PK\x03\x04"):
            try:
                _preflight_zip(data)
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    infos = archive.infolist()
                    if len(infos) > MAX_FILES:
                        raise ImportFailure("archive has too many entries")
                    total = 0
                    for info in infos:
                        safe = _safe_name(info.filename)
                        mode = info.external_attr >> 16
                        if info.is_dir():
                            continue
                        if stat.S_ISLNK(mode) or not safe.name.lower().endswith(".conf"):
                            if stat.S_ISLNK(mode):
                                raise ImportFailure("archive contains a link")
                            continue
                        if info.file_size > MAX_MEMBER or info.compress_size == 0 and info.file_size:
                            raise ImportFailure("archive member is unsafe")
                        total += info.file_size
                        if total > MAX_ARCHIVE:
                            raise ImportFailure("expanded archive is too large")
                        output.append((str(safe), archive.read(info)))
            except (zipfile.BadZipFile, RuntimeError) as exc:
                raise ImportFailure("invalid ZIP archive") from exc
        elif name.lower().endswith(".conf"):
            if len(data) > MAX_MEMBER:
                raise ImportFailure("configuration is too large")
            output.append((name, data))
    if not output:
        raise ImportFailure("no WireGuard configurations found")
    return output


def parse_profiles(files: Iterable[tuple[str, bytes]], locations: dict | None = None,
                   labels: dict | None = None) -> tuple[list[Profile], list[str]]:
    profiles: list[Profile] = []
    ambiguous: list[str] = []
    if locations is not None and not isinstance(locations, dict):
        raise ImportFailure("locations must be an object")
    locations = locations or {}
    if labels is not None and not isinstance(labels, dict):
        raise ImportFailure("labels must be an object")
    labels = labels or {}
    files = list(files)
    names = {name for name, _raw in files}
    if set(labels) - names:
        raise ImportFailure("labels must use exact source_name keys from this batch")
    for label in labels.values():
        if (not isinstance(label, str) or not label.strip() or len(label) > 128 or
                not label.isprintable()):
            raise ImportFailure("label must be nonempty printable text of at most 128 characters")
    for name, raw in files:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ImportFailure(f"{name}: configuration is not UTF-8") from exc
        profile = parse_config(name, text)
        if name in labels:
            profile = replace(profile, label=labels[name])
        location = locations.get(name)
        if location is not None:
            if not isinstance(location, dict) or set(location) != {"country", "city"}:
                raise ImportFailure(f"{name}: invalid location review")
            profile = replace(profile, country=_location(location["country"], name in labels),
                              city=_location(location["city"], name in labels))
        if (not profile.country or not profile.city) and name not in labels:
            ambiguous.append(name)
        profiles.append(profile)
    return profiles, ambiguous


def _location(value: object, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9 .'-]{2,64}", value):
        raise ImportFailure("invalid location")
    return value.strip()


def infer_location(name: str, endpoint: str) -> tuple[str, str]:
    # TorGuard assumption: infer location from country/city tokens in filenames and endpoint hosts.
    tokens = [token for token in re.split(r"[^a-z0-9]+", f"{name} {endpoint}".lower()) if token]
    countries = [(index, COUNTRY_CODES[token]) for index, token in enumerate(tokens) if token in COUNTRY_CODES]
    if len({country for _, country in countries}) != 1:
        return "", ""
    index, country = countries[0]
    ignored = {"wireguard", "wg", "torguard", "conf", "vpn", "prod"} | set(COUNTRY_CODES)
    candidates = []
    for token in tokens[index + 1:index + 4]:
        if token in ignored or token.isdigit():
            break
        candidates.append(token)
    if not candidates:
        candidates = [token for token in tokens[max(0, index - 2):index]
                      if token not in ignored and not token.isdigit()]
    return (country, " ".join(candidates).title()) if candidates else (country, "")


def parse_config(name: str, text: str) -> Profile:
    parser = configparser.ConfigParser(interpolation=None, strict=True, comment_prefixes=("#", ";"))
    parser.optionxform = str
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise ImportFailure(f"{name}: invalid INI") from exc
    if parser.sections() != ["Interface", "Peer"]:
        raise ImportFailure(f"{name}: requires exactly one Interface followed by exactly one Peer")
    interface = _canonical_section(name, parser["Interface"], INTERFACE_KEYS)
    peer = _canonical_section(name, parser["Peer"], PEER_KEYS)
    if "PrivateKey" not in interface:
        raise ImportFailure(f"{name}: missing private key")
    if "PublicKey" not in peer:
        raise ImportFailure(f"{name}: missing peer public key")
    if "Address" not in interface:
        raise ImportFailure(f"{name}: missing interface address")
    try:
        addresses = [ipaddress.ip_interface(item.strip()) for item in interface["Address"].split(",")]
    except ValueError as exc:
        raise ImportFailure(f"{name}: invalid interface address") from exc
    if not addresses:
        raise ImportFailure(f"{name}: missing interface address")
    if "DNS" not in interface:
        raise ImportFailure(f"{name}: missing DNS server")
    try:
        dns_servers = [str(ipaddress.ip_address(item.strip())) for item in interface["DNS"].split(",")]
    except ValueError as exc:
        raise ImportFailure(f"{name}: invalid DNS server") from exc
    if not dns_servers:
        raise ImportFailure(f"{name}: missing DNS server")
    allowed_text = peer.get("AllowedIPs", "")
    try:
        allowed = [ipaddress.ip_network(item.strip(), strict=False) for item in allowed_text.split(",") if item.strip()]
    except ValueError as exc:
        raise ImportFailure(f"{name}: invalid allowed IPs") from exc
    if ipaddress.ip_network("0.0.0.0/0") not in allowed:
        raise ImportFailure(f"{name}: peer must include the IPv4 default route")
    endpoint = peer.get("Endpoint", "")
    host, port = _endpoint(endpoint, name)
    if not interface["PrivateKey"].strip() or ("PresharedKey" in peer and not peer["PresharedKey"].strip()):
        raise ImportFailure(f"{name}: empty secret")
    interface["DNS"] = ", ".join(dns_servers)
    peer["PersistentKeepalive"] = "25"
    output = _render_config(interface, peer)
    country, city = infer_location(name, host)
    return Profile(name, country, city, host, port, output, PurePosixPath(name).stem)


def _canonical_section(name: str, section: configparser.SectionProxy,
                       allowed: dict[str, str]) -> dict[str, str]:
    output = {}
    seen = set()
    for key, value in section.items():
        lowered = key.lower()
        if lowered in seen:
            raise ImportFailure(f"{name}: duplicate option")
        seen.add(lowered)
        canonical = allowed.get(lowered)
        if canonical is None:
            raise ImportFailure(f"{name}: unsupported WireGuard option")
        if "\n" in value or "\r" in value:
            raise ImportFailure(f"{name}: multiline values are unsupported")
        output[canonical] = value.strip()
    return output


def _render_config(interface: dict[str, str], peer: dict[str, str]) -> str:
    interface_order = ("PrivateKey", "Address", "DNS", "ListenPort", "MTU")
    peer_order = ("PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive")
    lines = ["[Interface]"]
    lines.extend(f"{key} = {interface[key]}" for key in interface_order if key in interface)
    lines.extend(("", "[Peer]"))
    lines.extend(f"{key} = {peer[key]}" for key in peer_order if key in peer)
    return "\n".join(lines) + "\n"


def _endpoint(value: str, name: str) -> tuple[str, int]:
    value = value.strip()
    try:
        if value.startswith("["):
            host, port_text = value[1:].split("]:", 1)
            ipaddress.IPv6Address(host)
        else:
            host, port_text = value.rsplit(":", 1)
        port = int(port_text)
        if not host or not 1 <= port <= 65535:
            raise ValueError
    except ValueError as exc:
        raise ImportFailure(f"{name}: invalid endpoint") from exc
    if not re.fullmatch(r"[A-Za-z0-9:._-]+", host):
        raise ImportFailure(f"{name}: invalid endpoint host")
    return host, port
