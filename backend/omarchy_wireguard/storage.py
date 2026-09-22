import json
import os
import tempfile
from pathlib import Path
from typing import Any


class StateStore:
    def __init__(self, root: Path, owner_uid: int = 0):
        self.root = root
        self.owner_uid = owner_uid

    def prepare(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def read(self, name: str, default: Any) -> Any:
        path = self._path(name)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return default
        try:
            stat = os.fstat(fd)
            if not stat.st_mode & 0o170000 == 0o100000 or stat.st_uid != self.owner_uid:
                raise RuntimeError(f"unsafe state file: {name}")
            with os.fdopen(fd, "r", encoding="utf-8") as stream:
                fd = -1
                return json.load(stream)
        finally:
            if fd >= 0:
                os.close(fd)

    def write(self, name: str, value: Any) -> None:
        self.prepare()
        path = self._path(name)
        fd, temporary = tempfile.mkstemp(prefix=f".{name}.", dir=self.root)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                fd = -1
                json.dump(value, stream, separators=(",", ":"), sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _path(self, name: str) -> Path:
        if not name or "/" in name or name in (".", ".."):
            raise ValueError("invalid state file name")
        return self.root / name
