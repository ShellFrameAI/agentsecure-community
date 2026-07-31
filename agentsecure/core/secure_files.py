import json
import os
import tempfile
from typing import Any, Optional


PRIVATE_FILE_MODE = 0o600


def write_private_json(path: str, data: Any, temp_prefix: str) -> None:
    """Atomically write JSON with private POSIX permissions where supported."""

    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    raw_fd, temp_path = tempfile.mkstemp(prefix=temp_prefix, dir=directory)
    fd: Optional[int] = raw_fd
    try:
        fchmod = getattr(os, "fchmod", None)
        if callable(fchmod):
            fchmod(fd, PRIVATE_FILE_MODE)

        handle = os.fdopen(fd, "w")
        fd = None
        with handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")

        os.replace(temp_path, path)
        os.chmod(path, PRIVATE_FILE_MODE)
    finally:
        try:
            if fd is not None:
                os.close(fd)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
