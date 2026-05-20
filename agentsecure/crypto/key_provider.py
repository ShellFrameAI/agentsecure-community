import os
import base64


class LocalDeviceKeyProvider:
    """Creates and loads a local-only device encryption key."""

    def __init__(self, path: str = ".agentsecure/device.key") -> None:
        self._path = path

    @property
    def path(self) -> str:
        return self._path

    def get_or_create_key(self) -> bytes:
        if os.path.exists(self._path):
            return self._read_key()
        return self._create_key()

    def _read_key(self) -> bytes:
        with open(self._path, "rb") as handle:
            return handle.read().strip()

    def _create_key(self) -> bytes:
        directory = os.path.dirname(self._path) or "."
        os.makedirs(directory, exist_ok=True)
        key = base64.urlsafe_b64encode(os.urandom(32))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(self._path, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(key)
                handle.write(b"\n")
            os.chmod(self._path, 0o600)
        except Exception:
            if os.path.exists(self._path):
                os.unlink(self._path)
            raise
        return key
