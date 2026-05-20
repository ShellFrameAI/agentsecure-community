import json
import os
import tempfile
from typing import Dict, Optional

from agentsecure.interfaces.key_store import SecretStore


class LocalJsonSecretStore(SecretStore):
    """Minimal local secret store for MVP development.

    The file is chmodded to 0600. This is not a replacement for OS keychains,
    but it keeps real secrets out of agent-visible config and stdout.
    """

    def __init__(self, path: str = ".agentsecure/secrets.json") -> None:
        self._path = path

    def put(self, secret_id: str, secret_value: str) -> None:
        data = self._read()
        data[secret_id] = secret_value
        self._write(data)

    def get(self, secret_id: str) -> Optional[str]:
        return self._read().get(secret_id)

    def _read(self) -> Dict[str, str]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path, "r") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            return {}
        result = {}
        for key, value in data.items():
            result[str(key)] = str(value)
        return result

    def _write(self, data: Dict[str, str]) -> None:
        directory = os.path.dirname(self._path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".secrets-", dir=directory)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.replace(temp_path, self._path)
            os.chmod(self._path, 0o600)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

