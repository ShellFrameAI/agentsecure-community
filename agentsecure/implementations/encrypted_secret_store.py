import json
import os
from typing import Dict, Optional

from agentsecure.crypto.cipher import LocalSecretCipher
from agentsecure.core.secure_files import write_private_json
from agentsecure.interfaces.key_store import SecretStore


class EncryptedLocalSecretStore(SecretStore):
    """Stores real secrets encrypted at rest with a local device key."""

    def __init__(
        self,
        path: str = ".agentsecure/secrets.enc.json",
        cipher: LocalSecretCipher = None,
    ) -> None:
        self._path = path
        self._cipher = cipher

    def put(self, secret_id: str, secret_value: str) -> None:
        data = self._read_raw()
        data[secret_id] = {
            "version": 1,
            "cipher": "agentsecure-local-v1",
            "ciphertext": self._cipher_or_raise().encrypt(secret_value),
        }
        self._write_raw(data)

    def get(self, secret_id: str) -> Optional[str]:
        item = self._read_raw().get(secret_id)
        if not isinstance(item, dict):
            return None
        ciphertext = str(item.get("ciphertext", ""))
        if not ciphertext:
            return None
        try:
            return self._cipher_or_raise().decrypt(ciphertext)
        except (ValueError, TypeError):
            return None

    def delete(self, secret_id: str) -> bool:
        data = self._read_raw()
        if secret_id not in data:
            return False
        del data[secret_id]
        self._write_raw(data)
        return True

    def _cipher_or_raise(self) -> LocalSecretCipher:
        if self._cipher is None:
            raise RuntimeError("encrypted secret store requires a cipher")
        return self._cipher

    def _read_raw(self) -> Dict[str, Dict[str, str]]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path, "r") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            return {}
        result = {}
        for key, value in data.items():
            if isinstance(value, dict):
                result[str(key)] = dict(value)
        return result

    def _write_raw(self, data: Dict[str, Dict[str, str]]) -> None:
        write_private_json(self._path, data, ".secrets-enc-")
