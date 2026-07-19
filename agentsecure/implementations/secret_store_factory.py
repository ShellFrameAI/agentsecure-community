import os
import json

from agentsecure.crypto.aead_cipher import AeadSecretCipher, aead_available
from agentsecure.crypto.cipher import LocalSecretCipher
from agentsecure.crypto.key_provider import LocalDeviceKeyProvider
from agentsecure.implementations.encrypted_secret_store import EncryptedLocalSecretStore
from agentsecure.interfaces.key_store import SecretStore


def agentsecure_home() -> str:
    return os.path.abspath(os.path.expanduser(os.environ.get("AGENTSECURE_HOME", "~/.agentsecure")))


def encrypted_secret_store_for_vault() -> SecretStore:
    base = os.path.join(agentsecure_home(), "vault")
    store_path = os.path.join(base, "secrets.enc.json")
    format_version = detected_vault_format(store_path)
    if format_version not in (1, 2):
        raise RuntimeError("vault contains an unsupported, corrupt, or mixed record format")
    ciphers = local_ciphers_for_vault(create=not os.path.exists(store_path))
    if format_version == 2:
        cipher_name = AeadSecretCipher.NAME
        record_version = 2
    else:
        cipher_name = "agentsecure-local-v1"
        record_version = 1
    if cipher_name not in ciphers:
        raise RuntimeError(
            "vault format v%s requires the `cryptography` package; install AgentSecure from PyPI"
            % format_version
        )
    cipher = ciphers[cipher_name]
    return EncryptedLocalSecretStore(
        store_path,
        cipher,
        cipher_name=cipher_name,
        record_version=record_version,
        read_ciphers=ciphers,
    )


def local_cipher_for_vault() -> LocalSecretCipher:
    base = os.path.join(agentsecure_home(), "vault")
    key_provider = LocalDeviceKeyProvider(os.path.join(base, "device.key"))
    return LocalSecretCipher(key_provider)


def local_ciphers_for_vault(create: bool = True) -> dict:
    base = os.path.join(agentsecure_home(), "vault")
    key_path = os.path.join(base, "device.key")
    if not create:
        if os.path.islink(key_path) or not os.path.isfile(key_path):
            raise RuntimeError("vault device key is missing or is not a regular file")
    key_provider = LocalDeviceKeyProvider(key_path)
    ciphers = {"agentsecure-local-v1": LocalSecretCipher(key_provider)}
    if aead_available():
        ciphers[AeadSecretCipher.NAME] = AeadSecretCipher(key_provider)
    return ciphers


def detected_vault_format(store_path: str = "") -> int:
    path = store_path or os.path.join(agentsecure_home(), "vault", "secrets.enc.json")
    if not os.path.exists(path):
        return 2 if aead_available() else 1
    try:
        with open(path, "r") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return 0
    if not isinstance(data, dict):
        return 0
    if not data:
        manifest_path = os.path.join(os.path.dirname(path), "manifest.json")
        try:
            with open(manifest_path, "r") as handle:
                manifest = json.load(handle)
            return int(manifest.get("format_version", 1))
        except (OSError, ValueError, TypeError):
            return 1
    formats = set()
    for item in data.values():
        if not isinstance(item, dict):
            return 0
        cipher_name = str(item.get("cipher", ""))
        try:
            record_version = int(item.get("version", 0))
        except (TypeError, ValueError):
            return 0
        if cipher_name == "agentsecure-local-v1" and record_version == 1:
            formats.add(1)
        elif cipher_name == AeadSecretCipher.NAME and record_version == 2:
            formats.add(2)
        else:
            return 0
    return formats.pop() if len(formats) == 1 else 0


def encrypted_secret_store_for_project(project_root: str = ".") -> SecretStore:
    base = os.path.abspath(project_root)
    key_provider = LocalDeviceKeyProvider(os.path.join(base, ".agentsecure", "device.key"))
    cipher = LocalSecretCipher(key_provider)
    return EncryptedLocalSecretStore(
        os.path.join(base, ".agentsecure", "secrets.enc.json"),
        cipher,
    )


def encrypted_secret_store_for_config(config_path: str) -> SecretStore:
    config_dir = os.path.dirname(os.path.abspath(config_path)) or "."
    return encrypted_secret_store_for_project(config_dir)
