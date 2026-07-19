import os
import json

from agentsecure.crypto.aead_cipher import AeadSecretCipher, aead_available
from agentsecure.crypto.cipher import LocalSecretCipher
from agentsecure.crypto.key_provider import LocalDeviceKeyProvider
from agentsecure.crypto.wrapped_key_provider import WrappedDeviceKeyProvider
from agentsecure.implementations.encrypted_secret_store import EncryptedLocalSecretStore
from agentsecure.interfaces.key_store import SecretStore


_VAULT_KEY_PROVIDER_CACHE = {}


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
    return LocalSecretCipher(vault_key_provider(create=True))


def local_ciphers_for_vault(create: bool = True) -> dict:
    key_provider = vault_key_provider(create=create)
    ciphers = {"agentsecure-local-v1": LocalSecretCipher(key_provider)}
    if aead_available():
        ciphers[AeadSecretCipher.NAME] = AeadSecretCipher(key_provider)
    return ciphers


def vault_key_provider(create: bool = True):
    base = os.path.join(agentsecure_home(), "vault")
    raw_path = os.path.join(base, "device.key")
    wrapped_path = os.path.join(base, "device.key.wrap.json")
    raw_exists = os.path.isfile(raw_path) and not os.path.islink(raw_path)
    wrapped_exists = os.path.isfile(wrapped_path) and not os.path.islink(wrapped_path)
    if os.path.lexists(raw_path) and not raw_exists:
        raise RuntimeError("vault device key must be a regular, non-symbolic-link file")
    if os.path.lexists(wrapped_path) and not wrapped_exists:
        raise RuntimeError("wrapped vault key must be a regular, non-symbolic-link file")
    if raw_exists and wrapped_exists:
        raise RuntimeError(
            "vault has both raw and wrapped device keys; run `agentsecure vault key status` before continuing"
        )
    if wrapped_exists:
        provider_type = "passphrase_wrapped"
        provider_path = wrapped_path
    elif raw_exists or create:
        provider_type = "local_file"
        provider_path = raw_path
    else:
        raise RuntimeError("vault device key is missing")
    cache_key = (base, provider_type, provider_path)
    provider = _VAULT_KEY_PROVIDER_CACHE.get(cache_key)
    if provider is None:
        if provider_type == "passphrase_wrapped":
            provider = WrappedDeviceKeyProvider(provider_path)
        else:
            provider = LocalDeviceKeyProvider(provider_path)
        _VAULT_KEY_PROVIDER_CACHE.clear()
        _VAULT_KEY_PROVIDER_CACHE[cache_key] = provider
    return provider


def vault_key_provider_status() -> dict:
    base = os.path.join(agentsecure_home(), "vault")
    raw_path = os.path.join(base, "device.key")
    wrapped_path = os.path.join(base, "device.key.wrap.json")
    raw_exists = os.path.isfile(raw_path) and not os.path.islink(raw_path)
    wrapped_exists = os.path.isfile(wrapped_path) and not os.path.islink(wrapped_path)
    raw_invalid = os.path.lexists(raw_path) and not raw_exists
    wrapped_invalid = os.path.lexists(wrapped_path) and not wrapped_exists
    if raw_invalid or wrapped_invalid:
        provider = "invalid"
    elif raw_exists and wrapped_exists:
        provider = "ambiguous"
    elif wrapped_exists:
        provider = "passphrase_wrapped"
    elif raw_exists:
        provider = "local_file"
    else:
        provider = "missing"
    return {
        "provider": provider,
        "raw_key_exists": raw_exists,
        "raw_key_invalid": raw_invalid,
        "raw_key_path": raw_path,
        "wrapped_key_exists": wrapped_exists,
        "wrapped_key_invalid": wrapped_invalid,
        "wrapped_key_path": wrapped_path,
    }


def clear_vault_key_provider_cache() -> None:
    _VAULT_KEY_PROVIDER_CACHE.clear()


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
