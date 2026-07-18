import os

from agentsecure.crypto.cipher import LocalSecretCipher
from agentsecure.crypto.key_provider import LocalDeviceKeyProvider
from agentsecure.implementations.encrypted_secret_store import EncryptedLocalSecretStore
from agentsecure.interfaces.key_store import SecretStore


def agentsecure_home() -> str:
    return os.path.abspath(os.path.expanduser(os.environ.get("AGENTSECURE_HOME", "~/.agentsecure")))


def encrypted_secret_store_for_vault() -> SecretStore:
    base = os.path.join(agentsecure_home(), "vault")
    cipher = local_cipher_for_vault()
    return EncryptedLocalSecretStore(
        os.path.join(base, "secrets.enc.json"),
        cipher,
    )


def local_cipher_for_vault() -> LocalSecretCipher:
    base = os.path.join(agentsecure_home(), "vault")
    key_provider = LocalDeviceKeyProvider(os.path.join(base, "device.key"))
    return LocalSecretCipher(key_provider)


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
