import base64
import os

from agentsecure.crypto.key_provider import LocalDeviceKeyProvider


class AeadCipherUnavailable(RuntimeError):
    pass


def aead_available() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    except ImportError:
        return False
    return True


class AeadSecretCipher:
    """AES-256-GCM authenticated encryption for version-two vault records."""

    VERSION = b"AGENTSECURE2"
    NAME = "aes-256-gcm-v2"

    def __init__(self, key_provider: LocalDeviceKeyProvider) -> None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise AeadCipherUnavailable(
                "AES-256-GCM support requires the `cryptography` package; install AgentSecure from PyPI"
            )
        key = base64.urlsafe_b64decode(key_provider.get_or_create_key())
        if len(key) != 32:
            raise ValueError("AgentSecure device key must decode to 32 bytes")
        self._cipher = AESGCM(key)

    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(12)
        ciphertext = self._cipher.encrypt(nonce, plaintext.encode("utf-8"), self.VERSION)
        return base64.urlsafe_b64encode(self.VERSION + nonce + ciphertext).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        raw = base64.urlsafe_b64decode(ciphertext.encode("ascii"))
        version_len = len(self.VERSION)
        if raw[:version_len] != self.VERSION:
            raise ValueError("unsupported AEAD ciphertext version")
        nonce = raw[version_len : version_len + 12]
        encrypted = raw[version_len + 12 :]
        if len(nonce) != 12 or len(encrypted) < 16:
            raise ValueError("invalid AEAD ciphertext")
        plaintext = self._cipher.decrypt(nonce, encrypted, self.VERSION)
        return plaintext.decode("utf-8")
