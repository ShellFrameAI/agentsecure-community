import base64
import hmac
import hashlib
import os

from agentsecure.crypto.key_provider import LocalDeviceKeyProvider


class LocalSecretCipher:
    """Authenticated local encryption for secret values.

    This uses a local 256-bit device key, a random nonce, HMAC-SHA256
    authentication, and an HMAC-derived XOR stream. The key never leaves the
    machine. This keeps the single-file trial dependency-free; enterprise
    builds can swap this implementation for OS keychain or KMS-backed crypto.
    """

    VERSION = b"AGENTSECURE1"

    def __init__(self, key_provider: LocalDeviceKeyProvider) -> None:
        self._key_provider = key_provider
        self._key = None

    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(16)
        plaintext_bytes = plaintext.encode("utf-8")
        ciphertext = self._xor(plaintext_bytes, self._keystream(nonce, len(plaintext_bytes)))
        mac = self._mac(nonce, ciphertext)
        return base64.urlsafe_b64encode(self.VERSION + nonce + mac + ciphertext).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        raw = base64.urlsafe_b64decode(ciphertext.encode("ascii"))
        version_len = len(self.VERSION)
        if raw[:version_len] != self.VERSION:
            raise ValueError("unsupported secret ciphertext version")
        nonce = raw[version_len : version_len + 16]
        mac = raw[version_len + 16 : version_len + 48]
        encrypted = raw[version_len + 48 :]
        expected_mac = self._mac(nonce, encrypted)
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("secret ciphertext authentication failed")
        plaintext = self._xor(encrypted, self._keystream(nonce, len(encrypted)))
        return plaintext.decode("utf-8")

    def _keystream(self, nonce: bytes, size: int) -> bytes:
        key = self._key_bytes()
        output = b""
        counter = 0
        while len(output) < size:
            counter_bytes = counter.to_bytes(8, "big")
            output += hmac.new(key, b"stream" + nonce + counter_bytes, hashlib.sha256).digest()
            counter += 1
        return output[:size]

    def _mac(self, nonce: bytes, ciphertext: bytes) -> bytes:
        return hmac.new(self._key_bytes(), b"mac" + nonce + ciphertext, hashlib.sha256).digest()

    def _key_bytes(self) -> bytes:
        if self._key is None:
            key = base64.urlsafe_b64decode(self._key_provider.get_or_create_key())
            if len(key) != 32:
                raise ValueError("AgentSecure device key must decode to 32 bytes")
            self._key = key
        return self._key

    def _xor(self, left: bytes, right: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(left, right))
