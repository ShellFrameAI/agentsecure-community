import base64
import hashlib
import json
import os
import sys
from typing import Callable


WRAPPED_KEY_FORMAT = "agentsecure-wrapped-device-key"
WRAPPED_KEY_VERSION = 1
WRAPPED_KEY_AAD = b"AGENTSECURE-WRAPPED-KEY-1"
DEFAULT_SCRYPT_N = 2 ** 15
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1


class VaultKeyProviderError(RuntimeError):
    pass


class StaticDeviceKeyProvider:
    def __init__(self, encoded_key: bytes) -> None:
        self._encoded_key = bytes(encoded_key).strip()

    def get_or_create_key(self) -> bytes:
        return self._encoded_key


class WrappedDeviceKeyProvider:
    """Unlocks a device key with a passphrase obtained outside agent stdio."""

    def __init__(self, path: str, passphrase_reader: Callable[[], str] = None) -> None:
        self.path = path
        self._passphrase_reader = passphrase_reader or (
            lambda: read_passphrase_from_trusted_tty("AgentSecure vault passphrase: ")
        )
        self._encoded_key = None

    def get_or_create_key(self) -> bytes:
        if self._encoded_key is not None:
            return self._encoded_key
        if os.path.islink(self.path) or not os.path.isfile(self.path):
            raise VaultKeyProviderError("wrapped vault key is missing or is not a regular file")
        try:
            with open(self.path, "r") as handle:
                envelope = json.load(handle)
        except (OSError, ValueError) as exc:
            raise VaultKeyProviderError("failed to read wrapped vault key: %s" % exc)
        passphrase = self._passphrase_reader()
        try:
            self._encoded_key = unwrap_device_key(envelope, passphrase)
        finally:
            passphrase = None
        return self._encoded_key


def wrap_device_key(encoded_device_key: bytes, passphrase: str) -> dict:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise VaultKeyProviderError(
            "passphrase key protection requires the `cryptography` package; install AgentSecure from PyPI"
        )
    encoded_device_key = _validated_encoded_device_key(encoded_device_key)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    wrapping_key = _derive_wrapping_key(passphrase, salt, DEFAULT_SCRYPT_N, DEFAULT_SCRYPT_R, DEFAULT_SCRYPT_P)
    ciphertext = AESGCM(wrapping_key).encrypt(nonce, encoded_device_key, WRAPPED_KEY_AAD)
    return {
        "cipher": "aes-256-gcm",
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        "format": WRAPPED_KEY_FORMAT,
        "kdf": {
            "name": "scrypt",
            "n": DEFAULT_SCRYPT_N,
            "p": DEFAULT_SCRYPT_P,
            "r": DEFAULT_SCRYPT_R,
            "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
        },
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "version": WRAPPED_KEY_VERSION,
    }


def unwrap_device_key(envelope: dict, passphrase: str) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise VaultKeyProviderError(
            "passphrase key protection requires the `cryptography` package; install AgentSecure from PyPI"
        )
    if not isinstance(envelope, dict) or envelope.get("format") != WRAPPED_KEY_FORMAT:
        raise VaultKeyProviderError("unsupported wrapped vault key format")
    if envelope.get("version") != WRAPPED_KEY_VERSION:
        raise VaultKeyProviderError("unsupported wrapped vault key version")
    if envelope.get("cipher") != "aes-256-gcm":
        raise VaultKeyProviderError("unsupported wrapped vault key cipher")
    kdf = envelope.get("kdf", {})
    if not isinstance(kdf, dict) or kdf.get("name") != "scrypt":
        raise VaultKeyProviderError("unsupported wrapped vault key derivation")
    try:
        n = int(kdf.get("n", 0))
        r = int(kdf.get("r", 0))
        p = int(kdf.get("p", 0))
        if n != DEFAULT_SCRYPT_N or r != DEFAULT_SCRYPT_R or p != DEFAULT_SCRYPT_P:
            raise VaultKeyProviderError("unsupported wrapped vault key scrypt parameters")
        salt = _decode_urlsafe_field(kdf.get("salt", ""))
        nonce = _decode_urlsafe_field(envelope.get("nonce", ""))
        ciphertext = _decode_urlsafe_field(envelope.get("ciphertext", ""))
    except VaultKeyProviderError:
        raise
    except Exception as exc:
        raise VaultKeyProviderError("wrapped vault key encoding is invalid: %s" % exc)
    if len(salt) != 16 or len(nonce) != 12 or len(ciphertext) < 16:
        raise VaultKeyProviderError("wrapped vault key payload is invalid")
    wrapping_key = _derive_wrapping_key(passphrase, salt, n, r, p)
    try:
        encoded_device_key = AESGCM(wrapping_key).decrypt(nonce, ciphertext, WRAPPED_KEY_AAD)
    except Exception:
        raise VaultKeyProviderError("vault passphrase is incorrect or the wrapped key was modified")
    return _validated_encoded_device_key(encoded_device_key, "unwrapped device key")


def read_passphrase_from_trusted_tty(prompt: str) -> str:
    if os.name == "nt":
        value = _read_passphrase_from_windows_console(prompt)
    else:
        import termios

        try:
            with open("/dev/tty", "r+") as tty:
                if not os.isatty(tty.fileno()):
                    raise VaultKeyProviderError("the controlling terminal is not interactive")
                tty.write(prompt)
                tty.flush()
                original = termios.tcgetattr(tty.fileno())
                hidden = termios.tcgetattr(tty.fileno())
                hidden[3] &= ~termios.ECHO
                try:
                    termios.tcsetattr(tty.fileno(), termios.TCSADRAIN, hidden)
                    value = tty.readline()
                finally:
                    termios.tcsetattr(tty.fileno(), termios.TCSADRAIN, original)
                    tty.write("\n")
                    tty.flush()
                value = value.rstrip("\r\n")
        except (OSError, termios.error):
            raise VaultKeyProviderError(
                "vault is locked and no interactive TTY is available; unlock it from a user terminal"
            )
    if not value:
        raise VaultKeyProviderError("vault passphrase cannot be empty")
    return value


def _read_passphrase_from_windows_console(prompt: str) -> str:
    try:
        import msvcrt
    except ImportError:
        raise VaultKeyProviderError("a trusted Windows console is not available")
    sys.stderr.write(prompt)
    sys.stderr.flush()
    characters = []
    while True:
        character = msvcrt.getwch()
        if character in ("\r", "\n"):
            break
        if character == "\x03":
            raise KeyboardInterrupt
        if character == "\b":
            if characters:
                characters.pop()
            continue
        if character in ("\x00", "\xe0"):
            msvcrt.getwch()
            continue
        characters.append(character)
    sys.stderr.write("\n")
    sys.stderr.flush()
    return "".join(characters)


def _derive_wrapping_key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise VaultKeyProviderError("vault passphrase cannot be empty")
    try:
        return hashlib.scrypt(
            passphrase.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=32,
            maxmem=64 * 1024 * 1024,
        )
    except (TypeError, ValueError) as exc:
        raise VaultKeyProviderError("failed to derive wrapped vault key: %s" % exc)


def _decode_urlsafe_field(value) -> bytes:
    if not isinstance(value, str):
        raise VaultKeyProviderError("wrapped vault key encoding is invalid")
    try:
        return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except Exception:
        raise VaultKeyProviderError("wrapped vault key encoding is invalid")


def _validated_encoded_device_key(encoded_key: bytes, label: str = "device key") -> bytes:
    try:
        encoded_key = bytes(encoded_key).strip()
        raw_key = base64.b64decode(encoded_key, altchars=b"-_", validate=True)
    except Exception:
        raise VaultKeyProviderError("%s is not valid base64" % label)
    if len(raw_key) != 32:
        raise VaultKeyProviderError("%s must decode to 32 bytes" % label)
    return encoded_key
