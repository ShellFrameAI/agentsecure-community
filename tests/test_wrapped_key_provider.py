import base64
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from agentsecure.crypto.aead_cipher import AeadSecretCipher
from agentsecure.crypto.cipher import LocalSecretCipher
from agentsecure.crypto.wrapped_key_provider import (
    VaultKeyProviderError,
    WrappedDeviceKeyProvider,
    read_passphrase_from_trusted_tty,
    unwrap_device_key,
    wrap_device_key,
)


class WrappedKeyEnvelopeTest(unittest.TestCase):
    def setUp(self):
        self.encoded_key = base64.urlsafe_b64encode(bytes(range(32)))
        self.passphrase = "correct horse battery staple"

    def test_round_trip_uses_random_salt_nonce_and_hides_device_key(self):
        first = wrap_device_key(self.encoded_key, self.passphrase)
        second = wrap_device_key(self.encoded_key, self.passphrase)

        self.assertEqual(self.encoded_key, unwrap_device_key(first, self.passphrase))
        self.assertEqual(self.encoded_key, unwrap_device_key(second, self.passphrase))
        self.assertNotEqual(first["kdf"]["salt"], second["kdf"]["salt"])
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotIn(self.encoded_key.decode("ascii"), json.dumps(first))

    def test_wrong_passphrase_and_ciphertext_tampering_fail_closed(self):
        envelope = wrap_device_key(self.encoded_key, self.passphrase)
        with self.assertRaisesRegex(VaultKeyProviderError, "incorrect or.*modified"):
            unwrap_device_key(envelope, "incorrect passphrase")

        envelope["ciphertext"] = ("A" if envelope["ciphertext"][0] != "A" else "B") + envelope["ciphertext"][1:]
        with self.assertRaises(VaultKeyProviderError):
            unwrap_device_key(envelope, self.passphrase)

    def test_metadata_and_encoding_are_strictly_validated(self):
        mutations = (
            ("format", "unknown"),
            ("version", 99),
            ("cipher", "unknown"),
        )
        for field, value in mutations:
            envelope = wrap_device_key(self.encoded_key, self.passphrase)
            envelope[field] = value
            with self.subTest(field=field), self.assertRaises(VaultKeyProviderError):
                unwrap_device_key(envelope, self.passphrase)

        envelope = wrap_device_key(self.encoded_key, self.passphrase)
        envelope["kdf"]["n"] = 2 ** 14
        with self.assertRaisesRegex(VaultKeyProviderError, "scrypt parameters"):
            unwrap_device_key(envelope, self.passphrase)
        for path in (("nonce",), ("ciphertext",), ("kdf", "salt")):
            envelope = wrap_device_key(self.encoded_key, self.passphrase)
            if len(path) == 1:
                envelope[path[0]] = "not!base64"
            else:
                envelope[path[0]][path[1]] = "not!base64"
            with self.subTest(path=path), self.assertRaises(VaultKeyProviderError):
                unwrap_device_key(envelope, self.passphrase)

    def test_invalid_device_key_and_empty_passphrase_are_rejected(self):
        with self.assertRaisesRegex(VaultKeyProviderError, "32 bytes"):
            wrap_device_key(base64.urlsafe_b64encode(b"short"), self.passphrase)
        with self.assertRaisesRegex(VaultKeyProviderError, "valid base64"):
            wrap_device_key(b"not!base64", self.passphrase)
        with self.assertRaisesRegex(VaultKeyProviderError, "cannot be empty"):
            wrap_device_key(self.encoded_key, "")

    def test_provider_reads_passphrase_once_and_caches_only_unwrapped_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "device.key.wrap.json")
            with open(path, "w") as handle:
                json.dump(wrap_device_key(self.encoded_key, self.passphrase), handle)
            calls = []
            provider = WrappedDeviceKeyProvider(path, lambda: calls.append(True) or self.passphrase)

            self.assertEqual(self.encoded_key, provider.get_or_create_key())
            os.unlink(path)
            self.assertEqual(self.encoded_key, provider.get_or_create_key())
            self.assertEqual([True], calls)

    def test_provider_rejects_symlink(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            target = os.path.join(temp_dir, "target.json")
            link = os.path.join(temp_dir, "wrapped.json")
            with open(target, "w") as handle:
                json.dump(wrap_device_key(self.encoded_key, self.passphrase), handle)
            os.symlink(target, link)
            with self.assertRaisesRegex(VaultKeyProviderError, "regular file"):
                WrappedDeviceKeyProvider(link, lambda: self.passphrase).get_or_create_key()

    def test_ciphers_do_not_unlock_until_secret_data_is_used(self):
        calls = []
        provider = type("Provider", (), {"get_or_create_key": lambda instance: calls.append(True) or self.encoded_key})()
        v1 = LocalSecretCipher(provider)
        v2 = AeadSecretCipher(provider)
        self.assertEqual([], calls)

        v1.encrypt("value")
        v2.encrypt("value")
        self.assertEqual(2, len(calls))

    def test_missing_trusted_tty_never_falls_back_to_standard_input(self):
        with patch("builtins.open", side_effect=OSError("no tty")), patch(
            "sys.stdin.readline", side_effect=AssertionError("must not use stdin")
        ):
            with self.assertRaisesRegex(VaultKeyProviderError, "no interactive TTY"):
                read_passphrase_from_trusted_tty("Passphrase: ")


if __name__ == "__main__":
    unittest.main()
