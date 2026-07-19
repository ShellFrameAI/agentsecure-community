import os
import tempfile
import unittest

from agentsecure.crypto.aead_cipher import AeadSecretCipher
from agentsecure.crypto.key_provider import LocalDeviceKeyProvider


class AeadSecretCipherTest(unittest.TestCase):
    def test_aes_gcm_round_trip_uses_random_nonces(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cipher = AeadSecretCipher(LocalDeviceKeyProvider(os.path.join(temp_dir, "device.key")))

            first = cipher.encrypt("dummy-value")
            second = cipher.encrypt("dummy-value")

            self.assertNotEqual(first, second)
            self.assertEqual("dummy-value", cipher.decrypt(first))
            self.assertEqual("dummy-value", cipher.decrypt(second))

    def test_aes_gcm_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cipher = AeadSecretCipher(LocalDeviceKeyProvider(os.path.join(temp_dir, "device.key")))
            ciphertext = cipher.encrypt("dummy-value")
            tampered = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]

            with self.assertRaises(Exception):
                cipher.decrypt(tampered)


if __name__ == "__main__":
    unittest.main()
