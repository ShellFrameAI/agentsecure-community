import json
import os
import tempfile
import unittest

from agentsecure.crypto.cipher import LocalSecretCipher
from agentsecure.crypto.aead_cipher import AeadSecretCipher
from agentsecure.crypto.key_provider import LocalDeviceKeyProvider
from agentsecure.implementations.encrypted_secret_store import EncryptedLocalSecretStore


class EncryptedLocalSecretStoreTest(unittest.TestCase):
    def test_encrypts_secret_at_rest_and_decrypts_with_local_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            key_path = os.path.join(temp_dir, ".agentsecure", "device.key")
            store_path = os.path.join(temp_dir, ".agentsecure", "secrets.enc.json")
            cipher = LocalSecretCipher(LocalDeviceKeyProvider(key_path))
            store = EncryptedLocalSecretStore(store_path, cipher)

            store.put("openai_1", "sk-real-secret")

            self.assertEqual("sk-real-secret", store.get("openai_1"))
            with open(store_path, "r") as handle:
                raw = handle.read()
            self.assertNotIn("sk-real-secret", raw)
            data = json.loads(raw)
            self.assertEqual("agentsecure-local-v1", data["openai_1"]["cipher"])
            self.assertTrue(os.path.exists(key_path))
            self.assertEqual(0, os.stat(key_path).st_mode & 0o077)
            self.assertEqual(0, os.stat(store_path).st_mode & 0o077)

    def test_dual_reader_opens_v1_and_v2_records_during_migration_window(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            key_path = os.path.join(temp_dir, "device.key")
            store_path = os.path.join(temp_dir, "secrets.enc.json")
            key_provider = LocalDeviceKeyProvider(key_path)
            v1 = LocalSecretCipher(key_provider)
            v2 = AeadSecretCipher(key_provider)
            with open(store_path, "w") as handle:
                json.dump(
                    {
                        "legacy": {
                            "version": 1,
                            "cipher": "agentsecure-local-v1",
                            "ciphertext": v1.encrypt("legacy-value"),
                        },
                        "current": {
                            "version": 2,
                            "cipher": AeadSecretCipher.NAME,
                            "ciphertext": v2.encrypt("current-value"),
                        },
                    },
                    handle,
                )

            store = EncryptedLocalSecretStore(
                store_path,
                v2,
                cipher_name=AeadSecretCipher.NAME,
                record_version=2,
                read_ciphers={"agentsecure-local-v1": v1, AeadSecretCipher.NAME: v2},
            )

            self.assertEqual("legacy-value", store.get("legacy"))
            self.assertEqual("current-value", store.get("current"))
            store.put("new", "new-value")
            with open(store_path, "r") as handle:
                data = json.load(handle)
            self.assertEqual(2, data["new"]["version"])
            self.assertEqual(AeadSecretCipher.NAME, data["new"]["cipher"])


if __name__ == "__main__":
    unittest.main()
