import json
import os
import tempfile
import unittest

from agentsecure.crypto.cipher import LocalSecretCipher
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


if __name__ == "__main__":
    unittest.main()
