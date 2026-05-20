import json
import os
import tempfile
import unittest

from agentsecure.core.key_service import KeyManagementService
from agentsecure.implementations.grant_store import LocalJsonGrantStore
from agentsecure.implementations.local_secret_store import LocalJsonSecretStore


class MemoryAudit:
    def __init__(self):
        self.events = []

    def record(self, event_type, details):
        self.events.append((event_type, details))


class KeyManagementServiceTest(unittest.TestCase):
    def test_create_key_stores_secret_and_writes_virtual_binding(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            store_path = os.path.join(temp_dir, "secrets.json")
            grants_path = os.path.join(temp_dir, "grants.json")
            audit = MemoryAudit()
            service = KeyManagementService(
                config_path,
                LocalJsonSecretStore(store_path),
                LocalJsonGrantStore(grants_path),
                audit,
            )

            result = service.create_key(
                env_name="OPENAI_API_KEY",
                real_secret="sk-real-secret",
                provider="openai",
                ttl="30m",
            )

            self.assertEqual("OPENAI_API_KEY", result["env_name"])
            self.assertTrue(result["virtual_token"].startswith("virt_openai_"))
            self.assertNotIn("sk-real-secret", json.dumps(result))

            with open(config_path, "r") as handle:
                config = json.load(handle)
            self.assertEqual("OPENAI_API_KEY", config["secrets"][0]["env_name"])
            self.assertEqual(result["virtual_token"], config["secrets"][0]["virtual_token"])
            self.assertEqual(result["secret_ref"], config["secrets"][0]["real_secret_ref"])
            self.assertIn("api.openai.com", config["network"]["allow_domains"])
            self.assertNotIn("sk-real-secret", json.dumps(config))

            secret_id = result["secret_ref"].split(":", 1)[1]
            self.assertEqual("sk-real-secret", LocalJsonSecretStore(store_path).get(secret_id))
            grant = LocalJsonGrantStore(grants_path).get_by_virtual_token(result["virtual_token"])
            self.assertIsNotNone(grant)
            self.assertEqual("active", grant.status)
            self.assertEqual(1800, result["ttl_seconds"])
            self.assertEqual("key_created", audit.events[0][0])


if __name__ == "__main__":
    unittest.main()
