import os
import tempfile
import unittest

from agentsecure.core.config import JsonConfigWriter
from agentsecure.guard.network import GuardedNetworkCommandPolicy


class GuardedNetworkCommandPolicyTest(unittest.TestCase):
    def test_allows_plain_curl_to_unknown_domain(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = self._config(temp_dir, [])
            policy = GuardedNetworkCommandPolicy(config_path)

            decision = policy.validate("curl", ["https://jsonplaceholder.typicode.com/posts/1"])

            self.assertIsNone(decision)

    def test_blocks_credential_curl_to_unknown_domain(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = self._config(temp_dir, [])
            policy = GuardedNetworkCommandPolicy(config_path)

            decision = policy.validate(
                "curl",
                [
                    "-H",
                    "Authorization: Bearer virt_custom_123",
                    "https://jsonplaceholder.typicode.com/posts/1",
                ],
            )

            self.assertIsNotNone(decision)
            self.assertFalse(decision.allowed)
            self.assertEqual("network.allow_domain", decision.rule_id)

    def test_allows_credential_curl_to_allowed_domain(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = self._config(temp_dir, ["jsonplaceholder.typicode.com"])
            policy = GuardedNetworkCommandPolicy(config_path)

            decision = policy.validate(
                "curl",
                [
                    "-H",
                    "Authorization: Bearer virt_custom_123",
                    "https://jsonplaceholder.typicode.com/posts/1",
                ],
            )

            self.assertIsNone(decision)

    def _config(self, temp_dir, allow_domains):
        config_path = os.path.join(temp_dir, "agentsecure.json")
        JsonConfigWriter().save(
            config_path,
            {
                "secrets": [],
                "network": {
                    "allow_domains": allow_domains,
                    "deny_domains": [],
                    "allow_ports": [80, 443],
                    "deny_ip_literals": True,
                    "deny_private_networks": False,
                },
                "process": {"allowed_commands": []},
                "gateway": {"host": "127.0.0.1", "port": 8765},
                "audit": {"path": os.path.join(temp_dir, ".agentsecure", "audit.log")},
            },
        )
        return config_path


if __name__ == "__main__":
    unittest.main()

