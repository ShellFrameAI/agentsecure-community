import json
import os
import tempfile
import unittest

from agentsecure.core.config import JsonConfigLoader
from agentsecure.core.policy_ports import BrokerPortAllocator
from agentsecure.core.policy_mutation import LocalPolicyMutationService
from agentsecure.core.policy_validation import PolicyMutationValidator


class LocalPolicyMutationServiceTest(unittest.TestCase):
    def test_apply_persists_stable_port_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "w") as handle:
                json.dump(
                    {
                        "secrets": [],
                        "env_policy": {},
                        "capabilities": {},
                        "network": {"allow_domains": []},
                        "unknown_desktop_key": {"preserve": True},
                    },
                    handle,
                )
            payload = {
                "env_policy": {
                    "DATABASE_URL_DEV": {
                        "mode": "broker",
                        "capability": "postgres.dev.full",
                    }
                },
                "capabilities": {
                    "postgres.dev.full": {
                        "type": "postgres",
                        "expose_as": "DATABASE_URL_DEV",
                        "target_host": "test-dev.host.domain",
                        "target_port": 5432,
                        "access": "readwrite",
                        "database": "mydb",
                    }
                },
            }
            service = LocalPolicyMutationService(config_path)

            preview = service.preview(payload)
            self.assertTrue(preview["changed"])
            self.assertFalse(preview["applied"])
            self.assertEqual(15432, preview["broker_endpoint_plans"][0]["local_port"])
            with open(config_path, "r") as handle:
                self.assertEqual({}, json.load(handle)["capabilities"])

            applied = service.apply_local(payload)
            self.assertTrue(applied["changed"])
            self.assertTrue(applied["applied"])
            self.assertEqual(
                "postgres://agentsecure@127.0.0.1:15432/mydb",
                applied["broker_endpoint_plans"][0]["local_url"],
            )
            with open(config_path, "r") as handle:
                config_after_first_apply = json.load(handle)
            self.assertEqual({"preserve": True}, config_after_first_apply["unknown_desktop_key"])
            self.assertEqual(15432, config_after_first_apply["capabilities"]["postgres.dev.full"]["local_port"])
            JsonConfigLoader().load(config_path)

            second_apply = service.apply_local(payload)
            with open(config_path, "r") as handle:
                config_after_second_apply = json.load(handle)
            self.assertFalse(second_apply["changed"])
            self.assertFalse(second_apply["applied"])
            self.assertEqual(config_after_first_apply, config_after_second_apply)

    def test_apply_rejects_raw_secret_payload_and_does_not_serialize_it(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "w") as handle:
                json.dump({"secrets": [], "env_policy": {}, "capabilities": {}}, handle)
            raw_secret = "postgres://user:password@test-dev.host.domain:5432/mydb"
            payload = {
                "env_policy": {
                    "DATABASE_URL_DEV": {
                        "mode": "broker",
                        "capability": "postgres.dev.full",
                    }
                },
                "capabilities": {
                    "postgres.dev.full": {
                        "type": "postgres",
                        "target_host": "test-dev.host.domain",
                        "target_port": 5432,
                        "real_secret": raw_secret,
                    }
                },
            }

            with self.assertRaises(ValueError):
                LocalPolicyMutationService(config_path).apply_local(payload)
            with open(config_path, "r") as handle:
                self.assertNotIn(raw_secret, handle.read())

    def test_review_payload_has_policy_and_broker_plan_shape(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "w") as handle:
                json.dump(
                    {
                        "env_policy": {
                            "DATABASE_URL_DEV": {
                                "mode": "broker",
                                "capability": "postgres.dev.full",
                            },
                            "DATABASE_URL_PROD": {"mode": "deny"},
                        },
                        "capabilities": {
                            "postgres.dev.full": {
                                "type": "postgres",
                                "target_host": "test-dev.host.domain",
                                "target_port": 5432,
                                "local_port": 15444,
                                "access": "readwrite",
                                "database": "mydb",
                            }
                        },
                    },
                    handle,
                )

            review = LocalPolicyMutationService(config_path).review()

            self.assertTrue(review["valid"])
            self.assertFalse(review["changed"])
            self.assertEqual("deny", review["env_policy"]["DATABASE_URL_PROD"]["mode"])
            plan = review["broker_endpoint_plans"][0]
            self.assertEqual(
                set(
                    [
                        "env_name",
                        "capability",
                        "type",
                        "local_url",
                        "local_host",
                        "local_port",
                        "target_host",
                        "target_port",
                        "access",
                        "database",
                    ]
                ),
                set(plan.keys()),
            )
            self.assertEqual("DATABASE_URL_DEV", plan["env_name"])
            self.assertEqual("postgres://agentsecure@127.0.0.1:15444/mydb", plan["local_url"])

    def test_validator_normalizes_wrapped_policy_payload(self):
        payload = {
            "policy": {
                "env_policy": {
                    "DATABASE_URL_DEV": {
                        "mode": "broker",
                        "capability": "postgres.dev.full",
                    }
                }
            }
        }

        normalized = PolicyMutationValidator().extract_policy_payload(payload)

        self.assertEqual("broker", normalized["env_policy"]["DATABASE_URL_DEV"]["mode"])

    def test_validator_rejects_mixed_wrapped_payload(self):
        with self.assertRaises(ValueError):
            PolicyMutationValidator().extract_policy_payload({"policy": {}, "env_policy": {}})

    def test_validator_rejects_credential_host_value(self):
        validator = PolicyMutationValidator()

        with self.assertRaises(ValueError):
            validator.reject_raw_secret_value(
                "capabilities.postgres.dev.full.target_host",
                "postgres://user:pass@test-dev.host.domain:5432/mydb",
            )

    def test_broker_port_allocator_preserves_existing_ports_and_skips_used_ports(self):
        config = {
            "env_policy": {
                "DATABASE_URL_DEV": {"mode": "broker", "capability": "postgres.dev.full"},
                "DATABASE_URL_RO": {"mode": "broker", "capability": "postgres.prod.readonly"},
            },
            "capabilities": {
                "postgres.dev.full": {"local_port": 15433},
                "postgres.prod.readonly": {},
                "postgres.other": {"local_port": 15432},
            },
        }

        BrokerPortAllocator().assign(config, {"capabilities": {}})

        self.assertEqual(15433, config["capabilities"]["postgres.dev.full"]["local_port"])
        self.assertEqual(15434, config["capabilities"]["postgres.prod.readonly"]["local_port"])


if __name__ == "__main__":
    unittest.main()
