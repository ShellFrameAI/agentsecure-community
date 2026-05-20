import json
import os
import tempfile
import unittest

from agentsecure.core.capabilities import BrokerPlanningError, broker_endpoint_plan, broker_url_for_env
from agentsecure.core.config import ConfigError, JsonConfigLoader
from agentsecure.core.container import Container
from agentsecure.core.models import AgentSecureConfig, EnvKeyPolicy, EnvPolicy, SecretBinding, SecretReplacement
from agentsecure.implementations.secrets import ConfiguredVirtualEnvironmentProvider
from agentsecure.workspace.rewriter import DotenvFileRewriter


class EnvPolicyTest(unittest.TestCase):
    def test_config_loader_parses_env_policy_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "w") as handle:
                json.dump(
                    {
                        "env_policy": {
                            "DATABASE_URL_PROD": {"mode": "deny"},
                            "DATABASE_URL_DEV": {"mode": "virtualize", "access": "readwrite"},
                        }
                    },
                    handle,
                )

            config = JsonConfigLoader().load(config_path)

            self.assertEqual("deny", config.env_policy.rule_for("DATABASE_URL_PROD").mode)
            self.assertEqual("virtualize", config.env_policy.rule_for("DATABASE_URL_DEV").mode)
            self.assertEqual("readwrite", config.env_policy.rule_for("DATABASE_URL_DEV").access)
            self.assertEqual("virtualize", config.env_policy.rule_for("OPENAI_API_KEY").mode)

    def test_virtual_environment_never_includes_real_values_from_env_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "w") as handle:
                json.dump(
                    {
                        "secrets": [
                            {
                                "env_name": "OPENAI_API_KEY",
                                "virtual_token": "virt_openai_123",
                                "real_secret_env": "OPENAI_API_KEY",
                            }
                        ],
                        "env_policy": {
                            "DATABASE_URL_PROD": {"mode": "deny"},
                            "OPENAI_API_KEY": {"mode": "virtualize", "access": "readwrite"},
                        },
                    },
                    handle,
                )
            old_env = os.environ.copy()
            try:
                os.environ["OPENAI_API_KEY"] = "sk-real-openai"
                os.environ["DATABASE_URL_PROD"] = "postgres://prod:secret@prod.example/db"
                os.environ["DATABASE_URL_DEV"] = "postgres://dev:secret@dev.example/db"

                environment = Container.from_config_path(config_path).virtual_env_provider.build_environment()
            finally:
                os.environ.clear()
                os.environ.update(old_env)

            self.assertEqual("virt_openai_123", environment["OPENAI_API_KEY"])
            self.assertNotIn("postgres://dev:secret@dev.example/db", environment.values())
            self.assertNotIn("DATABASE_URL_DEV", environment)
            self.assertNotIn("DATABASE_URL_PROD", environment)

    def test_config_loader_rejects_real_value_exposure_mode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "w") as handle:
                json.dump({"env_policy": {"DATABASE_URL_DEV": {"mode": "allow"}}}, handle)

            with self.assertRaises(Exception):
                JsonConfigLoader().load(config_path)

    def test_config_loader_rejects_allow_real_mode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "w") as handle:
                json.dump({"env_policy": {"DATABASE_URL_DEV": {"mode": "allow_real"}}}, handle)

            with self.assertRaises(Exception):
                JsonConfigLoader().load(config_path)

    def test_env_key_policy_rejects_invalid_modes(self):
        with self.assertRaises(ValueError):
            EnvKeyPolicy(mode="allow_real")

    def test_config_loader_accepts_broker_policy_with_capability(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "w") as handle:
                json.dump(
                    {
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
                            }
                        },
                    },
                    handle,
                )

            config = JsonConfigLoader().load(config_path)

            rule = config.env_policy.rule_for("DATABASE_URL_DEV")
            capability = config.capabilities["postgres.dev.full"]
            self.assertEqual("broker", rule.mode)
            self.assertEqual("postgres.dev.full", rule.capability)
            self.assertEqual("postgres", capability.type)
            self.assertEqual("test-dev.host.domain", capability.target_host)
            self.assertEqual(5432, capability.target_port)

    def test_broker_endpoint_plan_contract(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "w") as handle:
                json.dump(
                    {
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
                                "local_port": 15440,
                            }
                        },
                    },
                    handle,
                )

            config = JsonConfigLoader().load(config_path)
            plan = broker_endpoint_plan(
                config,
                "DATABASE_URL_DEV",
                "postgres://user:secret@test-dev.host.domain:5432/mydb",
            )

            self.assertEqual("DATABASE_URL_DEV", plan.env_name)
            self.assertEqual("postgres.dev.full", plan.capability)
            self.assertEqual("postgres", plan.type)
            self.assertEqual("postgres://agentsecure@127.0.0.1:15440/mydb", plan.local_url)
            self.assertEqual("127.0.0.1", plan.local_host)
            self.assertEqual(15440, plan.local_port)
            self.assertEqual("test-dev.host.domain", plan.target_host)
            self.assertEqual(5432, plan.target_port)
            self.assertEqual("readwrite", plan.access)
            self.assertEqual("mydb", plan.database)

    def test_broker_planning_fails_for_missing_capability(self):
        config = AgentSecureConfig(
            env_policy=EnvPolicy(
                {
                    "DATABASE_URL_DEV": EnvKeyPolicy(
                        mode="broker",
                        capability="postgres.dev.missing",
                    )
                }
            )
        )

        with self.assertRaises(BrokerPlanningError):
            broker_endpoint_plan(config, "DATABASE_URL_DEV")
        with self.assertRaises(BrokerPlanningError):
            broker_url_for_env(config, "DATABASE_URL_DEV")

    def test_config_loader_rejects_broker_policy_without_valid_capability(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "w") as handle:
                json.dump({"env_policy": {"DATABASE_URL_DEV": {"mode": "broker"}}}, handle)

            with self.assertRaises(Exception):
                JsonConfigLoader().load(config_path)

    def test_config_loader_rejects_non_loopback_capability_local_host(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "w") as handle:
                json.dump(
                    {
                        "capabilities": {
                            "postgres.dev.full": {
                                "type": "postgres",
                                "target_host": "test-dev.host.domain",
                                "target_port": 5432,
                                "local_host": "0.0.0.0",
                            }
                        }
                    },
                    handle,
                )

            with self.assertRaises(ConfigError):
                JsonConfigLoader().load(config_path)

    def test_config_loader_rejects_invalid_capability_local_port(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "w") as handle:
                json.dump(
                    {
                        "capabilities": {
                            "postgres.dev.full": {
                                "type": "postgres",
                                "target_host": "test-dev.host.domain",
                                "target_port": 5432,
                                "local_port": 70000,
                            }
                        }
                    },
                    handle,
                )

            with self.assertRaises(ConfigError):
                JsonConfigLoader().load(config_path)

    def test_broker_environment_uses_localhost_url_not_real_secret(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "w") as handle:
                json.dump(
                    {
                        "secrets": [
                            {
                                "env_name": "DATABASE_URL_DEV",
                                "virtual_token": "virt_database_unused",
                                "real_secret_env": "DATABASE_URL_DEV_REAL",
                            }
                        ],
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
                            }
                        },
                    },
                    handle,
                )
            old_env = os.environ.copy()
            real_url = "postgres://user:dev_password@test-dev.host.domain:5432/mydb"
            try:
                os.environ["DATABASE_URL_DEV_REAL"] = real_url
                environment = Container.from_config_path(config_path).virtual_env_provider.build_environment()
            finally:
                os.environ.clear()
                os.environ.update(old_env)

            self.assertEqual("postgres://agentsecure@127.0.0.1:15432/mydb", environment["DATABASE_URL_DEV"])
            self.assertNotIn(real_url, environment.values())

    def test_provider_defaults_to_virtualized_bindings(self):
        provider = ConfiguredVirtualEnvironmentProvider(
            {"virt_openai_123": SecretBinding("OPENAI_API_KEY", "virt_openai_123")}
        )

        self.assertEqual({"OPENAI_API_KEY": "virt_openai_123"}, provider.build_environment())

    def test_dotenv_rewriter_removes_denied_lines_and_preserves_other_lines(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source_path = os.path.join(temp_dir, ".env")
            dest_path = os.path.join(temp_dir, "workspace.env")
            with open(source_path, "w") as handle:
                handle.write("DATABASE_URL_PROD=postgres://prod:secret@prod.example/db\n")
                handle.write("DATABASE_URL_DEV=postgres://dev:secret@dev.example/db\n")
                handle.write("OPENAI_API_KEY=sk-real-openai\n")

            DotenvFileRewriter().rewrite_file(
                source_path,
                dest_path,
                [
                    SecretReplacement(
                        source=".env",
                        name="DATABASE_URL_PROD",
                        real_value="postgres://prod:secret@prod.example/db",
                        virtual_value="",
                        action="remove",
                    ),
                    SecretReplacement(
                        source=".env",
                        name="OPENAI_API_KEY",
                        real_value="sk-real-openai",
                        virtual_value="virt_openai_123",
                    ),
                ],
            )

            with open(dest_path, "r") as handle:
                rewritten = handle.read()

            self.assertNotIn("DATABASE_URL_PROD", rewritten)
            self.assertIn("DATABASE_URL_DEV=postgres://dev:secret@dev.example/db", rewritten)
            self.assertIn("OPENAI_API_KEY=virt_openai_123", rewritten)


if __name__ == "__main__":
    unittest.main()
