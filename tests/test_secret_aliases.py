import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

from agentsecure.cli.main import main
from agentsecure.core.config import JsonConfigLoader
from agentsecure.core.container import Container


class SecretAliasesCliTest(unittest.TestCase):
    def test_project_assignment_stores_only_alias_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = os.path.join(temp_dir, "project")
            home_dir = os.path.join(temp_dir, "home")
            os.makedirs(project_dir)
            config_path = os.path.join(project_dir, "agentsecure.json")
            old_cwd = os.getcwd()
            old_home = os.environ.get("AGENTSECURE_HOME")
            os.environ["AGENTSECURE_HOME"] = home_dir
            try:
                os.chdir(project_dir)
                os.environ["TEST_REAL_DATABASE_URL"] = "database-secret-value-for-test"
                with redirect_stdout(StringIO()):
                    self.assertEqual(
                        0,
                        main(
                            [
                                "--config",
                                config_path,
                                "secrets",
                                "add",
                                "dev_db",
                                "--env-name",
                                "DATABASE_URL",
                                "--provider",
                                "database",
                                "--approved-host",
                                "db.example.com",
                                "--real-secret-env",
                                "TEST_REAL_DATABASE_URL",
                            ]
                        ),
                    )
                    self.assertEqual(0, main(["--config", config_path, "secrets", "use", "dev_db"]))

                with open(config_path, "r") as handle:
                    raw = json.load(handle)
                self.assertEqual("dev_db", raw["secret_aliases"][0]["alias_id"])
                self.assertNotIn("database-secret-value-for-test", json.dumps(raw))
                self.assertIn("db.example.com", raw["network"]["allow_domains"])

                config = JsonConfigLoader().load(config_path)
                from agentsecure.core.secret_aliases import SecretAliasService, local_secret_alias_store_for_home, project_id_for_path
                from agentsecure.implementations.grant_store import local_grant_store_for_config
                from agentsecure.implementations.secret_store_factory import encrypted_secret_store_for_vault

                class MemoryAudit:
                    def record(self, event_type, details):
                        pass

                bindings = SecretAliasService(
                    local_secret_alias_store_for_home(home_dir),
                    encrypted_secret_store_for_vault(),
                    local_grant_store_for_config(config_path),
                    MemoryAudit(),
                ).prepare_run_bindings(config.secret_aliases, "2h", project_id_for_path(config_path), "run_1")
                container = Container.from_config_path(config_path, runtime_bindings=bindings, run_id="run_1")
                token = bindings[0].virtual_token
                self.assertEqual(
                    "database-secret-value-for-test",
                    container.token_resolver.resolve(
                        token,
                        {"host": "db.example.com", "project_id": container.project_id, "run_id": "run_1"},
                    ),
                )
                self.assertIsNone(
                    container.token_resolver.resolve(
                        token,
                        {"host": "evil.example.com", "project_id": container.project_id, "run_id": "run_1"},
                    )
                )
            finally:
                os.chdir(old_cwd)
                os.environ.pop("TEST_REAL_DATABASE_URL", None)
                if old_home is None:
                    os.environ.pop("AGENTSECURE_HOME", None)
                else:
                    os.environ["AGENTSECURE_HOME"] = old_home


if __name__ == "__main__":
    unittest.main()
