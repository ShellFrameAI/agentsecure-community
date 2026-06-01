import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from agentsecure.cli.main import main
from agentsecure.core.config import JsonConfigLoader
from agentsecure.core.container import Container


class SecretAliasesCliTest(unittest.TestCase):
    def test_import_dotenv_moves_secrets_to_vault_and_rewrites_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = os.path.join(temp_dir, "project")
            home_dir = os.path.join(temp_dir, "home")
            os.makedirs(project_dir)
            config_path = os.path.join(project_dir, "agentsecure.json")
            env_path = os.path.join(project_dir, ".env")
            real_url = "postgres://user:password@dev.example.invalid/mydb"
            real_key = "sk_test_dummy_value_do_not_use"
            with open(env_path, "w") as handle:
                handle.write("DATABASE_URL=%s\n" % real_url)
                handle.write("STRIPE_API_KEY=%s\n" % real_key)
                handle.write("DEBUG=true\n")

            old_cwd = os.getcwd()
            old_home = os.environ.get("AGENTSECURE_HOME")
            os.environ["AGENTSECURE_HOME"] = home_dir
            try:
                os.chdir(project_dir)
                output = StringIO()
                with redirect_stdout(output):
                    self.assertEqual(0, main(["--config", config_path, "secrets", "import", ".env"]))

                result = json.loads(output.getvalue())
                self.assertTrue(result["rewritten"])
                self.assertEqual("local_vault", result["real_secrets_stored"])
                self.assertTrue(os.path.exists(result["backup"]))
                self.assertTrue(result["backup"].startswith(home_dir))

                with open(env_path, "r") as handle:
                    dotenv_text = handle.read()
                self.assertIn("DATABASE_URL=AGENTSECURE_ALIAS_DATABASE_URL", dotenv_text)
                self.assertIn("STRIPE_API_KEY=AGENTSECURE_ALIAS_STRIPE_API_KEY", dotenv_text)
                self.assertIn("DEBUG=true", dotenv_text)
                self.assertNotIn(real_url, dotenv_text)
                self.assertNotIn(real_key, dotenv_text)

                with open(config_path, "r") as handle:
                    raw = json.load(handle)
                raw_text = json.dumps(raw)
                self.assertNotIn(real_url, raw_text)
                self.assertNotIn(real_key, raw_text)
                self.assertEqual(
                    ["database_url", "stripe_api_key"],
                    [item["alias_id"] for item in raw["secret_aliases"]],
                )
                self.assertIn("dev.example.invalid", raw["network"]["allow_domains"])
                self.assertIn("api.stripe.com", raw["network"]["allow_domains"])

                with open(result["backup"], "r") as handle:
                    backup_text = handle.read()
                self.assertIn(real_url, backup_text)
                self.assertIn(real_key, backup_text)

                restore_output = StringIO()
                with redirect_stdout(restore_output):
                    self.assertEqual(0, main(["--config", config_path, "secrets", "restore", ".env"]))
                restore_result = json.loads(restore_output.getvalue())
                self.assertTrue(restore_result["restored"])
                self.assertEqual(result["backup"], restore_result["backup"])
                with open(env_path, "r") as handle:
                    restored_text = handle.read()
                self.assertIn(real_url, restored_text)
                self.assertIn(real_key, restored_text)
                self.assertNotIn("AGENTSECURE_ALIAS_DATABASE_URL", restored_text)
            finally:
                os.chdir(old_cwd)
                if old_home is None:
                    os.environ.pop("AGENTSECURE_HOME", None)
                else:
                    os.environ["AGENTSECURE_HOME"] = old_home

    def test_restore_dotenv_dry_run_reports_latest_backup(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = os.path.join(temp_dir, "project")
            home_dir = os.path.join(temp_dir, "home")
            os.makedirs(project_dir)
            config_path = os.path.join(project_dir, "agentsecure.json")
            env_path = os.path.join(project_dir, ".env")
            real_url = "postgres://user:password@dev.example.invalid/mydb"
            with open(env_path, "w") as handle:
                handle.write("DATABASE_URL=%s\n" % real_url)

            old_cwd = os.getcwd()
            old_home = os.environ.get("AGENTSECURE_HOME")
            os.environ["AGENTSECURE_HOME"] = home_dir
            try:
                os.chdir(project_dir)
                with redirect_stdout(StringIO()):
                    self.assertEqual(0, main(["--config", config_path, "secrets", "import", ".env"]))
                output = StringIO()
                with redirect_stdout(output):
                    self.assertEqual(0, main(["--config", config_path, "secrets", "restore", ".env", "--dry-run"]))
                result = json.loads(output.getvalue())
                self.assertTrue(result["dry_run"])
                self.assertTrue(result["would_restore"])
                self.assertTrue(result["backup"].startswith(home_dir))
                with open(env_path, "r") as handle:
                    self.assertIn("AGENTSECURE_ALIAS_DATABASE_URL", handle.read())
            finally:
                os.chdir(old_cwd)
                if old_home is None:
                    os.environ.pop("AGENTSECURE_HOME", None)
                else:
                    os.environ["AGENTSECURE_HOME"] = old_home

    def test_uninstall_can_restore_dotenv_when_user_approves(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = os.path.join(temp_dir, "project")
            home_dir = os.path.join(temp_dir, "home")
            install_dir = os.path.join(temp_dir, "bin")
            os.makedirs(project_dir)
            os.makedirs(install_dir)
            config_path = os.path.join(project_dir, "agentsecure.json")
            env_path = os.path.join(project_dir, ".env")
            real_url = "postgres://user:password@dev.example.invalid/mydb"
            with open(env_path, "w") as handle:
                handle.write("DATABASE_URL=%s\n" % real_url)

            old_cwd = os.getcwd()
            old_home = os.environ.get("AGENTSECURE_HOME")
            os.environ["AGENTSECURE_HOME"] = home_dir
            try:
                os.chdir(project_dir)
                with redirect_stdout(StringIO()):
                    self.assertEqual(0, main(["--config", config_path, "secrets", "import", ".env"]))
                with open(env_path, "r") as handle:
                    self.assertIn("AGENTSECURE_ALIAS_DATABASE_URL", handle.read())

                output = StringIO()
                with patch("builtins.input", side_effect=["y", "y"]):
                    with redirect_stdout(output):
                        self.assertEqual(
                            0,
                            main(["--config", config_path, "uninstall", "--install-dir", install_dir]),
                        )
                self.assertIn("Dotenv: restored .env", output.getvalue())
                with open(env_path, "r") as handle:
                    restored = handle.read()
                self.assertIn(real_url, restored)
                self.assertNotIn("AGENTSECURE_ALIAS_DATABASE_URL", restored)
                self.assertFalse(os.path.exists(config_path))
            finally:
                os.chdir(old_cwd)
                if old_home is None:
                    os.environ.pop("AGENTSECURE_HOME", None)
                else:
                    os.environ["AGENTSECURE_HOME"] = old_home

    def test_uninstall_leaves_dotenv_placeholder_when_user_declines_restore(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = os.path.join(temp_dir, "project")
            home_dir = os.path.join(temp_dir, "home")
            install_dir = os.path.join(temp_dir, "bin")
            os.makedirs(project_dir)
            os.makedirs(install_dir)
            config_path = os.path.join(project_dir, "agentsecure.json")
            env_path = os.path.join(project_dir, ".env")
            with open(env_path, "w") as handle:
                handle.write("DATABASE_URL=postgres://user:password@dev.example.invalid/mydb\n")

            old_cwd = os.getcwd()
            old_home = os.environ.get("AGENTSECURE_HOME")
            os.environ["AGENTSECURE_HOME"] = home_dir
            try:
                os.chdir(project_dir)
                with redirect_stdout(StringIO()):
                    self.assertEqual(0, main(["--config", config_path, "secrets", "import", ".env"]))

                output = StringIO()
                with patch("builtins.input", side_effect=["y", "n"]):
                    with redirect_stdout(output):
                        self.assertEqual(
                            0,
                            main(["--config", config_path, "uninstall", "--install-dir", install_dir]),
                        )
                self.assertIn("Dotenv: restore skipped.", output.getvalue())
                with open(env_path, "r") as handle:
                    self.assertIn("AGENTSECURE_ALIAS_DATABASE_URL", handle.read())
                self.assertFalse(os.path.exists(config_path))
            finally:
                os.chdir(old_cwd)
                if old_home is None:
                    os.environ.pop("AGENTSECURE_HOME", None)
                else:
                    os.environ["AGENTSECURE_HOME"] = old_home

    def test_import_dotenv_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = os.path.join(temp_dir, "project")
            home_dir = os.path.join(temp_dir, "home")
            os.makedirs(project_dir)
            config_path = os.path.join(project_dir, "agentsecure.json")
            env_path = os.path.join(project_dir, ".env")
            real_url = "postgres://user:password@dev.example.invalid/mydb"
            with open(env_path, "w") as handle:
                handle.write("DATABASE_URL=%s\n" % real_url)

            old_cwd = os.getcwd()
            old_home = os.environ.get("AGENTSECURE_HOME")
            os.environ["AGENTSECURE_HOME"] = home_dir
            try:
                os.chdir(project_dir)
                output = StringIO()
                with redirect_stdout(output):
                    self.assertEqual(0, main(["--config", config_path, "secrets", "import", ".env", "--dry-run"]))
                result = json.loads(output.getvalue())
                self.assertTrue(result["dry_run"])
                self.assertFalse(os.path.exists(config_path))
                with open(env_path, "r") as handle:
                    self.assertIn(real_url, handle.read())
            finally:
                os.chdir(old_cwd)
                if old_home is None:
                    os.environ.pop("AGENTSECURE_HOME", None)
                else:
                    os.environ["AGENTSECURE_HOME"] = old_home

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
