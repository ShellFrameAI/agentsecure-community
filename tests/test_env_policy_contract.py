import json
import os
import re
import sys
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from tests.integration.helpers import run_agentsecure
from agentsecure.core.models import SecretReplacement
from agentsecure.guard.sanitizer import SecretOutputSanitizer
from agentsecure.workspace.rewriter import DotenvFileRewriter


DUMMY_PROD_URL = "postgres://Admin:prod_password@Production.prod.host:5432/mydb"
DUMMY_PROD_RO_URL = "postgres://user_ro:readonly_password@Production.prod.host:5432/mydb"
DUMMY_DEV_URL = "postgres://user:dev_password@test-dev.host.domain/mydb"
DUMMY_API_KEY = "sk_test_dummy_value_do_not_use"


def write_project_config(project_dir, env_policy=None, allow_domains=None, capabilities=None):
    config_path = os.path.join(project_dir, "agentsecure.json")
    with open(config_path, "w") as handle:
        json.dump(
            {
                "secrets": [],
                "env_policy": env_policy or {},
                "capabilities": capabilities or {},
                "network": {"allow_domains": allow_domains or []},
            },
            handle,
        )
    return config_path


def write_dotenv(project_dir):
    with open(os.path.join(project_dir, ".env"), "w") as handle:
        handle.write("DATABASE_URL_DEV=%s\n" % DUMMY_DEV_URL)
        handle.write("DATABASE_URL_PROD=%s\n" % DUMMY_PROD_URL)
        handle.write("DATABASE_URL_PROD_RO=%s\n" % DUMMY_PROD_RO_URL)
        handle.write("OPENAI_API_KEY=%s\n" % DUMMY_API_KEY)


def skip_if_gateway_unavailable(testcase, result):
    if result.returncode != 0 and "gateway failed to start" in result.stderr:
        testcase.skipTest("local gateway bind is not permitted in this environment")


class EnvPolicyContractTest(unittest.TestCase):
    def test_deny_mode_removes_prod_line_from_sanitized_command_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = write_project_config(
                temp_dir,
                env_policy={"DATABASE_URL_PROD": {"mode": "deny"}},
            )

            sanitizer = SecretOutputSanitizer.from_config_path(config_path)
            sanitized = sanitizer.sanitize_text(
                "DATABASE_URL_DEV=%s\nDATABASE_URL_PROD=%s\n" % (DUMMY_DEV_URL, DUMMY_PROD_URL)
            )

            self.assertIn("DATABASE_URL_DEV=%s" % DUMMY_DEV_URL, sanitized)
            self.assertNotIn("DATABASE_URL_PROD=", sanitized)
            self.assertNotIn(DUMMY_PROD_URL, sanitized)

    def test_workspace_rewriter_contract_removes_denied_and_virtualizes_normal_secret(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source_path = os.path.join(temp_dir, ".env")
            dest_path = os.path.join(temp_dir, "workspace.env")
            with open(source_path, "w") as handle:
                handle.write("DATABASE_URL_DEV=%s\n" % DUMMY_DEV_URL)
                handle.write("DATABASE_URL_PROD=%s\n" % DUMMY_PROD_URL)
                handle.write("OPENAI_API_KEY=%s\n" % DUMMY_API_KEY)

            DotenvFileRewriter().rewrite_file(
                source_path,
                dest_path,
                [
                    SecretReplacement(
                        source=".env",
                        name="DATABASE_URL_PROD",
                        real_value=DUMMY_PROD_URL,
                        virtual_value="",
                        action="remove",
                    ),
                    SecretReplacement(
                        source=".env",
                        name="OPENAI_API_KEY",
                        real_value=DUMMY_API_KEY,
                        virtual_value="virt_openai_contract",
                    ),
                ],
            )

            with open(dest_path, "r") as handle:
                rewritten = handle.read()
            self.assertIn("DATABASE_URL_DEV=%s" % DUMMY_DEV_URL, rewritten)
            self.assertNotIn("DATABASE_URL_PROD=", rewritten)
            self.assertNotIn(DUMMY_PROD_URL, rewritten)
            self.assertIn("OPENAI_API_KEY=virt_openai_contract", rewritten)
            self.assertNotIn(DUMMY_API_KEY, rewritten)

    def test_deny_mode_hides_prod_key_in_command_guard_cat_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = write_project_config(
                temp_dir,
                env_policy={
                    "DATABASE_URL_PROD": {"mode": "deny"},
                    "DATABASE_URL_DEV": {"mode": "virtualize"},
                    "DATABASE_URL_PROD_RO": {"mode": "virtualize", "access": "readonly"},
                },
            )
            write_dotenv(temp_dir)

            result = run_agentsecure(
                [
                    "--config",
                    config_path,
                    "run",
                    "--runtime",
                    "command-guard",
                    "--protect-all",
                    "--",
                    sys.executable,
                    "-c",
                    "import subprocess; print(subprocess.check_output(['cat', '.env']).decode())",
                ],
                cwd=temp_dir,
            )

            skip_if_gateway_unavailable(self, result)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertNotIn("DATABASE_URL_PROD=", result.stdout)
            self.assertNotIn(DUMMY_PROD_URL, result.stdout)
            self.assertIn("DATABASE_URL_DEV=virt_database_", result.stdout)
            self.assertIn("DATABASE_URL_PROD_RO=virt_database_", result.stdout)
            self.assertNotIn(DUMMY_DEV_URL, result.stdout)
            self.assertNotIn(DUMMY_PROD_RO_URL, result.stdout)

    def test_deny_mode_hides_prod_key_in_workspace_dotenv(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = write_project_config(
                temp_dir,
                env_policy={
                    "DATABASE_URL_PROD": {"mode": "deny"},
                    "DATABASE_URL_DEV": {"mode": "virtualize"},
                    "DATABASE_URL_PROD_RO": {"mode": "virtualize", "access": "readonly"},
                },
            )
            write_dotenv(temp_dir)

            result = run_agentsecure(
                [
                    "--config",
                    config_path,
                    "run",
                    "--runtime",
                    "workspace",
                    "--protect-all",
                    "--workspace-keep",
                    "--",
                    sys.executable,
                    "-c",
                    "import os; print('CWD=' + os.getcwd()); print(open('.env').read())",
                ],
                cwd=temp_dir,
            )

            skip_if_gateway_unavailable(self, result)
            self.assertEqual(0, result.returncode, result.stderr)
            match = re.search(r"AgentSecure safe workspace: (.+)", result.stdout)
            self.assertIsNotNone(match)
            workspace_root = match.group(1).strip()
            with open(os.path.join(workspace_root, ".env"), "r") as handle:
                workspace_env = handle.read()
            self.assertNotIn("DATABASE_URL_PROD=", workspace_env)
            self.assertNotIn(DUMMY_PROD_URL, workspace_env)
            self.assertIn("DATABASE_URL_DEV=virt_database_", workspace_env)
            self.assertIn("DATABASE_URL_PROD_RO=virt_database_", workspace_env)

    def test_virtualize_mode_preserves_existing_secret_masking_behavior(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = write_project_config(
                temp_dir,
                env_policy={"OPENAI_API_KEY": {"mode": "virtualize"}},
            )
            with open(os.path.join(temp_dir, ".env"), "w") as handle:
                handle.write("OPENAI_API_KEY=%s\n" % DUMMY_API_KEY)

            result = run_agentsecure(
                [
                    "--config",
                    config_path,
                    "run",
                    "--runtime",
                    "command-guard",
                    "--protect-all",
                    "--",
                    sys.executable,
                    "-c",
                    "import subprocess; print(subprocess.check_output(['cat', '.env']).decode())",
                ],
                cwd=temp_dir,
            )

            skip_if_gateway_unavailable(self, result)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("OPENAI_API_KEY=virt_openai_", result.stdout)
            self.assertNotIn(DUMMY_API_KEY, result.stdout)

    def test_development_database_is_virtualized_not_exposed_as_real_value(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = write_project_config(
                temp_dir,
                env_policy={
                    "DATABASE_URL_DEV": {"mode": "virtualize", "access": "readwrite"},
                    "DATABASE_URL_PROD": {"mode": "deny"},
                },
            )
            write_dotenv(temp_dir)

            result = run_agentsecure(
                [
                    "--config",
                    config_path,
                    "run",
                    "--runtime",
                    "command-guard",
                    "--protect-all",
                    "--",
                    sys.executable,
                    "-c",
                    (
                        "import os, subprocess; "
                        "print('ENV_DEV=' + os.environ.get('DATABASE_URL_DEV', '')); "
                        "print(subprocess.check_output(['cat', '.env']).decode())"
                    ),
                ],
                cwd=temp_dir,
            )

            skip_if_gateway_unavailable(self, result)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("ENV_DEV=virt_database_", result.stdout)
            self.assertIn("DATABASE_URL_DEV=virt_database_", result.stdout)
            self.assertNotIn(DUMMY_DEV_URL, result.stdout)
            self.assertNotIn("DATABASE_URL_PROD=", result.stdout)
            self.assertNotIn(DUMMY_PROD_URL, result.stdout)

    def test_broker_database_urls_are_localhost_capability_urls(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = write_project_config(
                temp_dir,
                env_policy={
                    "DATABASE_URL_PROD": {"mode": "deny"},
                    "DATABASE_URL_DEV": {"mode": "broker", "capability": "postgres.dev.full"},
                    "DATABASE_URL_PROD_RO": {"mode": "broker", "capability": "postgres.prod.readonly"},
                },
                capabilities={
                    "postgres.dev.full": {
                        "type": "postgres",
                        "expose_as": "DATABASE_URL_DEV",
                        "target_host": "test-dev.host.domain",
                        "target_port": 5432,
                        "access": "readwrite",
                    },
                    "postgres.prod.readonly": {
                        "type": "postgres",
                        "expose_as": "DATABASE_URL_PROD_RO",
                        "target_host": "production.prod.host",
                        "target_port": 5432,
                        "access": "readonly",
                    },
                },
            )
            write_dotenv(temp_dir)

            result = run_agentsecure(
                [
                    "--config",
                    config_path,
                    "run",
                    "--runtime",
                    "command-guard",
                    "--protect-all",
                    "--",
                    sys.executable,
                    "-c",
                    (
                        "import os, subprocess; "
                        "print('ENV_DEV=' + os.environ.get('DATABASE_URL_DEV', '')); "
                        "print('ENV_PROD=' + os.environ.get('DATABASE_URL_PROD', 'missing')); "
                        "print('ENV_PROD_RO=' + os.environ.get('DATABASE_URL_PROD_RO', '')); "
                        "print(subprocess.check_output(['cat', '.env']).decode())"
                    ),
                ],
                cwd=temp_dir,
            )

            skip_if_gateway_unavailable(self, result)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("ENV_DEV=postgres://agentsecure@127.0.0.1:15432/mydb", result.stdout)
            self.assertIn("ENV_PROD=missing", result.stdout)
            self.assertIn("ENV_PROD_RO=postgres://agentsecure@127.0.0.1:15433/mydb", result.stdout)
            self.assertIn("DATABASE_URL_DEV=postgres://agentsecure@127.0.0.1:15432/mydb", result.stdout)
            self.assertIn("DATABASE_URL_PROD_RO=postgres://agentsecure@127.0.0.1:15433/mydb", result.stdout)
            self.assertNotIn("DATABASE_URL_PROD=", result.stdout)
            self.assertNotIn(DUMMY_DEV_URL, result.stdout)
            self.assertNotIn(DUMMY_PROD_URL, result.stdout)
            self.assertNotIn(DUMMY_PROD_RO_URL, result.stdout)
            audit_path = os.path.join(temp_dir, ".agentsecure", "audit.log")
            with open(audit_path, "r") as handle:
                audit = handle.read()
            self.assertIn("secret.brokered", audit)
            self.assertIn("capability.registered", audit)
            self.assertNotIn(DUMMY_DEV_URL, audit)
            self.assertNotIn(DUMMY_PROD_RO_URL, audit)

    def test_complete_env_policy_is_applied_without_interactive_secret_prompt(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = write_project_config(
                temp_dir,
                env_policy={
                    "DATABASE_URL_DEV": {"mode": "virtualize", "access": "readwrite"},
                    "DATABASE_URL_PROD": {"mode": "deny"},
                    "DATABASE_URL_PROD_RO": {"mode": "virtualize", "access": "readonly"},
                    "OPENAI_API_KEY": {"mode": "virtualize"},
                },
            )
            write_dotenv(temp_dir)

            result = run_agentsecure(
                [
                    "--config",
                    config_path,
                    "run",
                    "--runtime",
                    "command-guard",
                    "--",
                    sys.executable,
                    "-c",
                    (
                        "import os, subprocess; "
                        "print('ENV_DEV=' + os.environ.get('DATABASE_URL_DEV', '')); "
                        "print('ENV_PROD=' + os.environ.get('DATABASE_URL_PROD', 'missing')); "
                        "print(subprocess.check_output(['cat', '.env']).decode())"
                    ),
                ],
                cwd=temp_dir,
            )

            skip_if_gateway_unavailable(self, result)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertNotIn("Select secrets to virtualize", result.stdout)
            self.assertIn("AgentSecure applied local env_policy for 4 secret(s).", result.stdout)
            self.assertIn("ENV_DEV=virt_database_", result.stdout)
            self.assertIn("ENV_PROD=missing", result.stdout)
            self.assertIn("DATABASE_URL_DEV=virt_database_", result.stdout)
            self.assertIn("DATABASE_URL_PROD_RO=virt_database_", result.stdout)
            self.assertNotIn("DATABASE_URL_PROD=", result.stdout)
            self.assertNotIn(DUMMY_DEV_URL, result.stdout)
            self.assertNotIn(DUMMY_PROD_URL, result.stdout)
            self.assertNotIn(DUMMY_PROD_RO_URL, result.stdout)
            self.assertNotIn(DUMMY_API_KEY, result.stdout)

    def test_suggestions_do_not_auto_apply_to_network_allowlist(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = write_project_config(temp_dir)
            write_dotenv(temp_dir)

            result = run_agentsecure(["--config", config_path, "suggest"], cwd=temp_dir)

            self.assertEqual(0, result.returncode, result.stderr)
            with open(config_path, "r") as handle:
                config_after = json.load(handle)
            self.assertEqual([], config_after["network"]["allow_domains"])
            self.assertIn("network_suggestions", result.stdout)
            self.assertIn("test-dev.host.domain", result.stdout)

    def test_suggestions_work_without_config_and_do_not_print_secret_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            write_dotenv(temp_dir)

            result = run_agentsecure(["suggest"], cwd=temp_dir)

            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout)
            keys = [suggestion["key"] for suggestion in payload["env_suggestions"]]
            self.assertIn("DATABASE_URL_DEV", keys)
            self.assertIn("network_suggestions", payload)
            self.assertNotIn(DUMMY_DEV_URL, result.stdout)
            self.assertNotIn(DUMMY_PROD_URL, result.stdout)
            self.assertNotIn(DUMMY_PROD_RO_URL, result.stdout)
            self.assertNotIn(DUMMY_API_KEY, result.stdout)


if __name__ == "__main__":
    unittest.main()
