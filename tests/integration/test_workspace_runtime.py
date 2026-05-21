import os
import re
import sys
import tempfile
import unittest

from tests.integration.helpers import run_agentsecure


class WorkspaceRuntimeIntegrationTest(unittest.TestCase):
    def test_run_uses_safe_workspace_with_rewritten_dotenv(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            real_secret = "sk-workspace-real-secret"
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(os.path.join(temp_dir, ".env"), "w") as handle:
                handle.write("OPENAI_API_KEY=%s\n" % real_secret)

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
                    "import os; print('CWD=' + os.getcwd()); print(open('.env').read().strip())",
                ],
                cwd=temp_dir,
            )

            if result.returncode != 0 and "gateway failed to start" in result.stderr:
                self.skipTest("local gateway bind is not permitted in this environment")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("AgentSecure safe workspace:", result.stdout)
            self.assertIn("OPENAI_API_KEY=virt_openai_", result.stdout)
            self.assertNotIn(real_secret, result.stdout)

            with open(os.path.join(temp_dir, ".env"), "r") as handle:
                self.assertIn(real_secret, handle.read())

            match = re.search(r"AgentSecure safe workspace: (.+)", result.stdout)
            self.assertIsNotNone(match)
            workspace_root = match.group(1).strip()
            self.assertTrue(os.path.exists(workspace_root))
            self.assertFalse(os.path.commonpath([temp_dir, workspace_root]) == os.path.abspath(temp_dir))
            with open(os.path.join(workspace_root, ".env"), "r") as handle:
                workspace_env = handle.read()
            self.assertIn("OPENAI_API_KEY=virt_openai_", workspace_env)
            self.assertNotIn(real_secret, workspace_env)

            diff_result = run_agentsecure(["diff"], cwd=temp_dir)
            self.assertEqual(0, diff_result.returncode, diff_result.stderr)

    def test_external_workspace_copy_blocks_relative_traversal_to_source_dotenv(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            real_secret = "fake-workspace-traversal-secret"
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(os.path.join(temp_dir, ".env"), "w") as handle:
                handle.write("OPENAI_API_KEY=%s\n" % real_secret)

            result = run_agentsecure(
                [
                    "--config",
                    config_path,
                    "run",
                    "--runtime",
                    "workspace",
                    "--workspace-mode",
                    "copy",
                    "--protect-all",
                    "--",
                    sys.executable,
                    "-c",
                    (
                        "import os; "
                        "print('CWD=' + os.getcwd()); "
                        "print(open('.env').read().strip()); "
                        "\ntry:\n"
                        "    print(open('../../../.env').read().strip())\n"
                        "except OSError as exc:\n"
                        "    print(type(exc).__name__)\n"
                    ),
                ],
                cwd=temp_dir,
            )

            if result.returncode != 0 and "gateway failed to start" in result.stderr:
                self.skipTest("local gateway bind is not permitted in this environment")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("OPENAI_API_KEY=virt_openai_", result.stdout)
            self.assertIn("FileNotFoundError", result.stdout)
            self.assertNotIn(real_secret, result.stdout)

    def test_command_guard_runtime_runs_in_place_and_sanitizes_cat(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            real_secret = "sk-command-guard-real-secret"
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(os.path.join(temp_dir, ".env"), "w") as handle:
                handle.write("OPENAI_API_KEY=%s\n" % real_secret)

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
                        "print('CWD=' + os.getcwd()); "
                        "print(subprocess.check_output(['cat', '.env']).decode().strip())"
                    ),
                ],
                cwd=temp_dir,
            )

            if result.returncode != 0 and "gateway failed to start" in result.stderr:
                self.skipTest("local gateway bind is not permitted in this environment")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("AgentSecure runtime: command-guard", result.stdout)
            self.assertNotIn("AgentSecure safe workspace:", result.stdout)
            normalized_stdout = result.stdout.replace("/private/var/", "/var/")
            self.assertIn("CWD=%s" % temp_dir, normalized_stdout)
            self.assertIn("OPENAI_API_KEY=virt_openai_", result.stdout)
            self.assertNotIn(real_secret, result.stdout)
            self.assertFalse(os.path.isdir(os.path.join(temp_dir, ".agentsecure", "workspaces")))

            with open(os.path.join(temp_dir, ".env"), "r") as handle:
                self.assertIn(real_secret, handle.read())


if __name__ == "__main__":
    unittest.main()
