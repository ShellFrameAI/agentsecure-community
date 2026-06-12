import json
import os
import tempfile
import unittest

from tests.integration.helpers import run_agentsecure


class CliLifecycleIntegrationTest(unittest.TestCase):
    def test_init_status_and_doctor_first_run(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            init_result = run_agentsecure(["init"], cwd=temp_dir)
            self.assertEqual(0, init_result.returncode, init_result.stderr)
            self.assertIn("Initialized AgentSecure", init_result.stdout)
            self.assertIn("review AGENTSECURE.md", init_result.stdout)
            self.assertIn("agentsecure policy validate", init_result.stdout)
            self.assertIn("agentsecure discover", init_result.stdout)
            self.assertIn("agentsecure run --protect-all -- <agent-command>", init_result.stdout)
            self.assertIn("agentsecure status", init_result.stdout)
            self.assertNotIn("agentsecure api", init_result.stdout)
            self.assertTrue(os.path.exists(os.path.join(temp_dir, "agentsecure.json")))
            self.assertTrue(os.path.exists(os.path.join(temp_dir, "AGENTSECURE.md")))
            self.assertTrue(os.path.exists(os.path.join(temp_dir, ".agentsecure", ".gitignore")))

            status_result = run_agentsecure(["status"], cwd=temp_dir)
            self.assertEqual(0, status_result.returncode, status_result.stderr)
            self.assertIn("AGENTSECURE.md: AGENTSECURE.md (valid)", status_result.stdout)
            self.assertIn("Configured secrets: 0", status_result.stdout)
            self.assertIn("Secret runtime: strict", status_result.stdout)

            validate_result = run_agentsecure(["policy", "validate"], cwd=temp_dir)
            self.assertEqual(0, validate_result.returncode, validate_result.stderr)
            self.assertIn('"ok": true', validate_result.stdout)

            doctor_result = run_agentsecure(["doctor"], cwd=temp_dir)
            self.assertEqual(0, doctor_result.returncode, doctor_result.stderr)
            self.assertIn("[OK] config_exists", doctor_result.stdout)
            self.assertIn("[OK] agentsecure_md_valid", doctor_result.stdout)
            self.assertIn("[OK] secret_runtime_mode", doctor_result.stdout)

            with open(os.path.join(temp_dir, "AGENTSECURE.md"), "a", encoding="utf-8") as handle:
                handle.write("\nDATABASE_URL_DEV:\n  mode: allow\n")
            invalid_result = run_agentsecure(["policy", "validate"], cwd=temp_dir)
            self.assertEqual(1, invalid_result.returncode, invalid_result.stderr)
            self.assertIn('"code": "allow"', invalid_result.stdout)

            doctor_result = run_agentsecure(["doctor"], cwd=temp_dir)
            self.assertEqual(1, doctor_result.returncode, doctor_result.stderr)
            self.assertIn("[FAIL] agentsecure_md_valid", doctor_result.stdout)

            cleanup_result = run_agentsecure(["cleanup", "--yes"], cwd=temp_dir)
            self.assertEqual(0, cleanup_result.returncode, cleanup_result.stderr)
            self.assertFalse(os.path.exists(os.path.join(temp_dir, "agentsecure.json")))
            self.assertFalse(os.path.exists(os.path.join(temp_dir, ".agentsecure")))
            self.assertTrue(os.path.exists(os.path.join(temp_dir, "AGENTSECURE.md")))

    def test_files_protect_list_and_unprotect(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            init_result = run_agentsecure(["init"], cwd=temp_dir)
            self.assertEqual(0, init_result.returncode, init_result.stderr)

            protect_result = run_agentsecure(["files", "protect", "package.json", "README.md"], cwd=temp_dir)
            self.assertEqual(0, protect_result.returncode, protect_result.stderr)
            self.assertIn("package.json", protect_result.stdout)
            self.assertIn("README.md", protect_result.stdout)

            list_result = run_agentsecure(["files", "list"], cwd=temp_dir)
            self.assertEqual(0, list_result.returncode, list_result.stderr)
            self.assertIn("package.json", list_result.stdout)

            unprotect_result = run_agentsecure(["files", "unprotect", "package.json"], cwd=temp_dir)
            self.assertEqual(0, unprotect_result.returncode, unprotect_result.stderr)
            self.assertNotIn("package.json", unprotect_result.stdout)
            self.assertIn("README.md", unprotect_result.stdout)

    def test_network_allow_list_and_remove(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            init_result = run_agentsecure(["init"], cwd=temp_dir)
            self.assertEqual(0, init_result.returncode, init_result.stderr)

            allow_result = run_agentsecure(["network", "allow", "Example.COM."], cwd=temp_dir)
            self.assertEqual(0, allow_result.returncode, allow_result.stderr)
            self.assertIn("example.com", allow_result.stdout)

            list_result = run_agentsecure(["network", "list"], cwd=temp_dir)
            self.assertEqual(0, list_result.returncode, list_result.stderr)
            self.assertIn("example.com", list_result.stdout)

            remove_result = run_agentsecure(["network", "remove", "example.com"], cwd=temp_dir)
            self.assertEqual(0, remove_result.returncode, remove_result.stderr)
            self.assertNotIn("example.com", remove_result.stdout)

    def test_apply_copies_safe_workspace_changes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            init_result = run_agentsecure(["init"], cwd=temp_dir)
            self.assertEqual(0, init_result.returncode, init_result.stderr)

            workspace = os.path.join(temp_dir, ".agentsecure", "workspaces", "session_test")
            os.makedirs(workspace)
            with open(os.path.join(temp_dir, "app.py"), "w") as handle:
                handle.write("old\n")
            with open(os.path.join(temp_dir, ".env"), "w") as handle:
                handle.write("OPENAI_API_KEY=sk-real\n")
            with open(os.path.join(workspace, "app.py"), "w") as handle:
                handle.write("new\n")
            with open(os.path.join(workspace, "created.py"), "w") as handle:
                handle.write("created = True\n")
            with open(os.path.join(workspace, ".env"), "w") as handle:
                handle.write("OPENAI_API_KEY=bad\n")

            dry_run = run_agentsecure(["apply", "--dry-run"], cwd=temp_dir)
            self.assertEqual(0, dry_run.returncode, dry_run.stderr)
            self.assertIn("Would apply files:", dry_run.stdout)
            self.assertIn("app.py", dry_run.stdout)
            self.assertIn(".env (protected path)", dry_run.stdout)
            with open(os.path.join(temp_dir, "app.py"), "r") as handle:
                self.assertEqual("old\n", handle.read())

            apply_result = run_agentsecure(["apply"], cwd=temp_dir)
            self.assertEqual(0, apply_result.returncode, apply_result.stderr)
            self.assertIn("Applied files:", apply_result.stdout)
            with open(os.path.join(temp_dir, "app.py"), "r") as handle:
                self.assertEqual("new\n", handle.read())
            with open(os.path.join(temp_dir, "created.py"), "r") as handle:
                self.assertEqual("created = True\n", handle.read())
            with open(os.path.join(temp_dir, ".env"), "r") as handle:
                self.assertEqual("OPENAI_API_KEY=sk-real\n", handle.read())

    def test_create_key_writes_virtual_binding_without_leaking_secret(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            real_secret = "sk-integration-real-secret"

            result = run_agentsecure(
                [
                    "--config",
                    config_path,
                    "keys",
                    "create",
                    "--env-name",
                    "OPENAI_API_KEY",
                    "--provider",
                    "openai",
                    "--ttl",
                    "30m",
                    "--real-secret-env",
                    "TEST_OPENAI_KEY",
                ],
                cwd=temp_dir,
                env={"TEST_OPENAI_KEY": real_secret},
            )

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("virt_openai_", result.stdout)
            self.assertNotIn(real_secret, result.stdout)

            response = json.loads(result.stdout)
            self.assertEqual("OPENAI_API_KEY", response["env_name"])
            self.assertEqual(1800, response["ttl_seconds"])

            with open(config_path, "r") as handle:
                config_text = handle.read()
            self.assertIn(response["virtual_token"], config_text)
            self.assertNotIn(real_secret, config_text)

            secrets_path = os.path.join(temp_dir, ".agentsecure", "secrets.enc.json")
            device_key_path = os.path.join(temp_dir, ".agentsecure", "device.key")
            grants_path = os.path.join(temp_dir, ".agentsecure", "grants.json")
            self.assertTrue(os.path.exists(secrets_path))
            self.assertTrue(os.path.exists(device_key_path))
            self.assertTrue(os.path.exists(grants_path))
            with open(secrets_path, "r") as handle:
                self.assertNotIn(real_secret, handle.read())

            with open(grants_path, "r") as handle:
                grants = json.load(handle)
            grant = grants[response["virtual_token"]]
            self.assertEqual("active", grant["status"])
            self.assertAlmostEqual(1800, grant["expires_at"] - grant["created_at"], delta=2)

            env_result = run_agentsecure(["--config", config_path, "env"], cwd=temp_dir)
            self.assertEqual(0, env_result.returncode, env_result.stderr)
            self.assertIn("OPENAI_API_KEY=virt_openai_", env_result.stdout)
            self.assertNotIn(real_secret, env_result.stdout)

    def test_run_exposes_agent_guidance_file_for_alias_bindings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            home_dir = os.path.join(temp_dir, "home")
            real_secret = "guidance-real-secret-for-test"
            shared_env = {
                "AGENTSECURE_HOME": home_dir,
                "TEST_OPENAI_KEY": real_secret,
            }

            add_result = run_agentsecure(
                [
                    "--config",
                    config_path,
                    "secrets",
                    "add",
                    "openai_dev",
                    "--env-name",
                    "OPENAI_API_KEY",
                    "--provider",
                    "openai",
                    "--approved-host",
                    "api.openai.com",
                    "--real-secret-env",
                    "TEST_OPENAI_KEY",
                ],
                cwd=temp_dir,
                env=shared_env,
            )
            self.assertEqual(0, add_result.returncode, add_result.stderr)

            use_result = run_agentsecure(
                ["--config", config_path, "secrets", "use", "openai_dev"],
                cwd=temp_dir,
                env=shared_env,
            )
            self.assertEqual(0, use_result.returncode, use_result.stderr)

            script = (
                "import os; "
                "path=os.environ['AGENTSECURE_AGENT_GUIDE']; "
                "print(os.environ['AGENTSECURE_SKILL_FILE'] == path); "
                "print(path); "
                "print(open(path).read())"
            )
            run_result = run_agentsecure(
                [
                    "--config",
                    config_path,
                    "run",
                    "--no-discover",
                    "--",
                    "python3",
                    "-c",
                    script,
                ],
                cwd=temp_dir,
                env=shared_env,
            )

            if run_result.returncode != 0 and "gateway failed to start" in run_result.stderr:
                self.skipTest("local gateway bind is not permitted in this environment")
            self.assertEqual(0, run_result.returncode, run_result.stderr)
            self.assertIn("AgentSecure agent guide: .agentsecure/runs/", run_result.stdout)
            self.assertIn("True", run_result.stdout)
            self.assertIn("OPENAI_API_KEY", run_result.stdout)
            self.assertIn("provider=openai", run_result.stdout)
            self.assertIn("approved_hosts=api.openai.com", run_result.stdout)
            self.assertIn("Do not read `.env` files", run_result.stdout)
            self.assertNotIn(real_secret, run_result.stdout)

    def test_run_env_dump_does_not_expose_vault_alias_secret(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            home_dir = os.path.join(temp_dir, "home")
            real_secret = "env-dump-real-secret-for-test"
            setup_env = {
                "AGENTSECURE_HOME": home_dir,
                "TEST_OPENAI_KEY": real_secret,
            }

            add_result = run_agentsecure(
                [
                    "--config",
                    config_path,
                    "secrets",
                    "add",
                    "openai_dev",
                    "--env-name",
                    "OPENAI_API_KEY",
                    "--provider",
                    "openai",
                    "--approved-host",
                    "api.openai.com",
                    "--real-secret-env",
                    "TEST_OPENAI_KEY",
                ],
                cwd=temp_dir,
                env=setup_env,
            )
            self.assertEqual(0, add_result.returncode, add_result.stderr)

            use_result = run_agentsecure(
                ["--config", config_path, "secrets", "use", "openai_dev"],
                cwd=temp_dir,
                env=setup_env,
            )
            self.assertEqual(0, use_result.returncode, use_result.stderr)

            run_result = run_agentsecure(
                [
                    "--config",
                    config_path,
                    "run",
                    "--secret-mode",
                    "strict",
                    "--no-discover",
                    "--",
                    "python3",
                    "-c",
                    "import json, os; print(json.dumps(dict(os.environ), sort_keys=True))",
                ],
                cwd=temp_dir,
                env={"AGENTSECURE_HOME": home_dir},
            )

            if run_result.returncode != 0 and "gateway failed to start" in run_result.stderr:
                self.skipTest("local gateway bind is not permitted in this environment")
            self.assertEqual(0, run_result.returncode, run_result.stderr)
            self.assertIn("AgentSecure secret runtime: strict", run_result.stdout)
            self.assertIn('"OPENAI_API_KEY": "virt_openai_', run_result.stdout)
            self.assertNotIn(real_secret, run_result.stdout)

    def test_compat_secret_mode_warns_and_audits(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            init_result = run_agentsecure(["init"], cwd=temp_dir)
            self.assertEqual(0, init_result.returncode, init_result.stderr)

            run_result = run_agentsecure(
                [
                    "run",
                    "--secret-mode",
                    "compat",
                    "--no-discover",
                    "--",
                    "python3",
                    "-c",
                    "print('compat-ok')",
                ],
                cwd=temp_dir,
            )

            if run_result.returncode != 0 and "gateway failed to start" in run_result.stderr:
                self.skipTest("local gateway bind is not permitted in this environment")
            self.assertEqual(0, run_result.returncode, run_result.stderr)
            self.assertIn("AgentSecure secret runtime: compat", run_result.stdout)
            self.assertIn("trusted legacy code", run_result.stdout)
            self.assertIn("compat-ok", run_result.stdout)
            with open(os.path.join(temp_dir, ".agentsecure", "audit.log"), "r") as handle:
                audit = handle.read()
            self.assertIn("secret_mode_selected", audit)
            self.assertIn('"mode": "compat"', audit)


if __name__ == "__main__":
    unittest.main()
