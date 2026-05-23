import json
import os
import tempfile
import unittest

from tests.integration.helpers import run_agentsecure


class CliProxyTest(unittest.TestCase):
    def test_setup_openai_reads_provider_catalog_from_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            init = run_agentsecure(["init"], cwd=temp_dir)
            self.assertEqual(0, init.returncode, init.stderr)

            result = run_agentsecure(["proxy", "setup", "openai"], cwd=temp_dir)

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("OPENAI_BASE_URL=http://127.0.0.1:", result.stdout)
            self.assertIn("/providers/openai/v1", result.stdout)
            with open(os.path.join(temp_dir, "agentsecure.json"), "r") as handle:
                config = json.load(handle)
            self.assertEqual(
                "https://api.openai.com",
                config["provider_catalog"]["openai"]["upstream"],
            )
            self.assertEqual(
                "https://api.openai.com",
                config["provider_proxy"]["providers"]["openai"]["upstream"],
            )
            self.assertIn("api.openai.com", config["network"]["allow_domains"])

    def test_setup_openai_rejects_modified_catalog_entry_by_default(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            init = run_agentsecure(["init"], cwd=temp_dir)
            self.assertEqual(0, init.returncode, init.stderr)
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "r") as handle:
                config = json.load(handle)
            config["provider_catalog"]["openai"]["upstream"] = "https://api.openai.example.invalid"
            config["provider_catalog"]["openai"]["allow_domains"] = ["api.openai.example.invalid"]
            with open(config_path, "w") as handle:
                json.dump(config, handle)

            result = run_agentsecure(["proxy", "setup", "openai"], cwd=temp_dir)

            self.assertNotEqual(0, result.returncode)
            self.assertIn("differs from the packaged default", result.stderr)

    def test_setup_openai_can_trust_modified_catalog_entry_explicitly(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            init = run_agentsecure(["init"], cwd=temp_dir)
            self.assertEqual(0, init.returncode, init.stderr)
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "r") as handle:
                config = json.load(handle)
            config["provider_catalog"]["openai"]["upstream"] = "https://api.openai.example.invalid"
            config["provider_catalog"]["openai"]["allow_domains"] = ["api.openai.example.invalid"]
            with open(config_path, "w") as handle:
                json.dump(config, handle)

            result = run_agentsecure(["proxy", "setup", "openai", "--trust-local-catalog"], cwd=temp_dir)

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("upstream: https://api.openai.example.invalid", result.stdout)
            with open(config_path, "r") as handle:
                updated = json.load(handle)
            self.assertEqual(
                "https://api.openai.example.invalid",
                updated["provider_proxy"]["providers"]["openai"]["upstream"],
            )
            self.assertIn("api.openai.example.invalid", updated["network"]["allow_domains"])

    def test_setup_openai_fails_if_catalog_entry_missing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            init = run_agentsecure(["init"], cwd=temp_dir)
            self.assertEqual(0, init.returncode, init.stderr)
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "r") as handle:
                config = json.load(handle)
            config["provider_catalog"] = {}
            with open(config_path, "w") as handle:
                json.dump(config, handle)

            result = run_agentsecure(["proxy", "setup", "openai"], cwd=temp_dir)

            self.assertNotEqual(0, result.returncode)
            self.assertIn("provider_catalog.openai is missing", result.stderr)

    def test_setup_custom_rejects_bad_upstream_port(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            init = run_agentsecure(["init"], cwd=temp_dir)
            self.assertEqual(0, init.returncode, init.stderr)

            result = run_agentsecure(
                [
                    "proxy",
                    "setup",
                    "custom",
                    "--name",
                    "bad",
                    "--upstream",
                    "https://api.example.com:abc",
                    "--env",
                    "BAD_API_KEY",
                    "--base-url-env",
                    "BAD_BASE_URL",
                ],
                cwd=temp_dir,
            )

            self.assertNotEqual(0, result.returncode)
            self.assertIn("custom upstream port is invalid", result.stderr)


if __name__ == "__main__":
    unittest.main()
