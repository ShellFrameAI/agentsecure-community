import json
import os
import tempfile
import unittest

from agentsecure.core.product import ProductService
from agentsecure.discovery.scanner import CompositeSecretScanner


class ProductServiceTest(unittest.TestCase):
    def test_init_creates_config_and_local_gitignore(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                service = ProductService("agentsecure.json", CompositeSecretScanner([]))
                result = service.init_project()
                self.assertTrue(result["config_created"])
                self.assertTrue(result["agentsecure_md"]["created"])
                self.assertTrue(os.path.exists("agentsecure.json"))
                self.assertTrue(os.path.exists("AGENTSECURE.md"))
                self.assertTrue(os.path.exists(os.path.join(".agentsecure", ".gitignore")))
                with open("agentsecure.json", "r") as handle:
                    config = json.load(handle)
                self.assertEqual(
                    "https://api.openai.com",
                    config["provider_catalog"]["openai"]["upstream"],
                )
            finally:
                os.chdir(cwd)

    def test_available_port_returns_preferred_when_free(self):
        service = ProductService("agentsecure.json", CompositeSecretScanner([]))
        self.assertEqual(65530, service._available_port(65530))

    def test_doctor_reports_missing_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                service = ProductService("agentsecure.json", CompositeSecretScanner([]))
                result = service.doctor()
                self.assertFalse(result["ok"])
            finally:
                os.chdir(cwd)

    def test_status_reports_configuration_profile_for_desktop(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                os.makedirs(".agentsecure")
                with open("agentsecure.json", "w") as handle:
                    json.dump(
                        {
                            "cloud": {
                                "config_profile": {
                                    "id": "profile-1",
                                    "name": "Strict",
                                    "version": 2,
                                    "applied_version": 2,
                                    "last_applied_at": 123.0,
                                }
                            }
                        },
                        handle,
                    )
                with open(os.path.join(".agentsecure", "cloud.json"), "w") as handle:
                    json.dump(
                        {
                            "config_profile": {
                                "id": "profile-1",
                                "name": "Strict",
                                "version": 3,
                                "assigned_version": 3,
                                "last_synced_at": 456.0,
                            }
                        },
                        handle,
                    )

                service = ProductService("agentsecure.json", CompositeSecretScanner([]))
                result = service.status()

                profile = result["configuration_profile"]
                self.assertEqual(profile, result["config_profile"])
                self.assertEqual("profile-1", profile["id"])
                self.assertEqual("pending", profile["status"])
                self.assertEqual(3, profile["assigned_version"])
                self.assertEqual(2, profile["applied_version"])
                self.assertEqual(3, profile["pending_version"])
                self.assertEqual(456.0, profile["last_synced_at"])
                self.assertEqual(123.0, profile["last_applied_at"])
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
