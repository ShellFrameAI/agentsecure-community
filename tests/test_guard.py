import json
import os
import tempfile
import unittest

from agentsecure.core.key_service import KeyManagementService
from agentsecure.guard.sanitizer import SecretOutputSanitizer
from agentsecure.implementations.audit import JsonLineAuditLogger
from agentsecure.implementations.grant_store import LocalJsonGrantStore
from agentsecure.implementations.secret_store_factory import encrypted_secret_store_for_config


class SecretOutputSanitizerTest(unittest.TestCase):
    def test_replaces_real_secret_with_virtual_token(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            secret_store = encrypted_secret_store_for_config(config_path)
            grant_store = LocalJsonGrantStore(os.path.join(temp_dir, ".agentsecure", "grants.json"))
            audit_logger = JsonLineAuditLogger(os.path.join(temp_dir, ".agentsecure", "audit.log"))
            service = KeyManagementService(config_path, secret_store, grant_store, audit_logger)
            result = service.create_key(
                env_name="OPENAI_API_KEY",
                real_secret="sk-real-secret",
                provider="openai",
            )

            current = os.getcwd()
            try:
                os.chdir(temp_dir)
                sanitizer = SecretOutputSanitizer.from_config_path(config_path)
                sanitized = sanitizer.sanitize_text("OPENAI_API_KEY=sk-real-secret\n")
            finally:
                os.chdir(current)

            self.assertEqual("OPENAI_API_KEY=%s\n" % result["virtual_token"], sanitized)

    def test_denied_binding_removes_key_and_does_not_virtualize_value(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            secret_store = encrypted_secret_store_for_config(config_path)
            grant_store = LocalJsonGrantStore(os.path.join(temp_dir, ".agentsecure", "grants.json"))
            audit_logger = JsonLineAuditLogger(os.path.join(temp_dir, ".agentsecure", "audit.log"))
            service = KeyManagementService(config_path, secret_store, grant_store, audit_logger)
            result = service.create_key(
                env_name="DATABASE_URL_PROD",
                real_secret="postgres://prod:secret@prod.example/db",
                provider="database",
            )
            with open(config_path, "r") as handle:
                config = json.load(handle)
            config["env_policy"] = {"DATABASE_URL_PROD": {"mode": "deny"}}
            with open(config_path, "w") as handle:
                json.dump(config, handle)

            sanitizer = SecretOutputSanitizer.from_config_path(config_path)
            sanitized = sanitizer.sanitize_text(
                "DATABASE_URL_PROD=postgres://prod:secret@prod.example/db\n"
                "standalone postgres://prod:secret@prod.example/db\n"
            )

            self.assertNotIn("DATABASE_URL_PROD", sanitized)
            self.assertNotIn("postgres://prod:secret@prod.example/db", sanitized)
            self.assertNotIn(result["virtual_token"], sanitized)

    def test_config_path_controls_local_secret_store_location(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            secret_store = encrypted_secret_store_for_config(config_path)
            grant_store = LocalJsonGrantStore(os.path.join(temp_dir, ".agentsecure", "grants.json"))
            audit_logger = JsonLineAuditLogger(os.path.join(temp_dir, ".agentsecure", "audit.log"))
            service = KeyManagementService(config_path, secret_store, grant_store, audit_logger)
            result = service.create_key(
                env_name="DATABASE_URL",
                real_secret="postgres://user:password@localhost:5432/mydb",
                provider="database",
            )
            nested_dir = os.path.join(temp_dir, "src")
            os.mkdir(nested_dir)

            current = os.getcwd()
            try:
                os.chdir(nested_dir)
                sanitizer = SecretOutputSanitizer.from_config_path(config_path)
                sanitized = sanitizer.sanitize_text("postgres://user:password@localhost:5432/mydb")
            finally:
                os.chdir(current)

            self.assertEqual(result["virtual_token"], sanitized)


if __name__ == "__main__":
    unittest.main()
