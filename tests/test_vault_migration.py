import base64
import json
import os
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

from agentsecure.core.vault_migration import VaultMigrationError, VaultMigrationService
from agentsecure.crypto.cipher import LocalSecretCipher
from agentsecure.crypto.key_provider import LocalDeviceKeyProvider
from agentsecure.implementations.encrypted_secret_store import EncryptedLocalSecretStore
from agentsecure.implementations.secret_store_factory import (
    detected_vault_format,
    encrypted_secret_store_for_vault,
)


FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


class VaultMigrationServiceTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.home_dir = os.path.join(self.temp_dir.name, "home")
        self.vault_dir = os.path.join(self.home_dir, "vault")
        os.makedirs(self.vault_dir)
        self.key_path = os.path.join(self.vault_dir, "device.key")
        with open(self.key_path, "wb") as handle:
            handle.write(base64.urlsafe_b64encode(bytes(range(32))) + b"\n")
        os.chmod(self.key_path, 0o600)
        self.store_path = os.path.join(self.vault_dir, "secrets.enc.json")
        self.aliases_path = os.path.join(self.vault_dir, "aliases.json")
        shutil.copyfile(
            os.path.join(FIXTURE_DIR, "vault-v1-0.1.22-secrets.enc.json"),
            self.store_path,
        )
        shutil.copyfile(
            os.path.join(FIXTURE_DIR, "vault-v1-0.1.22-aliases.json"),
            self.aliases_path,
        )
        os.chmod(self.store_path, 0o600)
        os.chmod(self.aliases_path, 0o600)
        self.old_home = os.environ.get("AGENTSECURE_HOME")
        os.environ["AGENTSECURE_HOME"] = self.home_dir
        self.service = VaultMigrationService(self.home_dir)

    def tearDown(self):
        if self.old_home is None:
            os.environ.pop("AGENTSECURE_HOME", None)
        else:
            os.environ["AGENTSECURE_HOME"] = self.old_home
        self.temp_dir.cleanup()

    def test_status_and_verify_recognize_real_0_1_22_fixture(self):
        status = self.service.status()
        verification = self.service.verify()

        self.assertEqual(1, status["format_version"])
        self.assertEqual("agentsecure-local-v1", status["cipher"])
        self.assertEqual(2, status["records"])
        self.assertEqual("local_file", status["key_provider"])
        self.assertTrue(verification["ok"])
        self.assertEqual(2, verification["records"])
        self.assertNotIn("dummy-v1-api-value", json.dumps(status))
        self.assertNotIn("dummy-v1-api-value", json.dumps(verification))

    def test_migration_dry_run_verifies_without_writing(self):
        before = self._read_bytes(self.store_path)

        result = self.service.migrate(2, dry_run=True)

        self.assertEqual("planned", result["status"])
        self.assertEqual(1, result["source_format"])
        self.assertEqual(2, result["target_format"])
        self.assertEqual(before, self._read_bytes(self.store_path))
        self.assertFalse(os.path.exists(self.service.manifest_path))
        self.assertFalse(os.path.exists(self.service.recovery_dir))

    def test_migrate_to_v2_is_atomic_verified_and_recoverable(self):
        result = self.service.migrate(2)

        self.assertEqual("completed", result["status"])
        self.assertEqual(2, detected_vault_format(self.store_path))
        self.assertTrue(self.service.verify()["ok"])
        self.assertTrue(os.path.exists(result["recovery_snapshot"]))
        self.assertEqual(0, stat.S_IMODE(os.stat(result["recovery_snapshot"]).st_mode) & 0o077)
        with open(self.store_path, "r") as handle:
            migrated_text = handle.read()
            migrated = json.loads(migrated_text)
        self.assertNotIn("dummy-v1-api-value", migrated_text)
        self.assertEqual({2}, {item["version"] for item in migrated.values()})
        self.assertEqual({"aes-256-gcm-v2"}, {item["cipher"] for item in migrated.values()})
        with open(self.service.manifest_path, "r") as handle:
            manifest = json.load(handle)
        self.assertEqual(2, manifest["format_version"])
        self.assertEqual("migrate", manifest["last_operation"])
        self.assertEqual(0, stat.S_IMODE(os.stat(self.service.manifest_path).st_mode) & 0o077)

    def test_new_v2_secret_survives_rollback_and_opens_with_0_1_22_reader(self):
        self.service.migrate(2)
        current_store = encrypted_secret_store_for_vault()
        current_store.put("created_after_migration", "dummy-new-value")
        self.assertEqual("dummy-new-value", current_store.get("created_after_migration"))

        result = self.service.rollback(1)

        self.assertEqual("completed", result["status"])
        self.assertEqual(1, detected_vault_format(self.store_path))
        legacy_cipher = LocalSecretCipher(LocalDeviceKeyProvider(self.key_path))
        legacy_reader = EncryptedLocalSecretStore(self.store_path, legacy_cipher)
        self.assertEqual("dummy-v1-api-value", legacy_reader.get("alias_custom_fixture_api"))
        self.assertEqual("dummy-v1-database-value", legacy_reader.get("alias_database_fixture_db"))
        self.assertEqual("dummy-new-value", legacy_reader.get("created_after_migration"))

    def test_rollback_dry_run_preserves_v2_store(self):
        self.service.migrate(2)
        before = self._read_bytes(self.store_path)

        result = self.service.rollback(1, dry_run=True)

        self.assertEqual("planned", result["status"])
        self.assertEqual(before, self._read_bytes(self.store_path))

    def test_manifest_failure_restores_exact_previous_store_and_releases_lock(self):
        before = self._read_bytes(self.store_path)

        with patch.object(self.service, "_write_manifest", side_effect=OSError("simulated manifest failure")):
            with self.assertRaises(OSError):
                self.service.migrate(2)

        self.assertEqual(before, self._read_bytes(self.store_path))
        self.assertEqual(1, detected_vault_format(self.store_path))
        self.assertFalse(os.path.exists(self.service.lock_path))
        self.assertTrue(self.service.verify()["ok"])

    def test_active_lock_prevents_concurrent_migration(self):
        with open(self.service.lock_path, "w") as handle:
            json.dump({"pid": os.getpid(), "created_at": 1}, handle)

        with self.assertRaises(VaultMigrationError):
            self.service.migrate(2)

        self.assertEqual(1, detected_vault_format(self.store_path))

    def test_stale_lock_is_removed_and_migration_continues(self):
        with open(self.service.lock_path, "w") as handle:
            json.dump({"pid": 99999999, "created_at": 1}, handle)

        result = self.service.migrate(2)

        self.assertEqual("completed", result["status"])
        self.assertFalse(os.path.exists(self.service.lock_path))

    def test_old_malformed_lock_is_treated_as_stale_but_new_one_fails_closed(self):
        with open(self.service.lock_path, "w") as handle:
            handle.write("not-json\n")
        with self.assertRaises(VaultMigrationError):
            self.service.migrate(2)
        old = 1
        os.utime(self.service.lock_path, (old, old))

        status = self.service.status()
        self.assertTrue(status["migration_lock"]["stale"])
        result = self.service.migrate(2)

        self.assertEqual("completed", result["status"])
        self.assertFalse(os.path.exists(self.service.lock_path))

    def test_mixed_or_unknown_record_format_fails_closed(self):
        with open(self.store_path, "r") as handle:
            data = json.load(handle)
        data["alias_custom_fixture_api"]["version"] = 2
        data["alias_custom_fixture_api"]["cipher"] = "aes-256-gcm-v2"
        with open(self.store_path, "w") as handle:
            json.dump(data, handle)

        self.assertEqual(0, detected_vault_format(self.store_path))
        with self.assertRaises(VaultMigrationError):
            self.service.migrate(2)
        with self.assertRaises(RuntimeError):
            encrypted_secret_store_for_vault()

    def test_missing_device_key_fails_without_creating_replacement(self):
        os.unlink(self.key_path)

        result = self.service.verify()

        self.assertFalse(result["ok"])
        self.assertIn("device key", json.dumps(result))
        self.assertFalse(os.path.exists(self.key_path))
        with self.assertRaises(VaultMigrationError):
            self.service.migrate(2)
        self.assertFalse(os.path.exists(self.key_path))

    def test_wrong_device_key_never_replaces_existing_store(self):
        before = self._read_bytes(self.store_path)
        with open(self.key_path, "wb") as handle:
            handle.write(base64.urlsafe_b64encode(bytes(reversed(range(32)))) + b"\n")

        with self.assertRaises(VaultMigrationError):
            self.service.migrate(2)

        self.assertEqual(before, self._read_bytes(self.store_path))
        self.assertFalse(os.path.exists(self.service.manifest_path))

    def test_tampered_record_reports_identifier_but_never_plaintext(self):
        with open(self.store_path, "r") as handle:
            data = json.load(handle)
        ciphertext = data["alias_custom_fixture_api"]["ciphertext"]
        data["alias_custom_fixture_api"]["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
        with open(self.store_path, "w") as handle:
            json.dump(data, handle)

        result = self.service.verify()

        self.assertFalse(result["ok"])
        self.assertIn("alias_custom_fixture_api", json.dumps(result))
        self.assertNotIn("dummy-v1-api-value", json.dumps(result))

    def test_missing_alias_target_blocks_migration(self):
        with open(self.aliases_path, "r") as handle:
            aliases = json.load(handle)
        aliases["fixture_api"]["secret_ref"] = "local:missing"
        with open(self.aliases_path, "w") as handle:
            json.dump(aliases, handle)

        with self.assertRaises(VaultMigrationError):
            self.service.migrate(2)

    def test_symlinked_store_is_rejected(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        real_store = self.store_path + ".real"
        os.replace(self.store_path, real_store)
        os.symlink(real_store, self.store_path)

        with self.assertRaises(VaultMigrationError):
            self.service.verify()

    def test_repeated_migration_is_idempotent(self):
        self.service.migrate(2)

        result = self.service.migrate(2)

        self.assertEqual("already_current", result["status"])
        self.assertEqual(2, result["records"])

    def _read_bytes(self, path):
        with open(path, "rb") as handle:
            return handle.read()


class NewVaultDefaultsTest(unittest.TestCase):
    def test_new_vault_writes_v2_records(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_home = os.environ.get("AGENTSECURE_HOME")
            os.environ["AGENTSECURE_HOME"] = temp_dir
            try:
                store = encrypted_secret_store_for_vault()
                store.put("new", "dummy-new-install-value")

                store_path = os.path.join(temp_dir, "vault", "secrets.enc.json")
                self.assertEqual(2, detected_vault_format(store_path))
                with open(store_path, "r") as handle:
                    data = json.load(handle)
                self.assertEqual(2, data["new"]["version"])
                self.assertEqual("aes-256-gcm-v2", data["new"]["cipher"])
                self.assertEqual("dummy-new-install-value", store.get("new"))
            finally:
                if old_home is None:
                    os.environ.pop("AGENTSECURE_HOME", None)
                else:
                    os.environ["AGENTSECURE_HOME"] = old_home

    def test_dependency_light_runtime_falls_back_to_v1_instead_of_breaking_cli(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_home = os.environ.get("AGENTSECURE_HOME")
            os.environ["AGENTSECURE_HOME"] = temp_dir
            try:
                with patch(
                    "agentsecure.implementations.secret_store_factory.aead_available",
                    return_value=False,
                ):
                    store = encrypted_secret_store_for_vault()
                    store.put("new", "dummy-fallback-value")

                store_path = os.path.join(temp_dir, "vault", "secrets.enc.json")
                with open(store_path, "r") as handle:
                    data = json.load(handle)
                self.assertEqual(1, data["new"]["version"])
                self.assertEqual("agentsecure-local-v1", data["new"]["cipher"])
            finally:
                if old_home is None:
                    os.environ.pop("AGENTSECURE_HOME", None)
                else:
                    os.environ["AGENTSECURE_HOME"] = old_home


if __name__ == "__main__":
    unittest.main()
