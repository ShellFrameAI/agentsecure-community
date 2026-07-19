import base64
import json
import os
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

from agentsecure.core.dotenv_backups import backup_dotenv_to_vault, restore_dotenv_backup
from agentsecure.core.vault_key_migration import VaultKeyMigrationError, VaultKeyMigrationService
from agentsecure.core.vault_migration import VaultMigrationService
from agentsecure.crypto.cipher import LocalSecretCipher
from agentsecure.crypto.key_provider import LocalDeviceKeyProvider
from agentsecure.implementations.encrypted_secret_store import EncryptedLocalSecretStore
from agentsecure.implementations.secret_store_factory import (
    clear_vault_key_provider_cache,
    encrypted_secret_store_for_vault,
)


FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
FIXTURE_SECRETS = ("dummy-v1-api-value", "dummy-v1-database-value")


class VaultKeyMigrationServiceTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.home_dir = os.path.join(self.temp_dir.name, "home")
        self.vault_dir = os.path.join(self.home_dir, "vault")
        os.makedirs(self.vault_dir)
        self.raw_key_path = os.path.join(self.vault_dir, "device.key")
        self.encoded_key = base64.urlsafe_b64encode(bytes(range(32)))
        with open(self.raw_key_path, "wb") as handle:
            handle.write(self.encoded_key + b"\n")
        os.chmod(self.raw_key_path, 0o600)
        self.store_path = os.path.join(self.vault_dir, "secrets.enc.json")
        shutil.copyfile(os.path.join(FIXTURE_DIR, "vault-v1-0.1.22-secrets.enc.json"), self.store_path)
        shutil.copyfile(
            os.path.join(FIXTURE_DIR, "vault-v1-0.1.22-aliases.json"),
            os.path.join(self.vault_dir, "aliases.json"),
        )
        self.old_home = os.environ.get("AGENTSECURE_HOME")
        os.environ["AGENTSECURE_HOME"] = self.home_dir
        clear_vault_key_provider_cache()
        self.service = VaultKeyMigrationService(self.home_dir)
        self.passphrase = "correct horse battery staple"

    def tearDown(self):
        clear_vault_key_provider_cache()
        if self.old_home is None:
            os.environ.pop("AGENTSECURE_HOME", None)
        else:
            os.environ["AGENTSECURE_HOME"] = self.old_home
        self.temp_dir.cleanup()

    def test_protect_verifies_then_removes_raw_key_and_vault_stays_readable(self):
        result = self.service.protect(self.passphrase, self.passphrase)

        self.assertEqual("completed", result["status"])
        self.assertEqual("passphrase_wrapped", result["provider"])
        self.assertEqual(2, result["verification"]["vault_records_verified"])
        self.assertFalse(os.path.exists(self.raw_key_path))
        self.assertTrue(os.path.isfile(self.service.wrapped_key_path))
        self.assertEqual(0, stat.S_IMODE(os.stat(self.service.wrapped_key_path).st_mode) & 0o077)
        with open(self.service.wrapped_key_path, "r") as handle:
            wrapped_text = handle.read()
        self.assertNotIn(self.encoded_key.decode("ascii"), wrapped_text)
        for secret in FIXTURE_SECRETS:
            self.assertNotIn(secret, wrapped_text)

        with patch(
            "agentsecure.crypto.wrapped_key_provider.read_passphrase_from_trusted_tty",
            return_value=self.passphrase,
        ):
            store = encrypted_secret_store_for_vault()
            self.assertEqual(FIXTURE_SECRETS[0], store.get("alias_custom_fixture_api"))

    def test_dry_run_verifies_without_passphrase_prompt_or_writes(self):
        before = self._snapshot()
        with patch(
            "agentsecure.crypto.wrapped_key_provider.read_passphrase_from_trusted_tty",
            side_effect=AssertionError("must not prompt"),
        ):
            result = self.service.protect(dry_run=True)
        self.assertEqual("planned", result["status"])
        self.assertEqual(before, self._snapshot())

    def test_wrong_confirmation_or_short_passphrase_never_changes_key_files(self):
        before = self._snapshot()
        with self.assertRaisesRegex(VaultKeyMigrationError, "does not match"):
            self.service.protect(self.passphrase, "different passphrase")
        self.assertEqual(before, self._snapshot())
        with self.assertRaisesRegex(VaultKeyMigrationError, "at least 12"):
            self.service.protect("too short", "too short")
        self.assertEqual(before, self._snapshot())

    def test_post_write_verification_failure_keeps_original_raw_key(self):
        initial = self.service._verify_everything(self.encoded_key)
        with patch.object(
            self.service,
            "_verify_everything",
            side_effect=[initial, VaultKeyMigrationError("simulated post-write failure")],
        ):
            with self.assertRaisesRegex(VaultKeyMigrationError, "post-write"):
                self.service.protect(self.passphrase, self.passphrase)

        self.assertEqual(self.encoded_key, self.service._read_raw_key())
        self.assertFalse(os.path.exists(self.service.wrapped_key_path))

    def test_manifest_failure_rolls_back_to_exact_safe_provider_state(self):
        with patch.object(self.service, "_write_manifest", side_effect=OSError("simulated manifest failure")):
            with self.assertRaisesRegex(OSError, "manifest failure"):
                self.service.protect(self.passphrase, self.passphrase)

        self.assertEqual("local_file", self.service.status()["provider"])
        self.assertEqual(self.encoded_key, self.service._read_raw_key())
        self.assertFalse(os.path.exists(self.service.lock_path))

    def test_unprotect_prepares_exact_v1_reader_compatibility(self):
        self.service.protect(self.passphrase, self.passphrase)
        result = self.service.unprotect(self.passphrase)

        self.assertEqual("completed", result["status"])
        self.assertEqual("local_file", result["provider"])
        self.assertFalse(os.path.exists(self.service.wrapped_key_path))
        self.assertEqual(0, stat.S_IMODE(os.stat(self.raw_key_path).st_mode) & 0o077)
        legacy = EncryptedLocalSecretStore(
            self.store_path,
            LocalSecretCipher(LocalDeviceKeyProvider(self.raw_key_path)),
        )
        self.assertEqual(FIXTURE_SECRETS[0], legacy.get("alias_custom_fixture_api"))
        self.assertEqual(FIXTURE_SECRETS[1], legacy.get("alias_database_fixture_db"))

    def test_documented_protected_vault_downgrade_sequence_is_end_to_end_compatible(self):
        self.service.protect(self.passphrase, self.passphrase)
        with patch(
            "agentsecure.crypto.wrapped_key_provider.read_passphrase_from_trusted_tty",
            return_value=self.passphrase,
        ):
            VaultMigrationService(self.home_dir).migrate(2)
        clear_vault_key_provider_cache()
        with patch(
            "agentsecure.crypto.wrapped_key_provider.read_passphrase_from_trusted_tty",
            return_value=self.passphrase,
        ):
            VaultMigrationService(self.home_dir).rollback(1)
        self.service.unprotect(self.passphrase)

        legacy = EncryptedLocalSecretStore(
            self.store_path,
            LocalSecretCipher(LocalDeviceKeyProvider(self.raw_key_path)),
        )
        self.assertEqual(FIXTURE_SECRETS[0], legacy.get("alias_custom_fixture_api"))
        self.assertEqual(FIXTURE_SECRETS[1], legacy.get("alias_database_fixture_db"))

    def test_unprotect_dry_run_does_not_prompt_or_change_wrapped_key(self):
        self.service.protect(self.passphrase, self.passphrase)
        before = self._snapshot()
        with patch(
            "agentsecure.crypto.wrapped_key_provider.read_passphrase_from_trusted_tty",
            side_effect=AssertionError("must not prompt"),
        ):
            result = self.service.unprotect(dry_run=True)
        self.assertEqual("passphrase_required", result["status"])
        self.assertEqual(before, self._snapshot())

    def test_wrong_unprotect_passphrase_does_not_create_raw_key(self):
        self.service.protect(self.passphrase, self.passphrase)
        with self.assertRaisesRegex(RuntimeError, "incorrect or.*modified"):
            self.service.unprotect("wrong passphrase")
        self.assertEqual("passphrase_wrapped", self.service.status()["provider"])
        self.assertFalse(os.path.exists(self.raw_key_path))

    def test_unprotect_manifest_failure_restores_wrapped_state(self):
        self.service.protect(self.passphrase, self.passphrase)
        with patch.object(self.service, "_write_manifest", side_effect=OSError("simulated manifest failure")):
            with self.assertRaises(OSError):
                self.service.unprotect(self.passphrase)
        self.assertEqual("passphrase_wrapped", self.service.status()["provider"])
        self.assertFalse(os.path.exists(self.raw_key_path))

    def test_ambiguous_state_fails_factory_closed_but_command_can_finish_recovery(self):
        wrapped_bytes = None
        self.service.protect(self.passphrase, self.passphrase)
        with open(self.service.wrapped_key_path, "rb") as handle:
            wrapped_bytes = handle.read()
        with open(self.raw_key_path, "wb") as handle:
            handle.write(self.encoded_key + b"\n")
        clear_vault_key_provider_cache()

        self.assertEqual("ambiguous", self.service.status()["provider"])
        with self.assertRaisesRegex(RuntimeError, "both raw and wrapped"):
            encrypted_secret_store_for_vault()
        result = self.service.protect(self.passphrase, self.passphrase)
        self.assertEqual("completed", result["status"])
        self.assertFalse(os.path.exists(self.raw_key_path))
        with open(self.service.wrapped_key_path, "rb") as handle:
            self.assertEqual(wrapped_bytes, handle.read())

    def test_v2_vault_and_encrypted_backup_survive_key_provider_round_trip(self):
        VaultMigrationService(self.home_dir).migrate(2)
        dotenv_path = os.path.join(self.temp_dir.name, ".env")
        config_path = os.path.join(self.temp_dir.name, ".agentsecure.yaml")
        dotenv_secret = "BACKUP_TOKEN=dummy-backup-canary-value\n"
        with open(dotenv_path, "w") as handle:
            handle.write(dotenv_secret)
        backup_path = backup_dotenv_to_vault(dotenv_path, config_path)

        protected = self.service.protect(self.passphrase, self.passphrase)
        self.assertEqual(1, protected["verification"]["encrypted_backups_verified"])
        os.unlink(dotenv_path)
        with patch(
            "agentsecure.crypto.wrapped_key_provider.read_passphrase_from_trusted_tty",
            return_value=self.passphrase,
        ):
            restore_dotenv_backup(dotenv_path, backup_path)
        with open(dotenv_path, "r") as handle:
            self.assertEqual(dotenv_secret, handle.read())

        self.service.unprotect(self.passphrase)
        self.assertTrue(VaultMigrationService(self.home_dir).verify()["ok"])

    def test_invalid_or_missing_key_state_is_reported_without_creating_replacement(self):
        os.unlink(self.raw_key_path)
        self.assertEqual("missing", self.service.status()["provider"])
        with self.assertRaisesRegex(VaultKeyMigrationError, "missing"):
            self.service.protect(self.passphrase, self.passphrase)
        self.assertFalse(os.path.exists(self.raw_key_path))

        if hasattr(os, "symlink"):
            os.symlink(self.store_path, self.raw_key_path)
            self.assertEqual("invalid", self.service.status()["provider"])
            with self.assertRaisesRegex(VaultKeyMigrationError, "invalid"):
                self.service.protect(self.passphrase, self.passphrase)

    def test_empty_install_can_start_protected_without_ever_writing_raw_key(self):
        os.unlink(self.raw_key_path)
        os.unlink(self.store_path)
        os.unlink(os.path.join(self.vault_dir, "aliases.json"))
        self.assertEqual("uninitialized", self.service.status()["provider"])

        result = self.service.protect(self.passphrase, self.passphrase)

        self.assertEqual("completed", result["status"])
        self.assertEqual("passphrase_wrapped", self.service.status()["provider"])
        self.assertFalse(os.path.exists(self.raw_key_path))
        with patch(
            "agentsecure.crypto.wrapped_key_provider.read_passphrase_from_trusted_tty",
            return_value=self.passphrase,
        ):
            store = encrypted_secret_store_for_vault()
            store.put("first", "dummy-first-protected-value")
            self.assertEqual("dummy-first-protected-value", store.get("first"))

    def _snapshot(self):
        result = {}
        for name in ("device.key", "device.key.wrap.json", "manifest.json"):
            path = os.path.join(self.vault_dir, name)
            if os.path.exists(path):
                with open(path, "rb") as handle:
                    result[name] = handle.read()
            else:
                result[name] = None
        return result


if __name__ == "__main__":
    unittest.main()
