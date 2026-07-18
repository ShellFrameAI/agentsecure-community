import json
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from agentsecure.core.dotenv_backups import (
    DotenvBackupError,
    backup_dotenv_to_vault,
    dotenv_backup_directory,
    dotenv_backup_status,
    is_encrypted_dotenv_backup,
    latest_dotenv_backup,
    migrate_legacy_dotenv_backups,
    restore_dotenv_backup,
)


class DotenvBackupsTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.project_dir = os.path.join(self.temp_dir.name, "project")
        self.home_dir = os.path.join(self.temp_dir.name, "home")
        os.makedirs(self.project_dir)
        self.config_path = os.path.join(self.project_dir, "agentsecure.json")
        self.dotenv_path = os.path.join(self.project_dir, ".env")
        self.secret_text = "API_KEY=backup-secret-value\nDEBUG=true\n"
        with open(self.dotenv_path, "w") as handle:
            handle.write(self.secret_text)
        self.old_home = os.environ.get("AGENTSECURE_HOME")
        os.environ["AGENTSECURE_HOME"] = self.home_dir

    def tearDown(self):
        if self.old_home is None:
            os.environ.pop("AGENTSECURE_HOME", None)
        else:
            os.environ["AGENTSECURE_HOME"] = self.old_home
        self.temp_dir.cleanup()

    def test_backup_is_encrypted_at_rest_and_restores_atomically(self):
        backup_path = backup_dotenv_to_vault(self.dotenv_path, self.config_path)

        self.assertTrue(backup_path.endswith(".asbak"))
        self.assertTrue(is_encrypted_dotenv_backup(backup_path))
        with open(backup_path, "r") as handle:
            raw = handle.read()
        self.assertNotIn("backup-secret-value", raw)
        self.assertEqual(0, stat.S_IMODE(os.stat(backup_path).st_mode) & 0o077)
        self.assertEqual(0, stat.S_IMODE(os.stat(os.path.dirname(backup_path)).st_mode) & 0o077)

        with open(self.dotenv_path, "w") as handle:
            handle.write("API_KEY=placeholder\n")
        restore_dotenv_backup(self.dotenv_path, backup_path)

        with open(self.dotenv_path, "r") as handle:
            self.assertEqual(self.secret_text, handle.read())
        self.assertEqual(0o600, stat.S_IMODE(os.stat(self.dotenv_path).st_mode))

    def test_backup_names_are_unique_even_within_one_second(self):
        first = backup_dotenv_to_vault(self.dotenv_path, self.config_path)
        second = backup_dotenv_to_vault(self.dotenv_path, self.config_path)

        self.assertNotEqual(first, second)
        self.assertTrue(os.path.exists(first))
        self.assertTrue(os.path.exists(second))

    def test_tampered_encrypted_backup_is_rejected_without_changing_dotenv(self):
        backup_path = backup_dotenv_to_vault(self.dotenv_path, self.config_path)
        with open(backup_path, "r") as handle:
            envelope = json.load(handle)
        ciphertext = envelope["ciphertext"]
        envelope["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
        with open(backup_path, "w") as handle:
            json.dump(envelope, handle)
        with open(self.dotenv_path, "w") as handle:
            handle.write("SAFE=unchanged\n")

        with self.assertRaises(DotenvBackupError):
            restore_dotenv_backup(self.dotenv_path, backup_path)

        with open(self.dotenv_path, "r") as handle:
            self.assertEqual("SAFE=unchanged\n", handle.read())

    def test_malformed_asbak_is_never_restored_as_plaintext(self):
        backup_dir = dotenv_backup_directory(self.config_path)
        os.makedirs(backup_dir)
        malformed_path = os.path.join(backup_dir, ".env.bad.asbak")
        with open(malformed_path, "w") as handle:
            handle.write("not-an-encrypted-backup\n")
        with open(self.dotenv_path, "w") as handle:
            handle.write("SAFE=unchanged\n")

        with self.assertRaises(DotenvBackupError):
            restore_dotenv_backup(self.dotenv_path, malformed_path)

        with open(self.dotenv_path, "r") as handle:
            self.assertEqual("SAFE=unchanged\n", handle.read())
        status = dotenv_backup_status(self.config_path)
        self.assertEqual([malformed_path], status["invalid_encrypted"])
        self.assertFalse(status["ok"])

    def test_legacy_plaintext_backup_still_restores_for_backward_compatibility(self):
        backup_dir = dotenv_backup_directory(self.config_path)
        os.makedirs(backup_dir)
        legacy_path = os.path.join(backup_dir, ".env.20260101010101.bak")
        with open(legacy_path, "w") as handle:
            handle.write(self.secret_text)
        with open(self.dotenv_path, "w") as handle:
            handle.write("API_KEY=placeholder\n")

        restore_dotenv_backup(self.dotenv_path, legacy_path)

        with open(self.dotenv_path, "r") as handle:
            self.assertEqual(self.secret_text, handle.read())

    def test_latest_backup_supports_encrypted_and_legacy_formats(self):
        backup_dir = dotenv_backup_directory(self.config_path)
        os.makedirs(backup_dir)
        legacy_path = os.path.join(backup_dir, ".env.20260101010101.bak")
        with open(legacy_path, "w") as handle:
            handle.write(self.secret_text)
        os.utime(legacy_path, (1, 1))

        encrypted_path = backup_dotenv_to_vault(self.dotenv_path, self.config_path)

        self.assertEqual(encrypted_path, latest_dotenv_backup(self.dotenv_path, self.config_path))

    def test_migration_dry_run_does_not_write_or_delete(self):
        legacy_path = self._write_legacy_backup()

        result = migrate_legacy_dotenv_backups(self.config_path, dry_run=True)

        self.assertEqual(1, result["legacy_plaintext_count"])
        self.assertEqual([], result["migrated"])
        self.assertTrue(os.path.exists(legacy_path))
        self.assertFalse(os.path.exists(result["planned"][0]["target"]))

    def test_migration_verifies_encrypted_copy_before_removing_plaintext(self):
        legacy_path = self._write_legacy_backup()

        result = migrate_legacy_dotenv_backups(self.config_path)

        self.assertEqual([legacy_path], result["removed_plaintext"])
        self.assertFalse(os.path.exists(legacy_path))
        self.assertEqual(1, len(result["migrated"]))
        encrypted_path = result["migrated"][0]
        self.assertTrue(is_encrypted_dotenv_backup(encrypted_path))
        with open(encrypted_path, "r") as handle:
            self.assertNotIn("backup-secret-value", handle.read())
        with open(self.dotenv_path, "w") as handle:
            handle.write("API_KEY=placeholder\n")
        restore_dotenv_backup(self.dotenv_path, encrypted_path)
        with open(self.dotenv_path, "r") as handle:
            self.assertEqual(self.secret_text, handle.read())

    def test_migration_failure_never_removes_plaintext_source(self):
        legacy_path = self._write_legacy_backup()

        with patch(
            "agentsecure.core.dotenv_backups._write_encrypted_backup",
            side_effect=DotenvBackupError("simulated write failure"),
        ):
            with self.assertRaises(DotenvBackupError):
                migrate_legacy_dotenv_backups(self.config_path)

        self.assertTrue(os.path.exists(legacy_path))

    def test_status_reports_only_metadata_and_legacy_risk(self):
        legacy_path = self._write_legacy_backup()
        encrypted_path = backup_dotenv_to_vault(self.dotenv_path, self.config_path)

        status = dotenv_backup_status(self.config_path)

        self.assertFalse(status["ok"])
        self.assertEqual([encrypted_path], status["encrypted"])
        self.assertEqual([legacy_path], status["legacy_plaintext"])
        self.assertNotIn("backup-secret-value", json.dumps(status))

    def _write_legacy_backup(self):
        backup_dir = dotenv_backup_directory(self.config_path)
        os.makedirs(backup_dir, exist_ok=True)
        legacy_path = os.path.join(backup_dir, ".env.20260101010101.bak")
        with open(legacy_path, "w") as handle:
            handle.write(self.secret_text)
        os.chmod(legacy_path, 0o600)
        return legacy_path


if __name__ == "__main__":
    unittest.main()
