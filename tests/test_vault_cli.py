import base64
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import patch

from agentsecure.cli.main import main
from agentsecure.implementations.secret_store_factory import detected_vault_format
from agentsecure.implementations.secret_store_factory import clear_vault_key_provider_cache


FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


class VaultCliTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.home_dir = os.path.join(self.temp_dir.name, "home")
        vault_dir = os.path.join(self.home_dir, "vault")
        os.makedirs(vault_dir)
        with open(os.path.join(vault_dir, "device.key"), "wb") as handle:
            handle.write(base64.urlsafe_b64encode(bytes(range(32))) + b"\n")
        shutil.copyfile(
            os.path.join(FIXTURE_DIR, "vault-v1-0.1.22-secrets.enc.json"),
            os.path.join(vault_dir, "secrets.enc.json"),
        )
        shutil.copyfile(
            os.path.join(FIXTURE_DIR, "vault-v1-0.1.22-aliases.json"),
            os.path.join(vault_dir, "aliases.json"),
        )
        self.store_path = os.path.join(vault_dir, "secrets.enc.json")
        self.old_home = os.environ.get("AGENTSECURE_HOME")
        os.environ["AGENTSECURE_HOME"] = self.home_dir
        clear_vault_key_provider_cache()

    def tearDown(self):
        clear_vault_key_provider_cache()
        if self.old_home is None:
            os.environ.pop("AGENTSECURE_HOME", None)
        else:
            os.environ["AGENTSECURE_HOME"] = self.old_home
        self.temp_dir.cleanup()

    def test_status_and_verify_are_machine_readable_and_secret_free(self):
        status_output = StringIO()
        with redirect_stdout(status_output):
            self.assertEqual(0, main(["vault", "status"]))
        status = json.loads(status_output.getvalue())
        self.assertEqual(1, status["format_version"])

        verify_output = StringIO()
        with redirect_stdout(verify_output):
            self.assertEqual(0, main(["vault", "verify"]))
        verification = json.loads(verify_output.getvalue())
        self.assertTrue(verification["ok"])
        combined = status_output.getvalue() + verify_output.getvalue()
        self.assertNotIn("dummy-v1-api-value", combined)
        self.assertNotIn("dummy-v1-database-value", combined)

    def test_migrate_dry_run_does_not_prompt_or_write(self):
        with open(self.store_path, "rb") as handle:
            before = handle.read()
        output = StringIO()

        with patch("builtins.input", side_effect=AssertionError("must not prompt")):
            with redirect_stdout(output):
                self.assertEqual(0, main(["vault", "migrate", "--dry-run"]))

        result = json.loads(output.getvalue())
        self.assertEqual("planned", result["status"])
        with open(self.store_path, "rb") as handle:
            self.assertEqual(before, handle.read())

    def test_migrate_can_be_cancelled_without_writes(self):
        output = StringIO()
        with patch("builtins.input", return_value="n"):
            with redirect_stdout(output):
                self.assertEqual(1, main(["vault", "migrate"]))

        self.assertIn("cancelled", output.getvalue())
        self.assertEqual(1, detected_vault_format(self.store_path))

    def test_yes_migrates_and_rollback_prepares_v1(self):
        migrate_output = StringIO()
        with redirect_stdout(migrate_output):
            self.assertEqual(0, main(["vault", "migrate", "--yes"]))
        self.assertEqual(2, detected_vault_format(self.store_path))

        rollback_output = StringIO()
        with redirect_stdout(rollback_output):
            self.assertEqual(0, main(["vault", "rollback", "--yes"]))
        result = json.loads(rollback_output.getvalue())
        self.assertEqual("completed", result["status"])
        self.assertEqual(1, detected_vault_format(self.store_path))

    def test_invalid_vault_returns_concise_error_without_traceback_or_secret(self):
        with open(self.store_path, "w") as handle:
            handle.write("not-json\n")
        stdout = StringIO()
        stderr = StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(1, main(["vault", "verify"]))

        self.assertEqual("", stdout.getvalue())
        self.assertIn("vault verify failed", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertNotIn("dummy-v1-api-value", stderr.getvalue())

    def test_key_status_and_dry_run_do_not_unlock_or_write(self):
        before = self._key_snapshot()
        status_output = StringIO()
        dry_run_output = StringIO()
        with patch(
            "agentsecure.cli.main.read_passphrase_from_trusted_tty",
            side_effect=AssertionError("must not unlock"),
        ):
            with redirect_stdout(status_output):
                self.assertEqual(0, main(["vault", "key", "status"]))
            with redirect_stdout(dry_run_output):
                self.assertEqual(0, main(["vault", "key", "protect", "--dry-run"]))
        self.assertEqual("local_file", json.loads(status_output.getvalue())["provider"])
        self.assertEqual("planned", json.loads(dry_run_output.getvalue())["status"])
        self.assertEqual(before, self._key_snapshot())

    def test_key_protect_can_be_cancelled_before_passphrase_prompt(self):
        output = StringIO()
        with patch("builtins.input", return_value="n"), patch(
            "agentsecure.cli.main.read_passphrase_from_trusted_tty",
            side_effect=AssertionError("must not prompt after cancellation"),
        ):
            with redirect_stdout(output):
                self.assertEqual(1, main(["vault", "key", "protect"]))
        self.assertIn("cancelled", output.getvalue())
        self.assertTrue(os.path.exists(os.path.join(self.home_dir, "vault", "device.key")))

    def test_key_protect_and_unprotect_prompt_only_through_trusted_reader(self):
        outputs = []
        with patch(
            "agentsecure.cli.main.read_passphrase_from_trusted_tty",
            side_effect=["correct horse battery staple", "correct horse battery staple"],
        ) as reader:
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, main(["vault", "key", "protect", "--yes"]))
            outputs.append(output.getvalue())
            self.assertEqual(2, reader.call_count)
        wrapped_path = os.path.join(self.home_dir, "vault", "device.key.wrap.json")
        self.assertTrue(os.path.exists(wrapped_path))

        with patch(
            "agentsecure.cli.main.read_passphrase_from_trusted_tty",
            return_value="correct horse battery staple",
        ) as reader:
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, main(["vault", "key", "unprotect", "--yes"]))
            outputs.append(output.getvalue())
            self.assertEqual(1, reader.call_count)
        self.assertFalse(os.path.exists(wrapped_path))
        combined = "".join(outputs)
        self.assertNotIn("correct horse battery staple", combined)
        self.assertNotIn("dummy-v1-api-value", combined)

    def test_wrong_key_passphrase_is_concise_and_secret_free(self):
        with patch(
            "agentsecure.cli.main.read_passphrase_from_trusted_tty",
            side_effect=["correct horse battery staple", "correct horse battery staple"],
        ):
            with redirect_stdout(StringIO()):
                self.assertEqual(0, main(["vault", "key", "protect", "--yes"]))
        stdout = StringIO()
        stderr = StringIO()
        with patch("agentsecure.cli.main.read_passphrase_from_trusted_tty", return_value="wrong passphrase"):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(1, main(["vault", "key", "unprotect", "--yes"]))
        self.assertEqual("", stdout.getvalue())
        self.assertIn("vault key unprotect failed", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertNotIn("dummy-v1-api-value", stderr.getvalue())

    def _key_snapshot(self):
        snapshot = {}
        vault_dir = os.path.join(self.home_dir, "vault")
        for name in ("device.key", "device.key.wrap.json", "manifest.json"):
            path = os.path.join(vault_dir, name)
            if os.path.exists(path):
                with open(path, "rb") as handle:
                    snapshot[name] = handle.read()
            else:
                snapshot[name] = None
        return snapshot


if __name__ == "__main__":
    unittest.main()
