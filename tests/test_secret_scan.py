import os
import tempfile
import unittest
from unittest.mock import patch

from scripts.secret_scan import scan_path


class SecretScanTest(unittest.TestCase):
    def test_allows_marked_demo_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "README.md")
            with open(path, "w") as handle:
                handle.write("OPENAI_API_KEY=sk-demo-local-secret-do-not-use\n")

            self.assertEqual([], scan_path(temp_dir))

    def test_finds_unmarked_tokens(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "settings.txt")
            with open(path, "w") as handle:
                handle.write("token=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n")  # fake scanner fixture

            findings = scan_path(temp_dir)

        self.assertEqual(1, len(findings))
        self.assertEqual("github token", findings[0].kind)

    def test_marker_words_do_not_hide_real_looking_tokens(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "settings.txt")
            with open(path, "w") as handle:
                handle.write("REAL_TOKEN_FOR_test=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n")

            findings = scan_path(temp_dir)

        self.assertEqual(1, len(findings))
        self.assertEqual("github token", findings[0].kind)

    def test_allows_scanner_fixture_with_windows_path_separator(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "fixture.py")
            with open(path, "w") as handle:
                handle.write("token=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n")

            with patch(
                "scripts.secret_scan.os.path.relpath",
                return_value=r"tests\test_secret_scan.py",
            ):
                self.assertEqual([], scan_path(temp_dir))


if __name__ == "__main__":
    unittest.main()
