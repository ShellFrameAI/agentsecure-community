import os
import tempfile
import unittest

from agentsecure.core.agentsecure_md import ensure_agentsecure_md, validate_agentsecure_md


class AgentSecureMdTest(unittest.TestCase):
    def test_template_is_created_and_validates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                result = ensure_agentsecure_md()
                self.assertTrue(result["created"])
                validation = validate_agentsecure_md()
                self.assertTrue(validation["ok"], validation)
                self.assertEqual([], validation["errors"])
            finally:
                os.chdir(cwd)

    def test_rejects_raw_secret_assignment(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "AGENTSECURE.md")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("# AGENTSECURE.md\nOPENAI_API_KEY=sk-live-secret-value\n")
            validation = validate_agentsecure_md(path)
            self.assertFalse(validation["ok"])
            self.assertIn("raw_secret", {error["code"] for error in validation["errors"]})

    def test_rejects_private_key_and_allow_real(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "AGENTSECURE.md")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "# AGENTSECURE.md\n"
                    "mode: allow_real\n"
                    "-----BEGIN " + "PRIVATE KEY-----\n"
                )
            validation = validate_agentsecure_md(path)
            codes = {error["code"] for error in validation["errors"]}
            self.assertFalse(validation["ok"])
            self.assertIn("allow_real", codes)
            self.assertIn("private_key", codes)

    def test_rejects_allow_mode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "AGENTSECURE.md")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("# AGENTSECURE.md\nDATABASE_URL_DEV:\n  mode: allow\n")
            validation = validate_agentsecure_md(path)
            self.assertFalse(validation["ok"])
            self.assertIn("allow", {error["code"] for error in validation["errors"]})

    def test_rejects_production_secret_direct_allow_wording(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "AGENTSECURE.md")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("# AGENTSECURE.md\nallow production database credential\n")
            validation = validate_agentsecure_md(path)
            self.assertFalse(validation["ok"])
            self.assertIn("allow_production_secret", {error["code"] for error in validation["errors"]})


if __name__ == "__main__":
    unittest.main()
