import tempfile
import unittest

from tests.integration.helpers import run_agentsecure


class CliDemoTest(unittest.TestCase):
    def test_demo_masks_and_blocks_dotenv_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_agentsecure(["demo"], cwd=temp_dir)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("AgentSecure community demo", result.stdout)
        self.assertIn("Command: cat .env", result.stdout)
        self.assertIn("OPENAI_API_KEY=virt_openai_", result.stdout)
        self.assertIn("DATABASE_URL_PROD was removed", result.stdout)
        self.assertNotIn("sk-demo-local-secret-do-not-use", result.stdout)
        self.assertNotIn("postgres://demo:demo-password@production.example/app", result.stdout)


if __name__ == "__main__":
    unittest.main()
