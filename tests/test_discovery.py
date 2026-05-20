import os
import tempfile
import unittest

from agentsecure.discovery.dotenv_scanner import DotenvSecretScanner
from agentsecure.discovery.env_scanner import EnvironmentSecretScanner
from agentsecure.discovery.patterns import mask_secret


class DiscoveryTest(unittest.TestCase):
    def test_environment_scanner_finds_api_key(self):
        scanner = EnvironmentSecretScanner({"OPENAI_API_KEY": "sk-test-secret", "DEBUG": "true"})
        results = scanner.scan()
        self.assertEqual(1, len(results))
        self.assertEqual("OPENAI_API_KEY", results[0].name)
        self.assertEqual("openai", results[0].provider_hint)

    def test_dotenv_scanner_finds_secret(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, ".env"), "w") as handle:
                handle.write("STRIPE_SECRET_KEY=sk_test_123456789\n")
                handle.write("DEBUG=true\n")
            results = DotenvSecretScanner(temp_dir).scan()
            self.assertEqual(1, len(results))
            self.assertEqual("STRIPE_SECRET_KEY", results[0].name)
            self.assertEqual("stripe", results[0].provider_hint)

    def test_dotenv_scanner_finds_database_url_with_credentials(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, ".env"), "w") as handle:
                handle.write("DATABASE_URL=postgres://user:password@localhost:5432/mydb\n")
                handle.write("PUBLIC_URL=https://example.com\n")
            results = DotenvSecretScanner(temp_dir).scan()
            self.assertEqual(1, len(results))
            self.assertEqual("DATABASE_URL", results[0].name)
            self.assertEqual("database", results[0].provider_hint)

    def test_environment_scanner_finds_credential_url_even_with_custom_name(self):
        scanner = EnvironmentSecretScanner(
            {"SERVICE_DSN": "postgres://user:password@localhost:5432/mydb"}
        )
        results = scanner.scan()
        self.assertEqual(1, len(results))
        self.assertEqual("SERVICE_DSN", results[0].name)

    def test_mask_secret(self):
        self.assertEqual("sk-t...cret", mask_secret("sk-test-secret"))
        self.assertEqual("****", mask_secret("abcd"))


if __name__ == "__main__":
    unittest.main()
