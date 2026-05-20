import json
import os
import tempfile
import unittest

from agentsecure.implementations.audit import JsonLineAuditLogger


class JsonLineAuditLoggerTest(unittest.TestCase):
    def test_redacts_token_and_secret_fields(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_path = os.path.join(temp_dir, "audit.log")
            raw_secret = "postgres://user:password@test-dev.host.domain:5432/mydb"

            JsonLineAuditLogger(audit_path).record(
                "test",
                {
                    "virtual_token": "virt_openai_visible",
                    "secret_ref": "local:openai_1",
                    "reason": raw_secret,
                    "nested": {"api_key": "sk-real-secret-value"},
                    "host": "api.openai.com",
                },
            )

            with open(audit_path, "r") as handle:
                event = json.loads(handle.read())

            body = json.dumps(event)
            self.assertNotIn("virt_openai_visible", body)
            self.assertNotIn("local:openai_1", body)
            self.assertNotIn(raw_secret, body)
            self.assertNotIn("sk-real-secret-value", body)
            self.assertEqual("api.openai.com", event["details"]["host"])


if __name__ == "__main__":
    unittest.main()
