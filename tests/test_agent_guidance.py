import os
import tempfile
import unittest

from agentsecure.core.agent_guidance import (
    AGENT_GUIDE_FILENAME,
    render_agent_guidance,
    relative_agent_guidance_path,
    write_agent_guidance,
)
from agentsecure.core.models import SecretBinding


class AgentGuidanceTest(unittest.TestCase):
    def test_renders_managed_bindings_without_virtual_or_real_secret_values(self):
        text = render_agent_guidance(
            [
                SecretBinding(
                    env_name="OPENAI_API_KEY",
                    virtual_token="virt_openai_should_not_be_written",
                    real_secret_ref="vault://secret-ref-should-not-be-written",
                    provider="openai",
                    alias_id="openai_dev",
                    approved_hosts=["api.openai.com"],
                )
            ]
        )

        self.assertIn("OPENAI_API_KEY", text)
        self.assertIn("provider=openai", text)
        self.assertIn("approved_hosts=api.openai.com", text)
        self.assertIn("Do not read `.env` files", text)
        self.assertIn("agentsecure secrets import .env", text)
        self.assertIn("agentsecure secrets use <alias>", text)
        self.assertNotIn("virt_openai_should_not_be_written", text)
        self.assertNotIn("vault://secret-ref-should-not-be-written", text)

    def test_writes_per_run_guidance_under_agentsecure_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = write_agent_guidance(temp_dir, "run_test", [])

            self.assertEqual(
                os.path.join(temp_dir, ".agentsecure", "runs", "run_test", AGENT_GUIDE_FILENAME),
                path,
            )
            self.assertTrue(os.path.exists(path))
            self.assertEqual(
                os.path.join(".agentsecure", "runs", "run_test", AGENT_GUIDE_FILENAME),
                relative_agent_guidance_path(temp_dir, path),
            )


if __name__ == "__main__":
    unittest.main()
