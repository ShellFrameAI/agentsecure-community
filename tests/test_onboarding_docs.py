import os
import unittest


class OnboardingDocsTest(unittest.TestCase):
    def test_claude_setup_is_stack_aware_and_persistent(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        setup_path = os.path.join(root, "docs", "claude-code-setup.md")
        with open(setup_path, "r", encoding="utf-8") as handle:
            setup = handle.read()

        for stack_marker in ("uv.lock", "poetry.lock", "Pipfile", "environment.yml"):
            self.assertIn(stack_marker, setup)
        self.assertIn("agentsecure start --client claude", setup)
        self.assertIn("CLAUDE.md", setup)
        self.assertIn("agentsecure doctor", setup)
        self.assertIn("Do not introduce a different package manager", setup)

    def test_llms_index_points_agents_to_claude_setup(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "llms.txt"), "r", encoding="utf-8") as handle:
            index = handle.read()

        self.assertIn("docs/claude-code-setup.md", index)
        self.assertIn("agentsecure start --client claude", index)


if __name__ == "__main__":
    unittest.main()
