import os
import tempfile
import unittest

from agentsecure.client.wrappers import AgentWrapperInstaller


class AgentWrapperInstallerTest(unittest.TestCase):
    def test_install_list_and_remove_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            agentsecure = os.path.join(temp_dir, "agentsecure")
            with open(agentsecure, "w") as handle:
                handle.write("#!/bin/sh\n")
            os.chmod(agentsecure, 0o755)

            installer = AgentWrapperInstaller(temp_dir, agentsecure)
            installed = installer.install("claude")

            self.assertTrue(installed.installed)
            self.assertTrue(os.path.exists(installed.path))
            self.assertTrue(os.access(installed.path, os.X_OK))
            with open(installed.path, "r") as handle:
                source = handle.read()
            self.assertIn('exec "$AGENTSECURE_BIN" run -- "$REAL_AGENT" "$@"', source)
            self.assertIn("command -v claude", source)

            rows = {item.agent: item for item in installer.list()}
            self.assertTrue(rows["claude"].installed)
            self.assertFalse(rows["codex"].installed)

            removed = installer.remove("claude")
            self.assertFalse(removed.installed)
            self.assertFalse(os.path.exists(removed.path))

    def test_rejects_unsupported_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            installer = AgentWrapperInstaller(temp_dir)
            with self.assertRaises(ValueError):
                installer.install("unknown")


if __name__ == "__main__":
    unittest.main()
