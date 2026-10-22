import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class McpFakeSecretDemoTest(unittest.TestCase):
    def test_demo_checks_mcp_flow_without_changing_caller_project_or_vault(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            dotenv = work / '.env'
            dotenv.write_text('CALLER_VALUE=not-a-secret\n')
            vault = work / 'caller-vault'
            vault.mkdir()
            marker = vault / 'keep.txt'
            marker.write_text('unchanged')
            result = subprocess.run(
                [sys.executable, str(root / 'examples' / 'mcp_fake_secret_demo.py')],
                cwd=temp, env=dict(os.environ, AGENTSECURE_HOME=str(vault)),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=45,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(
                'Project file: DEMO_API_KEY=AGENTSECURE_ALIAS_DEMO_API_KEY\n'
                'Approved fixture: received the fake credential\n'
                'MCP response: Bearer [redacted]\n'
                'Unapproved destination: blocked\n'
                'Demo passed; temporary project and vault removed.\n',
                result.stdout,
            )
            self.assertEqual('CALLER_VALUE=not-a-secret\n', dotenv.read_text())
            self.assertEqual(['keep.txt'], sorted(p.name for p in vault.iterdir()))
            self.assertEqual('unchanged', marker.read_text())
            self.assertFalse((work / 'agentsecure.json').exists())

    def test_readme_local_links_are_absolute_for_pypi(self):
        import re
        root = Path(__file__).resolve().parents[1]
        text = (root / 'README.md').read_text()
        for target in re.findall(r'\]\(([^)]+)\)', text):
            self.assertTrue(target.startswith(('https://', '#')), target)


if __name__ == '__main__':
    unittest.main()
