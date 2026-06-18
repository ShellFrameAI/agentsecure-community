import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

from agentsecure.cli.main import build_parser, main


class ScanCliTest(unittest.TestCase):
    def test_scan_text_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_url = "postgres" + "://user:pass@prod.example/db"
            self._write(temp_dir, ".env.production", "DATABASE_URL=%s\n" % database_url)

            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, main(["scan", temp_dir]))

            text = output.getvalue()
            self.assertIn("AgentSecure AI Coding Agent Security Scanner", text)
            self.assertIn("Risk:", text)
            self.assertIn("Production-looking .env file found", text)
            self.assertIn("[ ] Create agent-safe `.env`", text)

    def test_scan_markdown_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write(temp_dir, "package.json", json.dumps({"scripts": {"deploy": "aws deploy"}}))

            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, main(["scan", temp_dir, "--format", "markdown"]))

            markdown = output.getvalue()
            self.assertIn("# AgentSecure AI Coding Agent Security Scanner", markdown)
            self.assertIn("## Medium", markdown)
            self.assertIn("Risky npm script found: deploy", markdown)

    def test_scan_json_output_redacts_secrets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            token = "ghp_" + ("A" * 36)
            self._write(temp_dir, "token.txt", "GITHUB_TOKEN=%s\n" % token)

            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, main(["scan", temp_dir, "--format", "json"]))

            rendered = output.getvalue()
            payload = json.loads(rendered)
            self.assertIn(payload["risk"], ("Low", "Medium", "High", "Critical"))
            self.assertTrue(payload["findings"])
            self.assertEqual(-1, rendered.find(token))
            self.assertIn("ghp_...", rendered)

    def test_audit_alias_parses(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, main(["audit", temp_dir, "--format", "json"]))

            payload = json.loads(output.getvalue())
            self.assertEqual(temp_dir, payload["path"])

    def test_existing_run_command_still_parses(self):
        args = build_parser().parse_args(["run", "--", "echo", "hello"])

        self.assertEqual("run", args.command)
        self.assertEqual(["--", "echo", "hello"], args.agent_command)

    def test_scan_rejects_missing_path(self):
        stderr = StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(2, main(["scan", "/path/that/does/not/exist"]))

        self.assertIn("scan path is not a directory", stderr.getvalue())

    def _write(self, root: str, rel_path: str, content: str) -> None:
        path = os.path.join(root, rel_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            handle.write(content)


if __name__ == "__main__":
    unittest.main()
