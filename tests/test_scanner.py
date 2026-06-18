import json
import os
import tempfile
import unittest

from agentsecure.scanner.reporters import render_report
from agentsecure.scanner.scanner import RepositoryScanner


class RepositoryScannerTest(unittest.TestCase):
    def test_clean_repo_has_low_risk(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write(temp_dir, "README.md", "# Demo\n")

            report = RepositoryScanner().scan(temp_dir)

            self.assertEqual([], report.findings)
            self.assertEqual(100, report.score)
            self.assertEqual("Low", report.risk_level)

    def test_env_file_and_secret_are_reported_with_redaction(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            secret = "sk-ant-" + ("A" * 40) + "1234"
            self._write(temp_dir, ".env", "ANTHROPIC_API_KEY=%s\n" % secret)

            report = RepositoryScanner().scan(temp_dir)
            text = render_report(report, "text")
            payload = render_report(report, "json")

            self.assertTrue(any(finding.path == ".env" for finding in report.findings))
            self.assertIn("sk-a...1234", text)
            self.assertEqual(-1, text.find(secret))
            self.assertEqual(-1, payload.find(secret))

    def test_mcp_config_with_broad_filesystem_access_is_high(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write(
                temp_dir,
                ".mcp.json",
                json.dumps(
                    {
                        "mcpServers": {
                            "filesystem": {
                                "command": "npx",
                                "args": ["@modelcontextprotocol/server-filesystem", "/"],
                            }
                        }
                    }
                ),
            )

            report = RepositoryScanner().scan(temp_dir)

            self.assertTrue(
                any(
                    finding.title == "MCP config exposes broad filesystem access"
                    and finding.severity == "High"
                    for finding in report.findings
                )
            )

    def test_risky_package_json_script_is_reported(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write(
                temp_dir,
                "package.json",
                json.dumps({"scripts": {"seed-prod": "node scripts/seed-prod.js"}}),
            )

            report = RepositoryScanner().scan(temp_dir)

            self.assertTrue(
                any(
                    finding.title == "Risky npm script found: seed-prod"
                    and finding.severity == "High"
                    for finding in report.findings
                )
            )

    def test_cloud_credential_patterns_are_redacted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            aws_key = "AKIA" + ("A" * 12) + "1234"
            self._write(temp_dir, "config.txt", "AWS_ACCESS_KEY_ID=%s\n" % aws_key)

            report = RepositoryScanner().scan(temp_dir)
            rendered = render_report(report, "markdown")

            self.assertIn("AKIA...1234", rendered)
            self.assertEqual(-1, rendered.find(aws_key))

    def test_supabase_and_jwt_credentials_are_detected_without_full_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            supabase_key = "eyJ" + ("a" * 30) + "." + ("b" * 30) + "." + ("c" * 30)
            jwt_secret = "jwt-secret-" + ("x" * 32)
            self._write(
                temp_dir,
                ".env.local",
                "SUPABASE_SERVICE_ROLE_KEY=%s\nJWT_SECRET=%s\n" % (supabase_key, jwt_secret),
            )

            report = RepositoryScanner().scan(temp_dir)
            rendered = render_report(report, "json")

            self.assertTrue(any("Supabase credential" in finding.title for finding in report.findings))
            self.assertTrue(any("JWT secret or private key" in finding.title for finding in report.findings))
            self.assertEqual(-1, rendered.find(supabase_key))
            self.assertEqual(-1, rendered.find(jwt_secret))

    def test_network_hints_focus_on_hosts_not_plain_prose(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write(
                temp_dir,
                "README.md",
                "Production-looking prose, agentsecure.core.product, firebase.json, and env.production should not be enough.\n",
            )
            self._write(temp_dir, "config.txt", "API_HOST=api.prod.example.com\n")

            report = RepositoryScanner().scan(temp_dir)
            network_findings = [
                finding for finding in report.findings if finding.title == "Production or cloud endpoint hint found"
            ]

            self.assertEqual(1, len(network_findings))
            self.assertEqual("config.txt", network_findings[0].path)

    def test_json_report_groups_findings_by_severity(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write(temp_dir, ".env.production", "SAFE_PLACEHOLDER=value\n")

            report = RepositoryScanner().scan(temp_dir)
            payload = json.loads(render_report(report, "json"))

            self.assertIn("findings_by_severity", payload)
            self.assertTrue(payload["findings_by_severity"]["Critical"])
            self.assertEqual("Production-looking .env file found", payload["findings_by_severity"]["Critical"][0]["title"])

    def test_symlinked_files_are_not_read(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks are not supported")
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            outside_secret = "ghp_" + ("B" * 36)
            self._write(outside_dir, "outside.txt", "GITHUB_TOKEN=%s\n" % outside_secret)
            os.symlink(os.path.join(outside_dir, "outside.txt"), os.path.join(temp_dir, "linked-secret.txt"))

            report = RepositoryScanner().scan(temp_dir)
            rendered = render_report(report, "json")

            self.assertEqual([], report.findings)
            self.assertEqual(1, report.skipped_files)
            self.assertEqual(-1, rendered.find(outside_secret))

    def test_non_regular_files_are_skipped(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("fifos are not supported")
        with tempfile.TemporaryDirectory() as temp_dir:
            os.mkfifo(os.path.join(temp_dir, "agentsecure-fifo"))

            report = RepositoryScanner().scan(temp_dir)

            self.assertEqual([], report.findings)
            self.assertEqual(1, report.skipped_files)

    def test_agentsecure_generated_state_is_ignored(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write(temp_dir, ".agentsecure/audit.log", "destination=prod.example.com\n")
            self._write(temp_dir, "README.md", "# Demo\n")

            report = RepositoryScanner().scan(temp_dir)

            self.assertEqual([], report.findings)
            self.assertEqual(1, report.scanned_files)

    def _write(self, root: str, rel_path: str, content: str) -> None:
        path = os.path.join(root, rel_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            handle.write(content)


if __name__ == "__main__":
    unittest.main()
