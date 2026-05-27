import unittest
import socket
from io import StringIO
from contextlib import redirect_stdout
from unittest.mock import patch

from agentsecure.cli.main import (
    _apply_proxy_environment,
    _apply_read_only_agent_mode,
    _strip_backing_secret_environment,
    _available_gateway_port,
    build_parser,
    _merge_no_proxy,
    _proxy_url,
    _should_preserve_interactive_tty,
)
from agentsecure.core.models import AgentSecureConfig, SecretBinding


class CliTest(unittest.TestCase):
    def test_adds_read_only_sandbox_for_codex(self):
        argv = _apply_read_only_agent_mode(["codex", "exec", "hi"], True)
        self.assertEqual(["codex", "--sandbox", "read-only", "exec", "hi"], argv)

    def test_does_not_override_existing_codex_sandbox(self):
        argv = _apply_read_only_agent_mode(["codex", "--sandbox", "workspace-write", "exec"], True)
        self.assertEqual(["codex", "--sandbox", "workspace-write", "exec"], argv)

    def test_leaves_non_codex_commands_unchanged(self):
        argv = _apply_read_only_agent_mode(["python", "-c", "print(1)"], True)
        self.assertEqual(["python", "-c", "print(1)"], argv)

    def test_proxy_environment_bypasses_local_services(self):
        env = {"NO_PROXY": "metadata.google.internal"}
        _apply_proxy_environment(env, "http://127.0.0.1:8765")

        self.assertEqual("http://127.0.0.1:8765", env["HTTP_PROXY"])
        self.assertIn("localhost", env["NO_PROXY"])
        self.assertIn("127.0.0.1", env["NO_PROXY"])
        self.assertIn("::1", env["NO_PROXY"])
        self.assertIn("metadata.google.internal", env["NO_PROXY"])
        self.assertEqual(env["NO_PROXY"], env["no_proxy"])

    def test_no_proxy_merge_deduplicates_values(self):
        merged = _merge_no_proxy("localhost,LOCALHOST,example.com")

        self.assertEqual(1, merged.split(",").count("localhost"))
        self.assertIn("example.com", merged)

    def test_no_proxy_merge_drops_wildcard(self):
        merged = _merge_no_proxy("*,api.openai.com")

        self.assertNotIn("*", merged.split(","))
        self.assertIn("api.openai.com", merged)

    def test_strips_backing_secret_environment(self):
        env = {
            "AGENTSECURE_REAL_OPENAI_KEY": "sk-real",
            "OPENAI_API_KEY": "sk-real",
        }
        config = AgentSecureConfig(
            secrets=[
                SecretBinding(
                    env_name="OPENAI_API_KEY",
                    virtual_token="virt_openai_test",
                    real_secret_env="AGENTSECURE_REAL_OPENAI_KEY",
                    provider="openai",
                )
            ]
        )
        container = type("Container", (), {"config": config})()

        _strip_backing_secret_environment(env, container)

        self.assertNotIn("AGENTSECURE_REAL_OPENAI_KEY", env)
        self.assertIn("OPENAI_API_KEY", env)

    def test_proxy_url_includes_session_as_proxy_username(self):
        self.assertEqual(
            "http://session_abc@127.0.0.1:8765",
            _proxy_url("127.0.0.1", 8765, "session_abc"),
        )

    def test_public_help_does_not_advertise_private_cloud_commands(self):
        output = StringIO()
        with redirect_stdout(output):
            build_parser().print_help()
        help_text = output.getvalue()

        for private_command in ("daemon", "api", "enroll", "cloud"):
            self.assertNotIn(private_command, help_text)
        self.assertNotIn("AgentSecure Cloud", help_text)

    def test_run_help_does_not_advertise_cloud_reporting_flags(self):
        parser = build_parser()
        output = StringIO()
        try:
            with redirect_stdout(output):
                parser.parse_args(["run", "--help"])
        except SystemExit as exc:
            self.assertEqual(0, exc.code)
        help_text = output.getvalue()

        self.assertNotIn("--cloud-debug", help_text)
        self.assertNotIn("--project", help_text)
        self.assertNotIn("--task", help_text)

    def test_available_gateway_port_skips_busy_preferred_port(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", 0))
        except PermissionError:
            sock.close()
            self.skipTest("local socket bind is not permitted in this environment")
        try:
            busy_port = sock.getsockname()[1]
            selected = _available_gateway_port("127.0.0.1", busy_port)
            self.assertNotEqual(busy_port, selected)
        finally:
            sock.close()

    def test_preserves_tty_for_bare_interactive_agent(self):
        with patch("agentsecure.cli.main._stdio_is_tty", return_value=True):
            self.assertTrue(_should_preserve_interactive_tty(["claude"]))

    def test_does_not_preserve_tty_for_regular_commands(self):
        with patch("agentsecure.cli.main._stdio_is_tty", return_value=True):
            self.assertFalse(_should_preserve_interactive_tty(["cat", ".env"]))

    def test_does_not_preserve_tty_when_agent_has_arguments(self):
        with patch("agentsecure.cli.main._stdio_is_tty", return_value=True):
            self.assertFalse(_should_preserve_interactive_tty(["claude", "--print", "hello"]))


if __name__ == "__main__":
    unittest.main()
