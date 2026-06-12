import unittest
import socket
import os
import tempfile
import json
from io import StringIO
from contextlib import redirect_stdout
from unittest.mock import patch

from agentsecure.cli.common import update_allowed_domains
from agentsecure.cli.main import (
    _apply_proxy_environment,
    _apply_read_only_agent_mode,
    _strip_backing_secret_environment,
    _available_gateway_port,
    build_parser,
    _merge_no_proxy,
    _proxy_url,
    _selected_secret_runtime_mode,
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
        _apply_proxy_environment(env, "http://127.0.0.1:8765", allow_loopback_bypass=True)

        self.assertEqual("http://127.0.0.1:8765", env["HTTP_PROXY"])
        self.assertIn("localhost", env["NO_PROXY"])
        self.assertIn("127.0.0.1", env["NO_PROXY"])
        self.assertIn("::1", env["NO_PROXY"])
        self.assertIn("metadata.google.internal", env["NO_PROXY"])
        self.assertEqual(env["NO_PROXY"], env["no_proxy"])

    def test_proxy_environment_defaults_to_no_extra_bypass(self):
        env = {"NO_PROXY": "metadata.google.internal"}
        _apply_proxy_environment(env, "http://127.0.0.1:8765")

        self.assertEqual("http://127.0.0.1:8765", env["HTTP_PROXY"])
        self.assertEqual("metadata.google.internal", env["NO_PROXY"])

    def test_proxy_environment_accepts_private_bypass(self):
        env = {}
        _apply_proxy_environment(
            env,
            "http://127.0.0.1:8765",
            private_bypass_hosts=["10.0.0.3:11434"],
        )

        self.assertEqual("10.0.0.3", env["NO_PROXY"])

    def test_no_proxy_merge_deduplicates_values(self):
        merged = _merge_no_proxy("localhost,LOCALHOST,example.com")

        self.assertEqual(1, merged.split(",").count("localhost"))
        self.assertIn("example.com", merged)

    def test_no_proxy_merge_drops_wildcard(self):
        merged = _merge_no_proxy("*,api.openai.com")

        self.assertNotIn("*", merged.split(","))
        self.assertIn("api.openai.com", merged)

    def test_network_allow_url_adds_domain_and_port(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    0,
                    update_allowed_domains(
                        config_path,
                        ["http://approved.127.0.0.1.nip.io:18080/whoami"],
                        add=True,
                    ),
                )

            import json

            with open(config_path, "r") as handle:
                config = json.load(handle)
            self.assertIn("approved.127.0.0.1.nip.io", config["network"]["allow_domains"])
            self.assertIn(18080, config["network"]["allow_ports"])

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

        self.assertIn("start", help_text)
        for private_command in ("daemon", "api", "enroll", "cloud"):
            self.assertNotIn(private_command, help_text)
        self.assertNotIn("AgentSecure Cloud", help_text)

    def test_secret_mode_uses_config_mode_by_default(self):
        config = AgentSecureConfig()
        config.secret_runtime.mode = "strict"
        container = type("Container", (), {"config": config})()
        args = type("Args", (), {"secret_mode": None})()

        self.assertEqual("strict", _selected_secret_runtime_mode(args, container))

    def test_secret_mode_cli_override_wins(self):
        config = AgentSecureConfig()
        config.secret_runtime.mode = "strict"
        container = type("Container", (), {"config": config})()
        args = type("Args", (), {"secret_mode": "compat"})()

        self.assertEqual("compat", _selected_secret_runtime_mode(args, container))

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
        self.assertIn("--secret-mode", help_text)

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

    def test_preserves_tty_for_ollama_launch_integration(self):
        with patch("agentsecure.cli.main._stdio_is_tty", return_value=True):
            self.assertTrue(
                _should_preserve_interactive_tty(
                    ["ollama", "launch", "claude", "--model", "gemma4:e4b-64k"]
                )
            )

    def test_does_not_preserve_tty_for_ollama_launch_help(self):
        with patch("agentsecure.cli.main._stdio_is_tty", return_value=True):
            self.assertFalse(_should_preserve_interactive_tty(["ollama", "launch", "--help"]))

    def test_start_guided_setup_imports_dotenv_and_prints_ready_summary(self):
        from agentsecure.cli.main import main

        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = os.path.join(temp_dir, "project")
            home_dir = os.path.join(temp_dir, "home")
            os.makedirs(project_dir)
            config_path = os.path.join(project_dir, "agentsecure.json")
            env_path = os.path.join(project_dir, ".env")
            with open(env_path, "w") as handle:
                handle.write("API_KEY=real-api-key-local-test\n")
            old_cwd = os.getcwd()
            old_home = os.environ.get("AGENTSECURE_HOME")
            os.environ["AGENTSECURE_HOME"] = home_dir
            try:
                os.chdir(project_dir)
                output = StringIO()
                with redirect_stdout(output):
                    self.assertEqual(
                        0,
                        main(
                            [
                                "--config",
                                config_path,
                                "start",
                                "--yes",
                                "--approved-host",
                                "https://api.example.com",
                            ]
                        ),
                    )
                text = output.getvalue()
                self.assertIn("Ready.", text)
                self.assertIn("codex mcp add agentsecure --", text)
                self.assertIn("Agent instructions: created AGENTS.md", text)
                with open(env_path, "r") as handle:
                    self.assertIn("API_KEY=AGENTSECURE_ALIAS_API_KEY", handle.read())
                with open(os.path.join(project_dir, "AGENTS.md"), "r") as handle:
                    agent_instructions = handle.read()
                self.assertIn("agentsecure.http.request", agent_instructions)
                self.assertIn("Do not source `.env`", agent_instructions)
                self.assertIn("AGENTSECURE_ALIAS_*", agent_instructions)
                with open(config_path, "r") as handle:
                    config = json.load(handle)
                self.assertIn("api.example.com", config["network"]["allow_domains"])
            finally:
                os.chdir(old_cwd)
                if old_home is None:
                    os.environ.pop("AGENTSECURE_HOME", None)
                else:
                    os.environ["AGENTSECURE_HOME"] = old_home

    def test_start_json_summary_can_skip_import(self):
        from agentsecure.cli.main import main

        with tempfile.TemporaryDirectory() as temp_dir:
            old_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                config_path = os.path.join(temp_dir, "agentsecure.json")
                output = StringIO()
                with redirect_stdout(output):
                    self.assertEqual(0, main(["--config", config_path, "start", "--skip-import", "--client", "none", "--json"]))
                payload = json.loads(output.getvalue())
                self.assertTrue(payload["ready"])
                self.assertEqual(config_path, payload["config_path"])
                self.assertEqual(
                    "created",
                    [step for step in payload["steps"] if step["name"] == "agent_instructions"][0]["status"],
                )
            finally:
                os.chdir(old_cwd)

    def test_start_agent_instructions_preserve_existing_content_and_stay_idempotent(self):
        from agentsecure.cli.main import main

        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            agents_path = os.path.join(temp_dir, "AGENTS.md")
            with open(agents_path, "w") as handle:
                handle.write("# Existing Instructions\n\nKeep this project-specific rule.\n")
            old_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                output = StringIO()
                with redirect_stdout(output):
                    self.assertEqual(
                        0,
                        main(["--config", config_path, "start", "--skip-import", "--client", "none", "--yes"]),
                    )
                with open(agents_path, "r") as handle:
                    first = handle.read()
                self.assertIn("Keep this project-specific rule.", first)
                self.assertIn("agentsecure.http.request", first)
                self.assertEqual(1, first.count("<!-- agentsecure:start -->"))

                output = StringIO()
                with redirect_stdout(output):
                    self.assertEqual(
                        0,
                        main(["--config", config_path, "start", "--skip-import", "--client", "none", "--yes"]),
                    )
                with open(agents_path, "r") as handle:
                    second = handle.read()
                self.assertEqual(first, second)
                self.assertEqual(1, second.count("<!-- agentsecure:start -->"))
                self.assertIn("Agent instructions: unchanged AGENTS.md", output.getvalue())
            finally:
                os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()
