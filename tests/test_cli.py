import unittest
import socket

from agentsecure.cli.main import (
    _apply_proxy_environment,
    _apply_read_only_agent_mode,
    _available_gateway_port,
    _merge_no_proxy,
    _proxy_url,
)


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

    def test_proxy_url_includes_session_as_proxy_username(self):
        self.assertEqual(
            "http://session_abc@127.0.0.1:8765",
            _proxy_url("127.0.0.1", 8765, "session_abc"),
        )

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


if __name__ == "__main__":
    unittest.main()
