import json
import os
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import StringIO

from agentsecure.cli.main import main
from agentsecure.mcp.http_request import perform_http_request
from agentsecure.mcp.placeholders import find_placeholders, replace_placeholders
from agentsecure.mcp.runtime import describe_config, safe_secret_status
from agentsecure.mcp.server import McpServer


class McpTest(unittest.TestCase):
    def test_placeholders_are_found_and_replaced(self):
        payload = {
            "headers": {"Authorization": "Bearer ${API_KEY}"},
            "json": {"secret": "${API_SECRET}"},
        }

        self.assertEqual(["API_KEY", "API_SECRET"], find_placeholders(payload))
        replaced = replace_placeholders(payload, lambda name: "real-" + name.lower())

        self.assertEqual("Bearer real-api_key", replaced["headers"]["Authorization"])
        self.assertEqual("real-api_secret", replaced["json"]["secret"])

    def test_mcp_request_requires_secret_placeholders(self):
        result = perform_http_request("missing-agentsecure.json", {"url": "https://api.example.com"})

        self.assertTrue(result["blocked"])
        self.assertEqual("mcp.no_secret_placeholders", result["rule_id"])

    def test_policy_and_secret_status_do_not_expose_values(self):
        with self._project() as project:
            config_path = project["config_path"]
            self._add_secret(project, "API_KEY", "real-api-key-local-test")

            description = describe_config(config_path)
            status = safe_secret_status(config_path, "API_KEY")
            serialized = json.dumps({"description": description, "status": status})

            self.assertIn("API_KEY", serialized)
            self.assertNotIn("real-api-key-local-test", serialized)
            self.assertTrue(status["exists"])

    def test_http_request_resolves_placeholders_only_for_allowed_destination(self):
        with self._project() as project:
            config_path = project["config_path"]
            self._add_secret(project, "API_KEY", "real-api-key-local-test")
            self._add_secret(project, "API_SECRET", "real-api-secret-local-test")
            try:
                server = _CaptureServer()
            except PermissionError:
                self.skipTest("local socket bind is not permitted in this environment")
            try:
                self._allow_local_destination(config_path, server.port)
                result = perform_http_request(
                    config_path,
                    {
                        "method": "GET",
                        "url": "http://127.0.0.1:%s/whoami" % server.port,
                        "headers": {
                            "Authorization": "Bearer ${API_KEY}",
                            "X-Api-Secret": "${API_SECRET}",
                        },
                    },
                )

                self.assertFalse(result["blocked"])
                self.assertEqual(200, result["status"])
                self.assertEqual("Bearer real-api-key-local-test", server.authorization)
                self.assertEqual("real-api-secret-local-test", server.api_secret)
                self.assertNotIn("real-api-key-local-test", result["body"])
                self.assertNotIn("real-api-secret-local-test", result["body"])
            finally:
                server.close()

    def test_http_request_denies_unallowlisted_destination_before_secret_resolution(self):
        with self._project() as project:
            config_path = project["config_path"]
            self._add_secret(project, "API_KEY", "real-api-key-local-test")

            result = perform_http_request(
                config_path,
                {
                    "url": "http://blocked.example.invalid/whoami",
                    "headers": {"Authorization": "Bearer ${API_KEY}"},
                },
            )

            self.assertTrue(result["blocked"])
            self.assertEqual("network.allow_domain", result["rule_id"])
            self.assertIn("agentsecure network allow", result["allow_command"])

    def test_mcp_server_lists_and_calls_tools(self):
        with self._project() as project:
            with redirect_stdout(StringIO()):
                self.assertEqual(0, main(["--config", project["config_path"], "init"]))
            server = McpServer(project["config_path"])

            listed = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            self.assertEqual("2.0", listed["jsonrpc"])
            self.assertIn("agentsecure.http.request", json.dumps(listed))

            called = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "agentsecure.policy.describe", "arguments": {}},
                }
            )
            self.assertIn("content", called["result"])

    def test_codex_install_prints_codex_mcp_add_command(self):
        with self._project() as project:
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, main(["--config", project["config_path"], "mcp", "install", "codex"]))

            text = output.getvalue()
            self.assertIn("codex mcp add agentsecure --", text)
            self.assertIn("agentsecure --config", text)
            self.assertIn(project["config_path"], text)
            self.assertIn("mcp serve", text)
            self.assertNotIn('"mcpServers"', text)

    def _project(self):
        return _ProjectContext()

    def _add_secret(self, project, env_name, value):
        old = os.environ.get(env_name)
        os.environ[env_name] = value
        try:
            with redirect_stdout(StringIO()):
                self.assertEqual(
                    0,
                    main(
                        [
                            "--config",
                            project["config_path"],
                            "secrets",
                            "add",
                            env_name.lower(),
                            "--env-name",
                            env_name,
                            "--real-secret-env",
                            env_name,
                        ]
                    ),
                )
                self.assertEqual(0, main(["--config", project["config_path"], "secrets", "use", env_name.lower()]))
        finally:
            if old is None:
                os.environ.pop(env_name, None)
            else:
                os.environ[env_name] = old

    def _allow_local_destination(self, config_path, port):
        with open(config_path, "r") as handle:
            config = json.load(handle)
        network = config.setdefault("network", {})
        network["allow_domains"] = ["127.0.0.1"]
        network["allow_ports"] = [port]
        network["deny_ip_literals"] = False
        network["deny_private_networks"] = False
        with open(config_path, "w") as handle:
            json.dump(config, handle)


class _ProjectContext:
    def __enter__(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.old_cwd = os.getcwd()
        self.old_home = os.environ.get("AGENTSECURE_HOME")
        self.project_dir = os.path.join(self.temp_dir.name, "project")
        self.home_dir = os.path.join(self.temp_dir.name, "home")
        os.makedirs(self.project_dir)
        os.environ["AGENTSECURE_HOME"] = self.home_dir
        os.chdir(self.project_dir)
        return {"config_path": os.path.join(self.project_dir, "agentsecure.json"), "project_dir": self.project_dir}

    def __exit__(self, exc_type, exc, tb):
        os.chdir(self.old_cwd)
        if self.old_home is None:
            os.environ.pop("AGENTSECURE_HOME", None)
        else:
            os.environ["AGENTSECURE_HOME"] = self.old_home
        self.temp_dir.cleanup()


class _CaptureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.authorization = self.headers.get("Authorization", "")
        self.server.api_secret = self.headers.get("X-Api-Secret", "")
        body = json.dumps(
            {
                "ok": self.server.authorization == "Bearer real-api-key-local-test"
                and self.server.api_secret == "real-api-secret-local-test",
                "echo_authorization": self.server.authorization,
                "echo_secret": self.server.api_secret,
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


class _CaptureServer:
    def __init__(self):
        self.server = HTTPServer(("127.0.0.1", 0), _CaptureHandler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    @property
    def port(self):
        return self.server.server_address[1]

    @property
    def authorization(self):
        return getattr(self.server, "authorization", "")

    @property
    def api_secret(self):
        return getattr(self.server, "api_secret", "")

    def close(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()


if __name__ == "__main__":
    unittest.main()
