import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from tests.integration.helpers import run_agentsecure


class SecretCanaryIntegrationTest(unittest.TestCase):
    def test_onboarding_hides_raw_secret_while_approved_mcp_request_uses_it(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = os.path.join(temp_dir, "project")
            home_dir = os.path.join(temp_dir, "home")
            config_path = os.path.join(project_dir, "agentsecure.json")
            audit_path = os.path.join(project_dir, ".agentsecure", "audit.log")
            raw_secret = "agentsecure-canary-real-secret-4f1c9a7e"
            os.makedirs(project_dir)

            with open(os.path.join(project_dir, ".env"), "w") as handle:
                handle.write("CANARY_API_KEY=%s\n" % raw_secret)

            try:
                server = _CanaryServer(raw_secret)
            except PermissionError:
                self.skipTest("local socket bind is not permitted in this environment")

            shared_env = {"AGENTSECURE_HOME": home_dir}
            approved_url = "http://127.0.0.1:%s/canary" % server.port
            try:
                setup_result = run_agentsecure(
                    [
                        "--config",
                        config_path,
                        "start",
                        "--client",
                        "none",
                        "--approved-host",
                        approved_url,
                        "--yes",
                        "--json",
                    ],
                    cwd=project_dir,
                    env=shared_env,
                )

                self.assertEqual(0, setup_result.returncode, setup_result.stderr)
                self.assertNotIn(raw_secret, setup_result.stdout)
                self.assertNotIn(raw_secret, setup_result.stderr)
                setup = json.loads(setup_result.stdout)
                secret_step = next(step for step in setup["steps"] if step["name"] == "secrets")
                self.assertEqual("imported", secret_step["status"])
                self.assertEqual(1, secret_step["count"])
                self.assertTrue(secret_step["rewritten"])

                with open(os.path.join(project_dir, ".env"), "r") as handle:
                    agent_visible_dotenv = handle.read()
                self.assertEqual(
                    "CANARY_API_KEY=AGENTSECURE_ALIAS_CANARY_API_KEY\n",
                    agent_visible_dotenv,
                )
                self.assertNotIn(raw_secret, agent_visible_dotenv)

                with open(config_path, "r") as handle:
                    config = json.load(handle)
                self.assertNotIn(raw_secret, json.dumps(config))
                self.assertIn("127.0.0.1", config["network"]["allow_domains"])
                self.assertIn(server.port, config["network"]["allow_ports"])
                self.assertEqual(
                    ["127.0.0.1"],
                    config["secret_aliases"][0]["approved_hosts"],
                )

                # The canary server is intentionally local. Production defaults deny
                # private and literal-IP destinations, so relax only those two rules
                # inside this isolated test project after verifying setup output.
                config["network"]["deny_ip_literals"] = False
                config["network"]["deny_private_networks"] = False
                with open(config_path, "w") as handle:
                    json.dump(config, handle, indent=2, sort_keys=True)
                    handle.write("\n")

                agent_script = (
                    "import json, os; "
                    "print(json.dumps({"
                    "'env': os.environ.get('CANARY_API_KEY'), "
                    "'dotenv': open('.env').read()"
                    "}, sort_keys=True))"
                )
                run_result = run_agentsecure(
                    [
                        "--config",
                        config_path,
                        "run",
                        "--secret-mode",
                        "strict",
                        "--no-discover",
                        "--",
                        "python3",
                        "-c",
                        agent_script,
                    ],
                    cwd=project_dir,
                    env=shared_env,
                )

                if run_result.returncode != 0 and "gateway failed to start" in run_result.stderr:
                    self.skipTest("local gateway bind is not permitted in this environment")
                self.assertEqual(0, run_result.returncode, run_result.stderr)
                self.assertIn('"env": "virt_custom_', run_result.stdout)
                self.assertIn("AGENTSECURE_ALIAS_CANARY_API_KEY", run_result.stdout)
                self.assertNotIn(raw_secret, run_result.stdout)
                self.assertNotIn(raw_secret, run_result.stderr)

                request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "agentsecure.http.request",
                        "arguments": {
                            "method": "GET",
                            "url": approved_url,
                            "headers": {
                                "Authorization": "Bearer ${CANARY_API_KEY}",
                            },
                        },
                    },
                }
                mcp_result = run_agentsecure(
                    ["--config", config_path, "mcp", "serve"],
                    cwd=project_dir,
                    env=shared_env,
                    stdin_text=json.dumps(request) + "\n",
                )

                self.assertEqual(0, mcp_result.returncode, mcp_result.stderr)
                self.assertNotIn(raw_secret, mcp_result.stdout)
                self.assertNotIn(raw_secret, mcp_result.stderr)
                response = json.loads(mcp_result.stdout.strip())
                payload = json.loads(response["result"]["content"][0]["text"])
                self.assertFalse(payload["blocked"])
                self.assertEqual(200, payload["status"])
                response_body = json.loads(payload["body"])
                self.assertTrue(response_body["ok"])
                self.assertEqual("Bearer [redacted]", response_body["echo_authorization"])
                self.assertEqual("Bearer %s" % raw_secret, server.authorization)

                with open(audit_path, "r") as handle:
                    audit_text = handle.read()
                self.assertIn("mcp_http_request", audit_text)
                self.assertIn('"allowed": true', audit_text)
                self.assertNotIn(raw_secret, audit_text)
            finally:
                server.close()


class _CanaryHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.authorization = self.headers.get("Authorization", "")
        body = json.dumps(
            {
                "ok": self.server.authorization == "Bearer %s" % self.server.expected_secret,
                "echo_authorization": self.server.authorization,
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


class _CanaryServer:
    def __init__(self, expected_secret):
        self.server = HTTPServer(("127.0.0.1", 0), _CanaryHandler)
        self.server.expected_secret = expected_secret
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    @property
    def port(self):
        return self.server.server_address[1]

    @property
    def authorization(self):
        return getattr(self.server, "authorization", "")

    def close(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()


if __name__ == "__main__":
    unittest.main()
