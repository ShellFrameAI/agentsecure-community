import http.client
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import StringIO
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from agentsecure.cli.main import main
from agentsecure.implementations.grant_store import local_grant_store_for_config
from agentsecure.mcp.http_request import perform_http_request
from agentsecure.mcp.server import McpServer


class McpSecurityTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.previous_cwd = os.getcwd()
        self.addCleanup(os.chdir, self.previous_cwd)
        self.project = os.path.join(self.temp.name, "project")
        os.makedirs(self.project)
        os.chdir(self.project)
        env = patch.dict(os.environ, {"AGENTSECURE_HOME": os.path.join(self.temp.name, "home")})
        env.start()
        self.addCleanup(env.stop)
        self.secret = "synthetic-mcp-canary-12345"
        self.long_secret = self.secret + "-second"
        self.config_path = os.path.join(self.project, "agentsecure.json")
        with open(".env", "w") as handle:
            handle.write("API_KEY=%s\nAPI_SECRET=%s\n" % (self.secret, self.long_secret))
        with redirect_stdout(StringIO()):
            self.assertEqual(0, main(["start", "--client", "none", "--yes", "--approved-host", "127.0.0.1"]))
        with open(self.config_path) as handle:
            self.config = json.load(handle)
        self.config["network"].update({"deny_ip_literals": False, "deny_private_networks": False, "allow_ports": [9]})
        self._save_config()

    def _save_config(self):
        with open(self.config_path, "w") as handle:
            json.dump(self.config, handle)

    def _arguments(self, **updates):
        args = {"url": "http://127.0.0.1:9/", "headers": {"Authorization": "Bearer ${API_KEY}"}}
        args.update(updates)
        return args

    def _message(self, arguments, message_id=1):
        return {"jsonrpc": "2.0", "id": message_id, "method": "tools/call", "params": {
            "name": "agentsecure.http.request", "arguments": arguments,
        }}

    def _assert_clean(self, result):
        self.assertNotIn(self.secret, json.dumps(result))
        with open(os.path.join(self.project, ".agentsecure", "audit.log")) as handle:
            self.assertNotIn(self.secret, handle.read())

    def _assert_revoked(self):
        grants = local_grant_store_for_config(self.config_path).list()
        self.assertTrue(grants)
        self.assertTrue(all(grant.status == "revoked" for grant in grants))

    def test_malformed_substituted_header_never_exposes_secret(self):
        response = McpServer(self.config_path).handle(self._message(self._arguments(
            headers={"Authorization": "Bearer ${API_KEY}\ninvalid"},
        )))
        self._assert_clean(response)
        self.assertTrue(response.get("error") or response["result"]["isError"])
        self._assert_revoked()

    def test_transport_exceptions_do_not_expose_plain_or_encoded_secrets(self):
        for exception in (OSError, http.client.InvalidURL, http.client.BadStatusLine, ValueError, RuntimeError):
            for detail in (self.secret, self.secret.encode().hex()):
                with self.subTest(exception=exception.__name__, encoded=detail != self.secret):
                    with patch("agentsecure.mcp.http_request._send", side_effect=exception(detail)):
                        response = McpServer(self.config_path).handle(self._message(self._arguments()))
                    self._assert_clean(response)
                    self.assertNotIn(detail, json.dumps(response))
                    self.assertTrue(response.get("error") or response["result"]["isError"])
                    self._assert_revoked()

    def test_all_response_fields_redacted_longest_secret_first(self):
        upstream = {"blocked": False, "status": 200, "reason": self.long_secret,
                    "headers": {"X-" + self.secret: self.long_secret, "Content-Type": "text/plain"},
                    "body": self.long_secret + " " + self.secret + " public response"}
        with patch("agentsecure.mcp.http_request._send", return_value=upstream):
            result = perform_http_request(self.config_path, self._arguments(
                headers={"Authorization": "${API_KEY}", "X-Other": "${API_SECRET}"},
            ))
        self._assert_clean(result)
        self.assertEqual(200, result["status"])
        self.assertFalse(result["blocked"])
        self.assertEqual("[redacted]", result["reason"])
        self.assertEqual("[redacted] [redacted] public response", result["body"])
        self.assertEqual("[redacted]", result["headers"]["X-[redacted]"])
        self.assertEqual("text/plain", result["headers"]["Content-Type"])
        self._assert_revoked()

    def test_cleanup_failure_never_exposes_exception_value(self):
        with patch("agentsecure.mcp.http_request._send", return_value={
            "blocked": False, "status": 200, "reason": "OK", "headers": {}, "body": "ok",
        }), patch("agentsecure.mcp.http_request.revoke_mcp_bindings", side_effect=RuntimeError(self.secret)):
            response = McpServer(self.config_path).handle(self._message(self._arguments()))
        self._assert_clean(response)
        self.assertIn("error", response)

    def test_audit_failure_never_exposes_exception_value(self):
        def fail_on_request(logger, event_type, details):
            if event_type == "mcp_http_request":
                raise OSError(self.secret)
            return original(logger, event_type, details)

        from agentsecure.implementations.audit import JsonLineAuditLogger
        original = JsonLineAuditLogger.record
        with patch("agentsecure.mcp.http_request._send", return_value={
            "blocked": False, "status": 200, "reason": "OK", "headers": {}, "body": "ok",
        }), patch.object(JsonLineAuditLogger, "record", fail_on_request):
            response = McpServer(self.config_path).handle(self._message(self._arguments()))
        self._assert_clean(response)
        self.assertTrue(response.get("error") or response["result"]["isError"])
        self._assert_revoked()

    def test_denied_host_blocks_before_resolution_and_send(self):
        with patch("agentsecure.implementations.secrets.PolicyAwareTokenResolver.resolve") as resolve, \
                patch("agentsecure.mcp.http_request._send") as send:
            result = perform_http_request(self.config_path, self._arguments(url="http://blocked.example.invalid:9/"))
        self.assertEqual("network.allow_domain", result["rule_id"])
        self.assertIn("agentsecure network allow", result["allow_command"])
        resolve.assert_not_called()
        send.assert_not_called()
        self._assert_clean(result)
        self._assert_revoked()

    def test_missing_alias_keeps_actionable_error_without_sending(self):
        with patch("agentsecure.mcp.http_request._send") as send:
            result = perform_http_request(self.config_path, self._arguments(headers={"Authorization": "${MISSING_KEY}"}))
        self.assertEqual("mcp.secret_resolution", result["rule_id"])
        self.assertIn("${MISSING_KEY}", result["reason"])
        send.assert_not_called()
        self._assert_clean(result)
        self._assert_revoked()

    def test_alias_destination_restriction_still_blocks_request(self):
        self.config["secret_aliases"][0]["approved_hosts"] = ["different.example.invalid"]
        self._save_config()
        with patch("agentsecure.mcp.http_request._send") as send:
            result = perform_http_request(self.config_path, self._arguments())
        self.assertTrue(result["blocked"])
        self.assertEqual("mcp.secret_resolution", result["rule_id"])
        self.assertIn("not approved", result["reason"])
        send.assert_not_called()
        self._assert_clean(result)
        self._assert_revoked()

    def test_sanitizer_failure_blocks_instead_of_returning_raw_response(self):
        with patch("agentsecure.mcp.http_request._send", return_value={
            "blocked": False, "status": 200, "reason": "OK", "headers": {}, "body": self.secret,
        }), patch("agentsecure.mcp.http_request.SecretOutputSanitizer.from_config_path", side_effect=RuntimeError(self.secret)):
            response = McpServer(self.config_path).handle(self._message(self._arguments()))
        self._assert_clean(response)
        self.assertIn("error", response)
        self._assert_revoked()

    def test_real_stdio_request_preserves_usage_and_recovers_after_bad_request(self):
        server = HTTPServer(("127.0.0.1", 0), _EchoHandler)
        server.requests = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        self.config["network"]["allow_ports"] = [server.server_port]
        self._save_config()
        base = "http://127.0.0.1:%s" % server.server_port
        messages = [
            {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}},
            self._message(self._arguments(url=base, headers={"Authorization": "${API_KEY}\ninvalid"}), 1),
            self._message(self._arguments(url=base + "/${API_KEY}", method="POST",
                query={"token": "${API_KEY}"}, json={"token": "${API_SECRET}", "public": "hello"}), 2),
            self._message(self._arguments(url=base + "/plain", method="POST", body="token=${API_KEY}&public=hello"), 3),
            self._message(self._arguments(url=base + "/not-found"), 4),
            {"jsonrpc": "2.0", "id": 5, "method": "tools/list"},
        ]
        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        process = subprocess.run([sys.executable, "-m", "agentsecure", "--config", self.config_path, "mcp", "serve"],
            input="".join(json.dumps(message) + "\n" for message in messages), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=15)
        self.assertEqual(0, process.returncode, process.stderr)
        self._assert_clean({"stdout": process.stdout, "stderr": process.stderr})
        responses = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual(list(range(6)), [item["id"] for item in responses])
        self.assertTrue(responses[1].get("error") or responses[1]["result"]["isError"])
        for item in responses[2:5]:
            self.assertFalse(item["result"]["isError"])
            result = json.loads(item["result"]["content"][0]["text"])
            self.assertEqual("[redacted]", result["reason"])
            self.assertEqual("[redacted]", result["headers"]["X-[redacted]"])
        self.assertEqual(404, json.loads(responses[4]["result"]["content"][0]["text"])["status"])
        self.assertEqual(3, len(server.requests))
        request = server.requests[0]
        self.assertEqual("/" + self.secret, urlsplit(request["path"]).path)
        self.assertEqual([self.secret], parse_qs(urlsplit(request["path"]).query)["token"])
        self.assertEqual("Bearer " + self.secret, request["authorization"])
        self.assertEqual({"token": self.long_secret, "public": "hello"}, json.loads(request["body"]))
        self.assertEqual("token=" + self.secret + "&public=hello", server.requests[1]["body"])
        self._assert_revoked()


class _EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.do_GET()

    def do_GET(self):
        authorization = self.headers.get("Authorization", "")
        secret = authorization.split(" ", 1)[-1]
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        self.server.requests.append({"path": self.path, "authorization": authorization, "body": body})
        self.send_response(404 if self.path == "/not-found" else 200, secret)
        self.send_header("X-" + secret, secret)
        self.end_headers()
        self.wfile.write((authorization + " public response").encode())

    def log_message(self, *args):
        pass
