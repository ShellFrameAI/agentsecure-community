"""Replay the MCP flow with a fake credential and isolated, temporary state."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = Path(__file__).resolve().parents[1]
FAKE_SECRET = "agentsecure-demo-fake-not-a-provider-key"


class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.authorization = self.headers.get("Authorization", "")
        body = json.dumps({"authorization": self.server.authorization}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    with tempfile.TemporaryDirectory(prefix="agentsecure-mcp-demo-") as temp:
        project = Path(temp) / "project"
        project.mkdir()
        (project / ".env").write_text("DEMO_API_KEY=" + FAKE_SECRET + "\n")
        env = dict(os.environ, AGENTSECURE_HOME=str(Path(temp) / "home"), PYTHONPATH=str(ROOT))
        server = HTTPServer(("127.0.0.1", 0), Fixture)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = "http://127.0.0.1:%s/demo" % server.server_port

            def cli(args, stdin=None):
                result = subprocess.run(
                    [sys.executable, "-m", "agentsecure"] + args,
                    cwd=str(project), env=env, input=stdin, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, universal_newlines=True, timeout=30,
                )
                require(result.returncode == 0, "AgentSecure command failed; no result claimed.")
                require(FAKE_SECRET not in result.stdout + result.stderr,
                        "Unexpected fake credential in CLI output.")
                return result.stdout

            cli(["start", "--client", "none", "--approved-host", url, "--yes", "--json"])
            dotenv = (project / ".env").read_text().strip()
            require(dotenv == "DEMO_API_KEY=AGENTSECURE_ALIAS_DEMO_API_KEY", "Alias rewrite failed.")
            config_path = project / "agentsecure.json"
            config = json.loads(config_path.read_text())
            require(FAKE_SECRET not in json.dumps(config), "Unexpected credential in project config.")
            # Only this disposable fixture permits loopback; normal policy is unchanged.
            config["network"]["deny_ip_literals"] = False
            config["network"]["deny_private_networks"] = False
            config_path.write_text(json.dumps(config))

            def request(destination):
                message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                    "name": "agentsecure.http.request", "arguments": {
                        "method": "GET", "url": destination,
                        "headers": {"Authorization": "Bearer ${DEMO_API_KEY}"},
                    }}}
                response = json.loads(cli(["mcp", "serve"], json.dumps(message) + "\n"))
                return json.loads(response["result"]["content"][0]["text"])

            response = request(url)
            require(not response["blocked"] and response["status"] == 200, "Fixture request failed.")
            require(server.authorization == "Bearer " + FAKE_SECRET, "Credential injection failed.")
            require(json.loads(response["body"])["authorization"] == "Bearer [redacted]", "Redaction failed.")
            # This reserved, unapproved host must be denied before any network request.
            denied = request("https://unapproved.invalid/demo")
            require(denied["blocked"] and denied.get("rule_id") == "network.allow_domain", "Policy denial failed.")
            print("Project file: " + dotenv)
            print("Approved fixture: received the fake credential")
            print("MCP response: Bearer [redacted]")
            print("Unapproved destination: blocked")
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
    print("Demo passed; temporary project and vault removed.")


if __name__ == "__main__":
    main()
