import argparse
import io
import json
import sys
from unittest.mock import patch

from agentsecure.core.models import PolicyDecision, ProviderProxyConfig, ProviderProxyProvider, SecretBinding
from agentsecure.gateway.proxy import GatewayRequestHandler


def handle_receipts(args: argparse.Namespace) -> int:
    if args.proxy:
        return run_proxy_receipts()
    sys.stderr.write("agentsecure: receipts currently requires --proxy\n")
    return 2


def run_proxy_receipts() -> int:
    passed = 0
    failed = 0

    print("AgentSecure provider proxy receipts")
    print("Fixture: local fake OpenAI upstream, no real provider call")
    print("")

    result = _exercise_provider_proxy("/v1/chat/completions?api_key=virt_openai_receipt")
    if result["upstream_authorization"] == "Bearer sk-receipt-real-secret":
        passed += 1
        _print("PASS", "P1", "real key injected at provider boundary")
    else:
        failed += 1
        _print("FAIL", "P1", "real key was not injected")

    if (
        "virt_openai_receipt" not in result["upstream_authorization"]
        and "virt_openai_receipt" not in result["upstream_path"]
        and "virt_openai_receipt" not in result["upstream_body"]
        and "virt_openai_receipt" not in result["upstream_headers"]
    ):
        passed += 1
        _print("PASS", "P2", "virtual key not forwarded upstream")
    else:
        failed += 1
        _print("FAIL", "P2", "virtual key reached upstream")

    if "sk-receipt-real-secret" not in result["client_body"]:
        passed += 1
        _print("PASS", "P3", "client output excludes real key")
    else:
        failed += 1
        _print("FAIL", "P3", "client output exposed real key")

    if result["upstream_content_length"] == str(len(result["upstream_body"].encode("utf-8"))):
        passed += 1
        _print("PASS", "P4", "content length updated after scrubbing")
    else:
        failed += 1
        _print("FAIL", "P4", "content length did not match scrubbed body")

    denied = _exercise_provider_proxy("/admin")
    if denied["status"] == 403 and "agentsecure_policy_denied" in denied["client_body"]:
        passed += 1
        _print("PASS", "P5", "disallowed provider path returns policy denial")
    else:
        failed += 1
        _print("FAIL", "P5", "disallowed provider path was not denied")

    if "Do not retry this key" in denied["client_body"]:
        passed += 1
        _print("PASS", "P6", "denial tells agent not to retry fake key")
    else:
        failed += 1
        _print("FAIL", "P6", "denial does not tell agent not to retry")

    print("")
    print("Summary: %s passed, %s failed" % (passed, failed))
    return 0 if failed == 0 else 1


def _print(status: str, receipt_id: str, message: str) -> None:
    print("%-5s %-3s %s" % (status, receipt_id, message))


def _exercise_provider_proxy(provider_path: str):
    handler = _receipt_handler()
    connections = []

    def create_connection(host, port, timeout=30):
        connection = _FakeConnection(host, port, timeout)
        connections.append(connection)
        return connection

    with patch("agentsecure.gateway.proxy.http.client.HTTPSConnection", side_effect=create_connection):
        handler._proxy_provider_http(handler.provider_proxy.providers["openai"], provider_path)

    authorization = ""
    if connections:
        authorization = connections[0].request_headers.get("Authorization", "")
    return {
        "status": handler.response_status,
        "client_body": handler.wfile.getvalue().decode("utf-8", "replace"),
        "upstream_authorization": authorization,
        "upstream_path": connections[0].request_path if connections else "",
        "upstream_body": connections[0].request_body.decode("utf-8", "replace") if connections else "",
        "upstream_headers": json.dumps(connections[0].request_headers, sort_keys=True) if connections else "",
        "upstream_content_length": connections[0].request_headers.get("Content-Length", "") if connections else "",
    }


def _receipt_handler():
    class ReceiptHandler(GatewayRequestHandler):
        def send_response(self, code, message=None):
            self.response_status = code

        def send_header(self, name, value):
            self.response_headers.append((name, value))

        def end_headers(self):
            return None

    handler = object.__new__(ReceiptHandler)
    handler.command = "POST"
    handler.headers = {
        "Authorization": "Bearer virt_openai_receipt",
        "X-Api-Key": "virt_openai_receipt",
        "X-Trace": "trace-virt_openai_receipt",
        "User-Agent": "agentsecure-receipt",
    }
    body = b'{"metadata":"virt_openai_receipt"}'
    handler.headers["Content-Length"] = str(len(body))
    handler.rfile = io.BytesIO(body)
    handler.wfile = io.BytesIO()
    handler.response_headers = []
    handler.response_status = None
    handler.policy_engine = _AllowPolicy()
    handler.token_resolver = _Resolver()
    handler.audit_logger = _Audit()
    handler.secret_bindings = {
        "virt_openai_receipt": SecretBinding(
            env_name="OPENAI_API_KEY",
            virtual_token="virt_openai_receipt",
            real_secret_ref="local:receipt",
            provider="openai",
        )
    }
    handler.provider_proxy = ProviderProxyConfig(
        enabled=True,
        providers={
            "openai": ProviderProxyProvider(
                name="openai",
                env_name="OPENAI_API_KEY",
                base_url_env="OPENAI_BASE_URL",
                upstream="https://api.openai.com",
                local_path="/providers/openai",
                allow_paths=["/v1/"],
            )
        },
    )
    return handler


class _AllowPolicy:
    def evaluate_network(self, destination):
        return PolicyDecision.allow("destination allowed", "network.allow_domain")


class _Resolver:
    def resolve(self, virtual_token):
        if virtual_token == "virt_openai_receipt":
            return "sk-receipt-real-secret"
        return None


class _Audit:
    def record(self, event, payload):
        _ = event, payload


class _FakeConnection:
    def __init__(self, host, port, timeout=30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.request_headers = {}

    def request(self, method, path, body=None, headers=None):
        self.request_method = method
        self.request_path = path
        self.request_body = body
        self.request_headers = headers or {}

    def getresponse(self):
        return _FakeResponse()

    def close(self):
        return None


class _FakeResponse:
    status = 200
    reason = "OK"

    def getheaders(self):
        return [("Content-Type", "application/json")]

    def read(self):
        return json.dumps({"ok": True}).encode("utf-8")
