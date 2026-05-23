import io
import json
import unittest
from unittest.mock import patch

from agentsecure.core.models import PolicyDecision, ProviderProxyConfig, ProviderProxyProvider, SecretBinding
from agentsecure.gateway.proxy import GatewayRequestHandler


class ProviderProxyGatewayTest(unittest.TestCase):
    def test_provider_proxy_injects_real_secret_without_forwarding_virtual_secret(self):
        handler = self._handler()
        connections = []

        def create_connection(host, port, timeout=30):
            connection = FakeConnection(host, port, timeout)
            connections.append(connection)
            return connection

        with patch("agentsecure.gateway.proxy.http.client.HTTPSConnection", side_effect=create_connection):
            handler._proxy_provider_http(handler.provider_proxy.providers["openai"], "/v1/chat/completions?api_key=virt_openai_test")

        connection = connections[0]
        self.assertEqual("api.openai.com", connection.host)
        self.assertEqual(443, connection.port)
        self.assertEqual("/v1/chat/completions", connection.request_path)
        self.assertEqual("Bearer sk-real-local-secret", connection.request_headers["Authorization"])
        self.assertNotIn("virt_openai_test", connection.request_headers["Authorization"])
        self.assertNotIn("virt_openai_test", connection.request_path)
        self.assertNotIn("virt_openai_test", str(connection.request_headers))
        self.assertNotIn("virt_openai_test", connection.request_body.decode("utf-8"))
        self.assertNotIn("X-Api-Key", connection.request_headers)
        self.assertNotIn("Transfer-Encoding", connection.request_headers)
        self.assertNotIn("content-length", connection.request_headers)
        self.assertEqual(str(len(connection.request_body)), connection.request_headers["Content-Length"])
        self.assertEqual(200, handler.response_status)
        self.assertNotIn(b"sk-real-local-secret", handler.wfile.getvalue())
        self.assertIn(b"[REDACTED]", handler.wfile.getvalue())
        audit_payload = json.dumps(handler.audit.records, sort_keys=True)
        self.assertNotIn("sk-real-local-secret", audit_payload)
        self.assertNotIn("virt_openai_test", audit_payload)

    def test_provider_proxy_scrubs_encoded_json_body(self):
        handler = self._handler(
            extra_headers={"Content-Type": "application/json"},
            body=b'{"metadata":"virt\\u005fopenai\\u005ftest"}',
        )
        connections = []

        def create_connection(host, port, timeout=30):
            connection = FakeConnection(host, port, timeout)
            connections.append(connection)
            return connection

        with patch("agentsecure.gateway.proxy.http.client.HTTPSConnection", side_effect=create_connection):
            handler._proxy_provider_http(handler.provider_proxy.providers["openai"], "/v1/chat/completions")

        self.assertNotIn("virt_openai_test", connections[0].request_body.decode("utf-8"))

    def test_provider_proxy_scrubs_form_body(self):
        handler = self._handler(
            extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=b"metadata=virt%5Fopenai%5Ftest&safe=1",
        )
        connections = []

        def create_connection(host, port, timeout=30):
            connection = FakeConnection(host, port, timeout)
            connections.append(connection)
            return connection

        with patch("agentsecure.gateway.proxy.http.client.HTTPSConnection", side_effect=create_connection):
            handler._proxy_provider_http(handler.provider_proxy.providers["openai"], "/v1/chat/completions")

        self.assertNotIn("virt_openai_test", connections[0].request_body.decode("utf-8"))
        self.assertIn("safe=1", connections[0].request_body.decode("utf-8"))

    def test_provider_proxy_blocks_disallowed_path_with_agent_friendly_json(self):
        handler = self._handler()

        handler._proxy_provider_http(handler.provider_proxy.providers["openai"], "/admin")

        self.assertEqual(403, handler.response_status)
        body = handler.wfile.getvalue().decode("utf-8")
        self.assertIn("agentsecure_policy_denied", body)
        self.assertIn("Do not retry this key", body)

    def test_real_secret_lookup_requires_matching_provider_identity(self):
        handler = self._handler()
        provider = ProviderProxyProvider(
            name="evil",
            env_name="OPENAI_API_KEY",
            base_url_env="EVIL_BASE_URL",
            upstream="https://evil.example.invalid",
            local_path="/providers/evil",
        )

        self.assertEqual("", handler._real_secret_for_provider(provider))

    def test_provider_path_matching_does_not_allow_prefix_confusion(self):
        handler = self._handler()

        provider, _ = handler._provider_for_path("/providers/openai2/v1/models")

        self.assertIsNone(provider)

    def test_provider_path_matching_supports_absolute_url_request_form(self):
        handler = self._handler()

        provider, path = handler._provider_for_path(
            "http://127.0.0.1:8765/providers/openai/v1/models?trace=virt_openai_test"
        )

        self.assertIsNotNone(provider)
        self.assertEqual("/v1/models?trace=virt_openai_test", path)

    def test_provider_path_matching_rejects_foreign_absolute_url_request_form(self):
        handler = self._handler()

        provider, _ = handler._provider_for_path(
            "http://evil.example/providers/openai/v1/models?trace=virt_openai_test"
        )

        self.assertIsNone(provider)

    def test_provider_path_matching_uses_longest_local_path(self):
        handler = self._handler()
        handler.provider_proxy.providers["generic"] = ProviderProxyProvider(
            name="generic",
            env_name="GENERIC_API_KEY",
            base_url_env="GENERIC_BASE_URL",
            upstream="https://generic.example.invalid",
            local_path="/providers",
            allow_paths=["/"],
        )

        provider, path = handler._provider_for_path("/providers/openai/v1/models")

        self.assertIsNotNone(provider)
        self.assertEqual("openai", provider.name)
        self.assertEqual("/v1/models", path)

    def test_provider_allow_path_does_not_allow_prefix_confusion(self):
        handler = self._handler()
        provider = handler.provider_proxy.providers["openai"]

        self.assertTrue(handler._provider_path_allowed(provider, "/v1/models"))
        self.assertFalse(handler._provider_path_allowed(provider, "/v10/models"))
        self.assertFalse(handler._provider_path_allowed(provider, "/v1evil/models"))

    def test_provider_allow_path_blocks_dot_segment_bypass(self):
        handler = self._handler()
        provider = handler.provider_proxy.providers["openai"]

        self.assertFalse(handler._provider_path_allowed(provider, "/v1/../admin"))
        self.assertFalse(handler._provider_path_allowed(provider, "/v1/%2e%2e/admin"))
        self.assertFalse(handler._provider_path_allowed(provider, "/v1/%5cadmin"))
        self.assertFalse(handler._provider_path_allowed(provider, "/v1/%2f..%2fadmin"))
        self.assertFalse(handler._provider_path_allowed(provider, "/v1/%5c..%5cadmin"))
        self.assertFalse(handler._provider_path_allowed(provider, "/v1/%252e%252e/admin"))
        self.assertFalse(handler._provider_path_allowed(provider, "/v1/%252f..%252fadmin"))

    def _handler(self, extra_headers=None, body=None):
        class TestHandler(GatewayRequestHandler):
            def send_response(self, code, message=None):
                self.response_status = code

            def send_header(self, name, value):
                self.response_headers.append((name, value))

            def end_headers(self):
                return None

        handler = object.__new__(TestHandler)
        handler.command = "POST"
        handler.headers = {
            "Authorization": "Bearer virt_openai_test",
            "X-Api-Key": "virt_openai_test",
            "X-Trace": "trace-virt_openai_test",
            "Transfer-Encoding": "chunked",
            "content-length": "999",
            "Content-Length": "0",
            "User-Agent": "agent-test",
        }
        if extra_headers:
            handler.headers.update(extra_headers)
        body = body if body is not None else b'{"metadata":"virt_openai_test"}'
        handler.headers["Content-Length"] = str(len(body))
        handler.rfile = io.BytesIO(body)
        handler.wfile = io.BytesIO()
        handler.response_headers = []
        handler.response_status = None
        handler.policy_engine = AllowPolicy()
        handler.token_resolver = Resolver()
        handler.audit = Audit()
        handler.audit_logger = handler.audit
        handler.secret_bindings = {
            "virt_openai_test": SecretBinding(
                env_name="OPENAI_API_KEY",
                virtual_token="virt_openai_test",
                real_secret_ref="local:test",
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


class AllowPolicy:
    def evaluate_network(self, destination):
        return PolicyDecision.allow("destination allowed", "network.allow_domain")


class Resolver:
    def resolve(self, virtual_token):
        if virtual_token == "virt_openai_test":
            return "sk-real-local-secret"
        return None


class Audit:
    def __init__(self):
        self.records = []

    def record(self, event, payload):
        self.records.append((event, payload))


class FakeConnection:
    def __init__(self, host, port, timeout=30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.request_path = None
        self.request_headers = None

    def request(self, method, path, body=None, headers=None):
        self.request_method = method
        self.request_path = path
        self.request_body = body
        self.request_headers = headers or {}

    def getresponse(self):
        return FakeResponse(self.request_headers.get("Authorization", ""))

    def close(self):
        return None


class FakeResponse:
    status = 200
    reason = "OK"

    def __init__(self, authorization):
        self.authorization = authorization

    def getheaders(self):
        return [("Content-Type", "application/json"), ("X-Debug-Auth", self.authorization)]

    def read(self):
        return ('{"debug_auth":"%s"}' % self.authorization).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
