import unittest

from agentsecure.cli.main import _start_local_gateway_thread
from agentsecure.gateway.proxy import GatewayRequestHandler


class GatewayCredentialDetectionTest(unittest.TestCase):
    def test_detects_authorization_header(self):
        handler = self._handler(["virt_openai_123"])

        self.assertTrue(handler._has_visible_credentials({"Authorization": "Bearer anything"}))

    def test_detects_virtual_token_in_headers_body_or_url(self):
        handler = self._handler(["virt_openai_123"])

        self.assertTrue(handler._has_visible_credentials({"X-Test": "virt_openai_123"}))
        self.assertTrue(handler._has_visible_credentials({}, b'{"key":"virt_openai_123"}'))
        self.assertTrue(handler._has_visible_credentials({}, b"", "http://example.com/?api_key=abc"))

    def test_plain_request_has_no_visible_credentials(self):
        handler = self._handler(["virt_openai_123"])

        self.assertFalse(handler._has_visible_credentials({"User-Agent": "claude"}, b"hello", "https://downloads.claude.ai/"))

    def _handler(self, tokens):
        class TestHandler(GatewayRequestHandler):
            pass

        TestHandler.secret_bindings = {token: object() for token in tokens}
        return object.__new__(TestHandler)


class GatewayStartupContextTest(unittest.TestCase):
    def test_local_gateway_receives_project_and_run_context(self):
        class FakeGateway:
            calls = []

            def __init__(self, *args):
                FakeGateway.calls.append(args)

            def serve_forever(self, ready_callback=None):
                if ready_callback:
                    ready_callback()

            def shutdown(self):
                pass

        class Container:
            policy_engine = object()
            token_resolver = object()
            audit_logger = object()
            bindings = {}
            project_id = "project_test"
            run_id = "run_test"

            class Config:
                provider_proxy = None

            config = Config()

        import agentsecure.cli.main as main_module

        original = main_module.LocalGateway
        main_module.LocalGateway = FakeGateway
        try:
            handle = _start_local_gateway_thread(Container(), "127.0.0.1", 8765)
            self.assertFalse(isinstance(handle, int))
        finally:
            main_module.LocalGateway = original
            if not isinstance(handle, int):
                handle.shutdown()

        self.assertEqual("project_test", FakeGateway.calls[0][7])
        self.assertEqual("run_test", FakeGateway.calls[0][8])


if __name__ == "__main__":
    unittest.main()
