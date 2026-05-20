import unittest

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


if __name__ == "__main__":
    unittest.main()

