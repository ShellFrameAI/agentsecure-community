import http.client
import base64
import select
import socket
import socketserver
from http.server import BaseHTTPRequestHandler
from typing import Callable, Dict, Optional, Tuple
from urllib.parse import urlsplit

from agentsecure.core.models import Destination, SecretBinding
from agentsecure.interfaces.audit import AuditLogger
from agentsecure.interfaces.policy import PolicyEngine
from agentsecure.interfaces.secrets import TokenResolver


class GatewayRequestHandler(BaseHTTPRequestHandler):
    policy_engine = None
    token_resolver = None
    audit_logger = None
    secret_bindings = {}

    def do_CONNECT(self) -> None:
        host, port = self._split_host_port(self.path, default_port=443)
        destination = Destination(
            "https",
            host,
            port,
            credentials_present=self._has_visible_credentials(self.headers),
        )
        decision = self.policy_engine.evaluate_network(destination)
        self.audit_logger.record(
            "outbound_connect",
            {
                "session_id": self._session_id(),
                "host": host,
                "port": port,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "credentials_present": destination.credentials_present,
            },
        )
        if not decision.allowed:
            self.send_error(403, self._deny_message(decision.reason, host))
            return
        self._tunnel(host, port)

    def do_GET(self) -> None:
        self._proxy_http()

    def do_POST(self) -> None:
        self._proxy_http()

    def do_PUT(self) -> None:
        self._proxy_http()

    def do_PATCH(self) -> None:
        self._proxy_http()

    def do_DELETE(self) -> None:
        self._proxy_http()

    def _proxy_http(self) -> None:
        parsed = urlsplit(self.path)
        if not parsed.scheme or not parsed.netloc:
            self.send_error(400, "proxy requests must use absolute URLs")
            return

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        host = parsed.hostname or ""
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        headers = self._build_forward_headers()
        credentials_present = self._has_visible_credentials(headers, body, self.path)
        destination = Destination(parsed.scheme, host, port, credentials_present=credentials_present)
        decision = self.policy_engine.evaluate_network(destination)
        self.audit_logger.record(
            "outbound_request",
            {
                "session_id": self._session_id(),
                "method": self.command,
                "scheme": parsed.scheme,
                "host": host,
                "port": port,
                "path": parsed.path or "/",
                "allowed": decision.allowed,
                "reason": decision.reason,
                "credentials_present": destination.credentials_present,
            },
        )
        if not decision.allowed:
            self.send_error(403, self._deny_message(decision.reason, host))
            return
        if parsed.scheme != "http":
            self.send_error(501, "direct HTTPS proxying is handled with CONNECT tunneling")
            return

        self._inject_credentials(headers)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        connection = http.client.HTTPConnection(host, port, timeout=30)
        try:
            connection.request(self.command, path, body=body, headers=headers)
            response = connection.getresponse()
            self.send_response(response.status, response.reason)
            for name, value in response.getheaders():
                if name.lower() not in ("transfer-encoding", "connection", "proxy-authenticate"):
                    self.send_header(name, value)
            self.end_headers()
            self.wfile.write(response.read())
        finally:
            connection.close()

    def _build_forward_headers(self) -> Dict[str, str]:
        headers = {}
        for key, value in self.headers.items():
            lower = key.lower()
            if lower not in ("proxy-connection", "proxy-authorization", "connection", "host"):
                headers[key] = value
        return headers

    def _session_id(self) -> str:
        header = self.headers.get("Proxy-Authorization", "")
        prefix = "Basic "
        if not header.startswith(prefix):
            return ""
        try:
            decoded = base64.b64decode(header[len(prefix) :]).decode("utf-8", "replace")
        except Exception:
            return ""
        username = decoded.split(":", 1)[0]
        return username if username.startswith("session_") else ""

    def _inject_credentials(self, headers: Dict[str, str]) -> None:
        auth_header = headers.get("Authorization")
        if auth_header:
            parts = auth_header.split(" ", 1)
            if len(parts) == 2:
                scheme, token = parts
                real_secret = self.token_resolver.resolve(token)
                if real_secret:
                    headers["Authorization"] = scheme + " " + real_secret

        for name, value in list(headers.items()):
            real_secret = self.token_resolver.resolve(value)
            if real_secret:
                headers[name] = real_secret

    def _has_visible_credentials(self, headers, body: bytes = b"", target: str = "") -> bool:
        credential_header_names = {
            "authorization",
            "x-api-key",
            "api-key",
            "apikey",
            "openai-api-key",
            "anthropic-api-key",
        }
        for name, value in headers.items():
            lower = name.lower()
            if lower in credential_header_names and str(value).strip():
                return True
            if self._contains_virtual_token(str(value)):
                return True
        if target and self._contains_virtual_token(target):
            return True
        if target and self._target_has_key_parameter(target):
            return True
        if body and self._contains_virtual_token(body.decode("utf-8", "ignore")):
            return True
        return False

    def _contains_virtual_token(self, value: str) -> bool:
        if "virt_" in value:
            return True
        for token in self.secret_bindings.keys():
            if token and token in value:
                return True
        return False

    def _target_has_key_parameter(self, target: str) -> bool:
        lowered = target.lower()
        return any(
            marker in lowered
            for marker in (
                "api_key=",
                "apikey=",
                "access_token=",
                "auth_token=",
                "token=",
            )
        )

    def _deny_message(self, reason: str, host: str) -> str:
        if reason == "domain is not allowlisted":
            return (
                "credential-bearing request is not allowed for %s. "
                "Run: agentsecure network allow %s"
            ) % (host, host)
        return reason

    def _split_host_port(self, value: str, default_port: int) -> Tuple[str, int]:
        if ":" not in value:
            return value, default_port
        host, port_text = value.rsplit(":", 1)
        return host, int(port_text)

    def _tunnel(self, host: str, port: int) -> None:
        upstream = socket.create_connection((host, port), timeout=30)
        self.send_response(200, "Connection established")
        self.end_headers()
        sockets = [self.connection, upstream]
        try:
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 30)
                if exceptional:
                    break
                if not readable:
                    break
                for source in readable:
                    target = upstream if source is self.connection else self.connection
                    data = source.recv(8192)
                    if not data:
                        return
                    target.sendall(data)
        finally:
            upstream.close()

    def log_message(self, fmt: str, *args: object) -> None:
        return


class LocalGateway:
    def __init__(
        self,
        host: str,
        port: int,
        policy_engine: PolicyEngine,
        token_resolver: TokenResolver,
        audit_logger: AuditLogger,
        secret_bindings: Dict[str, SecretBinding],
    ) -> None:
        self._host = host
        self._port = port
        self._policy_engine = policy_engine
        self._token_resolver = token_resolver
        self._audit = audit_logger
        self._secret_bindings = secret_bindings
        self._server = None

    def serve_forever(self, ready_callback: Optional[Callable[[], None]] = None) -> None:
        handler = self._handler_class()
        with ReusableThreadingTCPServer((self._host, self._port), handler) as server:
            self._server = server
            self._audit.record("gateway_started", {"host": self._host, "port": self._port})
            if ready_callback:
                ready_callback()
            server.serve_forever()

    def _handler_class(self):
        class BoundGatewayRequestHandler(GatewayRequestHandler):
            pass

        BoundGatewayRequestHandler.policy_engine = self._policy_engine
        BoundGatewayRequestHandler.token_resolver = self._token_resolver
        BoundGatewayRequestHandler.audit_logger = self._audit
        BoundGatewayRequestHandler.secret_bindings = self._secret_bindings
        return BoundGatewayRequestHandler


class ReusableThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
