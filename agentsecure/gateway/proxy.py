import http.client
import base64
import json
import select
import socket
import socketserver
from http.server import BaseHTTPRequestHandler
from typing import Callable, Dict, Optional, Tuple
from urllib.parse import parse_qsl, quote_plus, unquote, urlencode, urlsplit, urlunsplit

from agentsecure.core.models import Destination, ProviderProxyConfig, ProviderProxyProvider, SecretBinding
from agentsecure.interfaces.audit import AuditLogger
from agentsecure.interfaces.policy import PolicyEngine
from agentsecure.interfaces.secrets import TokenResolver


class GatewayRequestHandler(BaseHTTPRequestHandler):
    policy_engine = None
    token_resolver = None
    audit_logger = None
    secret_bindings = {}
    provider_proxy = ProviderProxyConfig()
    gateway_host = "127.0.0.1"
    gateway_port = 8765
    project_id = ""
    run_id = ""

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

    def do_HEAD(self) -> None:
        self._proxy_http()

    def do_OPTIONS(self) -> None:
        self._proxy_http()

    def _proxy_http(self) -> None:
        provider, provider_path = self._provider_for_path(self.path)
        if provider is not None:
            self._proxy_provider_http(provider, provider_path)
            return

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

        self._inject_credentials(headers, host)
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

    def _proxy_provider_http(self, provider: ProviderProxyProvider, provider_path: str) -> None:
        if not self._provider_path_allowed(provider, provider_path):
            self._send_policy_denied("provider path is not allowed")
            return
        parsed_upstream = urlsplit(provider.upstream)
        host = parsed_upstream.hostname or ""
        port = parsed_upstream.port or 443
        decision = self.policy_engine.evaluate_network(
            Destination("https", host, port, credentials_present=True)
        )
        self.audit_logger.record(
            "provider_proxy_request",
            {
                "session_id": self._session_id(),
                "provider": provider.name,
                "method": self.command,
                "host": host,
                "port": port,
                "path": urlsplit(provider_path).path or "/",
                "allowed": decision.allowed,
                "reason": decision.reason,
                "credentials_present": True,
            },
        )
        if not decision.allowed:
            self._send_policy_denied(decision.reason, host)
            return
        real_secret = self._real_secret_for_provider(provider)
        if not real_secret:
            self._send_policy_denied("no active local secret binding for provider", host)
            return

        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        headers = self._build_forward_headers()
        headers = self._provider_forward_headers(headers)
        headers["Authorization"] = "Bearer " + real_secret
        body = self._scrub_provider_body(body, headers)
        headers["Content-Length"] = str(len(body))
        upstream_path = provider_path or "/"
        if parsed_upstream.path and parsed_upstream.path != "/":
            upstream_path = parsed_upstream.path.rstrip("/") + "/" + upstream_path.lstrip("/")
        upstream_path = self._scrub_provider_path(upstream_path)

        connection = http.client.HTTPSConnection(host, port, timeout=30)
        try:
            connection.request(self.command, upstream_path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = self._scrub_secret_bytes(response.read(), real_secret)
            self.send_response(response.status, response.reason)
            for name, value in self._provider_response_headers(response.getheaders(), real_secret).items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)
        except (OSError, ValueError, http.client.HTTPException):
            self._send_provider_error("provider proxy upstream request failed")
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

    def _inject_credentials(self, headers: Dict[str, str], host: str = "") -> None:
        auth_header = headers.get("Authorization")
        if auth_header:
            parts = auth_header.split(" ", 1)
            if len(parts) == 2:
                scheme, token = parts
                real_secret = self._resolve_virtual_token(token, host)
                if real_secret:
                    headers["Authorization"] = scheme + " " + real_secret

        for name, value in list(headers.items()):
            real_secret = self._resolve_virtual_token(value, host)
            if real_secret:
                headers[name] = real_secret

    def _resolve_virtual_token(self, virtual_token: str, host: str = "") -> str:
        try:
            return self.token_resolver.resolve(virtual_token, self._resolution_context(host)) or ""
        except TypeError:
            return self.token_resolver.resolve(virtual_token) or ""

    def _resolution_context(self, host: str = "") -> Dict[str, str]:
        return {
            "host": host,
            "project_id": self.project_id,
            "run_id": self._session_id() or self.run_id,
        }

    def _provider_forward_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        credential_header_names = {
            "authorization",
            "x-api-key",
            "api-key",
            "apikey",
            "openai-api-key",
            "anthropic-api-key",
        }
        hop_by_hop_header_names = {
            "content-length",
            "transfer-encoding",
            "trailer",
            "expect",
            "connection",
            "keep-alive",
            "upgrade",
        }
        result = {}
        for name, value in headers.items():
            lower = name.lower()
            if (
                lower in credential_header_names
                or lower in hop_by_hop_header_names
                or lower.startswith("proxy-")
                or self._invalid_header(name, str(value))
            ):
                continue
            result[name] = self._scrub_virtual_tokens_text(str(value))
        return result

    def _provider_response_headers(self, headers, real_secret: str) -> Dict[str, str]:
        blocked = {
            "content-length",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "trailer",
            "upgrade",
        }
        result = {}
        for name, value in headers:
            lower = name.lower()
            if lower in blocked or lower.startswith("proxy-") or self._invalid_header(name, str(value)):
                continue
            result[name] = self._scrub_secret_text(str(value), real_secret)
        return result

    def _invalid_header(self, name: str, value: str) -> bool:
        return "\r" in name or "\n" in name or "\r" in value or "\n" in value

    def _scrub_provider_body(self, body: bytes, headers: Dict[str, str]) -> bytes:
        content_type = ""
        for name, value in headers.items():
            if name.lower() == "content-type":
                content_type = value.lower()
                break
        if "application/json" in content_type:
            scrubbed = self._scrub_json_body(body)
            if scrubbed is not None:
                return scrubbed
        if "application/x-www-form-urlencoded" in content_type:
            scrubbed = self._scrub_form_body(body)
            if scrubbed is not None:
                return scrubbed
        return self._scrub_virtual_tokens_bytes(body)

    def _scrub_json_body(self, body: bytes) -> Optional[bytes]:
        try:
            value = json.loads(body.decode("utf-8"))
        except (TypeError, ValueError, UnicodeDecodeError):
            return None
        scrubbed = self._scrub_json_value(value)
        return json.dumps(scrubbed, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def _scrub_json_value(self, value):
        if isinstance(value, str):
            return self._scrub_virtual_tokens_text(value)
        if isinstance(value, list):
            return [self._scrub_json_value(item) for item in value]
        if isinstance(value, dict):
            return {key: self._scrub_json_value(item) for key, item in value.items()}
        return value

    def _scrub_form_body(self, body: bytes) -> Optional[bytes]:
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return None
        fields = []
        for key, value in parse_qsl(text, keep_blank_values=True):
            fields.append((key, self._scrub_virtual_tokens_text(value)))
        return urlencode(fields, quote_via=quote_plus).encode("utf-8")

    def _scrub_virtual_tokens_text(self, value: str) -> str:
        scrubbed = value
        for token in self.secret_bindings.keys():
            if token:
                scrubbed = scrubbed.replace(token, "")
        return scrubbed

    def _scrub_secret_text(self, value: str, real_secret: str) -> str:
        scrubbed = value.replace(real_secret, "[REDACTED]") if real_secret else value
        return self._scrub_virtual_tokens_text(scrubbed)

    def _scrub_secret_bytes(self, value: bytes, real_secret: str) -> bytes:
        scrubbed = value
        if real_secret:
            scrubbed = scrubbed.replace(real_secret.encode("utf-8"), b"[REDACTED]")
        return self._scrub_virtual_tokens_bytes(scrubbed)

    def _scrub_virtual_tokens_bytes(self, value: bytes) -> bytes:
        scrubbed = value
        for token in self.secret_bindings.keys():
            if token:
                scrubbed = scrubbed.replace(token.encode("utf-8"), b"")
        return scrubbed

    def _scrub_provider_path(self, value: str) -> str:
        parsed = urlsplit(value)
        credential_params = {"api_key", "apikey", "access_token", "auth_token", "token"}
        query = []
        for key, item_value in parse_qsl(parsed.query, keep_blank_values=True):
            lower = key.lower()
            if lower in credential_params:
                continue
            scrubbed_value = self._scrub_virtual_tokens_text(item_value)
            query.append((key, scrubbed_value))
        path = self._scrub_virtual_tokens_text(parsed.path or "/")
        return urlunsplit(("", "", path, urlencode(query), ""))

    def _provider_for_path(self, target: str) -> Tuple[Optional[ProviderProxyProvider], str]:
        if not self.provider_proxy.enabled:
            return None, ""
        parsed = urlsplit(target)
        if parsed.netloc and not self._absolute_target_is_local(parsed):
            return None, ""
        path = parsed.path or "/"
        providers = sorted(
            self.provider_proxy.providers.values(),
            key=lambda item: len(item.local_path.rstrip("/")),
            reverse=True,
        )
        for provider in providers:
            local_path = provider.local_path.rstrip("/")
            if path == local_path:
                return provider, "/"
            if path.startswith(local_path + "/"):
                provider_path = "/" + path[len(local_path) :].lstrip("/")
                if parsed.query:
                    provider_path += "?" + parsed.query
                return provider, provider_path
        return None, ""

    def _absolute_target_is_local(self, parsed) -> bool:
        host = parsed.hostname or ""
        port = parsed.port or self.gateway_port
        if int(port) != int(self.gateway_port):
            return False
        allowed_hosts = {self.gateway_host, "127.0.0.1", "localhost", "::1"}
        return host in allowed_hosts

    def _provider_path_allowed(self, provider: ProviderProxyProvider, provider_path: str) -> bool:
        path = urlsplit(provider_path).path or "/"
        if self._has_unsafe_path_segment(path):
            return False
        allow_paths = provider.allow_paths or ["/"]
        for allow_path in allow_paths:
            normalized = allow_path if allow_path.startswith("/") else "/" + allow_path
            if normalized == "/":
                return True
            normalized = normalized.rstrip("/") + "/"
            if path == normalized.rstrip("/") or path.startswith(normalized):
                return True
        return False

    def _has_unsafe_path_segment(self, path: str) -> bool:
        for segment in path.split("/"):
            decoded = self._decode_segment(segment)
            if decoded in (".", "..") or "/" in decoded or "\\" in decoded:
                return True
        return False

    def _decode_segment(self, segment: str) -> str:
        decoded = segment
        for _ in range(3):
            next_value = unquote(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        return decoded

    def _real_secret_for_provider(self, provider: ProviderProxyProvider) -> str:
        for binding in self.secret_bindings.values():
            if binding.env_name == provider.env_name and binding.provider == provider.name:
                return self._resolve_virtual_token(binding.virtual_token, "")
        return ""

    def _send_policy_denied(self, reason: str, host: str = "") -> None:
        message = (
            "Access denied by AgentSecure policy. "
            "This is not an authentication failure. Do not retry this key."
        )
        body = {
            "error": "agentsecure_policy_denied",
            "retry": False,
            "message": message,
            "reason": reason,
        }
        if host:
            body["host"] = host
        payload = json.dumps(body, sort_keys=True).encode("utf-8")
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_provider_error(self, reason: str) -> None:
        payload = json.dumps(
            {
                "error": "agentsecure_provider_proxy_error",
                "retry": False,
                "message": "AgentSecure provider proxy failed before exposing provider credentials.",
                "reason": reason,
            },
            sort_keys=True,
        ).encode("utf-8")
        self.send_response(502)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

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
        provider_proxy: ProviderProxyConfig = None,
        project_id: str = "",
        run_id: str = "",
    ) -> None:
        self._host = host
        self._port = port
        self._policy_engine = policy_engine
        self._token_resolver = token_resolver
        self._audit = audit_logger
        self._secret_bindings = secret_bindings
        self._provider_proxy = provider_proxy or ProviderProxyConfig()
        self._project_id = project_id
        self._run_id = run_id
        self._server = None

    def serve_forever(self, ready_callback: Optional[Callable[[], None]] = None) -> None:
        handler = self._handler_class()
        with ReusableThreadingTCPServer((self._host, self._port), handler) as server:
            self._server = server
            self._audit.record("gateway_started", {"host": self._host, "port": self._port})
            if ready_callback:
                ready_callback()
            server.serve_forever()

    def shutdown(self) -> None:
        if self._server is not None:
            self._server.shutdown()

    def _handler_class(self):
        class BoundGatewayRequestHandler(GatewayRequestHandler):
            pass

        BoundGatewayRequestHandler.policy_engine = self._policy_engine
        BoundGatewayRequestHandler.token_resolver = self._token_resolver
        BoundGatewayRequestHandler.audit_logger = self._audit
        BoundGatewayRequestHandler.secret_bindings = self._secret_bindings
        BoundGatewayRequestHandler.provider_proxy = self._provider_proxy
        BoundGatewayRequestHandler.gateway_host = self._host
        BoundGatewayRequestHandler.gateway_port = self._port
        BoundGatewayRequestHandler.project_id = self._project_id
        BoundGatewayRequestHandler.run_id = self._run_id
        return BoundGatewayRequestHandler


class ReusableThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address) -> None:
        return
