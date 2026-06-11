import http.client
import json
import ssl
from typing import Any, Dict
from urllib.parse import urlencode, urlsplit, urlunsplit

from agentsecure.core.models import Destination
from agentsecure.guard.sanitizer import SecretOutputSanitizer
from agentsecure.mcp.placeholders import PLACEHOLDER_RE, find_placeholders, replace_placeholders, to_text_body
from agentsecure.mcp.runtime import env_token_map, prepare_mcp_container, revoke_mcp_bindings


class McpHttpError(ValueError):
    pass


def perform_http_request(config_path: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    placeholders = find_placeholders(
        {
            "url": arguments.get("url", ""),
            "headers": arguments.get("headers", {}),
            "query": arguments.get("query", {}),
            "json": arguments.get("json"),
            "body": arguments.get("body", ""),
        }
    )
    if not placeholders:
        return {
            "blocked": True,
            "reason": "No AgentSecure secret placeholders were provided. Use normal agent network tools for non-secret calls.",
            "rule_id": "mcp.no_secret_placeholders",
        }

    container, bindings, run_id = prepare_mcp_container(config_path, str(arguments.get("ttl", "2h") or "2h"))
    resolved_values: Dict[str, str] = {}
    try:
        parsed = _parse_url(str(arguments.get("url", "")))
        if PLACEHOLDER_RE.search(parsed.netloc):
            raise McpHttpError("Secret placeholders are not allowed in URL host or port")
        method = str(arguments.get("method", "GET") or "GET").upper()
        destination = Destination(parsed.scheme, parsed.hostname or "", parsed.port or _default_port(parsed.scheme), True)
        decision = container.policy_engine.evaluate_network(destination)
        if not decision.allowed:
            container.audit_logger.record(
                "mcp_http_request",
                {
                    "allowed": False,
                    "host": destination.host,
                    "port": destination.port,
                    "method": method,
                    "reason": decision.reason,
                    "rule_id": decision.rule_id,
                    "placeholders": placeholders,
                    "run_id": run_id,
                },
            )
            return {
                "blocked": True,
                "reason": decision.reason,
                "rule_id": decision.rule_id,
                "allow_command": "agentsecure network allow %s" % _allow_hint(parsed),
            }

        tokens = env_token_map(container)

        def resolve_env(name: str) -> str:
            if name in resolved_values:
                return resolved_values[name]
            token = tokens.get(name)
            if not token:
                raise McpHttpError("No AgentSecure secret is assigned to ${%s}" % name)
            value = container.token_resolver.resolve(
                token,
                {
                    "host": destination.host,
                    "project_id": container.project_id,
                    "run_id": run_id,
                },
            )
            if value is None:
                raise McpHttpError("Secret ${%s} is not approved for %s" % (name, destination.host))
            resolved_values[name] = value
            return value

        headers = _headers(arguments.get("headers", {}))
        query = _query(arguments.get("query", {}))
        body_value = arguments.get("body")
        if "json" in arguments and arguments.get("json") is not None:
            body_value = json.dumps(replace_placeholders(arguments.get("json"), resolve_env), separators=(",", ":"))
            headers.setdefault("Content-Type", "application/json")
        else:
            body_value = replace_placeholders(body_value or "", resolve_env)
        headers = replace_placeholders(headers, resolve_env)
        query = replace_placeholders(query, resolve_env)
        request_url = replace_placeholders(_with_query(parsed, query), resolve_env)
        body_text = to_text_body(body_value)
        response = _send(method, request_url, headers, body_text, arguments)
        sanitized = _sanitize_response(config_path, resolved_values, response)
        container.audit_logger.record(
            "mcp_http_request",
            {
                "allowed": True,
                "host": destination.host,
                "port": destination.port,
                "method": method,
                "status": sanitized["status"],
                "placeholders": placeholders,
                "run_id": run_id,
            },
        )
        return sanitized
    except McpHttpError as exc:
        container.audit_logger.record("mcp_http_request", {"allowed": False, "reason": str(exc), "placeholders": placeholders, "run_id": run_id})
        return {"blocked": True, "reason": str(exc), "rule_id": "mcp.secret_resolution"}
    except (OSError, http.client.HTTPException, TimeoutError) as exc:
        container.audit_logger.record("mcp_http_request", {"allowed": False, "reason": str(exc), "placeholders": placeholders, "run_id": run_id})
        return {"blocked": True, "reason": str(exc), "rule_id": "mcp.request_failed"}
    finally:
        revoke_mcp_bindings(config_path, bindings, run_id)


def _parse_url(url: str):
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise McpHttpError("url must be an http or https URL with a host")
    return parsed


def _headers(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        raise McpHttpError("headers must be an object")
    return {str(key): str(item) for key, item in value.items()}


def _query(value: Any) -> Dict[str, str]:
    if value in (None, ""):
        return {}
    if not isinstance(value, dict):
        raise McpHttpError("query must be an object")
    return {str(key): str(item) for key, item in value.items()}


def _with_query(parsed, query: Dict[str, str]) -> str:
    existing = parsed.query
    added = urlencode(query)
    full_query = "&".join(item for item in (existing, added) if item)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", full_query, ""))


def _send(method: str, url: str, headers: Dict[str, str], body: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    parsed = urlsplit(url)
    timeout = float(arguments.get("timeout_seconds", 30) or 30)
    port = parsed.port or _default_port(parsed.scheme)
    if parsed.scheme == "https":
        context = None
        if arguments.get("verify_tls") is False:
            context = ssl._create_unverified_context()
        connection = http.client.HTTPSConnection(parsed.hostname, port, timeout=timeout, context=context)
    else:
        connection = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        connection.request(method, path, body=body.encode("utf-8") if body else None, headers=headers)
        response = connection.getresponse()
        data = response.read()
        return {
            "blocked": False,
            "status": response.status,
            "reason": response.reason,
            "headers": {key: value for key, value in response.getheaders()},
            "body": data.decode("utf-8", "replace"),
        }
    finally:
        connection.close()


def _sanitize_response(config_path: str, resolved_values: Dict[str, str], response: Dict[str, Any]) -> Dict[str, Any]:
    sanitizer = SecretOutputSanitizer.from_config_path(config_path)
    text = sanitizer.sanitize_text(str(response.get("body", "")))
    headers = {}
    for key, value in dict(response.get("headers", {})).items():
        sanitized_value = sanitizer.sanitize_text(str(value))
        for secret in resolved_values.values():
            if not secret:
                continue
            sanitized_value = sanitized_value.replace(secret, "[redacted]")
        headers[key] = sanitized_value
    for secret in resolved_values.values():
        if not secret:
            continue
        text = text.replace(secret, "[redacted]")
    result = dict(response)
    result["headers"] = headers
    result["body"] = text
    return result


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _allow_hint(parsed) -> str:
    port = parsed.port
    if port:
        return "%s://%s:%s%s" % (parsed.scheme, parsed.hostname, port, parsed.path or "/")
    return parsed.hostname or ""
