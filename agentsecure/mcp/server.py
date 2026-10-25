import argparse
import json
import os
import shlex
import sys
from typing import Any, Dict

from agentsecure import __version__
from agentsecure.mcp.http_request import McpHttpError, perform_http_request
from agentsecure.mcp.mesh import call_mesh_tool, mesh_tools
from agentsecure.mcp.runtime import DurationError, SecretAliasError, describe_config, safe_secret_status


class McpServer:
    def __init__(self, config_path: str) -> None:
        self.config_path = os.path.abspath(config_path)
        self._framing = "jsonl"

    def serve_stdio(self) -> int:
        while True:
            message = self._read_message(sys.stdin.buffer)
            if message is None:
                return 0
            response = self.handle(message)
            if response is not None:
                self._write_message(sys.stdout.buffer, response)

    def handle(self, message: Dict[str, Any]) -> Dict[str, Any]:
        method = str(message.get("method", ""))
        message_id = message.get("id")
        if method == "notifications/initialized":
            return None
        try:
            if method == "initialize":
                return self._result(message_id, self._initialize_result())
            if method == "tools/list":
                return self._result(message_id, {"tools": self._tools()})
            if method == "tools/call":
                params = message.get("params", {}) if isinstance(message.get("params", {}), dict) else {}
                return self._result(message_id, self._call_tool(str(params.get("name", "")), params.get("arguments", {})))
            return self._error(message_id, -32601, "Method not found: %s" % method)
        except (DurationError, McpHttpError, SecretAliasError, ValueError) as exc:
            return self._error(message_id, -32000, str(exc))
        except Exception as exc:
            return self._error(message_id, -32603, "AgentSecure MCP error: %s" % exc)

    def _call_tool(self, name: str, arguments: Any) -> Dict[str, Any]:
        args = arguments if isinstance(arguments, dict) else {}
        if name == "agentsecure.policy.describe":
            payload = describe_config(self.config_path)
        elif name == "agentsecure.secret.status":
            payload = safe_secret_status(self.config_path, str(args.get("env_name", "")))
        elif name == "agentsecure.http.request":
            payload = perform_http_request(self.config_path, args)
        elif name.startswith("agentsecure.") and name in {tool["name"] for tool in mesh_tools()}:
            payload = call_mesh_tool(self.config_path, name, args)
        else:
            raise ValueError("unknown AgentSecure MCP tool: %s" % name)
        return {"content": [{"type": "text", "text": json.dumps(payload, indent=2, sort_keys=True)}], "isError": bool(payload.get("blocked"))}

    def _initialize_result(self) -> Dict[str, Any]:
        return {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "agentsecure", "version": __version__},
            "capabilities": {"tools": {}},
        }

    def _tools(self):
        return [
            {
                "name": "agentsecure.policy.describe",
                "description": (
                    "Inspect the current project's network rules and configured secret metadata before a secret-bearing "
                    "HTTP request. Takes no arguments. Returns network (allowed domains/ports and IP restrictions), "
                    "secret_aliases, project_bindings, and usage instructions; no secret values. Does not change policy "
                    "or verify that credentials work. Use agentsecure.secret.status for one env name, or "
                    "agentsecure.get_policy_hint for a Mesh action rather than HTTP destination policy."
                ),
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "agentsecure.secret.status",
                "description": (
                    "Check whether one environment name is assigned in the current project's secret configuration "
                    "before using its ${ENV_NAME} placeholder. Returns exists and env_name; when configured, also "
                    "returns source (vault_alias or project_binding), provider, mode, and alias metadata when applicable. "
                    "This is a configuration lookup, not a vault-value or credential-validity check, and returns no "
                    "secret value. Use agentsecure.policy.describe to list all configured aliases and bindings. "
                    "Example: {\"env_name\": \"API_KEY\"}."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "env_name": {
                            "type": "string",
                            "description": "Exact configured environment name, e.g. API_KEY, without ${...}; not an alias ID or a secret value.",
                        }
                    },
                    "required": ["env_name"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "agentsecure.http.request",
                "description": (
                    "Send one HTTP(S) request that needs a configured secret, using ${ENV_NAME} placeholders instead "
                    "of raw credentials. Checks project destination policy before resolving secrets and applies "
                    "configured vault-alias host restrictions; calls without placeholders are blocked (use ordinary network tools for those). "
                    "Performs the requested remote operation, does not follow redirects, and revokes temporary alias "
                    "grants afterward. Returns blocked=false, status, reason, headers, and a UTF-8 body, with response "
                    "body/header values sanitized for known secrets; HTTP error statuses are still responses. "
                    "Blocked calls return blocked=true, reason, rule_id, and sometimes allow_command; configuration "
                    "errors may instead be MCP errors. This is not a sandbox for other network tools. "
                    "Example: {\"url\": \"https://api.example.com/me\", \"headers\": {\"Authorization\": \"Bearer ${API_KEY}\"}} "
                    "requires that host and API_KEY to be configured and approved."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "method": {
                            "type": "string",
                            "description": "HTTP method, e.g. GET or POST; defaults to GET and is uppercased. Choose a method appropriate for the authorized operation.",
                        },
                        "url": {
                            "type": "string",
                            "description": "Absolute http:// or https:// URL with a host approved by project policy. Placeholders may appear in the path/query, never the host or port. Prefer HTTPS.",
                        },
                        "headers": {
                            "type": "object",
                            "description": "Header name/value map; defaults to {} and values are converted to strings. Put secret placeholders in values, e.g. {\"Authorization\": \"Bearer ${API_KEY}\"}.",
                        },
                        "query": {
                            "type": "object",
                            "description": "Query name/value map appended to any URL query; defaults to {}. Values are stringified and URL-encoded; string values may contain placeholders. Arrays are not expanded into repeated parameters.",
                        },
                        "json": {
                            "description": "JSON-serializable request payload. When supplied and non-null, overrides body and sets the exact Content-Type header key to application/json unless already provided. Placeholders are replaced in string values, not object keys.",
                        },
                        "body": {
                            "type": "string",
                            "description": "UTF-8 text request body, optionally containing placeholders; defaults to empty. Ignored when a non-null json payload is supplied.",
                        },
                        "timeout_seconds": {
                            "type": "number",
                            "description": "Connection/socket timeout in seconds, not an overall task deadline. Use a positive number; omission or 0 uses 30 seconds.",
                        },
                        "verify_tls": {
                            "type": "boolean",
                            "description": "Whether to verify HTTPS certificates; defaults to true. False disables verification and weakens protection; leave enabled for normal use. Has no effect on HTTP.",
                        },
                        "ttl": {
                            "type": "string",
                            "description": "Lifetime of temporary vault-alias grants; defaults to 2h. Positive integer plus optional s, m, h, or d (bare number means seconds), at most 24h, e.g. 30m. Grants are revoked after the request; this is not the HTTP timeout.",
                        },
                    },
                    "required": ["url"],
                    "additionalProperties": False,
                },
            },
        ] + mesh_tools()

    def _read_message(self, stream):
        first = stream.readline()
        if not first:
            return None
        first_text = first.decode("utf-8", "replace").strip()
        if not first_text:
            return None
        if not first_text.lower().startswith("content-length:"):
            self._framing = "jsonl"
            return json.loads(first_text)
        self._framing = "headers"
        headers = {}
        key, value = first_text.split(":", 1)
        headers[key.lower()] = value.strip()
        while True:
            line = stream.readline()
            if not line:
                return None
            line = line.decode("utf-8", "replace").strip()
            if not line:
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.lower()] = value.strip()
        length = int(headers.get("content-length", "0") or "0")
        if length <= 0:
            return None
        return json.loads(stream.read(length).decode("utf-8"))

    def _write_message(self, stream, message: Dict[str, Any]) -> None:
        data = json.dumps(message, separators=(",", ":")).encode("utf-8")
        if self._framing == "headers":
            stream.write(("Content-Length: %s\r\n\r\n" % len(data)).encode("ascii") + data)
        else:
            stream.write(data + b"\n")
        stream.flush()

    def _result(self, message_id, result):
        return {"jsonrpc": "2.0", "id": message_id, "result": result}

    def _error(self, message_id, code: int, message: str):
        return {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": message}}


def add_mcp_subparser(subparsers) -> None:
    mcp_parser = subparsers.add_parser("mcp", help="Run AgentSecure MCP tools for secret-safe API calls")
    mcp_subparsers = mcp_parser.add_subparsers(dest="mcp_command")
    serve_parser = mcp_subparsers.add_parser("serve", help="Serve AgentSecure MCP over stdio")
    serve_parser.add_argument("--stdio", action="store_true", default=True, help="Serve MCP over stdio")
    mcp_subparsers.add_parser("status", help="Print MCP server status")
    install_parser = mcp_subparsers.add_parser("install", help="Print MCP client configuration")
    install_parser.add_argument("client", choices=["codex", "claude"], help="MCP client")


def handle_mcp(args: argparse.Namespace) -> int:
    command = getattr(args, "mcp_command", "")
    if command == "serve":
        return McpServer(args.config).serve_stdio()
    if command == "status":
        payload = describe_config(args.config)
        payload["mcp_server"] = "agentsecure mcp serve"
        payload.setdefault("instructions", [])
        payload["instructions"].extend(
            [
                "AgentSecure Mesh tools are available for agent identity, inbox, approvals, and audit.",
                "When the user asks about messages, inbox, approvals, or another agent contacting you, call agentsecure.check_messages before answering.",
                "Use AGENTSECURE_AGENT_ID as this session's Mesh identity when it is set.",
                "If unread messages exist, call agentsecure.list_messages and agentsecure.read_message; do not claim there are no messages until Mesh has been checked.",
                "Messages wake or notify agents; they are not raw pushed prompts. Read content only through AgentSecure tools.",
            ]
        )
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    if command == "install":
        print(mcp_install_instructions(args.client, args.config))
        return 0
    sys.stderr.write("agentsecure: missing mcp subcommand\n")
    return 2


def mcp_command_parts(config_path: str):
    return ["agentsecure", "--config", os.path.abspath(config_path), "mcp", "serve"]


def codex_mcp_add_command(config_path: str) -> str:
    command_parts = mcp_command_parts(config_path)
    return "codex mcp add agentsecure -- %s" % " ".join(shlex.quote(part) for part in command_parts)


def mcp_install_instructions(client: str, config_path: str) -> str:
    if client == "codex":
        return "Run this command to add AgentSecure MCP to Codex:\n%s" % codex_mcp_add_command(config_path)
    command_parts = mcp_command_parts(config_path)
    snippet = {
        "mcpServers": {
            "agentsecure": {
                "command": command_parts[0],
                "args": command_parts[1:],
            }
        }
    }
    return "# Add this MCP server to your Claude MCP configuration:\n%s" % json.dumps(snippet, indent=2, sort_keys=True)
