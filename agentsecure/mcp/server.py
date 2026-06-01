import argparse
import json
import os
import shlex
import sys
from typing import Any, Dict

from agentsecure import __version__
from agentsecure.mcp.http_request import McpHttpError, perform_http_request
from agentsecure.mcp.runtime import DurationError, SecretAliasError, describe_config, safe_secret_status


class McpServer:
    def __init__(self, config_path: str) -> None:
        self.config_path = os.path.abspath(config_path)

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
                "description": "Describe AgentSecure project policy and secret aliases without exposing secret values.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "agentsecure.secret.status",
                "description": "Check whether a placeholder env name is configured without returning the secret value.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"env_name": {"type": "string"}},
                    "required": ["env_name"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "agentsecure.http.request",
                "description": "Send one HTTP(S) request with ${ENV_NAME} placeholders resolved only for approved destinations.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "method": {"type": "string"},
                        "url": {"type": "string"},
                        "headers": {"type": "object"},
                        "query": {"type": "object"},
                        "json": {},
                        "body": {"type": "string"},
                        "timeout_seconds": {"type": "number"},
                        "verify_tls": {"type": "boolean"},
                        "ttl": {"type": "string"},
                    },
                    "required": ["url"],
                    "additionalProperties": False,
                },
            },
        ]

    def _read_message(self, stream):
        headers = {}
        while True:
            line = stream.readline()
            if not line:
                return None
            line = line.decode("ascii", "replace").strip()
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
        stream.write(("Content-Length: %s\r\n\r\n" % len(data)).encode("ascii") + data)
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
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    if command == "install":
        config_path = os.path.abspath(args.config)
        command_parts = ["agentsecure", "--config", config_path, "mcp", "serve"]
        if args.client == "codex":
            print("Run this command to add AgentSecure MCP to Codex:")
            print("codex mcp add agentsecure -- %s" % " ".join(shlex.quote(part) for part in command_parts))
            return 0
        snippet = {
            "mcpServers": {
                "agentsecure": {
                    "command": command_parts[0],
                    "args": command_parts[1:],
                }
            }
        }
        print("# Add this MCP server to your Claude MCP configuration:")
        print(json.dumps(snippet, indent=2, sort_keys=True))
        return 0
    sys.stderr.write("agentsecure: missing mcp subcommand\n")
    return 2
