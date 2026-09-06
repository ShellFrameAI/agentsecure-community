# MCP Usage

AgentSecure MCP is the default boundary for secret-bearing HTTP requests. The
coding agent runs normally and calls AgentSecure only when a request needs a
configured secret.

## Install the MCP server

Guided setup prints the required configuration:

```bash
agentsecure start --client claude
agentsecure start --client codex --install-mcp
```

For manual setup, print a client-specific configuration:

```bash
agentsecure mcp install claude
agentsecure mcp install codex
```

For Codex, the printed command has this form:

```bash
codex mcp add agentsecure -- agentsecure --config /absolute/path/to/agentsecure.json mcp serve
```

For Claude Code, AgentSecure prints an `mcpServers` JSON entry whose command is
`agentsecure` and whose arguments include the absolute project configuration
path and `mcp serve`.

The MCP server uses stdio:

```bash
agentsecure --config /absolute/path/to/agentsecure.json mcp serve
```

## Primary tools

### `agentsecure.policy.describe`

Returns network policy, assigned aliases, and safe usage instructions without
returning raw secret values.

### `agentsecure.secret.status`

Checks whether an environment placeholder is configured. It returns safe
metadata, not the backing value.

### `agentsecure.http.request`

Sends one HTTP or HTTPS request containing at least one `${ENV_NAME}`
placeholder. Placeholders may appear in the URL path, headers, query, JSON, or
body. They are rejected in the URL host or port.

Example arguments:

```json
{
  "method": "GET",
  "url": "https://api.example.com/v1/whoami",
  "headers": {
    "Authorization": "Bearer ${API_KEY}"
  }
}
```

The tool:

1. requires at least one secret placeholder;
2. parses the destination and evaluates its host and port before resolving a
   secret;
3. creates short-lived virtual bindings for the request;
4. resolves only aliases assigned to the project and approved for that host;
5. sends the request from the AgentSecure MCP process;
6. sanitizes response headers (names and values), reason, and body before returning them;
7. revokes the temporary bindings when the request ends.

If policy blocks the destination, the result includes a suggested
`agentsecure network allow ...` command. Requests without secret placeholders
are intentionally blocked; use normal agent networking tools for those.

Transport and unexpected runtime errors use fixed diagnostic messages instead
of raw exception text, because exceptions can include substituted credentials.
Malformed request values return `mcp.invalid_request`; connection and HTTP
transport failures return `mcp.request_failed`. Missing-secret and destination
policy errors retain their safe guidance. Ordinary upstream HTTP statuses,
including 4xx and 5xx responses, are still returned as HTTP responses.

## Status and diagnostics

```bash
agentsecure mcp status
agentsecure doctor
```

`mcp status` describes configuration and aliases without exposing secret
values. `doctor` checks local project setup; it does not prove that a specific
client has loaded the MCP configuration.

## Important limits

- The MCP request tool supports HTTP and HTTPS requests, not arbitrary
  protocols.
- Network policy protects AgentSecure-managed credential injection. It does not
  restrict all ordinary network access by an agent running normally.
- Response sanitation removes configured and resolved secret strings, but it
  is not a general data-loss-prevention engine.
- TLS verification is enabled by default. Disabling it with MCP request
  arguments weakens destination assurance.

See [network policy](network-policy.md) and
[security model and limitations](security-model.md).
