# Implementation Architecture

This page describes the current Community implementation. It is a reference,
not an additional onboarding path.

## Main components

| Area | Path | Responsibility |
| --- | --- | --- |
| CLI | `agentsecure/cli/` | Argument parsing, guided setup, secret commands, scanner, policy, proxy, and runtime orchestration |
| MCP | `agentsecure/mcp/` | Stdio protocol, safe metadata tools, placeholder parsing, and secret-bearing HTTP requests |
| Core | `agentsecure/core/` | Configuration models, aliases, policy mutation, product initialization, backup helpers, and runtime metadata |
| Crypto and stores | `agentsecure/crypto/`, `agentsecure/implementations/` | Local key generation, authenticated encryption, grants, aliases, audit logs, and policy engines |
| Discovery and scanner | `agentsecure/discovery/`, `agentsecure/scanner/` | Dotenv/environment discovery and read-only repository risk inspection |
| Guard and gateway | `agentsecure/guard/`, `agentsecure/gateway/` | Optional command wrappers, output sanitation, destination checks, and provider proxying |
| Workspace | `agentsecure/workspace/` | Sanitized symlink or copy workspaces, diff, and apply |
| Internal services | `agentsecure/api/`, `agentsecure/daemon/` | Internal local service and session implementation not exposed as public daemon/API CLI commands |

## Default request path

1. `agentsecure start` initializes the project, imports accepted dotenv
   secrets, writes agent instructions, and configures MCP.
2. The selected coding agent starts normally and launches
   `agentsecure --config <absolute-path> mcp serve` over stdio.
3. `agentsecure.http.request` collects `${ENV_NAME}` placeholders without
   resolving them.
4. Network policy evaluates the parsed host and port.
5. The MCP runtime creates request-scoped virtual grants for project aliases.
6. The policy-aware resolver verifies project, run, expiry, environment mode,
   and alias-specific host restrictions.
7. The encrypted vault store returns the real value to the AgentSecure process.
8. The HTTP client sends the request and sanitizes the response.
9. Audit metadata is written and request-scoped grants are revoked.

## Storage boundaries

- `agentsecure.json` is project policy and alias metadata.
- `.agentsecure/` is ignored project-local runtime state.
- `~/.agentsecure/vault/` is the reusable user-level alias vault.
- `~/.agentsecure/backups/` contains plaintext dotenv recovery copies.

See [vault and backup behavior](vault-and-backups.md) and
[security model and limitations](security-model.md) for the security
properties of each boundary.
