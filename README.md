# AgentSecure Community

**By ShellFrame AI**

[![PyPI](https://img.shields.io/pypi/v/agentsecure.svg)](https://pypi.org/project/agentsecure/)
[![CI](https://github.com/ShellFrameAI/agentsecure-community/actions/workflows/ci.yml/badge.svg)](https://github.com/ShellFrameAI/agentsecure-community/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

AgentSecure lets AI coding agents use credentials without exposing the real
secret values to the agent.

## Why AgentSecure

AI coding agents can access `.env` files, shell environments, MCP
configuration, and local credentials. Ignore files are not a security boundary.
AgentSecure keeps real secrets outside the agent's normal project and MCP
context.

## Quick Start

Run these commands from the project you want to protect.

### 1. Install AgentSecure

```bash
uv tool install agentsecure
```

### 2. Optionally scan the project

```bash
agentsecure scan .
```

The scan is local and does not change the project.

### 3. Run guided setup once

For Claude Code:

```bash
agentsecure start --client claude
```

Follow the printed MCP configuration step, then start Claude Code normally:

```bash
claude
```

For Codex:

```bash
agentsecure start --client codex --install-mcp
```

Then start Codex normally:

```bash
codex
```

`agentsecure start` is guided one-time project setup. It initializes the
project, offers to move `.env` secrets into the local vault, writes persistent
agent guidance, and prints or installs the selected MCP configuration.

It is not a persistent background service. After setup finishes, start Claude
Code or Codex normally. You do not normally wrap the agent with
`agentsecure run`.

## How It Works

1. During setup, real secrets are moved into the local AgentSecure vault.
2. Project files receive aliases or safe placeholders instead of real values.
3. The coding agent starts and runs normally.
4. Secret-bearing requests use the AgentSecure MCP tool.
5. AgentSecure validates the destination and injects the real secret while
   sending the request outside the agent's context.

## Security Boundaries

AgentSecure helps protect against:

- exposing raw secrets to the coding agent through the default MCP flow;
- keeping real secrets in agent-readable project files;
- sending protected secrets to destinations that are not approved by policy.

AgentSecure is not:

- a complete operating-system sandbox;
- a VM or container;
- protection from an attacker who already controls the local user or machine;
- a replacement for endpoint, identity, network, or cloud security controls.

The local user and machine remain inside the trust boundary. See the
[security model and limitations](docs/security-model.md) for the full threat
model.

## Documentation

- [Default workflow](docs/default-workflow.md)
- [Claude Code setup](docs/claude-code-setup.md)
- [Codex setup](docs/codex-setup.md)
- [Secret management](docs/secret-management.md)
- [MCP usage](docs/mcp.md)
- [Network policy](docs/network-policy.md)
- [Security model and limitations](docs/security-model.md)
- [Vault and backup behavior](docs/vault-and-backups.md)
- [Scanner reference](docs/scanner.md)
- [Advanced runtime mode](docs/advanced-runtime.md)
- [CLI reference](docs/cli-reference.md)
- [Implementation architecture](docs/architecture.md)
- [Uninstall and restore](docs/uninstall-and-restore.md)

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
