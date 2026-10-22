# AgentSecure Community

**By ShellFrame AI**

[![PyPI](https://img.shields.io/pypi/v/agentsecure.svg)](https://pypi.org/project/agentsecure/)
[![CI](https://github.com/ShellFrameAI/agentsecure-community/actions/workflows/ci.yml/badge.svg)](https://github.com/ShellFrameAI/agentsecure-community/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/ShellFrameAI/agentsecure-community/blob/main/LICENSE)

Make credential-bearing HTTP(S) requests from Claude Code and Codex through
MCP, using placeholders instead of raw credentials in project files and MCP
responses.

AgentSecure imports dotenv secrets into a local vault, checks destinations,
and injects credentials when sending approved requests. It is not an OS sandbox
or a system-wide firewall: the local user and machine remain trusted.

## Try it with a fake credential first

No API account, real credentials, or coding-agent installation is needed for
this local MCP demo. With Python 3.8+ installed:

```bash
git clone https://github.com/ShellFrameAI/agentsecure-community.git
cd agentsecure-community
python3 examples/mcp_fake_secret_demo.py
```

The demo creates a temporary project and vault, imports a fake credential,
and calls a loopback HTTP fixture through the actual MCP stdio server. It
checks the result before printing:

```text
Project file: DEMO_API_KEY=AGENTSECURE_ALIAS_DEMO_API_KEY
Approved fixture: received the fake credential
MCP response: Bearer [redacted]
Unapproved destination: blocked
Demo passed; temporary project and vault removed.
```

Only the temporary fixture policy permits loopback traffic. The demo does not
change your project, client configuration, or normal vault, and does not contact
an external API. This demonstrates the managed MCP flow, not isolation from an
unrestricted process running as your local user.

`AGENTSECURE_ALIAS_*` values are non-secret project-file placeholders;
`${DEMO_API_KEY}` is the placeholder used in an MCP request. Neither is a real
provider credential. Internal `virt_*` bindings are separate from these aliases.

## Why AgentSecure

AI coding agents can access `.env` files, shell environments, MCP
configuration, and local credentials. Ignore files are not a security boundary.
AgentSecure keeps real secrets outside the agent's normal project and MCP
context.

## Quick Start

After trying the demo, run these commands from the project you want to configure.
You need Python 3.8+, [uv](https://docs.astral.sh/uv/getting-started/installation/),
and your chosen coding-agent CLI. Use least-privilege development credentials.
Before importing, review the
[vault and backup behavior](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/vault-and-backups.md):
dotenv backups are plaintext, with owner-only permissions, under your home directory.

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

### 4. Verify a fresh agent session

Restart the coding agent after applying the MCP configuration. Ask it to inspect
the AgentSecure setup and call `agentsecure.policy.describe` and
`agentsecure.secret.status` without printing secret values. Confirm it sees the
AgentSecure MCP tools. `agentsecure doctor` checks local setup, but does not
prove that the client loaded MCP. Claude setup prints a configuration step;
Codex setup above requests automatic MCP installation.

For a credential-bearing request, use `agentsecure.http.request` with a
`${ENV_NAME}` placeholder and an approved destination. Ordinary requests without
secret placeholders should use the agent's normal networking tools. See the
[MCP usage guide](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/mcp.md).

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
[security model and limitations](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/security-model.md) for the full threat
model.

## Documentation

- [Default workflow](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/default-workflow.md)
- [Claude Code setup](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/claude-code-setup.md)
- [Codex setup](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/codex-setup.md)
- [Secret management](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/secret-management.md)
- [MCP usage](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/mcp.md)
- [Network policy](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/network-policy.md)
- [Security model and limitations](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/security-model.md)
- [Vault and backup behavior](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/vault-and-backups.md)
- [Scanner reference](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/scanner.md)
- [Advanced runtime mode](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/advanced-runtime.md)
- [CLI reference](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/cli-reference.md)
- [Implementation architecture](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/architecture.md)
- [Uninstall and restore](https://github.com/ShellFrameAI/agentsecure-community/blob/main/docs/uninstall-and-restore.md)

## License

Licensed under the Apache License 2.0. See [LICENSE](https://github.com/ShellFrameAI/agentsecure-community/blob/main/LICENSE).
