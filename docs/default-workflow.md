# Default MCP-First Workflow

AgentSecure is designed to be set up once per project. After setup, start the
coding agent normally and use AgentSecure MCP only for requests that need a
protected secret.

## Install

Install AgentSecure as an isolated tool so it does not change the project's
dependencies or lock files:

```bash
uv tool install agentsecure
```

An optional local scan can show files and configuration an agent may be able to
access:

```bash
agentsecure scan .
```

## Set up Claude Code

```bash
agentsecure start --client claude
```

Apply the MCP configuration printed by the command. Then start Claude Code
normally:

```bash
claude
```

See [Claude Code setup](claude-code-setup.md) for the generated files and
verification steps.

## Set up Codex

```bash
agentsecure start --client codex --install-mcp
```

Then start Codex normally:

```bash
codex
```

See [Codex setup](codex-setup.md) for manual MCP installation and verification.

## What guided setup does

`agentsecure start`:

1. creates `agentsecure.json` and private `.agentsecure/` project state when
   needed;
2. offers to import secrets from `.env` into the user-level local vault;
3. backs up and rewrites `.env` with safe aliases when the import is accepted;
4. adds approved destinations supplied during setup;
5. creates or updates a bounded AgentSecure section in `AGENTS.md` and, for
   Claude, `CLAUDE.md`;
6. prints the MCP configuration and can install it for Codex.

The command exits after setup. It is not a daemon or persistent background
service. It is safe to rerun when the setup needs to be refreshed; the managed
instruction sections are updated without duplication.

## Normal use

Use ordinary agent tools for file edits, tests, and requests that do not need a
protected secret. For a secret-bearing HTTP request, the agent uses
`agentsecure.http.request` with placeholders such as `${API_KEY}`. AgentSecure
checks policy, resolves the placeholder locally, sends the request, and
sanitizes the response.

Do not normally launch Claude Code or Codex with `agentsecure run`. That wrapper
is an [advanced runtime mode](advanced-runtime.md) for compatibility and
additional process-level controls.
