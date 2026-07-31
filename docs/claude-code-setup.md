# Set Up AgentSecure with Claude Code

Install AgentSecure as an isolated command-line tool. It should not be added to
the repository's application dependencies or lock files.

## Copy this prompt into Claude Code

```text
Set up AgentSecure in this repository.

First inspect the repository without changing files. Check whether the
`agentsecure` command is already available. If it is not, install AgentSecure as
an isolated command-line tool with `uv tool install agentsecure`. Do not add it
to the project's dependencies and do not modify package or lock files. Then run:

agentsecure start --client claude

Preserve all existing CLAUDE.md and AGENTS.md content. Apply the Claude MCP
configuration printed by AgentSecure. After setup, run agentsecure doctor and
report the files changed and any check that still needs attention. Never print
or paste real secret values.
```

## Install the standalone tool

```bash
uv tool install agentsecure
agentsecure --version
```

If the tool is already installed and should be updated, run:

```bash
uv tool upgrade agentsecure
```

## Run guided setup

```bash
agentsecure start --client claude
```

The command:

- offers to import `.env` secrets into the local vault;
- creates or updates bounded AgentSecure sections in `AGENTS.md` and
  `CLAUDE.md` while preserving existing content;
- prints an `mcpServers` JSON entry bound to the absolute path of this
  project's `agentsecure.json`;
- exits after setup.

Add the printed MCP entry to Claude Code's MCP configuration before starting a
fresh session. The current implementation prints this configuration; it does
not install it automatically for Claude Code.

## Start Claude Code normally

```bash
claude
```

Do not normally use `agentsecure run -- claude`. Secret-bearing requests should
use the AgentSecure MCP tool while Claude Code otherwise runs normally.

## Verify a fresh session

1. Close any Claude Code session that performed setup.
2. Start a new Claude Code session in the same repository.
3. Ask: `Explain how this repository uses AgentSecure and verify its setup.`
4. Confirm Claude reads `CLAUDE.md`, runs `agentsecure doctor`, and can see the
   AgentSecure MCP tools.

Do not consider onboarding complete if the new session needs the original setup
conversation to understand AgentSecure.

See [MCP usage](mcp.md) for the manual configuration format and
[secret management](secret-management.md) for import and restore options.
