# Set Up AgentSecure with Codex

## Install the standalone tool

```bash
uv tool install agentsecure
agentsecure --version
```

Run the command from the project you want to protect:

```bash
agentsecure start --client codex --install-mcp
```

The setup creates or updates `AGENTS.md`, offers to import `.env` secrets, and
runs a project-specific command equivalent to:

```bash
codex mcp add agentsecure -- agentsecure --config /absolute/path/to/agentsecure.json mcp serve
```

The absolute configuration path keeps the MCP server bound to the intended
project.

## If automatic MCP installation fails

Print the command without executing it:

```bash
agentsecure mcp install codex
```

Run the printed `codex mcp add` command, then start Codex normally:

```bash
codex
```

## Verify the setup

In a fresh Codex session, ask it to explain how the repository uses
AgentSecure. It should read `AGENTS.md` and use AgentSecure MCP for
secret-bearing HTTP requests.

You can also verify the local project state:

```bash
agentsecure doctor
agentsecure mcp status
```

The default workflow does not use `agentsecure run -- codex`. See
[MCP usage](mcp.md) and [advanced runtime mode](advanced-runtime.md).
