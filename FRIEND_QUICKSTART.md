# AgentSecure Community Quickstart

The canonical quick start is now the MCP-first flow in the
[main README](README.md#quick-start).

Set up AgentSecure once:

```bash
uv tool install agentsecure
agentsecure start --client claude
# or
agentsecure start --client codex --install-mcp
```

Apply any MCP configuration step printed during setup, then start `claude` or
`codex` normally.

Do not normally wrap the coding agent with `agentsecure run`. Manual secret
commands, workspace mode, provider proxy mode, and the runtime wrapper are
documented under [`docs/`](docs/default-workflow.md).
