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

Preserve all existing CLAUDE.md and AGENTS.md content. After setup, run
agentsecure doctor and report the files changed and any check that still needs
attention. Never print or paste real secret values.
```

## Install the standalone tool

```bash
uv tool install agentsecure
agentsecure --version
```

If the tool is already installed and should be updated, run
`uv tool upgrade agentsecure`.

## Initialize Claude Code

```bash
agentsecure start --client claude
```

The command keeps the existing `AGENTS.md` behavior and also creates or updates
a bounded AgentSecure section in `CLAUDE.md`. Existing project instructions are
preserved. Running the command again updates that section without duplicating
it.

The generated Claude instructions explain how to use protected secrets and tell
each fresh session to verify the setup with:

```bash
agentsecure doctor
```

AgentSecure also prints the Claude MCP configuration for the current project.

## Verify a fresh session

1. Close the Claude Code session that performed setup.
2. Start a new Claude Code session in the same repository.
3. Ask: `Explain how this repository uses AgentSecure and verify its setup.`
4. Confirm Claude reads `CLAUDE.md` and runs `agentsecure doctor`.

Do not consider onboarding complete if the new session needs the original setup
conversation to understand AgentSecure.
