# Set Up AgentSecure with Claude Code

AgentSecure should be installed with the Python tooling the repository already
uses. Do not replace the project's package manager or create an extra virtual
environment before checking the repository.

## Copy this prompt into Claude Code

```text
Set up AgentSecure in this repository.

First inspect the repository without changing files. Detect the existing Python
tooling from files and available commands, including uv.lock, poetry.lock,
Pipfile, environment.yml, requirements files, pyproject.toml and an active
virtual environment.

Use the existing toolchain. Do not introduce a different package manager and do
not delete or regenerate lock files. Install AgentSecure using the matching
command from the official setup guide. Then run:

agentsecure start --client claude

Preserve all existing CLAUDE.md and AGENTS.md content. After setup, run
agentsecure doctor and report the selected toolchain, files changed, and any
check that still needs attention. Never print or paste real secret values.
```

## Choose the matching installation

### uv

For AgentSecure as an isolated command-line tool:

```bash
uv tool install agentsecure
agentsecure --version
```

If the tool is already installed and should be updated, run
`uv tool upgrade agentsecure`.

If the project intentionally keeps development tools in its lock file:

```bash
uv add --dev agentsecure
uv run agentsecure --version
```

Continue with `uv run agentsecure` instead of `agentsecure` for a
project-managed installation.

### Poetry

```bash
poetry add --group dev agentsecure
poetry run agentsecure --version
```

Continue with `poetry run agentsecure` for the remaining commands.

### Pipenv

```bash
pipenv install --dev agentsecure
pipenv run agentsecure --version
```

Continue with `pipenv run agentsecure` for the remaining commands.

### Existing virtual environment or pip

Activate the project's existing environment first, then run:

```bash
python -m pip install --upgrade agentsecure
python -m agentsecure --version
```

Do not create a second environment when the project already has one.

## Initialize Claude Code

Run the command through the selected toolchain:

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
