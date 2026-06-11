# AgentSecure Community

**By ShellFrame AI**

[![PyPI](https://img.shields.io/pypi/v/agentsecure.svg)](https://pypi.org/project/agentsecure/)
[![CI](https://github.com/ShellFrameAI/agentsecure-community/actions/workflows/ci.yml/badge.svg)](https://github.com/ShellFrameAI/agentsecure-community/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

AI coding agents run where developer secrets already live: `.env` files, shell environments, MCP configs, local credentials, and project settings. GitGuardian's 2026 State of Secrets Sprawl report found [28.65 million new hardcoded secrets in public GitHub commits in 2025](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/) and [24,008 unique secrets in MCP-related configuration files, including 2,117 valid credentials](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/). Reported testing has also shown agent tools reading `.env` files despite ignore-file expectations; [The Register reproduced Claude Code reading `.env` with `.claudeignore` and `.gitignore` entries present](https://www.theregister.com/2026/01/28/claude_code_ai_secrets_files/), while [Anthropic's current docs recommend explicit file-access deny rules for sensitive files](https://code.claude.com/docs/en/configuration).

AgentSecure Community is a local-first CLI for AI coding-agent workflows. It demonstrates a simple idea: ignore files are not a secret boundary, so real secrets should live in AgentSecure's local vault, projects should reference aliases, and the agent should receive temporary virtual tokens instead of raw `.env` values.

The community release is intentionally scoped to local CLI, local command guard, basic policy config, local secret virtualization, and tests. Hosted cloud sync, enterprise policy management, billing/licensing, and sensitive commercial detection logic are not part of this release.

## Install

```bash
python3 -m pip install --upgrade agentsecure
python3 -m agentsecure demo
```

`python3 -m agentsecure` works even when `pip` installs the `agentsecure`
executable into a user script directory that is not on your `PATH`. If you want
the shorter `agentsecure` command, add Python's user script directory to your
shell path:

```bash
export PATH="$(python3 -m site --user-base)/bin:$PATH"
agentsecure demo
```

You do not need a virtual environment to run AgentSecure. Use one only if you
want the install isolated to this project:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install agentsecure
agentsecure demo
```

For the easiest secret-safe API calls, add the AgentSecure MCP server to your agent client and run the agent normally:

```bash
agentsecure start
```

The guided start command initializes the project, offers to import `.env` secrets into the local vault, writes AgentSecure instructions into `AGENTS.md`, prints the MCP setup command, and ends with a ready summary.

Manual setup is still available:

```bash
agentsecure mcp install codex
agentsecure mcp install claude
```

Those commands print the local MCP setup for this project. For Codex, AgentSecure prints a `codex mcp add ...` command. The MCP server exposes safe tools that can describe policy and send approved credentialed HTTP requests without showing the agent real secret values.

## Where Secrets Go

Keep real secrets in one local AgentSecure vault:

```bash
agentsecure secrets import .env
agentsecure mcp status
```

Or use the guided setup:

```bash
agentsecure start --approved-host https://api.example.com
```

`secrets import` is the easiest migration path. It scans the dotenv file, stores discovered real secret values in the local vault, assigns those aliases to the current project, writes a private backup under `~/.agentsecure/backups/`, and replaces the values in `.env` with non-secret `AGENTSECURE_ALIAS_...` placeholders.

Use `--dry-run` to preview the import, or `--keep-file` if you want to store aliases without rewriting `.env`.

To undo the rewrite and bring the original `.env` back from the latest private backup:

```bash
agentsecure secrets restore .env
```

During uninstall, AgentSecure offers the same restore before it removes project state:

```bash
agentsecure uninstall
```

For non-interactive uninstall, restoring real secrets to the project file stays explicit:

```bash
agentsecure uninstall --yes --restore-dotenv
```

For manual control, add one alias at a time:

```bash
printf '%s' "$DATABASE_URL" | agentsecure secrets add dev_db \
  --env-name DATABASE_URL \
  --provider database \
  --approved-host db.example.com \
  --real-secret-stdin

agentsecure secrets use dev_db
agentsecure run -- claude
```

What this does:

- The real value is stored locally under `~/.agentsecure/vault/`.
- `agentsecure.json` stores only alias metadata such as `dev_db`, `DATABASE_URL`, provider, and approved hosts.
- For MCP calls, AgentSecure creates a short-lived fake token such as `virt_database_...`.
- The MCP request tool swaps placeholders for real secrets only when the destination host and port are allowed by network policy.
- The fake token is revoked after the MCP request.

Do not put real secrets in project `.env` files. Use `.env` for non-secret config or fake placeholders that are safe for an agent to read.

Approve a destination with its URL when the port is not 80 or 443:

```bash
agentsecure network allow https://api.example.com:8443/v1/test
```

This adds `api.example.com` to `network.allow_domains` and `8443` to `network.allow_ports`.

## MCP Agent Guidance

AgentSecure Community is MCP-first for developer ergonomics: let the coding agent edit files, install packages, run tests, and use normal tools directly. Use AgentSecure only when a request needs a protected secret.

After importing or adding secrets, attach the MCP server printed by:

```bash
agentsecure mcp install codex
```

`agentsecure start` also creates or updates `AGENTS.md` with bounded AgentSecure guidance. The generated section tells the agent to use `agentsecure.http.request` for secret-bearing API calls, pass placeholders such as `${API_KEY}` and `${API_SECRET}`, and never source `.env` or send `AGENTSECURE_ALIAS_*` / `virt_*` values to APIs.

For a secret-bearing API request, tell the agent to use AgentSecure MCP:

```text
Use AgentSecure MCP agentsecure.http.request to GET https://api.example.com/v1/whoami.
Send Authorization: Bearer ${API_KEY}.
```

Codex users should run the printed command, which looks like:

```bash
codex mcp add agentsecure -- agentsecure --config /path/to/agentsecure.json mcp serve
```

Then tell the agent:

```text
For API calls that need secrets, use the AgentSecure MCP tool `agentsecure.http.request`.
Use placeholders such as ${API_KEY} and ${API_SECRET}; never ask me to paste real secrets and never read .env for secrets.
If AgentSecure blocks the destination, show me the suggested `agentsecure network allow ...` command.
```

Example MCP tool arguments:

```json
{
  "method": "GET",
  "url": "https://api.example.com/v1/whoami",
  "headers": {
    "Authorization": "Bearer ${API_KEY}",
    "X-Api-Secret": "${API_SECRET}"
  }
}
```

What happens:

- The agent sees only placeholder names such as `API_KEY`.
- AgentSecure checks `agentsecure.json` network policy before resolving anything.
- AgentSecure sends the request itself with real secrets only to approved destinations.
- The response is sanitized before it is returned to the agent.
- Local audit logs record the destination, placeholders, policy decision, and status without raw secret values.

For non-secret requests, the agent should use normal `curl`, SDKs, tests, or application code. The MCP tool intentionally blocks calls that do not contain `${ENV_NAME}` placeholders so AgentSecure does not become a general network proxy.

## Optional Agent Run Guidance

`agentsecure run` is still available when you want command wrappers, output masking, or safe workspaces around a whole local process:

```bash
agentsecure run -- claude
```

Every `agentsecure run` creates a small per-run guide under `.agentsecure/runs/` and prints its relative path:

```text
AgentSecure agent guide: .agentsecure/runs/run_.../AGENTSECURE_AGENT_GUIDE.md
```

The launched agent receives the absolute guide path in both `AGENTSECURE_AGENT_GUIDE` and `AGENTSECURE_SKILL_FILE`. The file contains only operational guidance and safe metadata, such as managed secret environment variable names, providers, and approved hosts from runtime alias bindings when available. It does not include raw secrets or virtual token values.

Agents should use the injected environment variables and virtual tokens. They should not read `.env` to recover secrets or ask a human to paste secrets. If an expected secret env var is missing, ask the user to run:

```bash
agentsecure secrets import .env
agentsecure secrets use <alias>
```

## What The Demo Shows

The built-in demo creates a temporary local project with fake secrets, applies a small sample policy, simulates a command reading `.env`, and prints what the agent would see:

```text
AgentSecure community demo (local only)
Command: cat .env
Decision: mask OPENAI_API_KEY and block DATABASE_URL_PROD

Agent-visible output:
OPENAI_API_KEY=virt_openai_...

Why:
  OPENAI_API_KEY was replaced with virt_openai_...
  DATABASE_URL_PROD was removed because env_policy sets mode=deny
  Real secret values stayed local in the demo project
  No cloud service, billing service, or enterprise policy sync was used
```

## Quickstart In A Project

Create a local config and repo guidance file:

```bash
agentsecure init
```

This creates `agentsecure.json`, local private state under `.agentsecure/`, and `AGENTSECURE.md`. Review the Markdown file before running agents:

```bash
agentsecure policy validate
```

Create a fake `.env` for testing. This file must not contain real credentials:

```bash
cat > .env <<'EOF'
OPENAI_API_KEY=fake-openai-key-for-demo-only
DATABASE_URL_PROD=postgres://fake:fake-password@example.invalid/app
EOF
```

Discover likely secrets:

```bash
agentsecure discover
```

For real credentials, use the vault/alias flow:

```bash
printf '%s' "$OPENAI_API_KEY" | agentsecure secrets add openai_dev \
  --env-name OPENAI_API_KEY \
  --provider openai \
  --approved-host api.openai.com \
  --real-secret-stdin

agentsecure secrets use openai_dev
```

Run a command through the local guard:

```bash
agentsecure run --protect-all -- python3 -c 'import subprocess; print(subprocess.check_output(["cat", ".env"]).decode())'
```

By default, `--protect-all` virtualizes discovered values. Prefer the `agentsecure secrets add/use` flow above for real secrets because it keeps real values out of project files entirely. The command output should contain `virt_...` tokens instead of real values. The real `.env`, if you still have one, remains local and unchanged.

Denied values are removed only when policy sets `mode: "deny"` for that environment variable. The built-in `agentsecure demo` includes that policy for `DATABASE_URL_PROD` so you can see both behaviors: virtualize and deny.

## Provider Proxy Preview

Virtual secrets keep real values out of the agent context. Provider proxy mode goes one step further for tools and SDKs that honor `OPENAI_BASE_URL`: the agent gets a virtual key and a local base URL, while AgentSecure injects the real key only when forwarding to the configured provider.

Configure OpenAI from `agentsecure.json.provider_catalog.openai`:

```bash
agentsecure proxy setup openai
```

Then run the agent:

```bash
agentsecure run --protect-all -- codex
```

The agent-visible environment includes:

```text
OPENAI_API_KEY=virt_openai_...
OPENAI_BASE_URL=http://127.0.0.1:8765/providers/openai/v1
```

AgentSecure forwards provider calls to the configured upstream:

```json
{
  "provider_proxy": {
    "providers": {
      "openai": {
        "upstream": "https://api.openai.com",
        "local_path": "/providers/openai"
      }
    }
  }
}
```

Run the proxy proof:

```bash
agentsecure receipts --proxy
```

Provider proxy mode is local-only. It is not a system-wide proxy, not TLS MITM, and not browser-wide interception. Tools must use the provider base URL environment variable.

## What It Demonstrates

- Discover likely secrets in `.env` files and environment variables.
- Store reusable real secrets locally under `~/.agentsecure/vault/`.
- Store project assignments as alias metadata in `agentsecure.json`.
- Expose virtual values such as `OPENAI_API_KEY=virt_openai_...`.
- Sanitize common `.env` reads through command-guard mode.
- Remove denied env values from agent-visible output.
- Keep basic network, process, and file policy in JSON.

Command-guard mode is a usability guard, not a hard sandbox. A determined process can bypass wrapper-based masking. Use workspace copy mode, containers, read-only mounts, no-network defaults, or OS sandboxing for stronger isolation.

## Example Policy

See [examples/agentsecure.community.json](examples/agentsecure.community.json), [examples/AGENTSECURE.md](examples/AGENTSECURE.md), and [examples/.env.example](examples/.env.example).

Minimal policy shape:

```json
{
  "secret_aliases": [
    {
      "alias_id": "openai_dev",
      "env_name": "OPENAI_API_KEY",
      "provider": "openai",
      "approved_hosts": ["api.openai.com"],
      "mode": "virtualize"
    }
  ],
  "env_policy": {
    "OPENAI_API_KEY": {
      "mode": "virtualize",
      "reason": "Agents see a virtual token, not the local real value."
    },
    "DATABASE_URL_PROD": {
      "mode": "deny",
      "reason": "Production database credentials are never exposed."
    }
  },
  "network": {
    "allow_domains": ["api.openai.com"],
    "allow_ports": [80, 443],
    "deny_ip_literals": true,
    "deny_private_networks": true
  }
}
```

## Common Commands

```bash
agentsecure init
agentsecure policy validate
agentsecure status
agentsecure doctor
agentsecure discover
agentsecure suggest
agentsecure env
agentsecure secrets add dev_db --env-name DATABASE_URL --provider database --approved-host db.example.com --real-secret-stdin
agentsecure secrets use dev_db
agentsecure secrets list
agentsecure keys list
agentsecure network list
agentsecure proxy setup openai
agentsecure proxy doctor
agentsecure receipts --proxy
```

Run an agent or command through local command guard:

```bash
python3 -m agentsecure run --protect-all -- codex
python3 -m agentsecure run --protect-all -- claude
python3 -m agentsecure run --protect-all -- python3 -c 'import subprocess; print(subprocess.check_output(["cat", ".env"]).decode())'
```

Bare interactive agent launches keep the terminal attached so tools such as
Claude Code can open normally. Non-interactive commands are still output
sanitized by AgentSecure.

Use workspace copy mode when you want review-before-apply:

```bash
agentsecure run --runtime workspace --workspace-mode copy --protect-all --workspace-keep -- codex
agentsecure diff
agentsecure apply --dry-run
agentsecure apply
```

## Developer Setup

```bash
git clone https://github.com/ShellFrameAI/agentsecure-community.git
cd agentsecure-community
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
agentsecure demo
```

## Screenshots / GIFs

Planned public demo assets:

- `docs/assets/demo-command-guard.gif`: `agentsecure demo` showing a virtual key.
- `docs/assets/dotenv-masking.png`: before/after `.env` masking.
- `docs/assets/workspace-diff.png`: review-before-apply workflow.

## Repository Layout

```text
agentsecure/
  cli/                 CLI entry point
  core/                models, config loading, policy helpers
  mcp/                 MCP tools for approved secret-bearing HTTP calls
  guard/               local command guard and output sanitizer
  discovery/           local secret discovery
  implementations/     local secret, grant, policy, and audit storage
  workspace/           safe workspace materialization and apply flow
examples/              community-safe config and fake .env examples
scripts/               release and safety scripts
tests/                 unit and local integration tests
```

## Testing

```bash
source .venv/bin/activate
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/secret_scan.py .
```

CI runs tests across supported Python versions and runs the local secret scan.

## AGENTSECURE.md

`AGENTSECURE.md` is a small repo-level policy guidance file for humans and AI coding agents. In the community release, AgentSecure creates it and validates that it does not contain raw secrets or unsupported raw-secret passthrough modes.

Supported community secret modes in the Markdown guidance are `virtualize` and `deny`. Do not use `allow` or `allow_real` for secrets. The Markdown file is guidance plus local validation; it is not a full sandbox by itself.

## Public Release Boundary

This community release does not include hosted backend integration, enterprise policy sync, billing/licensing, production secrets, internal endpoints, or sensitive commercial heuristics. See [OPEN_SOURCE_PLAN.md](OPEN_SOURCE_PLAN.md) and [OPEN_SOURCE_READINESS_REPORT.md](OPEN_SOURCE_READINESS_REPORT.md) for the public/private boundary.

## Ownership

AgentSecure and ShellFrame AI are ShellFrame AI project names. This community repository is published to demonstrate the local-first secret virtualization model while keeping commercial/backend features private.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
