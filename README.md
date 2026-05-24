# AgentSecure Community

**By ShellFrame AI**

[![PyPI](https://img.shields.io/pypi/v/agentsecure.svg)](https://pypi.org/project/agentsecure/)
[![CI](https://github.com/ShellFrameAI/agentsecure-community/actions/workflows/ci.yml/badge.svg)](https://github.com/ShellFrameAI/agentsecure-community/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

AI coding agents run where developer secrets already live: `.env` files, shell environments, MCP configs, local credentials, and project settings. GitGuardian's 2026 State of Secrets Sprawl report found [28.65 million new hardcoded secrets in public GitHub commits in 2025](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/) and [24,008 unique secrets in MCP-related configuration files, including 2,117 valid credentials](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/). Reported testing has also shown agent tools reading `.env` files despite ignore-file expectations; [The Register reproduced Claude Code reading `.env` with `.claudeignore` and `.gitignore` entries present](https://www.theregister.com/2026/01/28/claude_code_ai_secrets_files/), while [Anthropic's current docs recommend explicit file-access deny rules for sensitive files](https://code.claude.com/docs/en/configuration).

AgentSecure Community is a local-first CLI for AI coding-agent workflows. It demonstrates a simple idea: ignore files are not a secret boundary, so the agent should see virtual or masked secrets instead of raw `.env` values.

The community release is intentionally scoped to local CLI, local command guard, basic policy config, local secret virtualization, and tests. Hosted cloud sync, enterprise policy management, billing/licensing, and sensitive commercial detection logic are not part of this release.

## Install

```bash
python3 -m pip install agentsecure
agentsecure demo
```

Use a virtual environment if you want to keep it isolated:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install agentsecure
agentsecure demo
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

Create a fake `.env` for testing:

```bash
cat > .env <<'EOF'
OPENAI_API_KEY=sk-demo-local-secret-do-not-use
DATABASE_URL_PROD=postgres://demo:demo-password@example.invalid/app
EOF
```

Discover likely secrets:

```bash
agentsecure discover
```

Run a command through the local guard:

```bash
agentsecure run --protect-all -- python3 -c 'import subprocess; print(subprocess.check_output(["cat", ".env"]).decode())'
```

By default, `--protect-all` virtualizes discovered secrets. The command output should contain `virt_...` tokens instead of the real values. The real `.env` remains local and unchanged.

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
- Store real values locally under `.agentsecure/`.
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
agentsecure keys list
agentsecure network list
agentsecure proxy setup openai
agentsecure proxy doctor
agentsecure receipts --proxy
```

Run an agent or command through local command guard:

```bash
agentsecure run --protect-all -- codex
agentsecure run --protect-all -- claude
agentsecure run --protect-all -- python3 -c 'import subprocess; print(subprocess.check_output(["cat", ".env"]).decode())'
```

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
