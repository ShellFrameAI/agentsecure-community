# AgentSecure Community

**By ShellFrame AI**

[![PyPI](https://img.shields.io/pypi/v/agentsecure.svg)](https://pypi.org/project/agentsecure/)
[![CI](https://github.com/ShellFrameAI/agentsecure-community/actions/workflows/ci.yml/badge.svg)](https://github.com/ShellFrameAI/agentsecure-community/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

AgentSecure Community is a local-first CLI for AI coding-agent workflows. It demonstrates a simple idea: the agent can work in a real project, but it should see virtual or masked secrets instead of raw `.env` values.

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

The demo creates a temporary local project with fake secrets, simulates a command reading `.env`, and prints what the agent would see:

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

Create a local config:

```bash
agentsecure init
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

The command output should contain a `virt_...` token instead of the real secret. The real `.env` remains local and unchanged.

## What It Demonstrates

- Discover likely secrets in `.env` files and environment variables.
- Store real values locally under `.agentsecure/`.
- Expose virtual values such as `OPENAI_API_KEY=virt_openai_...`.
- Sanitize common `.env` reads through command-guard mode.
- Remove denied env values from agent-visible output.
- Keep basic network, process, and file policy in JSON.

Command-guard mode is a usability guard, not a hard sandbox. A determined process can bypass wrapper-based masking. Use workspace copy mode, containers, read-only mounts, no-network defaults, or OS sandboxing for stronger isolation.

## Example Policy

See [examples/agentsecure.community.json](examples/agentsecure.community.json) and [examples/.env.example](examples/.env.example).

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
agentsecure status
agentsecure doctor
agentsecure discover
agentsecure suggest
agentsecure env
agentsecure keys list
agentsecure network list
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

## Public Release Boundary

This community release does not include hosted backend integration, enterprise policy sync, billing/licensing, production secrets, internal endpoints, or sensitive commercial heuristics. See [OPEN_SOURCE_PLAN.md](OPEN_SOURCE_PLAN.md) and [OPEN_SOURCE_READINESS_REPORT.md](OPEN_SOURCE_READINESS_REPORT.md) for the public/private boundary.

## Ownership

AgentSecure and ShellFrame AI are ShellFrame AI project names. This community repository is published to demonstrate the local-first secret virtualization model while keeping commercial/backend features private.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
