# AgentSecure Community

AgentSecure Community is a local-first demo runtime for AI coding agents. It shows how an agent can work in a real project while seeing virtual secrets instead of raw `.env` values.

This repository is the community/lite release. It is intentionally scoped to local CLI, local command guard, basic policy config, local secret virtualization, and tests. Hosted cloud sync, enterprise policy management, billing/licensing, and sensitive commercial detection logic are not part of this release.

## What It Demonstrates

- Discover likely secrets in `.env` files and environment variables.
- Store real values locally under `.agentsecure/`.
- Expose virtual values such as `OPENAI_API_KEY=virt_openai_...`.
- Sanitize common `.env` reads through command-guard mode.
- Remove denied env values from agent-visible output.
- Keep basic network, process, and file policy in JSON.

Command-guard mode is a usability guard, not a hard sandbox. A determined process can bypass wrapper-based masking. Use workspace copy mode or OS sandboxing for stronger isolation.

## Install

```bash
python3 -m pip install -e .
```

## Quickstart

Run the safe local demo:

```bash
agentsecure demo
```

Expected output includes a virtual OpenAI key and an explanation that `DATABASE_URL_PROD` was removed by policy:

```text
Agent-visible output:
OPENAI_API_KEY=virt_openai_...
```

Try it in a project:

```bash
agentsecure init
printf 'OPENAI_API_KEY=sk-demo-local-secret-do-not-use\n' > .env
agentsecure run --protect-all -- python3 -c 'import subprocess; print(subprocess.check_output(["cat", ".env"]).decode())'
```

The agent-visible output contains a `virt_...` token. The real `.env` remains local and unchanged.

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

## Screenshots / GIFs

Placeholders for the public release:

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
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/secret_scan.py .
```

CI runs tests across supported Python versions and runs the local secret scan.

## Public Release Boundary

This community release should not include hosted backend integration, enterprise policy sync, billing/licensing, production secrets, internal endpoints, or sensitive commercial heuristics. See [OPEN_SOURCE_PLAN.md](OPEN_SOURCE_PLAN.md) before publishing a public GitHub repository.

## License

Apache License 2.0 is suggested for the community release. See [LICENSE](LICENSE).
