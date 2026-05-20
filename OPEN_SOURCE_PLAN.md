# AgentSecure Community / Lite Open-Source Plan

## Recommended Public Repository

Recommended name: `agentsecure-community`

Rationale: the name is clear, keeps the community release distinct from ShellFrame AI commercial services, and leaves room for a separate private monorepo or enterprise package.

## Public Scope

The community repository should include only local-first functionality that demonstrates the core idea without depending on hosted services:

- CLI entry point and local project initialization.
- Local command guard for common read/search commands.
- Local `.env` discovery, masking, and virtualization examples.
- Local encrypted secret storage using a device-local key.
- Basic JSON policy config for environment, process, file, and network rules.
- Local-only demo mode that shows real `.env` content being replaced with virtual values and deny-mode values being removed.
- Local gateway and local API only when bound to loopback and documented as development/demo boundaries.
- Workspace copy/symlink demo mode, diff, and apply flows.
- Tests that exercise local behavior without cloud or commercial services.

## Private / Excluded Scope

These areas should stay out of the public repository or be published only as stubs/interfaces:

- Hosted cloud/backend integration and runtime sync.
- Enterprise policy sync, config profile assignment, remote commands, and session control.
- Billing, licensing, entitlements, seat management, and commercial telemetry.
- Sensitive production detection heuristics, scoring models, and customer-specific policy packs.
- Production secrets, enrollment tokens, private keys, device tokens, and generated `.agentsecure/` state.
- Internal endpoints, non-public API URLs, deployment details, and dashboard contracts.
- Any real customer examples, logs, audit traces, prompts, or source snippets.

## Risk Review

- Current CLI imports cloud and daemon command paths. For a true public split, remove those modules from the community branch or replace them with no-op extension points.
- Current docs mention hosted cloud commands. Public README should describe local/community behavior only.
- Existing tests and docs contain fake `sk-...` and credential URL strings. They are placeholders, but CI should include a secret scan to catch accidental real values.
- Local command-guard mode is not a hard sandbox. Public docs must state that it masks common command output and should not be marketed as isolation.
- The local gateway validates destinations, but HTTPS header injection is limited without TLS interception. Public docs should keep this framed as a demo/developer control.

## Initial Files Changed

- `OPEN_SOURCE_PLAN.md`
- `README.md`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `LICENSE`
- `.gitignore`
- `.github/workflows/ci.yml`
- `examples/agentsecure.community.json`
- `examples/.env.example`
- `scripts/secret_scan.py`
- `agentsecure/cli/main.py`
- `tests/test_cli_demo.py`
- `tests/test_secret_scan.py`

## Publishing Checklist

- Run tests with `python3 -m unittest discover -s tests -p 'test_*.py' -v`.
- Run secret scan with `python3 scripts/secret_scan.py .`.
- Review `git status --short` and inspect all changed files.
- Before creating the public repository, physically exclude or stub the private scope listed above. Feature flags are not sufficient if the source itself is sensitive.
