# Open-Source Readiness Report

Date: 2026-05-20
Repository reviewed: `ShellFrameAI/agentsecure-community`
Current GitHub visibility: public

## Current Status

AgentSecure Community is close to a safe public community release, but it is not fully polished yet. The core local demo, secret virtualization flow, tests, license, security policy, contributing guide, examples, and CI are present. The remaining issues are mostly public-facing hygiene and clarity, not evidence of real secret leakage.

Final recommendation before cleanup: not fully ready as-is because the CLI help still advertises private/cloud/daemon/API commands and the documented install path is fragile on older system Python setups.

## Post-Cleanup Status

The low-risk cleanup from this report has been applied:

- Public CLI help no longer advertises `daemon`, `api`, `enroll`, `cloud`, or cloud reporting flags.
- README install instructions now use a virtual environment and upgraded pip.
- Added `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, issue templates, and a pull request template.
- Removed ignored local build artifacts from the working tree.
- Added tests for public CLI help boundaries.

Final recommendation after cleanup: ready for public GitHub release/announcement, with the remaining risks documented below.

## What Is Already Done

- Public repository exists under the official org: `https://github.com/ShellFrameAI/agentsecure-community`.
- README explains the community/lite scope, local-first concept, quickstart demo, examples, limitations, and commercial boundary.
- Apache-2.0 license is present.
- `SECURITY.md`, `CONTRIBUTING.md`, and `NOTICE` are present.
- GitHub Actions CI runs the test suite across Python 3.8-3.12 and runs `scripts/secret_scan.py`.
- Safe examples exist:
  - `examples/agentsecure.community.json`
  - `examples/.env.example`
- Local-only demo exists:
  - `agentsecure demo`
  - It shows `OPENAI_API_KEY=virt_openai_...`
  - It removes `DATABASE_URL_PROD`
  - It explains that real values stay local and no cloud/billing/enterprise sync is used.
- Cloud/API/daemon implementation files in this community repo are stubs rather than private implementation code.
- Tracked files do not include `dist/`, `agentsecure.egg-info/`, `.agentsecure/`, `.env`, logs, or Python caches.

## Safe To Publish

The following areas are appropriate for the community release:

- Local CLI commands for init, status, doctor, discover, suggest, protect, run, env, keys, network, files, policy review/apply, diff/apply, wrappers, and demo.
- Local command guard and output sanitizer.
- Local dotenv/environment discovery.
- Local encrypted secret storage and local grant store.
- Basic JSON config models and loader/writer.
- Local network guard and gateway validation.
- Workspace materialization, diff, and apply flow.
- Tests that use fake placeholder secrets and local temporary directories.
- Community examples and fake `.env.example`.

## Should Stay Private

These should remain out of the public community implementation:

- Hosted cloud/backend sync and reporting.
- Enterprise policy distribution and remote session commands.
- Billing, licensing, entitlements, seat management, and commercial telemetry.
- Sensitive or customer-specific detection heuristics.
- Production config profiles and internal policy packs.
- Internal endpoints, deployment details, real cloud URLs, tokens, or customer data.

## Exposed Private/Commercial Surface

No private cloud/backend implementation appears to be present. However, public CLI help still exposes private/commercial surfaces as commands or flags:

- Top-level help advertises `daemon`, `api`, `enroll`, and `cloud`.
- `agentsecure run --help` advertises `--project`, `--task`, and `--cloud-debug` as cloud reporting flags.
- `agentsecure/core/config_profiles.py`, `policy_response.py`, and policy mutation helpers remain present. They do not contain secrets, but they read like product/enterprise plumbing and should be clearly scoped as local policy helpers or hidden if not intended for community.
- `agentsecure/core/product.py` still reads `.agentsecure/cloud.json` metadata for status display. This is not secret leakage, but the naming is confusing for a community repo.

## Secret And Sensitive Data Review

Commands run:

- `python3 scripts/secret_scan.py .` passed.
- Manual regex scan found only fake/demo/test values:
  - `sk-demo-local-secret-do-not-use`
  - `sk-real-*` test fixtures
  - dummy Postgres URLs using `localhost`, `example`, `test-dev.host.domain`, or `Production.prod.host`
  - one fake GitHub token fixture in `tests/test_secret_scan.py`
- Git history has only three commits in this public repo. History scan found fake/demo `sk-*` fixtures only.
- File search found no tracked certificates, private keys, logs, databases, `.agentsecure/` state, or real `.env` files.
- `examples/.env.example` is intentionally tracked and uses fake values.
- Ignored local artifacts currently exist in the working directory:
  - `dist/agentsecure.pyz`
  - `agentsecure.egg-info/`
  They are ignored and untracked, but should be removed locally before packaging or publishing source archives from the working tree.

## GitHub Readiness Checklist

Present:

- `README.md`
- `LICENSE`
- `NOTICE`
- `SECURITY.md`
- `CONTRIBUTING.md`
- GitHub Actions CI
- Example policy file
- Fake `.env.example`
- Quickstart demo
- Secret scan script and CI step

Missing:

- `CODE_OF_CONDUCT.md`
- Issue templates
- Pull request template
- `CHANGELOG.md`
- A clearer release boundary in CLI help, not only docs.

## Developer First Experience

Strengths:

- A new developer can understand the core idea from the README in under 30 seconds.
- `agentsecure demo` runs quickly and demonstrates virtual secret output plus deny-mode removal.
- Tests pass locally from source.
- The phrase “agent never sees the real secret” is clear in README and demo output.

Problems:

- The README install command `python3 -m pip install -e .` failed on the local system Python due an older pip/setuptools editable install path and disabled user site packages.
- A venv with old pip also failed until pip is upgraded. README should instruct developers to create a venv and upgrade pip first.
- Public CLI help contains cloud/daemon/API options that are not part of the community product.

## Product And Positioning

Good:

- Problem statement is clear: AI coding agents should not receive raw local secrets.
- Target user is clear enough: developers and teams running Claude, Codex, Cursor, and similar tools.
- README avoids strong sandbox claims and explicitly says command-guard mode is not a hard sandbox.
- Commercial/private boundary is stated.

Needs cleanup:

- Public CLI help should match the README boundary.
- README should avoid linking to screenshot/GIF placeholders that do not exist, or mark them as planned.
- Use “ShellFrame AI” consistently for the company/org; use `ShellFrameAI` only for GitHub org/URL.

## Tests And CI

Current test result:

- `python3 -m unittest discover -s tests -p 'test_*.py' -q`
- Result: 100 tests passed.

Current secret scan result:

- `python3 scripts/secret_scan.py .`
- Result: passed.

CI appears adequate for this stage. It should become more robust by adding GitHub issue/PR templates and possibly a stronger third-party secret scanner later.

## Repo Hygiene

Good:

- Tracked files are small.
- `.gitignore` covers `.env`, `.env.*`, `.agentsecure/`, `dist/`, `*.egg-info/`, logs, Python caches, coverage files, and common virtualenvs.
- Git object size is small.

Needs cleanup:

- Remove ignored local artifacts from the working directory:
  - `dist/`
  - `agentsecure.egg-info/`
- Hide or remove community-unavailable CLI commands from public help.
- Add missing GitHub community files.

## Must Fix Before Public Release

The repo is already public, so these should be fixed before announcing or driving traffic to it:

1. Hide or disable cloud/backend/daemon/API commands in public CLI help.
2. Remove cloud reporting flags from community `agentsecure run --help`.
3. Update README install instructions to use a virtual environment and upgraded pip.
4. Add minimal GitHub issue templates and PR template.
5. Add `CODE_OF_CONDUCT.md` and `CHANGELOG.md`.
6. Remove ignored local build artifacts from the working tree before any source packaging.

## Nice To Have After Publish

- Add a short architecture diagram.
- Add an animated demo GIF or terminal recording.
- Add GitHub branch protection and required CI.
- Add a stronger scanner such as Gitleaks or GitHub Advanced Security if available.
- Add a `docs/` page explaining command-guard limitations and workspace mode in more detail.
- Add a `pipx` install path after package metadata is modernized.

## Exact Files Planned To Change

Low-risk cleanup planned after this report:

- `README.md`
  - Make install instructions venv-first.
  - Clarify demo and limitation wording.
- `agentsecure/cli/main.py`
  - Hide/remove cloud/backend/daemon/API commands from community help.
  - Remove cloud reporting flags from community `run --help`.
  - Return clear community messages if unavailable commands are invoked through old scripts.
- `tests/test_cli.py`
  - Add assertions that public help does not advertise cloud/backend/daemon/API commands.
- `.github/ISSUE_TEMPLATE/bug_report.md`
- `.github/ISSUE_TEMPLATE/feature_request.md`
- `.github/ISSUE_TEMPLATE/config.yml`
- `.github/pull_request_template.md`
- `CODE_OF_CONDUCT.md`
- `CHANGELOG.md`
- `.gitignore`
  - Add any missing local packaging/build safety ignores if needed.

No major architecture changes are planned.
