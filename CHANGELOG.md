# Changelog

## Unreleased

- Encrypt new dotenv recovery backups instead of copying plaintext secrets under `~/.agentsecure/backups/`.
- Added backup status, dry-run migration, verified legacy-backup migration, and encrypted/legacy restore compatibility.
- Added doctor reporting and explicit documentation for the current same-OS-user local vault threat model.
- Added AES-256-GCM v2 vault records for new vaults plus explicit status, verification, migration, recovery snapshots, and v1 rollback for older releases.
- Existing v1 vaults remain unchanged until confirmed migration; rollback re-encrypts the current record set so post-upgrade secrets are preserved.
- Added passphrase-wrapped vault keys with trusted-terminal prompting, lazy unlock, verified key-provider migration, interrupted-state recovery, and a tested raw-key rollback path for AgentSecure 0.1.22.

## 0.1.22 - 2026-07-14

- Added an end-to-end secret canary release gate covering guided setup, protected agent execution, approved MCP credential use, response redaction, and audit-log safety.
- Normalized URL-form `--approved-host` values before storing per-secret host policy so the network allowlist and secret resolver enforce the same destination.
- Simplified the README quick start to install, optionally scan, run guided setup, and start the coding agent normally.

## 0.1.21 - 2026-07-13

- Added persistent, idempotent `CLAUDE.md` guidance for `agentsecure start --client claude` while preserving existing project instructions and the current `AGENTS.md` behavior.
- Added a Claude-readable setup guide for installing AgentSecure as an isolated command-line tool, plus an `llms.txt` index.
- Preserved the legacy JSON `status` and `path` meaning for `AGENTS.md` while adding per-file results and `overall_status` for multi-file onboarding.
- Refused to modify symbolic links and non-regular `AGENTS.md` or `CLAUDE.md` paths during onboarding.

## 0.1.20 - 2026-06-18

- Ignored generated `.agentsecure/` state during `agentsecure scan` to avoid noisy audit-log findings.

## 0.1.19 - 2026-06-18

- Added `agentsecure scan [path]` and `agentsecure audit [path]` for local AI coding-agent safety reports.
- Added text, Markdown, and JSON scanner reports with severity grouping, score, risk level, and checklist.
- Added local-only checks for sensitive files, secret-looking values, AI agent config files, risky MCP configurations, risky scripts, and production/cloud endpoint hints.
- Redacted scanner evidence in all output formats and hardened scans to skip symlinks and non-regular files.

## 0.1.18 - 2026-06-12

- Added `secret_runtime.mode` policy configuration with `strict`, `virtual`, and `compat` modes.
- Added `agentsecure run --secret-mode` override plus status, doctor, output, and audit visibility for the selected mode.
- Kept compat mode as trusted legacy labeling while Community still keeps vault secrets virtual or brokered.

## 0.1.7 - 2026-05-31

- Added central local secret aliases with `agentsecure secrets add/list/use`.
- Added run-scoped virtual tokens for assigned aliases; real alias values stay under `~/.agentsecure/vault/`.
- Added per-alias approved-host checks before gateway credential injection.
- Updated community docs to make `.env` fake-only and point real secrets to the local vault.

## 0.1.6 - 2026-05-27

- Clarified that virtual environments are optional in the install instructions.
- Added the direct `python3 -m agentsecure run claude` command to the install quickstart.

## 0.1.5 - 2026-05-27

- Preserved terminal attachment for bare interactive agent launches such as `agentsecure run -- claude`.
- Suppressed internal gateway request tracebacks during guarded agent runs.
- Documented `python -m agentsecure` usage for installs where the user script directory is not on `PATH`.

## 0.1.4 - 2026-05-24

- Added `AGENTSECURE.md` creation during `agentsecure init`.
- Added `agentsecure policy validate` for local repo guidance validation.
- Added status and doctor checks for `AGENTSECURE.md`.
- Rejected raw secrets, private keys, `allow`, and `allow_real` in AGENTSECURE.md guidance.

## 0.1.3 - 2026-05-23

- Added config-driven provider proxy setup for OpenAI.
- Added provider proxy receipts with proof that virtual keys are not forwarded upstream.
- Added agent-friendly policy denial JSON for provider proxy blocks.
- Hardened provider proxy path validation, response sanitization, request framing, and config validation.
- Added provider proxy docs and example config.

## 0.1.2 - 2026-05-21

- Added parent-process stdout/stderr sanitization for `agentsecure run`.
- Moved CLI workspace sessions outside the source repo to prevent relative traversal back to original `.env` files.
- Added replayable security receipts and adversarial receipt checks.
- Added README risk context and friend quickstart guide.

## 0.1.1 - 2026-05-21

- Updated README install and first-run instructions for PyPI users.
- Clarified default `--protect-all` behavior versus explicit deny policy behavior.
- Removed private API command guidance from `agentsecure init` next steps.

## 0.1.0 - 2026-05-20

- Initial AgentSecure Community release.
- Added local-only `agentsecure demo`.
- Added local command guard and `.env` output sanitization.
- Added local virtual secret storage and basic policy config.
- Added example community policy and fake `.env.example`.
- Added tests and CI with secret scanning.
