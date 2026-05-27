# Changelog

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
