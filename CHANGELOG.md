# Changelog

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
