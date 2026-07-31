# Security Policy

## Supported Scope

This community release supports local-only AgentSecure behavior:

- Guided local project setup for Claude Code and Codex.
- Local `.env` discovery, vault import, backup, and placeholder rewriting.
- MCP tools for approved secret-bearing HTTP requests.
- Central local secret aliases stored under `~/.agentsecure/vault/`.
- Local virtual secret storage under `.agentsecure/`.
- Basic policy config and optional local runtime controls.
- Local tests and examples.

Hosted cloud sync, enterprise policy distribution, billing/licensing, and private ShellFrame AI services are outside the community security scope.

## Reporting a Vulnerability

Please do not open a public issue for suspected secret exposure, bypasses, or vulnerabilities.

Report privately by emailing the project maintainer or opening a private security advisory in GitHub. Include:

- Affected version or commit.
- Reproduction steps.
- Expected and actual behavior.
- Whether any real secret, token, endpoint, or customer data may be involved.

## Secret Handling Rules

- Never commit real `.env` files, private keys, access tokens, database URLs, generated `.agentsecure/` state, or `~/.agentsecure/vault/` contents.
- Prefer `agentsecure start --client <client>` for guided import and MCP setup. Use the manual `agentsecure secrets` commands only when needed.
- Dotenv backups under `~/.agentsecure/backups/` contain plaintext real values with owner-only file permissions. Protect and retain them accordingly.
- Use `examples/.env.example` for fake demo values only.
- Run `python3 scripts/secret_scan.py .` before publishing.
- Rotate any credential immediately if it was committed, even if later removed from Git history.

## Known Limitations

AgentSecure is not a hard sandbox and does not protect against compromise of
the local user or machine. Command-guard mode can be bypassed by unwrapped
tools, absolute binary paths, or custom code. See the
[security model and limitations](docs/security-model.md) and
[vault and backup behavior](docs/vault-and-backups.md).
