# Security Policy

## Supported Scope

This community release supports local-only AgentSecure behavior:

- CLI demo and local project initialization.
- Local `.env` discovery and masking.
- Local virtual secret storage under `.agentsecure/`.
- Basic policy config and local command guard.
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

- Never commit real `.env` files, private keys, access tokens, database URLs, or generated `.agentsecure/` state.
- Use `examples/.env.example` for fake demo values only.
- Run `python3 scripts/secret_scan.py .` before publishing.
- Rotate any credential immediately if it was committed, even if later removed from Git history.

## Known Limitations

Command-guard mode masks common read/search command output. It is not a hard sandbox and can be bypassed by unwrapped tools, absolute binary paths, or custom code that reads files directly.

For stronger isolation, use workspace copy mode and operating-system sandboxing.
