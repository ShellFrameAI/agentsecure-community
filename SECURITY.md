# Security Policy

## Supported Scope

This community release supports local-only AgentSecure behavior:

- CLI demo and local project initialization.
- Local `.env` discovery and masking for fake/demo project values.
- Central local secret aliases stored under `~/.agentsecure/vault/`.
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

- Never commit real `.env` files, private keys, access tokens, database URLs, generated `.agentsecure/` state, or `~/.agentsecure/vault/` contents.
- Use `agentsecure secrets add` to store real secrets locally, `agentsecure secrets use` to assign aliases to a project, and `examples/.env.example` for fake demo values only.
- Run `python3 scripts/secret_scan.py .` before publishing.
- Rotate any credential immediately if it was committed, even if later removed from Git history.

## Known Limitations

Command-guard mode masks common read/search command output. It is not a hard sandbox and can be bypassed by unwrapped tools, absolute binary paths, or custom code that reads files directly.

Vault secret values are encrypted at rest. Existing installations begin with a local-file encryption key under the same OS user's AgentSecure home for compatibility. `agentsecure vault key protect` can replace that raw key with a passphrase-wrapped key after authenticating the vault and backups. This protects copied at-rest files, but it does not isolate an unlocked process or an unsigned prompt from a hostile process with unrestricted access as the same OS user. Do not treat either provider as a sandbox boundary against the coding agent itself.

Current dotenv recovery backups use an encrypted `.asbak` format. Older AgentSecure releases created plaintext `.bak` recovery files with owner-only permissions. `agentsecure doctor` reports those files, and `agentsecure secrets backups migrate` encrypts and verifies them before removing the plaintext originals.

New vaults use AES-256-GCM v2 records. Existing v1 vaults require an explicit, verified `agentsecure vault migrate`; package installation alone does not mutate stored credentials. Before installing 0.1.22, use both `agentsecure vault rollback --to-format v1` and `agentsecure vault key unprotect` while the newer release is still installed. Vault-format and key-provider upgrades do not create a hard same-user process boundary.

For stronger isolation, use workspace copy mode and operating-system sandboxing.
