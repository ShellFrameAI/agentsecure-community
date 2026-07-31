# Vault and Backup Behavior

AgentSecure uses separate storage for reusable vault secrets, project metadata,
temporary grants, and dotenv backups. These files do not all have the same
protection.

## User-level vault

Imported and manually added aliases use:

```text
~/.agentsecure/vault/
  aliases.json
  device.key
  secrets.enc.json
```

- `secrets.enc.json` stores each real secret as authenticated ciphertext.
- `device.key` is a locally generated 256-bit key encoded for storage.
- `aliases.json` stores alias metadata and a reference to the encrypted value.
- Newly written vault files and the device key use owner-only `0600`
  permissions.

The current dependency-free cipher uses a random nonce, an HMAC-SHA256-derived
stream, and HMAC-SHA256 authentication. The key is stored on the same machine
and under the same local user as the ciphertext; it is not backed by an OS
keychain, hardware module, or remote KMS.

Encryption at rest prevents the ciphertext file alone from revealing its
contents. It does not protect against a process that can read both the vault and
its key as the local user.

## Project-local state

Guided setup creates `.agentsecure/` and an internal `.gitignore` that ignores
its contents except that ignore file. Depending on the commands used,
project-local state can include:

- a project device key and encrypted legacy secret store;
- temporary grant metadata and virtual tokens;
- audit logs;
- generated runtime guidance and workspaces.

Do not commit generated `.agentsecure/` state. Git ignore rules reduce accidental
commits; they are not a runtime security boundary.

## Dotenv backups

Before the default import rewrites a dotenv file, AgentSecure copies the
original to:

```text
~/.agentsecure/backups/<project-id>/.env.<timestamp>.bak
```

The backup:

- contains the original real secret values;
- is a regular plaintext copy, not vault ciphertext;
- is written with owner-only `0600` permissions;
- is selected for restore by matching the dotenv basename and taking the newest
  modification time.

Backups are intentionally outside the project, but they remain readable to the
local user. Secure home-directory permissions, disk encryption, endpoint
controls, and backup retention remain the user's responsibility.

## Import options

```bash
agentsecure secrets import .env --dry-run
agentsecure secrets import .env --keep-file
agentsecure secrets import .env --no-backup
```

- `--dry-run` reports the planned aliases without writing.
- `--keep-file` leaves the original real values in `.env`.
- `--no-backup` rewrites without creating the recovery copy.

Guided `agentsecure start` does not expose `--no-backup`; accepted imports
create a backup before rewriting.

## Restore behavior

```bash
agentsecure secrets restore .env
```

Restore copies the selected backup over the target dotenv file. It does not
delete the backup or remove the corresponding secrets and aliases from the
vault.

During interactive uninstall, AgentSecure offers to restore the latest backup
before removing project state. Non-interactive restore must be requested
explicitly.

See [uninstall and restore](uninstall-and-restore.md) and
[secret management](secret-management.md).
