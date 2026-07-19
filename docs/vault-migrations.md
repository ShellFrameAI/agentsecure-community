# Vault format migration and rollback

AgentSecure vault migrations are explicit. Installing a newer package does not silently rewrite an existing vault.

## Upgrade an existing vault

After upgrading AgentSecure, inspect and verify the current vault before changing its format:

```bash
agentsecure vault status
agentsecure vault verify
agentsecure vault migrate --dry-run
agentsecure vault migrate
```

The migration command:

1. acquires an exclusive vault-operation lock;
2. authenticates and decrypts every source record;
3. creates the complete target vault in a private temporary file;
4. decrypts the candidate again and compares every secret by hash;
5. stores an encrypted recovery snapshot of the previous vault;
6. atomically replaces `secrets.enc.json`;
7. writes a versioned, secret-free `manifest.json`.

If any step before replacement fails, the active vault is unchanged. If writing the manifest fails after replacement, AgentSecure restores the exact previous store from the recovery snapshot. Neither command output nor the manifest contains secret values.

## Downgrade to AgentSecure 0.1.22

Run the rollback while the newer AgentSecure version is still installed:

```bash
agentsecure vault verify
agentsecure vault rollback --dry-run --to-format v1
agentsecure vault rollback --to-format v1
```

Then install the older package version. Rollback converts the current vault, including secrets created or rotated after migration, instead of copying an outdated pre-migration snapshot.

Do not downgrade the package before preparing the vault. AgentSecure 0.1.22 does not understand v2 records and intentionally fails to resolve them rather than treating ciphertext as plaintext.

## Compatibility

| Vault data | Current release | AgentSecure 0.1.22 |
|---|---:|---:|
| v1 `agentsecure-local-v1` | Read/write until explicit migration | Read/write |
| v2 `aes-256-gcm-v2` | Read/write | Unsupported |
| v2 converted with `vault rollback` | Read/write as v1 | Read/write |

New vaults use v2. Existing v1 vaults remain v1 until the user runs `agentsecure vault migrate`, which keeps package upgrades non-destructive and makes the format change reviewable.

The supported PyPI installation declares the `cryptography` dependency used by v2. The dependency-light development zipapp does not bundle native cryptography libraries; when they are unavailable on the host it continues using v1 instead of making the rest of the CLI unusable, and v2 migration reports an actionable installation error.

## Recovery snapshots

Snapshots live under `~/.agentsecure/vault/recovery/`, contain encrypted vault records, and have owner-only permissions. They are crash-recovery artifacts, not a second plaintext secret store. The device key remains local-file-backed in this release; moving key access behind a stronger trust boundary is a separate migration.
