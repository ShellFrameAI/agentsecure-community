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

## Protect the vault device key

Vault record encryption and key storage are separate migrations. After verifying the record format, inspect and protect the device key explicitly:

```bash
agentsecure vault key status
agentsecure vault key protect --dry-run
agentsecure vault key protect
```

`protect` asks for a passphrase directly through the controlling terminal. It never accepts a passphrase from an argument, environment variable, pipe, or MCP stdio. The dry run does not prompt. The operation:

1. validates the existing raw device key and authenticates every vault record and encrypted `.asbak` backup;
2. derives a wrapping key with scrypt and creates a randomized AES-256-GCM envelope;
3. unwraps the candidate and compares it with the active device key;
4. authenticates the vault and backups again with the unwrapped candidate;
5. removes the raw `device.key` only after all verification succeeds; and
6. updates the secret-free manifest.

If a write, verification, or manifest update fails, AgentSecure restores the prior provider state. If a process is interrupted during the two-file handoff, both key files may remain. Secret access then fails closed with an ambiguous-provider error; re-running the intended `vault key protect` or `vault key unprotect` command verifies that both files represent the same key before completing recovery.

Metadata-only operations such as `vault key status`, `vault status`, and listing encrypted record identifiers do not need the passphrase. A command that decrypts or writes secret data unlocks lazily and prompts on first use.

On an uninitialized installation with no vault records, encrypted backups, or recovery snapshots, `vault key protect` creates the first device key directly in wrapped form. No raw key file is written in that path.

## Downgrade to AgentSecure 0.1.22

Run the rollback while the newer AgentSecure version is still installed:

```bash
agentsecure vault verify
agentsecure vault rollback --dry-run --to-format v1
agentsecure vault rollback --to-format v1
agentsecure vault key unprotect --dry-run
agentsecure vault key unprotect
python -m pip install agentsecure==0.1.22
```

Run both rollback commands while the newer AgentSecure version is still installed. Record rollback converts the current vault, including secrets created or rotated after migration, instead of copying an outdated snapshot. Key unprotect verifies the wrapped key and all encrypted data before atomically restoring the same owner-only `device.key` expected by 0.1.22.

Do not downgrade the package before preparing both the record format and key provider. AgentSecure 0.1.22 does not understand v2 records or the wrapped-key provider.

## Compatibility

| Vault state | Current release | AgentSecure 0.1.22 |
|---|---:|---:|
| v1 records + raw key | Read/write | Read/write |
| v2 records + raw or wrapped key | Read/write | Unsupported |
| v1 records + wrapped key | Read/write after terminal unlock | Unsupported |
| v1 rollback + `vault key unprotect` | Read/write | Read/write |

New vaults use v2. Existing v1 vaults remain v1 until the user runs `agentsecure vault migrate`, which keeps package upgrades non-destructive and makes the format change reviewable.

The supported PyPI installation declares the `cryptography` dependency used by v2. The dependency-light development zipapp does not bundle native cryptography libraries; when they are unavailable on the host it continues using v1 instead of making the rest of the CLI unusable, and v2 migration reports an actionable installation error.

## Recovery snapshots

Snapshots live under `~/.agentsecure/vault/recovery/`, contain encrypted vault records, and have owner-only permissions. They are crash-recovery artifacts, not a second plaintext secret store. They remain decryptable with the same device key after either key-provider migration.

## Remaining threat model

Passphrase wrapping means that directly reading or copying `~/.agentsecure/vault/*` does not reveal the device key or credentials without the passphrase. It does not protect an already unlocked Python process from another process with unrestricted access as the same OS user, and it cannot make an unsigned terminal prompt resistant to same-user tampering or phishing. Use scoped development credentials plus an OS sandbox or separate execution identity for hostile agents. A signed OS helper with user-presence or keychain policy is a stronger future boundary, not a property implied by this migration.
