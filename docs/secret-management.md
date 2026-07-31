# Secret Management

The default workflow imports dotenv secrets during `agentsecure start`. Manual
commands remain available for migrations, rotation, and projects that do not
use a conventional `.env` file.

## Guided import

Run the setup for the selected client:

```bash
agentsecure start --client claude
# or
agentsecure start --client codex --install-mcp
```

When `.env` exists, setup offers to:

- store each discovered real value in the user-level local vault;
- add alias metadata to `agentsecure.json`;
- create an owner-only plaintext backup;
- replace real dotenv values with `AGENTSECURE_ALIAS_<ENV_NAME>`
  placeholders;
- add inferred and explicitly approved credential destinations.

Non-secret dotenv entries are preserved.

## Manual dotenv import

Preview an import:

```bash
agentsecure secrets import .env --dry-run
```

Import and rewrite the file:

```bash
agentsecure secrets import .env
```

Useful options:

- `--approved-host HOST_OR_URL` adds another destination to imported aliases;
- `--keep-file` stores aliases without rewriting the dotenv file;
- `--no-backup` skips the pre-rewrite backup;
- `--project NAME` changes audit metadata.

`--keep-file` means real values remain in the original file. `--no-backup`
removes a recovery mechanism. Use both only when their trade-offs are
intentional.

## Add and assign one alias

Store a real value without placing it on the command line:

```bash
printf '%s' "$DATABASE_URL" | agentsecure secrets add dev_db \
  --env-name DATABASE_URL \
  --provider database \
  --approved-host db.example.com \
  --real-secret-stdin
```

Assign the alias to the current project:

```bash
agentsecure secrets use dev_db
```

Assignment writes only alias metadata to `agentsecure.json`, adds a
`virtualize` environment rule, and merges the alias's approved hosts into
network policy. Re-adding the same alias rotates its backing secret and revokes
active grants for the old value.

List aliases without printing secret values:

```bash
agentsecure secrets list
```

## Restore a dotenv file

Restore the latest matching backup:

```bash
agentsecure secrets restore .env
```

Preview or select a specific backup:

```bash
agentsecure secrets restore .env --dry-run
agentsecure secrets restore .env --backup /path/to/.env.TIMESTAMP.bak
```

Backups contain the original real values. Read
[vault and backup behavior](vault-and-backups.md) before relying on them.

## Files and values

- `~/.agentsecure/vault/secrets.enc.json` contains encrypted secret values.
- `~/.agentsecure/vault/device.key` contains the local vault key.
- `~/.agentsecure/vault/aliases.json` contains alias metadata and secret
  references.
- `agentsecure.json` contains project assignments and policy, not imported raw
  values.
- `.env` normally contains safe `AGENTSECURE_ALIAS_*` placeholders after
  import.
- `.agentsecure/grants.json` contains temporary virtual-token metadata, not raw
  secret values.
