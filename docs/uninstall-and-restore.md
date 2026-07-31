# Uninstall and Restore

Guided import normally rewrites `.env` with safe aliases after creating a
owner-only plaintext backup. Restore real values before uninstalling when the
project needs to run without AgentSecure.

## Restore without uninstalling

Preview the latest matching backup:

```bash
agentsecure secrets restore .env --dry-run
```

Restore it:

```bash
agentsecure secrets restore .env
```

Select a specific backup:

```bash
agentsecure secrets restore .env --backup /path/to/.env.TIMESTAMP.bak
```

Restore overwrites the target dotenv file. The backup remains in place.

## Interactive uninstall

```bash
agentsecure uninstall
```

When a matching backup exists, interactive uninstall offers to restore it
before removing project state.

## Non-interactive uninstall

Restore explicitly:

```bash
agentsecure uninstall --yes --restore-dotenv
```

Skip restore explicitly:

```bash
agentsecure uninstall --yes --no-restore-dotenv
```

With `--yes` alone, AgentSecure does not prompt and does not automatically
restore the dotenv backup.

Use `--dotenv PATH` for a dotenv file other than `.env`. `--install-dir`
changes the legacy user-bin directory checked for `agentsecure` and
`agentsecure.pyz`.

## What the command removes

`agentsecure uninstall` removes:

- the current project's `agentsecure.json`;
- the current project's `.agentsecure/` directory;
- AgentSecure launcher files found in the selected user-bin directory.

It does not remove:

- user-level vault aliases or encrypted secret values;
- user-level dotenv backups;
- AgentSecure sections written to `AGENTS.md` or `CLAUDE.md`;
- `AGENTSECURE.md`;
- an installation managed by `uv tool` or another package manager.

After reviewing recovery needs, remove a uv-managed installation separately:

```bash
uv tool uninstall agentsecure
```

Remove managed instruction sections and user-level vault or backup files only
after confirming they are no longer needed.

See [vault and backup behavior](vault-and-backups.md) for storage locations and
protection details.
