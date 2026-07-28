# Scanner Reference

The AgentSecure scanner is an optional, read-only inspection step:

```bash
agentsecure scan .
```

`agentsecure audit` is an alias for the same repository scanner.

## Output formats

```bash
agentsecure scan . --format text
agentsecure scan . --format markdown
agentsecure scan . --format json
```

Reports include a score from 0 to 100, a risk level, findings grouped by
severity, evidence, recommendations, and a short checklist.

## Checks

The scanner applies local rules for:

- sensitive paths such as dotenv files, private keys, and credential files;
- AI-agent configuration and instruction files;
- common cloud, API-key, token, private-key, database, and webhook patterns;
- MCP configuration with risky shell or broad filesystem access;
- risky package, shell, and Docker Compose commands;
- production-looking hostnames and cloud endpoint hints.

Pattern findings are indicators for review, not proof that a value is valid or
exploitable.

## Traversal limits

The scanner:

- reads files only from the requested directory tree;
- skips symlinks, non-regular files, binary files, and files larger than 1 MiB;
- skips common generated directories including `.git`, `.agentsecure`,
  `node_modules`, virtual environments, build output, and caches;
- does not modify scanned files;
- performs no upload or network request in the scanner implementation.

Skipped files are counted in the report. A clean score does not prove the
repository or runtime is safe, especially when relevant files are skipped or
secrets exist only outside the scanned tree.

## Exit behavior

A completed scan returns success even when it reports findings. An invalid scan
path returns an error. Treat the report content, not only the process exit code,
as the result.
