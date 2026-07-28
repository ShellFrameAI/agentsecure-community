# Security Model and Limitations

## Goal

AgentSecure's default workflow keeps imported real secret values out of
agent-readable project files and out of the MCP response returned to the coding
agent. The agent refers to a secret by an environment name such as
`${API_KEY}`; AgentSecure resolves it locally only while sending an approved
request.

## Trust boundary

AgentSecure assumes the local user account and machine are trusted. The coding
agent is treated as a potentially over-broad consumer of project context, not
as an attacker isolated from the operating system.

The AgentSecure process, local vault key, encrypted vault, dotenv backups, and
outbound request process all run under the same local user. A process that
already controls that user account or machine can read or modify user-accessible
files and is outside this threat model.

## What the default MCP flow protects

- Guided import moves discovered real dotenv values into the local user vault.
- The project dotenv file receives non-secret `AGENTSECURE_ALIAS_*`
  placeholders.
- Project configuration stores alias and policy metadata rather than imported
  raw values.
- MCP policy and secret-status tools return metadata without raw values.
- `agentsecure.http.request` evaluates destination policy before secret
  resolution.
- Alias-specific approved hosts provide a second destination check in addition
  to project network policy.
- The HTTP response is sanitized for configured and resolved secret strings
  before it is returned to the agent.
- Audit logging redacts token and secret-like fields.
- Temporary MCP grants are scoped to a project and request run, expire, and are
  revoked after the request.

## What AgentSecure does not provide

AgentSecure is not:

- an operating-system sandbox, VM, container, or separate security principal;
- protection against compromise of the local user, device, Python runtime, or
  AgentSecure process;
- a guarantee that an unrestricted local agent cannot inspect files elsewhere
  in the user's home directory;
- a system-wide firewall or control over all non-AgentSecure network traffic;
- a general data-loss-prevention or endpoint detection product;
- a replacement for least-privilege credentials, provider-side scopes,
  rotation, MFA, endpoint security, or cloud security controls.

The default MCP flow sends real secret bytes from the AgentSecure process to the
approved destination. The values necessarily exist in local process memory
during resolution and transmission; the boundary is that they are not returned
to the coding agent.

## Runtime and command-guard limits

`agentsecure run` is optional and not the default onboarding path.
Command-guard mode installs `PATH`-first wrappers only for common tools such as
`cat`, `grep`, `rg`, `curl`, and `wget`. Unwrapped tools, absolute paths, custom
code, shell indirection, and an interactive agent process can bypass or avoid
that output boundary. Interactive terminal output is not post-processed.

Workspace copy mode can provide a cleaner review boundary for project files,
but it is still not an OS sandbox. Use containers, separate users, restricted
mounts, and network controls when stronger isolation is required.

## Backup limitation

The vault secret store is encrypted at rest. Dotenv backups are not encrypted:
they are plaintext copies with owner-only `0600` permissions under
`~/.agentsecure/backups/`. A coding agent or attacker with the local user's file
access may be able to read them.

See [vault and backup behavior](vault-and-backups.md) before importing real
secrets.

## Operational recommendations

- Use development credentials with the minimum provider-side scope.
- Approve exact hosts and only required ports.
- Keep TLS verification enabled.
- Protect the local account and home directory.
- Rotate a credential if raw exposure is suspected.
- Use OS or container isolation for untrusted code or agents.
- Review `agentsecure.json`, `.agentsecure/audit.log`, and destination changes.

For replayable implementation evidence, see
[Security Receipts](../SECURITY_RECEIPTS.md).
