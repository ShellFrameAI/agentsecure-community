# Advanced Runtime Mode

`agentsecure run` is still supported. It is not the default MCP-first workflow:
new users should run guided setup once, then start Claude Code or Codex
normally.

## When `agentsecure run` is useful

Use the wrapper when a process cannot use AgentSecure MCP directly and needs
one of these compatibility features:

- virtual secret environment variables for legacy tools or SDKs;
- a provider-specific local base URL that injects a real credential upstream;
- `PATH`-first wrappers for common read and network commands;
- non-interactive stdout and stderr secret masking;
- a sanitized workspace for review before changes are applied;
- security-receipt testing of runtime controls.

It is an additional process boundary, not a complete sandbox.

## Command-guard mode

The default runtime is command guard:

```bash
agentsecure run --no-discover -- claude
```

Without `--no-discover`, `run` scans configured dotenv files and the local
environment before launch. `--protect-all` is already the default; use
`--prompt-secrets` to choose discoveries interactively.

Command-guard mode:

- runs the command in the real project directory;
- exposes virtual values rather than configured real values;
- starts a local gateway for the duration of the process;
- places wrappers for `cat`, `head`, `tail`, `grep`, `rg`, `curl`, and `wget`
  first on `PATH`;
- sanitizes wrapper output and non-interactive parent-process output.

Absolute executable paths, other tools, custom code, and shell indirection can
bypass the wrappers. A bare interactive agent keeps its terminal attached, so
its output is not post-processed.

## Workspace mode

Create a sanitized workspace:

```bash
agentsecure run --runtime workspace --workspace-mode copy \
  --workspace-keep -- codex
```

`--workspace-mode copy` keeps ordinary edits in a copy. The default
`--workspace-mode symlink` is faster, but normal file edits can affect the real
project while protected files are materialized separately.

Additional controls:

```bash
agentsecure run --runtime workspace --workspace-mode copy \
  --read-only-workspace -- codex

agentsecure run --runtime workspace --workspace-mode copy \
  --no-new-files --workspace-keep -- codex
```

Review and apply a kept workspace:

```bash
agentsecure diff
agentsecure apply --dry-run
agentsecure apply
```

Protected files such as `.env` are excluded from normal apply behavior.
Workspace copy mode is not an OS sandbox; the launched process still runs as
the local user.

## Strict proxy mode

Command guard does not route all HTTP and HTTPS traffic through AgentSecure by
default. Opt in for a wrapped process:

```bash
agentsecure run --strict-proxy -- <command>
```

Loopback and private proxy bypasses require explicit flags. These flags weaken
proxy coverage and accept only private, loopback, or link-local destinations:

```bash
agentsecure run --strict-proxy --allow-loopback-proxy-bypass -- <command>
agentsecure run --strict-proxy \
  --allow-private-proxy-bypass 10.0.0.3 -- <command>
```

## Provider proxy mode

Provider proxy mode supports tools or SDKs that accept a provider base URL but
cannot call MCP. Configure a built-in OpenAI proxy:

```bash
agentsecure proxy setup openai
agentsecure proxy doctor
agentsecure run --no-discover -- <command>
```

Or configure an HTTPS provider:

```bash
agentsecure proxy setup custom \
  --name example \
  --upstream https://api.example.com \
  --env EXAMPLE_API_KEY \
  --base-url-env EXAMPLE_BASE_URL \
  --allow-path /v1/
```

The wrapped process receives a virtual key and a local base URL. AgentSecure
injects the real authorization value only when forwarding an allowed provider
path to an approved upstream.

Provider proxy mode is local-only. It is not a system-wide proxy, TLS
interception, or browser-wide protection. The client must honor its base URL
environment variable.

## Secret runtime modes

```bash
agentsecure run --secret-mode strict -- <command>
agentsecure run --secret-mode virtual -- <command>
agentsecure run --secret-mode compat -- <command>
```

New configurations default to `strict`. `virtual` preserves the older virtual
binding behavior. `compat` marks trusted legacy execution for warning and audit
purposes; Community still keeps vault aliases virtual or brokered rather than
passing raw vault values into the process environment.

## Gateway and daemon behavior

`agentsecure run` starts a local gateway for the process and stops it when the
run ends unless it detects compatible internal daemon state.

`agentsecure gateway` is a foreground command that runs only the local gateway.
The current public CLI does not expose a `daemon` subcommand, even though
internal daemon implementation modules remain in the repository.

`agentsecure start` does not run either service. It is one-time setup and exits.

See [security model and limitations](security-model.md) before relying on
runtime wrappers as a security boundary.
