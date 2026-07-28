# CLI Reference

Use `agentsecure <command> --help` as the source of truth for the installed
version.

Global options:

```text
--version
--config PATH
```

`--config` defaults to `agentsecure.json`.

## Default workflow

| Command | Purpose |
| --- | --- |
| `start` | Guided project setup, dotenv import, agent guidance, and MCP configuration |
| `scan` | Inspect a repository for agent-visible security risks |
| `doctor` | Check local project setup |
| `status` | Summarize project configuration and local runtime state |
| `mcp` | Serve, inspect, or print client configuration for AgentSecure MCP |

The default onboarding command is `start`, followed by launching the coding
agent normally.

## Secret and policy management

| Command | Purpose |
| --- | --- |
| `secrets add` | Store or rotate one reusable local alias |
| `secrets list` | List aliases without raw values |
| `secrets use` | Assign aliases to the current project |
| `secrets import` | Import dotenv values into the vault |
| `secrets restore` | Restore a dotenv backup |
| `network list` | Show approved credential domains and ports |
| `network allow` | Add credential destinations |
| `network remove` | Remove credential domains |
| `policy` | Validate, inspect, or apply supported local policy updates |
| `files` | Manage protected-write paths for workspace mode |

See [secret management](secret-management.md),
[network policy](network-policy.md), and
[vault and backup behavior](vault-and-backups.md).

## Advanced and compatibility commands

| Command | Purpose |
| --- | --- |
| `run` | Launch a process with compatibility runtime controls |
| `gateway` | Run only the local gateway in the foreground |
| `proxy` | Configure or diagnose provider proxy mode |
| `setup` | Install or remove persistent command wrappers |
| `diff` | Review changes in a kept workspace |
| `apply` | Apply changes from a kept workspace |
| `guard` | Internal entry point used by command wrappers |
| `receipts` | Run replayable local security demonstrations |
| `demo` | Run the local community dotenv-masking demo |

See [advanced runtime mode](advanced-runtime.md).

## Discovery and legacy key commands

| Command | Purpose |
| --- | --- |
| `discover` | Scan dotenv files and the shell environment for likely secrets |
| `suggest` | Suggest environment and network policy from discoveries |
| `protect` | Create virtual bindings for discoveries |
| `env` | Print configured agent-visible virtual environment values |
| `keys create` | Create a project-local virtual key grant |
| `keys list` | List virtual key grants |
| `keys revoke` | Revoke a virtual key grant |
| `init` | Initialize low-level project state without completing MCP onboarding |
| `cleanup` | Remove project config and `.agentsecure/` state |
| `audit` | Alias for the repository scanner |

These commands remain supported, but they are not separate steps in the
recommended onboarding flow. `agentsecure start` already handles project
initialization and conventional `.env` import.

## Agent Mesh

`mesh` manages local agent identity, inbox, approvals, and audit features. MCP
also exposes the corresponding Mesh tools. It is independent of the default
secret setup flow.

## Public command boundary

The repository contains internal API, daemon, and cloud-related implementation
modules, but the current public parser does not expose `daemon`, `api`,
`enroll`, or `cloud` subcommands. Do not rely on those names as public CLI
interfaces.
