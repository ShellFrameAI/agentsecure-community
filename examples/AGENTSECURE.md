# AGENTSECURE.md

## Start

Set up AgentSecure MCP once:

```bash
agentsecure start --client claude
# or
agentsecure start --client codex --install-mcp
```

Apply any printed MCP configuration, then start Claude Code or Codex normally.
For secret-bearing HTTP requests, use
`agentsecure.http.request`. The `agentsecure run` wrapper is an advanced
compatibility mode, not the default flow.

## Secrets

Do not paste real secrets, raw `.env` files, private keys, tokens, prompts, or request bodies into this file.

```yaml
DATABASE_URL_DEV:
  mode: virtualize
  note: use a local/dev-only value approved by the human

DATABASE_URL_PROD:
  mode: deny

OPENAI_API_KEY:
  mode: virtualize
```

## Commands

Allowed:
- npm test
- npm run build

Blocked:
- printenv
- env

Require approval:
- production deploys
- database migrations

## Network

Allowed:
- localhost
- test-dev.example.internal

Blocked:
- prod.example.internal
- unknown private IPs
- credential-bearing requests to unapproved domains

## When Policy Denies Access

Do not retry the same credential.
Use the suggested safe alternative when one exists.
Ask the human before requesting broader access.

## Local-First Trust

Real secrets stay on the developer machine. Community AgentSecure validates this guidance locally. Team profile sync, assignment, and audit visibility are commercial ShellFrame Console features.
