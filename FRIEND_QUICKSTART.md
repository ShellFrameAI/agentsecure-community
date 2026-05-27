# AgentSecure Community Quickstart

Use this inside your own repo.

## 1. Install

```bash
cd your-repo

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade agentsecure
```

Check:

```bash
python -m agentsecure --help
```

If you prefer the shorter `agentsecure` command outside a virtual environment,
make sure Python's user script directory is on your shell path:

```bash
export PATH="$(python3 -m site --user-base)/bin:$PATH"
```

## 2. Init

```bash
agentsecure init
```

This creates:

```text
agentsecure.json
.agentsecure/
```

Do not commit `.agentsecure/`.

## 3. Discover Secrets

```bash
agentsecure discover
```

This scans local `.env` style files and environment variables.

## 4. Configure Policy

Open `agentsecure.json`.

Use this simple policy:

```json
{
  "env_policy": {
    "OPENAI_API_KEY": {
      "mode": "virtualize",
      "reason": "Agent sees a virtual key, not the real key."
    },
    "ANTHROPIC_API_KEY": {
      "mode": "virtualize",
      "reason": "Agent sees a virtual key, not the real key."
    },
    "DATABASE_URL_PROD": {
      "mode": "deny",
      "reason": "Production database secrets are blocked."
    },
    "STRIPE_SECRET_KEY": {
      "mode": "deny",
      "reason": "Payment secrets are blocked."
    }
  },
  "network": {
    "allow_domains": [
      "api.openai.com",
      "api.anthropic.com"
    ],
    "deny_domains": [
      "pastebin.com",
      "*.requestbin.net"
    ],
    "allow_ports": [80, 443],
    "deny_ip_literals": true,
    "deny_private_networks": true
  },
  "process": {
    "allowed_commands": []
  },
  "files": {
    "protect_write": [
      ".env",
      ".env.local",
      ".env.development",
      "agentsecure.json"
    ]
  },
  "gateway": {
    "host": "127.0.0.1",
    "port": 8765
  }
}
```

Meaning:

```text
virtualize = replace real value with virt_...
deny       = remove/block the value
```

## 5. Allow Network Domains

Optional helper commands:

```bash
agentsecure network allow api.openai.com api.anthropic.com
agentsecure network list
```

Remove a domain:

```bash
agentsecure network remove api.openai.com
```

## 6. Test `.env` Protection

```bash
agentsecure run --protect-all -- cat .env
```

Expected:

```text
OPENAI_API_KEY=virt_openai_...
DATABASE_URL_PROD is removed if policy mode is deny
```

The real `.env` file is not changed.

## 7. Run Your Agent

Use this pattern:

```bash
agentsecure run --protect-all -- <your-normal-command>
```

Examples:

```bash
agentsecure run --protect-all -- codex
agentsecure run --protect-all -- claude
agentsecure run --protect-all -- npm test
agentsecure run --protect-all -- python script.py
```

## 8. Check Status

```bash
agentsecure status
agentsecure doctor
```

## 9. List Or Revoke Virtual Keys

```bash
agentsecure keys list
```

Revoke one:

```bash
agentsecure keys revoke virt_openai_...
```

## Important

Do not put real secrets in `agentsecure.json`.

Real secrets stay in:

```text
.env
local shell environment
local secret store under .agentsecure/
```

AgentSecure Community is a local guard, not a full sandbox. For risky agent runs, also use Docker, no network by default, read-only mounts, and fake/dev credentials.
