import os
import re
from typing import Any, Dict, List


AGENTSECURE_MD = "AGENTSECURE.md"
AGENTSECURE_MD_TEMPLATE_VERSION = "0.1.6"

AGENTSECURE_MD_TEMPLATE = """# AGENTSECURE.md

## Start

Run coding agents through AgentSecure:

```bash
agentsecure run --protect-all -- claude
```

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
"""


SECRET_TOKEN_PATTERNS = [
    re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{10,}", re.IGNORECASE),
    re.compile(r"sk-(?:live|test|proj)-[A-Za-z0-9_-]{10,}", re.IGNORECASE),
    re.compile(r"rk_live_[A-Za-z0-9]{10,}", re.IGNORECASE),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}", re.IGNORECASE),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}", re.IGNORECASE),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{16,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
]

SECRET_ASSIGNMENT_RE = re.compile(
    r"^\s*([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASS|API_KEY|PRIVATE_KEY|DATABASE_URL|DB_URL|CREDENTIAL)[A-Z0-9_]*)\s*=\s*(.+?)\s*$",
    re.IGNORECASE,
)

PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
FORBIDDEN_MODE_RE = re.compile(r"^\s*mode:\s*(allow|allow[_-]?real)\s*$", re.IGNORECASE)
ALLOW_PRODUCTION_SECRET_RE = re.compile(
    r"\ballow\b.{0,40}\bproduction\b.{0,40}\b(secret|credential|key|token|password)\b",
    re.IGNORECASE,
)


def ensure_agentsecure_md(path: str = AGENTSECURE_MD, force: bool = False) -> Dict[str, Any]:
    exists = os.path.exists(path)
    if exists and not force:
        return {"path": path, "created": False, "overwritten": False}
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(AGENTSECURE_MD_TEMPLATE)
    return {"path": path, "created": not exists, "overwritten": exists}


def validate_agentsecure_md(path: str = AGENTSECURE_MD) -> Dict[str, Any]:
    errors: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    if not os.path.exists(path):
        return {
            "path": path,
            "exists": False,
            "ok": False,
            "template_version": AGENTSECURE_MD_TEMPLATE_VERSION,
            "errors": [{"line": 0, "code": "missing_file", "message": "AGENTSECURE.md was not found"}],
            "warnings": [],
        }
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    if "# AGENTSECURE.md" not in text:
        warnings.append({"line": 0, "code": "missing_title", "message": "Expected '# AGENTSECURE.md' title"})
    for index, line in enumerate(text.splitlines(), start=1):
        _validate_line(line, index, errors)
    return {
        "path": path,
        "exists": True,
        "ok": not errors,
        "template_version": AGENTSECURE_MD_TEMPLATE_VERSION,
        "errors": errors,
        "warnings": warnings,
    }


def agentsecure_md_status(path: str = AGENTSECURE_MD) -> Dict[str, Any]:
    if os.path.exists(path):
        return validate_agentsecure_md(path)
    return {
        "path": path,
        "exists": False,
        "ok": False,
        "template_version": AGENTSECURE_MD_TEMPLATE_VERSION,
        "errors": [],
        "warnings": [],
    }


def _validate_line(line: str, line_number: int, errors: List[Dict[str, Any]]) -> None:
    mode_match = FORBIDDEN_MODE_RE.search(line)
    if mode_match:
        code = "allow_real" if "real" in mode_match.group(1).lower() else "allow"
        errors.append(_error(line_number, code, "Raw real-secret passthrough is not supported"))
    if PRIVATE_KEY_RE.search(line):
        errors.append(_error(line_number, "private_key", "Private keys must not be stored in AGENTSECURE.md"))
    if ALLOW_PRODUCTION_SECRET_RE.search(line):
        errors.append(_error(line_number, "allow_production_secret", "Production secrets must not be allowed directly"))
    for pattern in SECRET_TOKEN_PATTERNS:
        if pattern.search(line):
            errors.append(_error(line_number, "raw_secret", "Secret-looking token found"))
            break
    assignment = SECRET_ASSIGNMENT_RE.match(line)
    if assignment and _looks_like_raw_value(assignment.group(2)):
        errors.append(_error(line_number, "raw_env_assignment", "Raw secret-looking .env assignment found"))


def _looks_like_raw_value(value: str) -> bool:
    cleaned = value.strip().strip("\"'")
    if not cleaned:
        return False
    lowered = cleaned.lower()
    safe_markers = [
        "example",
        "localhost",
        "dev.local",
        "test-dev",
        "virt_",
        "[removed",
        "<",
        "your-",
        "placeholder",
        "dummy",
    ]
    if any(marker in lowered for marker in safe_markers):
        return False
    return len(cleaned) >= 8


def _error(line: int, code: str, message: str) -> Dict[str, Any]:
    return {"line": line, "code": code, "message": message}
