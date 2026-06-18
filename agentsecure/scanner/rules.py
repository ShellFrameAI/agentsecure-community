import json
import os
import posixpath
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Pattern
from urllib.parse import urlsplit

from agentsecure.discovery.patterns import mask_secret
from agentsecure.scanner.models import Finding


WHY_SECRET = "AI coding agents may read this file while working on the repo and can accidentally expose or use real credentials."
WHY_MCP = "An agent may access more files, commands, or environment data than intended through MCP tools."
WHY_SCRIPT = "An agent may run destructive, production-related, or cloud-affecting scripts while trying to complete a coding task."
WHY_NETWORK = "Production or cloud endpoints increase the chance that an agent action affects real infrastructure or data."


@dataclass(frozen=True)
class FileContext:
    root: str
    rel_path: str
    abs_path: str
    text: str

    @property
    def lines(self) -> List[str]:
        return self.text.splitlines()


@dataclass(frozen=True)
class PathContext:
    root: str
    rel_path: str
    abs_path: str
    is_dir: bool


class Rule:
    def check_path(self, context: PathContext) -> List[Finding]:
        return []

    def check_file(self, context: FileContext) -> List[Finding]:
        return []


def normalized_rel(path: str) -> str:
    return path.replace(os.sep, "/").strip("/")


def basename(path: str) -> str:
    return posixpath.basename(normalized_rel(path))


def redact_value(value: str) -> str:
    return mask_secret(value.strip())


class SensitivePathRule(Rule):
    def check_path(self, context: PathContext) -> List[Finding]:
        rel = normalized_rel(context.rel_path)
        name = basename(rel)
        findings: List[Finding] = []
        sensitive_files: Dict[str, Dict[str, str]] = {
            ".env": {"severity": "High", "title": "Agent-visible .env file found"},
            ".env.local": {"severity": "High", "title": "Local dotenv file found"},
            ".env.production": {"severity": "Critical", "title": "Production-looking .env file found"},
            ".npmrc": {"severity": "High", "title": "npm credentials file found"},
            ".pypirc": {"severity": "High", "title": "Python package credentials file found"},
            "service-account.json": {"severity": "High", "title": "Service account file found"},
            "firebase.json": {"severity": "Medium", "title": "Firebase config file found"},
            "docker-compose.yml": {"severity": "Medium", "title": "Docker compose file found"},
            "compose.yml": {"severity": "Medium", "title": "Docker compose file found"},
        }
        if rel == ".aws/credentials":
            findings.append(
                Finding(
                    title="AWS credentials file found",
                    path=rel,
                    severity="Critical",
                    why=WHY_SECRET,
                    recommendation="Move AWS credentials out of the repository and expose only agent-safe aliases or development credentials.",
                )
            )
        if not context.is_dir and name in sensitive_files:
            meta = sensitive_files[name]
            findings.append(
                Finding(
                    title=meta["title"],
                    path=rel,
                    severity=meta["severity"],
                    why=WHY_SECRET,
                    recommendation="Move real credentials out of agent-visible files and create an agent-safe `.env` with non-production placeholders.",
                )
            )
        return findings


class AgentConfigPathRule(Rule):
    def check_path(self, context: PathContext) -> List[Finding]:
        rel = normalized_rel(context.rel_path)
        name = basename(rel)
        agent_dirs = {".cursor", ".windsurf", ".claude", ".codex"}
        agent_files = {
            ".cursorrules",
            "CLAUDE.md",
            "mcp.json",
            ".mcp.json",
            "claude_desktop_config.json",
        }
        if context.is_dir and name in agent_dirs:
            return [
                Finding(
                    title="AI agent configuration directory found",
                    path=rel,
                    severity="Info",
                    why="Repo-local agent instructions or tool settings can change what an AI coding agent reads, writes, or runs.",
                    recommendation="Review this agent configuration before starting an AI coding agent in the repository.",
                )
            ]
        if not context.is_dir and name in agent_files:
            severity = "Medium" if name in {"mcp.json", ".mcp.json", "claude_desktop_config.json"} else "Info"
            return [
                Finding(
                    title="AI agent configuration file found",
                    path=rel,
                    severity=severity,
                    why="Repo-local agent instructions or tool settings can change what an AI coding agent reads, writes, or runs.",
                    recommendation="Review this file for broad tools, production instructions, and access to sensitive files before using an agent.",
                )
            ]
        return []


@dataclass(frozen=True)
class SecretPattern:
    name: str
    regex: Pattern[str]
    severity: str
    recommendation: str
    value_group: int = 0


class SecretPatternRule(Rule):
    def __init__(self) -> None:
        self.patterns = [
            SecretPattern(
                "AWS access key",
                re.compile(r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b"),
                "Critical",
                "Revoke the key if real, move it to a local vault, and use short-lived or development-only credentials for agent work.",
            ),
            SecretPattern(
                "GitHub token",
                re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
                "Critical",
                "Revoke the token if real and replace it with a least-privilege development token outside the repo.",
            ),
            SecretPattern(
                "Anthropic API key",
                re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
                "High",
                "Move API keys out of repo files and use AgentSecure aliases or development-only credentials.",
            ),
            SecretPattern(
                "OpenAI API key",
                re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
                "High",
                "Move API keys out of repo files and use AgentSecure aliases or development-only credentials.",
            ),
            SecretPattern(
                "Supabase credential",
                re.compile(
                    r"\bSUPABASE_(?:SERVICE_ROLE_KEY|ANON_KEY|JWT_SECRET)\b\s*[:=]\s*[\"']?([A-Za-z0-9_.-]{16,})",
                    re.IGNORECASE,
                ),
                "High",
                "Move Supabase credentials out of agent-visible files and use development-only project keys for agent work.",
                1,
            ),
            SecretPattern(
                "Gemini or Firebase API key",
                re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
                "High",
                "Move API keys out of repo files and restrict the key to safe development use if it must exist locally.",
            ),
            SecretPattern(
                "Firebase credential",
                re.compile(
                    r"\bFIREBASE_(?:API_KEY|PRIVATE_KEY|CLIENT_SECRET|SERVICE_ACCOUNT)\b\s*[:=]\s*[\"']?([^\"'\s]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
                    re.IGNORECASE,
                ),
                "High",
                "Move Firebase credentials out of agent-visible files and use restricted development credentials for agent work.",
                1,
            ),
            SecretPattern(
                "JWT secret or private key",
                re.compile(
                    r"\bJWT_(?:SECRET|PRIVATE_KEY)\b\s*[:=]\s*[\"']?([^\"'\s]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
                    re.IGNORECASE,
                ),
                "High",
                "Move JWT signing material out of agent-visible files and rotate it if an agent may have seen it.",
                1,
            ),
            SecretPattern(
                "JWT-looking token",
                re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"),
                "High",
                "Move bearer tokens out of agent-visible files and use short-lived development tokens for agent work.",
            ),
            SecretPattern(
                "Stripe secret key",
                re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b"),
                "Critical",
                "Revoke live payment keys if real and keep Stripe credentials outside agent-visible files.",
            ),
            SecretPattern(
                "MongoDB connection string",
                re.compile(r"\bmongodb(?:\+srv)?://[^\s'\"<>]+", re.IGNORECASE),
                "High",
                "Move database URLs out of agent-visible files and use a development database for agent work.",
            ),
            SecretPattern(
                "Postgres connection URL",
                re.compile(r"\bpostgres(?:ql)?://[^\s'\"<>]+", re.IGNORECASE),
                "High",
                "Move database URLs out of agent-visible files and use a development database for agent work.",
            ),
            SecretPattern(
                "MySQL connection URL",
                re.compile(r"\bmysql://[^\s'\"<>]+", re.IGNORECASE),
                "High",
                "Move database URLs out of agent-visible files and use a development database for agent work.",
            ),
            SecretPattern(
                "PEM private key",
                re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
                "Critical",
                "Remove private keys from the repo, rotate them if real, and store them outside agent-visible files.",
            ),
        ]

    def check_file(self, context: FileContext) -> List[Finding]:
        findings: List[Finding] = []
        for line_number, line in enumerate(context.lines, start=1):
            for pattern in self.patterns:
                for match in pattern.regex.finditer(line):
                    evidence_value = match.group(pattern.value_group)
                    findings.append(
                        Finding(
                            title="Secret-looking value found: %s" % pattern.name,
                            path=context.rel_path,
                            line=line_number,
                            severity=pattern.severity,
                            why=WHY_SECRET,
                            recommendation=pattern.recommendation,
                            evidence=redact_value(evidence_value),
                        )
                    )
        return findings


class McpConfigRule(Rule):
    MCP_FILES = {"mcp.json", ".mcp.json", "claude_desktop_config.json"}

    def check_file(self, context: FileContext) -> List[Finding]:
        if basename(context.rel_path) not in self.MCP_FILES:
            return []
        findings: List[Finding] = []
        data = self._load_json(context.text)
        lowered = context.text.lower()
        if data is not None:
            findings.extend(self._check_json_config(context, data))
        if any(term in lowered for term in ("printenv", "process.env", "env |", "dotenv", "environment")):
            findings.append(
                Finding(
                    title="MCP config may expose environment variables",
                    path=context.rel_path,
                    severity="High",
                    why=WHY_MCP,
                    recommendation="Remove tools that expose process environment values or restrict them to explicit non-secret variables.",
                )
            )
        return findings

    def _load_json(self, text: str) -> Optional[Any]:
        try:
            return json.loads(text)
        except ValueError:
            return None

    def _check_json_config(self, context: FileContext, data: Any) -> List[Finding]:
        findings: List[Finding] = []
        strings = list(_strings_in(data))
        lowered_strings = [value.lower() for value in strings]
        if self._has_broad_filesystem(context.root, strings):
            findings.append(
                Finding(
                    title="MCP config exposes broad filesystem access",
                    path=context.rel_path,
                    severity="High",
                    why=WHY_MCP,
                    recommendation="Restrict MCP filesystem scope to the minimum project subdirectories needed for the task.",
                )
            )
        if any("filesystem" in value for value in lowered_strings) and any(value in ("/", "~") for value in strings):
            findings.append(
                Finding(
                    title="MCP filesystem server has unrestricted-looking roots",
                    path=context.rel_path,
                    severity="High",
                    why=WHY_MCP,
                    recommendation="Replace broad filesystem roots with an explicit allowlist of safe project paths.",
                )
            )
        if any(term in value for value in lowered_strings for term in ("shell", "command", "exec", "terminal")):
            if any(posixpath.basename(value) in ("bash", "sh", "zsh", "powershell", "cmd", "python", "node", "npx") for value in strings):
                findings.append(
                    Finding(
                        title="MCP config exposes broad shell or command tools",
                        path=context.rel_path,
                        severity="High",
                        why=WHY_MCP,
                        recommendation="Disable broad shell MCP tools or require explicit AgentSecure policy approval before use.",
                    )
                )
        return findings

    def _has_broad_filesystem(self, root: str, strings: Iterable[str]) -> bool:
        home = os.path.expanduser("~")
        root_abs = os.path.abspath(root)
        for value in strings:
            expanded = os.path.abspath(os.path.expanduser(value)) if value else value
            if value in ("/", "~", ".", root_abs, home):
                return True
            if expanded in ("/", root_abs, home):
                return True
        return False


class ScriptRiskRule(Rule):
    RISK_TERMS = (
        "seed-prod",
        "production",
        "prod",
        "deploy",
        "drop",
        "truncate",
        "delete",
        "rm -rf",
        "kubectl",
        "aws",
        "gcloud",
        "az ",
        "docker compose",
    )

    def check_file(self, context: FileContext) -> List[Finding]:
        name = basename(context.rel_path)
        if name == "package.json":
            return self._check_package_json(context)
        if name in ("Makefile", "makefile", "docker-compose.yml", "compose.yml") or name.endswith(".sh"):
            return self._check_script_text(context)
        return []

    def _check_package_json(self, context: FileContext) -> List[Finding]:
        try:
            data = json.loads(context.text)
        except ValueError:
            return []
        scripts = data.get("scripts")
        if not isinstance(scripts, dict):
            return []
        findings: List[Finding] = []
        for script_name, command in scripts.items():
            command_text = str(command)
            combined = ("%s %s" % (script_name, command_text)).lower()
            if any(term in combined for term in self.RISK_TERMS):
                findings.append(
                    Finding(
                        title="Risky npm script found: %s" % script_name,
                        path=context.rel_path,
                        severity=self._script_severity(combined),
                        why=WHY_SCRIPT,
                        recommendation="Rename, guard, or block this command in AgentSecure policy before running agents in the repo.",
                        evidence=script_name,
                    )
                )
        return findings

    def _check_script_text(self, context: FileContext) -> List[Finding]:
        findings: List[Finding] = []
        for line_number, line in enumerate(context.lines, start=1):
            lowered = line.lower()
            if any(term in lowered for term in self.RISK_TERMS):
                findings.append(
                    Finding(
                        title="Risky script command found",
                        path=context.rel_path,
                        line=line_number,
                        severity=self._script_severity(lowered),
                        why=WHY_SCRIPT,
                        recommendation="Guard destructive or production commands and require explicit approval before an agent can run them.",
                    )
                )
        return findings

    def _script_severity(self, text: str) -> str:
        if any(term in text for term in ("rm -rf", "drop", "truncate", "delete", "seed-prod")):
            return "High"
        return "Medium"


class NetworkProductionHintRule(Rule):
    URL_RE = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
    HOST_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9.-]+\b", re.IGNORECASE)
    CLOUD_MARKERS = ("rds.amazonaws.com", "mongodb.net", "supabase", "firebase", "stripe", "aws", "gcp", "azure")
    FILE_EXTENSIONS = {
        "cfg",
        "conf",
        "env",
        "ini",
        "json",
        "lock",
        "md",
        "production",
        "py",
        "toml",
        "txt",
        "yaml",
        "yml",
    }

    def check_file(self, context: FileContext) -> List[Finding]:
        findings: List[Finding] = []
        for line_number, line in enumerate(context.lines, start=1):
            candidate = self._first_hint(line)
            if candidate:
                findings.append(
                    Finding(
                        title="Production or cloud endpoint hint found",
                        path=context.rel_path,
                        line=line_number,
                        severity="Low",
                        why=WHY_NETWORK,
                        recommendation="Add a network allowlist and make sure agent runs use development endpoints by default.",
                        evidence=redact_value(candidate),
                    )
                )
        return findings

    def _first_hint(self, line: str) -> Optional[str]:
        for match in self.URL_RE.finditer(line):
            candidate = match.group(0)
            if self._is_hint(candidate):
                return candidate
        for match in self.HOST_RE.finditer(line):
            candidate = match.group(0)
            if self._looks_like_host(candidate) and self._is_hint(candidate):
                return candidate
        return None

    def _is_hint(self, candidate: str) -> bool:
        parsed = urlsplit(candidate)
        host = parsed.hostname or candidate
        lowered_host = host.lower()
        if any(marker in lowered_host for marker in self.CLOUD_MARKERS):
            return True
        labels = [label for label in lowered_host.split(".") if label]
        if any(_label_has_prod_token(label) for label in labels):
            return True
        path_tokens = [token for token in re.split(r"[^a-z0-9]+", parsed.path.lower()) if token]
        return any(token in ("prod", "production") for token in path_tokens)

    def _looks_like_host(self, candidate: str) -> bool:
        labels = [label for label in candidate.lower().strip(".").split(".") if label]
        if len(labels) < 2:
            return False
        if labels[-1] in self.FILE_EXTENSIONS:
            return False
        if len(labels) >= 3:
            return True
        return any(marker in candidate.lower() for marker in self.CLOUD_MARKERS)


def _label_has_prod_token(label: str) -> bool:
    if label == "production" or "production" in label:
        return True
    return bool(re.search(r"(?:^|-)prod(?:-|$)", label))


def _strings_in(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            for child in _strings_in(item):
                yield child
    elif isinstance(value, list):
        for item in value:
            for child in _strings_in(item):
                yield child
