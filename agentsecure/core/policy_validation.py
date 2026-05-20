import re
from typing import Any, Dict, Set
from urllib.parse import urlsplit


ENV_POLICY_FIELDS = set(
    [
        "mode",
        "access",
        "environment",
        "risk",
        "approved_hosts",
        "reason",
        "capability",
    ]
)
CAPABILITY_FIELDS = set(
    [
        "type",
        "expose_as",
        "target_host",
        "target_port",
        "access",
        "database",
        "local_host",
        "local_port",
    ]
)
RAW_SECRET_FIELD_NAMES = set(
    [
        "secret",
        "secrets",
        "real_secret",
        "real_value",
        "password",
        "token",
        "api_key",
        "private_key",
        "connection_string",
        "value",
    ]
)
SECRET_VALUE_RE = re.compile(r"(://[^\s/@]+:[^\s/@]+@|\bsk-[A-Za-z0-9_-]{8,}\b|-----BEGIN [^-]*PRIVATE KEY-----)")


class PolicyMutationValidator:
    """Validates local policy mutation payloads before config merge."""

    def extract_policy_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if payload is None:
            return {}
        if not isinstance(payload, dict):
            raise ValueError("policy mutation payload must be a JSON object")
        if "policy" in payload:
            if len(payload) != 1:
                raise ValueError("policy mutation payload must not mix policy with other fields")
            payload = payload["policy"]
        if not isinstance(payload, dict):
            raise ValueError("policy mutation payload must be a JSON object")
        unexpected = sorted(set(payload) - set(["env_policy", "capabilities"]))
        if unexpected:
            if any(self.looks_like_raw_secret_field(field) for field in unexpected):
                raise ValueError("policy mutation payload must not include raw secrets")
            raise ValueError("unsupported policy mutation field: %s" % unexpected[0])
        return payload

    def validate_fields(self, path: str, value: Dict[str, Any], allowed: Set[str]) -> None:
        for field in sorted(set(value) - allowed):
            if self.looks_like_raw_secret_field(field):
                raise ValueError("%s must not include raw secrets" % path)
            raise ValueError("unsupported %s field: %s" % (path, field))

    def reject_raw_secret_value(self, path: str, value: Any) -> None:
        values = value if isinstance(value, list) else [value]
        for item in values:
            if not isinstance(item, str):
                continue
            if path.endswith(".target_host") and ("://" in item or "/" in item or "@" in item):
                raise ValueError("%s must be a host name, not a URL or credential" % path)
            if self.looks_like_raw_secret_value(item):
                raise ValueError("%s must not include raw secrets" % path)

    def looks_like_raw_secret_field(self, field: str) -> bool:
        normalized = str(field).strip().lower()
        return normalized in RAW_SECRET_FIELD_NAMES or normalized.endswith("_secret")

    def looks_like_raw_secret_value(self, value: str) -> bool:
        text = str(value)
        if SECRET_VALUE_RE.search(text):
            return True
        if "://" in text:
            try:
                parsed = urlsplit(text)
            except ValueError:
                return False
            return bool(parsed.password)
        return False
