import json
import os
import time
from typing import Any, Dict

from agentsecure.core.policy_validation import PolicyMutationValidator
from agentsecure.interfaces.audit import AuditLogger


REDACTED = "[redacted]"
TOKEN_FIELD_NAMES = set(
    [
        "authorization",
        "cookie",
        "set-cookie",
        "virtual_token",
        "device_token",
        "secret_ref",
        "secret_id",
    ]
)


class JsonLineAuditLogger(AuditLogger):
    def __init__(self, path: str) -> None:
        self._path = path
        self._validator = PolicyMutationValidator()
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def record(self, event_type: str, details: Dict[str, Any]) -> None:
        event = {
            "ts": time.time(),
            "type": event_type,
            "details": self._sanitize(details),
        }
        with open(self._path, "a") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")

    def _sanitize(self, value: Any, field_name: str = "") -> Any:
        normalized = str(field_name).strip().lower()
        if normalized in TOKEN_FIELD_NAMES or normalized.endswith("_token"):
            return REDACTED
        if normalized and self._validator.looks_like_raw_secret_field(normalized):
            return REDACTED
        if isinstance(value, dict):
            return {str(key): self._sanitize(item, str(key)) for key, item in value.items()}
        if isinstance(value, list):
            return [self._sanitize(item, field_name) for item in value]
        if isinstance(value, str) and self._validator.looks_like_raw_secret_value(value):
            return REDACTED
        return value
