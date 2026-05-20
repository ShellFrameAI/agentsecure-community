from typing import Any, Dict, Iterable

from agentsecure.core.policy_validation import PolicyMutationValidator


PROFILE_CONTAINER_KEYS = (
    "config_profile",
    "profile",
    "selected_profile",
)
PROFILE_POLICY_KEYS = (
    "policy",
    "config",
    "body",
    "config_body",
)
SAFE_POLICY_KEYS = set(
    [
        "network",
        "files",
        "file",
        "process",
        "agents",
        "env_policy",
        "capabilities",
        "runtime_defaults",
    ]
)


def normalize_profile_selector(value: Any) -> str:
    return str(value or "").strip()


def profile_metadata_from_response(
    payload: Any,
    fallback_id: str = "",
    source: str = "cloud",
) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return profile_metadata(payload, fallback_id=fallback_id, source=source)

    top_level_metadata = profile_metadata(payload, fallback_id=fallback_id, source=source)
    for key in PROFILE_CONTAINER_KEYS:
        metadata = profile_metadata(payload.get(key), fallback_id=fallback_id, source=source)
        if metadata:
            merged = dict(top_level_metadata)
            merged.update(metadata)
            return merged

    assignment = payload.get("assignment")
    if isinstance(assignment, dict):
        for key in PROFILE_CONTAINER_KEYS:
            metadata = profile_metadata(assignment.get(key), fallback_id=fallback_id, source=source)
            if metadata:
                merged = dict(top_level_metadata)
                merged.update(metadata)
                return merged

    return top_level_metadata


def profile_metadata(value: Any, fallback_id: str = "", source: str = "") -> Dict[str, Any]:
    if isinstance(value, str):
        value = {"id": value}
    if not isinstance(value, dict):
        value = {}

    validator = PolicyMutationValidator()
    profile_id = _first_string(
        value,
        ("id", "profile_id", "config_profile_id"),
        fallback=fallback_id,
        validator=validator,
    )
    name = _first_string(
        value,
        ("name", "display_name", "profile_name", "config_profile_name"),
        validator=validator,
    )
    version = _first_int(value, ("version", "profile_version", "policy_version"))
    assigned_version = _first_int(value, ("assigned_version", "assigned_profile_version"))
    applied_version = _first_int(value, ("applied_version", "applied_profile_version"))
    pending_version = _first_int(value, ("pending_version", "pending_profile_version"))
    assignment_id = _assignment_id(value, validator)
    status = _first_string(value, ("status",), validator=validator)
    last_synced_at = _first_number(value, ("last_synced_at",))
    last_applied_at = _first_number(value, ("last_applied_at",))

    if not profile_id and not name and not assignment_id:
        return {}

    metadata: Dict[str, Any] = {}
    if profile_id:
        metadata["id"] = profile_id
    if name:
        metadata["name"] = name
    if version > 0:
        metadata["version"] = version
    if status:
        metadata["status"] = status
    if assignment_id:
        metadata["assignment_id"] = assignment_id
    if assigned_version > 0:
        metadata["assigned_version"] = assigned_version
    if applied_version > 0:
        metadata["applied_version"] = applied_version
    if pending_version > 0:
        metadata["pending_version"] = pending_version
    if last_synced_at > 0:
        metadata["last_synced_at"] = last_synced_at
    if last_applied_at > 0:
        metadata["last_applied_at"] = last_applied_at
    if source:
        metadata["source"] = source
    return metadata


def profile_policy_body_from_response(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    for key in PROFILE_CONTAINER_KEYS:
        body = profile_policy_body(payload.get(key))
        if body:
            return body
    return {}


def profile_policy_body(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    for key in PROFILE_POLICY_KEYS:
        body = value.get(key)
        if isinstance(body, dict):
            return body
    body = {key: value[key] for key in SAFE_POLICY_KEYS if key in value}
    return body if body else {}


def _first_string(
    data: Dict[str, Any],
    keys: Iterable[str],
    fallback: str = "",
    validator: PolicyMutationValidator = None,
) -> str:
    validator = validator or PolicyMutationValidator()
    for key in keys:
        value = data.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text and not validator.looks_like_raw_secret_value(text):
            return text
    fallback = str(fallback or "").strip()
    if fallback and not validator.looks_like_raw_secret_value(fallback):
        return fallback
    return ""


def _first_int(data: Dict[str, Any], keys: Iterable[str]) -> int:
    for key in keys:
        try:
            value = int(data.get(key, 0) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
    return 0


def _first_number(data: Dict[str, Any], keys: Iterable[str]) -> float:
    for key in keys:
        try:
            value = float(data.get(key, 0) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
    return 0


def _assignment_id(data: Dict[str, Any], validator: PolicyMutationValidator) -> str:
    assignment = data.get("assignment")
    if isinstance(assignment, dict):
        value = _first_string(assignment, ("id", "assignment_id"), validator=validator)
        if value:
            return value
    return _first_string(
        data,
        ("assignment_id", "profile_assignment_id", "config_profile_assignment_id"),
        validator=validator,
    )
