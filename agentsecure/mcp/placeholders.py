import json
import re
from typing import Any, Callable, Iterable, List, Set


PLACEHOLDER_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def find_placeholders(value: Any) -> List[str]:
    names = set()
    _collect(value, names)
    return sorted(names)


def replace_placeholders(value: Any, resolver: Callable[[str], str]) -> Any:
    if isinstance(value, str):
        return PLACEHOLDER_RE.sub(lambda match: resolver(match.group(1)), value)
    if isinstance(value, dict):
        return {str(key): replace_placeholders(item, resolver) for key, item in value.items()}
    if isinstance(value, list):
        return [replace_placeholders(item, resolver) for item in value]
    return value


def to_text_body(body: Any) -> str:
    if body is None:
        return ""
    if isinstance(body, str):
        return body
    return json.dumps(body, separators=(",", ":"), sort_keys=True)


def _collect(value: Any, names: Set[str]) -> None:
    if isinstance(value, str):
        names.update(match.group(1) for match in PLACEHOLDER_RE.finditer(value))
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _collect(str(key), names)
            _collect(item, names)
        return
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        for item in value:
            _collect(item, names)

