from typing import Iterable
from urllib.parse import urlsplit


SECRET_NAME_MARKERS = (
    "API_KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "DATABASE_URL",
    "DB_URL",
    "POSTGRES_URL",
    "POSTGRESQL_URL",
    "MYSQL_URL",
    "REDIS_URL",
    "MONGO_URL",
    "MONGODB_URL",
)

PROVIDER_HINTS = (
    ("OPENAI", "openai"),
    ("ANTHROPIC", "anthropic"),
    ("GITHUB", "github"),
    ("STRIPE", "stripe"),
    ("AWS", "aws"),
    ("DATABASE", "database"),
    ("POSTGRES", "postgres"),
    ("POSTGRESQL", "postgres"),
    ("MYSQL", "mysql"),
    ("REDIS", "redis"),
    ("MONGO", "mongodb"),
    ("MONGODB", "mongodb"),
)


def looks_like_secret_name(name: str) -> bool:
    upper = name.upper()
    return any(marker in upper for marker in SECRET_NAME_MARKERS)


def is_discoverable_secret(name: str, value: str) -> bool:
    if not is_probable_secret_value(value):
        return False
    return looks_like_secret_name(name) or is_credential_url(value)


def provider_hint_for_name(name: str) -> str:
    upper = name.upper()
    for marker, provider in PROVIDER_HINTS:
        if marker in upper:
            return provider
    return "custom"


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "..." + value[-4:]


def is_probable_secret_value(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 8:
        return False
    lowered = stripped.lower()
    if lowered in ("true", "false", "localhost", "development"):
        return False
    return True


def is_credential_url(value: str) -> bool:
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return False
    if not parsed.scheme or not parsed.netloc:
        return False
    return bool(parsed.username and parsed.password)


def unique_names(names: Iterable[str]):
    seen = set()
    result = []
    for name in names:
        if name not in seen:
            seen.add(name)
            result.append(name)
    return result
