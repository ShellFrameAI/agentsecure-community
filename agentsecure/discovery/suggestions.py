import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from agentsecure.core.models import AgentSecureConfig, DiscoveredSecret, EnvKeyPolicy


HIGH_RISK_MARKERS = set(["PROD", "PRODUCTION", "ADMIN", "ROOT", "WRITE", "RW", "MASTER"])
LOWER_RISK_MARKERS = set(["DEV", "TEST", "LOCAL", "STAGING"])
READONLY_MARKERS = set(["RO", "READONLY", "READ_ONLY"])


class PolicySuggestionService:
    def __init__(self, config: AgentSecureConfig, discoveries: Iterable[DiscoveredSecret]) -> None:
        self._config = config
        self._discoveries = list(discoveries)

    def suggest(self) -> Dict[str, Any]:
        env_suggestions = []
        allowed_hosts = []
        capability_hosts = []
        for secret in self._discoveries:
            suggested_policy, reason = self._suggest_env_policy(secret)
            env_suggestions.append(
                {
                    "key": secret.name,
                    "suggested_policy": self._policy_payload(suggested_policy),
                    "reason": reason,
                }
            )
            effective_policy = self._config.env_policy.rules.get(secret.name, suggested_policy)
            host = database_url_host(secret)
            if host:
                if self._allows_network(effective_policy):
                    allowed_hosts.append((host, secret.name))
                elif effective_policy.mode == "broker":
                    capability_hosts.append((host, secret.name, effective_policy.capability))
        return {
            "env_suggestions": env_suggestions,
            "network_suggestions": self._network_suggestions(allowed_hosts),
            "capability_suggestions": self._capability_suggestions(capability_hosts),
        }

    def _suggest_env_policy(self, secret: DiscoveredSecret):
        markers = key_markers(secret.name)
        readonly = bool(markers & READONLY_MARKERS)
        high_risk = bool(markers & HIGH_RISK_MARKERS)
        lower_risk = bool(markers & LOWER_RISK_MARKERS)
        if high_risk and not readonly:
            return EnvKeyPolicy(mode="deny", access="readwrite", environment="production", risk="high"), "looks like a production write/admin secret"
        if readonly:
            return EnvKeyPolicy(mode="virtualize", access="readonly", environment="production", risk="medium"), "looks like a read-only secret"
        if lower_risk:
            return EnvKeyPolicy(mode="virtualize", access="readwrite", environment="development", risk="low"), "looks like a lower-risk development or test secret"
        return EnvKeyPolicy(mode="virtualize", risk="unknown"), "secret should be virtualized by default"

    def _network_suggestions(self, hosts: List[Tuple[str, str]]) -> List[Dict[str, str]]:
        configured = set(domain.lower() for domain in self._config.network.allow_domains)
        suggestions = []
        seen = set()
        for host, env_name in hosts:
            if host in configured or host in seen:
                continue
            seen.add(host)
            suggestions.append(
                {
                    "host": host,
                    "reason": "host is used by virtualized env key %s but is missing from network.allow_domains" % env_name,
                }
            )
        return suggestions

    def _capability_suggestions(self, hosts: List[Tuple[str, str, str]]) -> List[Dict[str, str]]:
        suggestions = []
        seen = set()
        for host, env_name, capability in hosts:
            key = (host, env_name, capability)
            if key in seen:
                continue
            seen.add(key)
            suggestions.append(
                {
                    "host": host,
                    "env_name": env_name,
                    "capability": capability,
                    "network_scope": "broker-only",
                    "reason": "host is a broker-only capability target and should not be added as normal agent direct network access",
                }
            )
        return suggestions

    def _allows_network(self, policy: EnvKeyPolicy) -> bool:
        return policy.mode == "virtualize"

    def _policy_payload(self, policy: EnvKeyPolicy) -> Dict[str, str]:
        payload = {"mode": policy.mode}
        if policy.access:
            payload["access"] = policy.access
        if policy.environment:
            payload["environment"] = policy.environment
        if policy.risk:
            payload["risk"] = policy.risk
        return payload


def key_markers(name: str):
    parts = [marker for marker in re.split(r"[^A-Z0-9]+", name.upper()) if marker]
    markers = set(parts)
    compact = "_".join(parts)
    if "READ_ONLY" in compact:
        markers.add("READ_ONLY")
    return markers


DATABASE_URL_MARKERS = set(
    [
        "DATABASE_URL",
        "DB_URL",
        "POSTGRES_URL",
        "POSTGRESQL_URL",
        "MYSQL_URL",
        "REDIS_URL",
        "MONGO_URL",
        "MONGODB_URL",
    ]
)
DATABASE_PROVIDERS = set(["database", "postgres", "mysql", "redis", "mongodb"])
DATABASE_SCHEMES = set(["postgres", "postgresql", "mysql", "mysql+pymysql", "redis", "rediss", "mongodb", "mongodb+srv"])


def database_url_host(secret: DiscoveredSecret) -> Optional[str]:
    if not _looks_like_database_url(secret):
        return None
    try:
        parsed = urlsplit(secret.value.strip())
    except ValueError:
        return None
    if not parsed.scheme or not parsed.hostname:
        return None
    return parsed.hostname.lower()


def _looks_like_database_url(secret: DiscoveredSecret) -> bool:
    upper_name = secret.name.upper()
    provider = secret.provider_hint.lower()
    if provider in DATABASE_PROVIDERS:
        return True
    if any(marker in upper_name for marker in DATABASE_URL_MARKERS):
        return True
    try:
        parsed = urlsplit(secret.value.strip())
    except ValueError:
        return False
    return parsed.scheme.lower() in DATABASE_SCHEMES
