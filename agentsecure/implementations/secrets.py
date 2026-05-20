import os
from typing import Dict, Optional

from agentsecure.core.time import now_seconds
from agentsecure.core.capabilities import broker_url_for_env
from agentsecure.core.models import AgentSecureConfig, EnvPolicy, SecretBinding
from agentsecure.interfaces.audit import AuditLogger
from agentsecure.interfaces.grants import GrantStore
from agentsecure.interfaces.key_store import SecretStore
from agentsecure.interfaces.secrets import TokenResolver, VirtualEnvironmentProvider


class InMemoryTokenResolver(TokenResolver):
    """Resolves virtual tokens to real secrets loaded from local env vars."""

    def __init__(self, token_map: Dict[str, str], audit_logger: AuditLogger) -> None:
        self._token_map = token_map
        self._audit = audit_logger

    def resolve(self, virtual_token: str) -> Optional[str]:
        secret = self._token_map.get(virtual_token)
        self._audit.record(
            "secret_resolution",
            {
                "virtual_token": virtual_token,
                "resolved": secret is not None,
            },
        )
        return secret


class GrantAwareTokenResolver(TokenResolver):
    """Resolves virtual tokens only while their grant is active."""

    def __init__(
        self,
        secret_store: SecretStore,
        grant_store: GrantStore,
        audit_logger: AuditLogger,
        legacy_token_map: Optional[Dict[str, str]] = None,
    ) -> None:
        self._secret_store = secret_store
        self._grant_store = grant_store
        self._audit = audit_logger
        self._legacy_token_map = legacy_token_map or {}

    def resolve(self, virtual_token: str) -> Optional[str]:
        grant = self._grant_store.get_by_virtual_token(virtual_token)
        if grant:
            if grant.status != "active":
                self._audit.record(
                    "secret_resolution_revoked",
                    {"virtual_token": virtual_token, "status": grant.status},
                )
                return None
            if grant.expires_at <= now_seconds():
                self._audit.record(
                    "secret_resolution_expired",
                    {"virtual_token": virtual_token, "expires_at": grant.expires_at},
                )
                return None
            secret = None
            if grant.secret_ref.startswith("local:"):
                secret = self._secret_store.get(grant.secret_ref.split(":", 1)[1])
            self._audit.record(
                "secret_resolution",
                {
                    "virtual_token": virtual_token,
                    "resolved": secret is not None,
                    "expires_at": grant.expires_at,
                },
            )
            return secret

        secret = self._legacy_token_map.get(virtual_token)
        self._audit.record(
            "secret_resolution",
            {
                "virtual_token": virtual_token,
                "resolved": secret is not None,
                "legacy": True,
            },
        )
        return secret


class ConfiguredVirtualEnvironmentProvider(VirtualEnvironmentProvider):
    def __init__(
        self,
        bindings: Dict[str, SecretBinding],
        env_policy: Optional[EnvPolicy] = None,
        config: Optional[AgentSecureConfig] = None,
        secret_store: Optional[SecretStore] = None,
    ) -> None:
        self._bindings = bindings
        self._env_policy = env_policy or EnvPolicy()
        self._config = config
        self._secret_store = secret_store

    def build_environment(self) -> Dict[str, str]:
        environment = {}
        for binding in self._bindings.values():
            rule = self._env_policy.rule_for(binding.env_name)
            if rule.mode == "deny":
                continue
            if rule.mode == "broker" and self._config:
                environment[binding.env_name] = broker_url_for_env(
                    self._config,
                    binding.env_name,
                    _real_value_for_binding(binding, self._secret_store),
                )
                continue
            environment[binding.env_name] = binding.virtual_token
        return environment


def _real_value_for_binding(binding: SecretBinding, secret_store: Optional[SecretStore] = None) -> str:
    if binding.real_secret_ref.startswith("local:") and secret_store:
        return secret_store.get(binding.real_secret_ref.split(":", 1)[1]) or ""
    if binding.real_secret_env:
        return os.environ.get(binding.real_secret_env, "")
    return ""


def build_token_map_from_environment(
    bindings: Dict[str, SecretBinding],
    secret_store: Optional[SecretStore] = None,
) -> Dict[str, str]:
    token_map = {}
    for binding in bindings.values():
        value = None
        if binding.real_secret_ref.startswith("local:") and secret_store:
            value = secret_store.get(binding.real_secret_ref.split(":", 1)[1])
        if not value and binding.real_secret_env:
            value = os.environ.get(binding.real_secret_env)
        if value:
            token_map[binding.virtual_token] = value
    return token_map
