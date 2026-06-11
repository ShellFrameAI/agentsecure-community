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

    def resolve(self, virtual_token: str, context: Optional[Dict] = None) -> Optional[str]:
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
        alias_secret_store: Optional[SecretStore] = None,
    ) -> None:
        self._secret_store = secret_store
        self._alias_secret_store = alias_secret_store or secret_store
        self._grant_store = grant_store
        self._audit = audit_logger
        self._legacy_token_map = legacy_token_map or {}

    def resolve(self, virtual_token: str, context: Optional[Dict] = None) -> Optional[str]:
        context = context or {}
        grant = self._grant_store.get_by_virtual_token(virtual_token)
        if grant:
            if grant.status != "active":
                self._audit.record(
                    "secret_resolution_revoked",
                    {"virtual_token": virtual_token, "status": grant.status},
                )
                return None
            expected_project_id = str(context.get("project_id", ""))
            if grant.project_id and grant.project_id != expected_project_id:
                self._audit.record(
                    "secret_resolution_wrong_project",
                    {"virtual_token": virtual_token, "project_id": expected_project_id},
                )
                return None
            expected_run_id = str(context.get("run_id", ""))
            if grant.run_id and grant.run_id != expected_run_id:
                self._audit.record(
                    "secret_resolution_wrong_run",
                    {"virtual_token": virtual_token, "run_id": expected_run_id},
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
                store = self._alias_secret_store if grant.alias_id else self._secret_store
                secret = store.get(grant.secret_ref.split(":", 1)[1])
            self._audit.record(
                "secret_resolution",
                {
                    "virtual_token": virtual_token,
                    "resolved": secret is not None,
                    "expires_at": grant.expires_at,
                    "alias_id": grant.alias_id,
                    "scope": grant.scope,
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


class PolicyAwareTokenResolver(TokenResolver):
    """Blocks alias token injection unless the destination is approved for that alias."""

    def __init__(
        self,
        delegate: TokenResolver,
        bindings: Dict[str, SecretBinding],
        env_policy: Optional[EnvPolicy],
        audit_logger: AuditLogger,
    ) -> None:
        self._delegate = delegate
        self._bindings = bindings
        self._env_policy = env_policy or EnvPolicy()
        self._audit = audit_logger

    def resolve(self, virtual_token: str, context: Optional[Dict] = None) -> Optional[str]:
        context = context or {}
        binding = self._bindings.get(virtual_token)
        if binding:
            rule = self._env_policy.rule_for(binding.env_name)
            if rule.mode in ("broker", "deny"):
                self._audit.record(
                    "secret_resolution_denied",
                    {"virtual_token": virtual_token, "env_name": binding.env_name, "mode": rule.mode},
                )
                return None
            approved_hosts = binding.approved_hosts or rule.approved_hosts
            host = str(context.get("host", "")).lower().rstrip(".")
            if binding.alias_id and approved_hosts:
                if not host or not _host_matches_any(host, approved_hosts):
                    self._audit.record(
                        "secret_resolution_wrong_destination",
                        {
                            "virtual_token": virtual_token,
                            "env_name": binding.env_name,
                            "alias_id": binding.alias_id,
                            "host": host,
                        },
                    )
                    return None
        return self._delegate.resolve(virtual_token, context)


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
        if binding.expires_at is not None:
            continue
        value = None
        if binding.real_secret_ref.startswith("local:") and secret_store:
            value = secret_store.get(binding.real_secret_ref.split(":", 1)[1])
        if not value and binding.real_secret_env:
            value = os.environ.get(binding.real_secret_env)
        if value:
            token_map[binding.virtual_token] = value
    return token_map


def _host_matches_any(host: str, patterns) -> bool:
    for pattern in patterns:
        normalized = str(pattern).lower().rstrip(".")
        if not normalized:
            continue
        if normalized.startswith("*."):
            suffix = normalized[1:]
            if host.endswith(suffix) and host != normalized[2:]:
                return True
        elif host == normalized:
            return True
    return False
