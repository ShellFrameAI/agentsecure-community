import os

from typing import Dict, List

from agentsecure.core.config import JsonConfigLoader
from agentsecure.core.models import AgentSecureConfig, SecretBinding
from agentsecure.gateway.proxy import LocalGateway
from agentsecure.implementations.audit import JsonLineAuditLogger
from agentsecure.implementations.grant_store import local_grant_store_for_project
from agentsecure.implementations.policy import DefaultPolicyEngine, StrictDestinationValidator
from agentsecure.implementations.secret_store_factory import encrypted_secret_store_for_project, encrypted_secret_store_for_vault
from agentsecure.implementations.secrets import (
    ConfiguredVirtualEnvironmentProvider,
    GrantAwareTokenResolver,
    PolicyAwareTokenResolver,
    build_token_map_from_environment,
)


class Container:
    def __init__(
        self,
        config: AgentSecureConfig,
        project_root: str = ".",
        config_path: str = "agentsecure.json",
        runtime_bindings: List[SecretBinding] = None,
        run_id: str = "",
    ) -> None:
        _ = config_path
        self.config = config
        self.run_id = run_id
        self.project_id = self._project_id(project_root)
        self.bindings = self._bindings_by_token(config, runtime_bindings or [])
        self.audit_logger = JsonLineAuditLogger(config.audit.path)
        self.secret_store = encrypted_secret_store_for_project(project_root)
        self.alias_secret_store = encrypted_secret_store_for_vault()
        self.grant_store = local_grant_store_for_project(project_root)
        self.destination_validator = StrictDestinationValidator(config.network)
        self.policy_engine = DefaultPolicyEngine(
            self.destination_validator,
            config.process,
            self.audit_logger,
        )
        grant_resolver = GrantAwareTokenResolver(
            self.secret_store,
            self.grant_store,
            self.audit_logger,
            build_token_map_from_environment(self.bindings, self.secret_store),
            self.alias_secret_store,
        )
        self.token_resolver = PolicyAwareTokenResolver(
            grant_resolver,
            self.bindings,
            config.env_policy,
            self.audit_logger,
        )
        self.virtual_env_provider = ConfiguredVirtualEnvironmentProvider(
            self.bindings,
            config.env_policy,
            config,
            self.secret_store,
        )

    @classmethod
    def from_config_path(
        cls,
        path: str,
        runtime_bindings: List[SecretBinding] = None,
        run_id: str = "",
    ) -> "Container":
        config_path = os.path.abspath(path)
        project_root = os.path.dirname(config_path) or "."
        return cls(
            JsonConfigLoader().load(config_path),
            project_root,
            config_path,
            runtime_bindings,
            run_id,
        )

    def gateway(self) -> LocalGateway:
        return LocalGateway(
            self.config.gateway.host,
            self.config.gateway.port,
            self.policy_engine,
            self.token_resolver,
            self.audit_logger,
            self.bindings,
            self.config.provider_proxy,
            self.project_id,
            self.run_id,
        )

    def _bindings_by_token(self, config: AgentSecureConfig, runtime_bindings: List[SecretBinding]) -> Dict[str, SecretBinding]:
        bindings = {binding.virtual_token: binding for binding in config.secrets}
        for binding in runtime_bindings:
            bindings[binding.virtual_token] = binding
        return bindings

    def _project_id(self, project_root: str) -> str:
        import hashlib

        return hashlib.sha256(os.path.abspath(project_root).encode("utf-8")).hexdigest()[:16]
