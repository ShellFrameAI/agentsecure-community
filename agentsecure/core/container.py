import os

from typing import Dict

from agentsecure.core.config import JsonConfigLoader
from agentsecure.core.models import AgentSecureConfig, SecretBinding
from agentsecure.gateway.proxy import LocalGateway
from agentsecure.implementations.audit import JsonLineAuditLogger
from agentsecure.implementations.grant_store import LocalJsonGrantStore
from agentsecure.implementations.policy import DefaultPolicyEngine, StrictDestinationValidator
from agentsecure.implementations.secret_store_factory import encrypted_secret_store_for_project
from agentsecure.implementations.secrets import (
    ConfiguredVirtualEnvironmentProvider,
    GrantAwareTokenResolver,
    build_token_map_from_environment,
)


class Container:
    def __init__(
        self,
        config: AgentSecureConfig,
        project_root: str = ".",
        config_path: str = "agentsecure.json",
    ) -> None:
        _ = config_path
        self.config = config
        self.bindings = self._bindings_by_token(config)
        self.audit_logger = JsonLineAuditLogger(config.audit.path)
        self.secret_store = encrypted_secret_store_for_project(project_root)
        self.grant_store = LocalJsonGrantStore()
        self.destination_validator = StrictDestinationValidator(config.network)
        self.policy_engine = DefaultPolicyEngine(
            self.destination_validator,
            config.process,
            self.audit_logger,
        )
        self.token_resolver = GrantAwareTokenResolver(
            self.secret_store,
            self.grant_store,
            self.audit_logger,
            build_token_map_from_environment(self.bindings, self.secret_store),
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
    ) -> "Container":
        config_path = os.path.abspath(path)
        project_root = os.path.dirname(config_path) or "."
        return cls(
            JsonConfigLoader().load(config_path),
            project_root,
            config_path,
        )

    def gateway(self) -> LocalGateway:
        return LocalGateway(
            self.config.gateway.host,
            self.config.gateway.port,
            self.policy_engine,
            self.token_resolver,
            self.audit_logger,
            self.bindings,
        )

    def _bindings_by_token(self, config: AgentSecureConfig) -> Dict[str, SecretBinding]:
        return {binding.virtual_token: binding for binding in config.secrets}
