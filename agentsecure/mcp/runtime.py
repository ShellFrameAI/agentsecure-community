import os
import uuid
from typing import Dict, Iterable, List, Tuple

from agentsecure.core.config import JsonConfigLoader
from agentsecure.core.container import Container
from agentsecure.core.models import SecretBinding
from agentsecure.core.secret_aliases import (
    SecretAliasError,
    SecretAliasService,
    local_secret_alias_store_for_home,
    project_id_for_path,
)
from agentsecure.core.time import DurationError
from agentsecure.implementations.audit import JsonLineAuditLogger
from agentsecure.implementations.grant_store import local_grant_store_for_config
from agentsecure.implementations.secret_store_factory import agentsecure_home, encrypted_secret_store_for_vault


def describe_config(config_path: str) -> Dict:
    config = JsonConfigLoader().load(os.path.abspath(config_path))
    aliases = []
    for alias in config.secret_aliases:
        aliases.append(
            {
                "alias_id": alias.alias_id,
                "env_name": alias.env_name,
                "provider": alias.provider,
                "mode": alias.mode,
                "approved_hosts": list(alias.approved_hosts),
                "required": alias.required,
            }
        )
    project_bindings = []
    for binding in config.secrets:
        project_bindings.append(
            {
                "env_name": binding.env_name,
                "provider": binding.provider,
                "inject_as": binding.inject_as,
            }
        )
    return {
        "network": {
            "allow_domains": list(config.network.allow_domains),
            "allow_ports": list(config.network.allow_ports),
            "deny_ip_literals": config.network.deny_ip_literals,
            "deny_private_networks": config.network.deny_private_networks,
        },
        "secret_aliases": aliases,
        "project_bindings": project_bindings,
        "instructions": [
            "Use agentsecure.http.request only for calls that need configured secrets.",
            "Put placeholders such as ${API_KEY} in headers, query, JSON, or body.",
            "AgentSecure resolves placeholders only for policy-approved destinations and never returns raw secret values.",
        ],
    }


def prepare_mcp_container(config_path: str, ttl: str = "2h") -> Tuple[Container, List[SecretBinding], str]:
    absolute_config = os.path.abspath(config_path)
    config = JsonConfigLoader().load(absolute_config)
    run_id = "mcp_" + uuid.uuid4().hex[:16]
    bindings = []
    if config.secret_aliases:
        bindings = secret_alias_service(absolute_config).prepare_run_bindings(
            config.secret_aliases,
            ttl,
            project_id_for_path(absolute_config),
            run_id,
        )
    return Container.from_config_path(absolute_config, runtime_bindings=bindings, run_id=run_id), bindings, run_id


def revoke_mcp_bindings(config_path: str, bindings: Iterable[SecretBinding], run_id: str) -> None:
    secret_alias_service(os.path.abspath(config_path)).revoke_run_bindings(bindings, run_id)


def secret_alias_service(config_path: str) -> SecretAliasService:
    home = agentsecure_home()
    return SecretAliasService(
        local_secret_alias_store_for_home(home),
        encrypted_secret_store_for_vault(),
        local_grant_store_for_config(config_path),
        JsonLineAuditLogger(".agentsecure/audit.log"),
    )


def env_token_map(container: Container) -> Dict[str, str]:
    return {binding.env_name: binding.virtual_token for binding in container.bindings.values() if binding.env_name}


def safe_secret_status(config_path: str, env_name: str) -> Dict:
    config = JsonConfigLoader().load(os.path.abspath(config_path))
    for alias in config.secret_aliases:
        if alias.env_name == env_name:
            return {
                "exists": True,
                "source": "vault_alias",
                "alias_id": alias.alias_id,
                "env_name": alias.env_name,
                "provider": alias.provider,
                "mode": alias.mode,
                "approved_hosts": list(alias.approved_hosts),
            }
    for binding in config.secrets:
        if binding.env_name == env_name:
            return {
                "exists": True,
                "source": "project_binding",
                "env_name": binding.env_name,
                "provider": binding.provider,
                "mode": config.env_policy.rule_for(binding.env_name).mode,
            }
    return {"exists": False, "env_name": env_name}


__all__ = [
    "DurationError",
    "SecretAliasError",
    "describe_config",
    "env_token_map",
    "prepare_mcp_container",
    "revoke_mcp_bindings",
    "safe_secret_status",
]

