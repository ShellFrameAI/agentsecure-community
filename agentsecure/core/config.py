import copy
import json
import os
import tempfile
from typing import Any, Dict, List

from agentsecure.core.capabilities import is_loopback_host, is_valid_port
from agentsecure.core.models import (
    AgentSecureConfig,
    AuditConfig,
    Capability,
    EnvKeyPolicy,
    EnvPolicy,
    GatewayConfig,
    FilePolicy,
    NetworkPolicy,
    ProcessPolicy,
    SecretBinding,
)


class ConfigError(Exception):
    pass


class JsonConfigLoader:
    """Loads AgentSecure configuration from JSON."""

    def load(self, path: str) -> AgentSecureConfig:
        with open(path, "r") as handle:
            data = json.load(handle)
        return self.load_data(data)

    def load_data(self, data: Dict[str, Any]) -> AgentSecureConfig:
        if not isinstance(data, dict):
            raise ConfigError("config root must be a JSON object")
        return self._parse(copy.deepcopy(data))

    def _parse(self, data: Dict[str, Any]) -> AgentSecureConfig:
        secrets = self._parse_secrets(data.get("secrets", []))
        capabilities = self._parse_capabilities(data.get("capabilities", {}))
        env_policy = self._parse_env_policy(data.get("env_policy", {}), capabilities)
        network_data = data.get("network", {})
        process_data = data.get("process", {})
        files_data = data.get("files", {})
        audit_data = data.get("audit", {})
        gateway_data = data.get("gateway", {})

        return AgentSecureConfig(
            secrets=secrets,
            env_policy=env_policy,
            network=NetworkPolicy(
                allow_domains=list(network_data.get("allow_domains", [])),
                deny_domains=list(network_data.get("deny_domains", [])),
                allow_ports=list(network_data.get("allow_ports", [80, 443])),
                deny_ip_literals=bool(network_data.get("deny_ip_literals", True)),
                deny_private_networks=bool(network_data.get("deny_private_networks", True)),
            ),
            process=ProcessPolicy(
                allowed_commands=list(process_data.get("allowed_commands", [])),
            ),
            files=FilePolicy(
                protect_write=list(files_data.get("protect_write", [])),
            ),
            audit=AuditConfig(path=str(audit_data.get("path", ".agentsecure/audit.log"))),
            gateway=GatewayConfig(
                host=str(gateway_data.get("host", "127.0.0.1")),
                port=int(gateway_data.get("port", 8765)),
            ),
            capabilities=capabilities,
            raw=data,
        )

    def _parse_secrets(self, values: List[Dict[str, Any]]) -> List[SecretBinding]:
        bindings = []
        for item in values:
            bindings.append(
                SecretBinding(
                    env_name=str(item["env_name"]),
                    virtual_token=str(item["virtual_token"]),
                    real_secret_env=str(item.get("real_secret_env", "")),
                    real_secret_ref=str(item.get("real_secret_ref", "")),
                    inject_as=str(item.get("inject_as", "authorization_bearer")),
                    provider=str(item.get("provider", "custom")),
                )
            )
        return bindings

    def _parse_env_policy(self, value: Dict[str, Any], capabilities: Dict[str, Capability]) -> EnvPolicy:
        if not isinstance(value, dict):
            raise ConfigError("env_policy must be a JSON object")
        rules = {}
        for env_name, rule_data in value.items():
            if not isinstance(rule_data, dict):
                raise ConfigError("env_policy.%s must be a JSON object" % env_name)
            mode = str(rule_data.get("mode", "virtualize"))
            if mode not in ("deny", "virtualize", "broker"):
                raise ConfigError("env_policy.%s.mode must be deny, virtualize, or broker" % env_name)
            capability = str(rule_data.get("capability", ""))
            if mode == "broker":
                if not capability:
                    raise ConfigError("env_policy.%s.capability is required for broker mode" % env_name)
                if capability not in capabilities:
                    raise ConfigError("env_policy.%s.capability must reference a configured capability" % env_name)
            access = str(rule_data.get("access", ""))
            rules[str(env_name)] = EnvKeyPolicy(
                mode=mode,
                access=access,
                environment=str(rule_data.get("environment", "")),
                risk=str(rule_data.get("risk", "")),
                approved_hosts=list(rule_data.get("approved_hosts", [])),
                reason=str(rule_data.get("reason", "")),
                capability=capability,
            )
        return EnvPolicy(rules)

    def _parse_capabilities(self, value: Dict[str, Any]) -> Dict[str, Capability]:
        if not isinstance(value, dict):
            raise ConfigError("capabilities must be a JSON object")
        capabilities = {}
        for name, capability_data in value.items():
            if not isinstance(capability_data, dict):
                raise ConfigError("capabilities.%s must be a JSON object" % name)
            capability_type = str(capability_data.get("type", ""))
            target_host = str(capability_data.get("target_host", ""))
            try:
                target_port = int(capability_data.get("target_port", 0))
            except (TypeError, ValueError):
                raise ConfigError("capabilities.%s.target_port must be an integer" % name)
            try:
                local_port = int(capability_data.get("local_port", 0) or 0)
            except (TypeError, ValueError):
                raise ConfigError("capabilities.%s.local_port must be an integer" % name)
            local_host = str(capability_data.get("local_host", "127.0.0.1")).strip() or "127.0.0.1"
            if capability_type not in ("postgres",):
                raise ConfigError("capabilities.%s.type must be postgres" % name)
            if not target_host:
                raise ConfigError("capabilities.%s.target_host is required" % name)
            if not is_valid_port(target_port):
                raise ConfigError("capabilities.%s.target_port must be between 1 and 65535" % name)
            if not is_loopback_host(local_host):
                raise ConfigError("capabilities.%s.local_host must be loopback-only" % name)
            if not is_valid_port(local_port, allow_zero=True):
                raise ConfigError("capabilities.%s.local_port must be between 1 and 65535" % name)
            capabilities[str(name)] = Capability(
                name=str(name),
                type=capability_type,
                expose_as=str(capability_data.get("expose_as", "")),
                target_host=target_host,
                target_port=target_port,
                access=str(capability_data.get("access", "")),
                database=str(capability_data.get("database", "")),
                local_host=local_host,
                local_port=local_port,
            )
        return capabilities


class JsonConfigWriter:
    """Persists AgentSecure configuration without storing real secret values."""

    def save(self, path: str, data: Dict[str, Any]) -> None:
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".agentsecure-config-", dir=directory)
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.replace(temp_path, path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
