import copy
import json
import os
import re
import tempfile
from typing import Any, Dict, List
from urllib.parse import urlsplit

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
    ProviderProxyConfig,
    ProviderProxyProvider,
    ProjectSecretAlias,
    ProcessPolicy,
    SecretRuntimeConfig,
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
        secret_aliases = self._parse_secret_aliases(data.get("secret_aliases", []))
        capabilities = self._parse_capabilities(data.get("capabilities", {}))
        env_policy = self._parse_env_policy(data.get("env_policy", {}), capabilities)
        network_data = data.get("network", {})
        process_data = data.get("process", {})
        files_data = data.get("files", {})
        audit_data = data.get("audit", {})
        gateway_data = data.get("gateway", {})
        gateway = self._parse_gateway(gateway_data)
        secret_runtime = self._parse_secret_runtime(data.get("secret_runtime", {}))
        provider_proxy = self._parse_provider_proxy(data.get("provider_proxy", {}))

        return AgentSecureConfig(
            secrets=secrets,
            secret_aliases=secret_aliases,
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
            gateway=gateway,
            secret_runtime=secret_runtime,
            provider_proxy=provider_proxy,
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
                    expires_at=(float(item["expires_at"]) if "expires_at" in item else None),
                    alias_id=str(item.get("alias_id", "")),
                    approved_hosts=list(item.get("approved_hosts", [])),
                )
            )
        return bindings

    def _parse_secret_aliases(self, values: List[Dict[str, Any]]) -> List[ProjectSecretAlias]:
        if not isinstance(values, list):
            raise ConfigError("secret_aliases must be a list")
        aliases = []
        for item in values:
            if not isinstance(item, dict):
                raise ConfigError("secret_aliases entries must be JSON objects")
            alias_id = str(item.get("alias_id", item.get("alias", ""))).strip()
            if not alias_id:
                raise ConfigError("secret_aliases.alias_id is required")
            mode = str(item.get("mode", "virtualize"))
            if mode not in ("deny", "virtualize"):
                raise ConfigError("secret_aliases.%s.mode must be deny or virtualize" % alias_id)
            aliases.append(
                ProjectSecretAlias(
                    alias_id=alias_id,
                    env_name=str(item.get("env_name", "")),
                    provider=str(item.get("provider", "")),
                    inject_as=str(item.get("inject_as", "authorization_bearer")),
                    approved_hosts=list(item.get("approved_hosts", [])),
                    required=bool(item.get("required", True)),
                    mode=mode,
                )
            )
        return aliases

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

    def _parse_provider_proxy(self, value: Dict[str, Any]) -> ProviderProxyConfig:
        if not value:
            return ProviderProxyConfig()
        if not isinstance(value, dict):
            raise ConfigError("provider_proxy must be a JSON object")
        providers_data = value.get("providers", {})
        if not isinstance(providers_data, dict):
            raise ConfigError("provider_proxy.providers must be a JSON object")
        providers = {}
        for name, provider_data in providers_data.items():
            if not isinstance(provider_data, dict):
                raise ConfigError("provider_proxy.providers.%s must be a JSON object" % name)
            provider_name = str(name).strip()
            env_name = str(provider_data.get("env_name", "")).strip()
            base_url_env = str(provider_data.get("base_url_env", "")).strip()
            upstream = str(provider_data.get("upstream", "")).strip().rstrip("/")
            local_path = "/" + str(provider_data.get("local_path", "")).strip().strip("/")
            inject_as = str(provider_data.get("inject_as", "authorization_bearer"))
            allow_paths_value = provider_data.get("allow_paths", [])
            if not provider_name:
                raise ConfigError("provider_proxy provider name is required")
            self._validate_env_name("provider_proxy.providers.%s.env_name" % provider_name, env_name)
            self._validate_env_name("provider_proxy.providers.%s.base_url_env" % provider_name, base_url_env)
            self._validate_upstream("provider_proxy.providers.%s.upstream" % provider_name, upstream)
            if local_path == "/":
                raise ConfigError("provider_proxy.providers.%s.local_path is required" % provider_name)
            if inject_as != "authorization_bearer":
                raise ConfigError("provider_proxy.providers.%s.inject_as must be authorization_bearer" % provider_name)
            if not isinstance(allow_paths_value, list):
                raise ConfigError("provider_proxy.providers.%s.allow_paths must be a list" % provider_name)
            allow_paths = [str(path) for path in allow_paths_value]
            providers[provider_name] = ProviderProxyProvider(
                name=provider_name,
                env_name=env_name,
                base_url_env=base_url_env,
                upstream=upstream,
                local_path=local_path,
                inject_as=inject_as,
                allow_paths=allow_paths,
            )
        self._validate_provider_proxy_paths(providers)
        return ProviderProxyConfig(
            enabled=bool(value.get("enabled", False)),
            providers=providers,
        )

    def _validate_provider_proxy_paths(self, providers: Dict[str, ProviderProxyProvider]) -> None:
        paths = []
        for provider in providers.values():
            local_path = provider.local_path.rstrip("/")
            for existing_name, existing_path in paths:
                if (
                    local_path == existing_path
                    or local_path.startswith(existing_path + "/")
                    or existing_path.startswith(local_path + "/")
                ):
                    raise ConfigError(
                        "provider_proxy.providers.%s.local_path overlaps with provider_proxy.providers.%s.local_path"
                        % (provider.name, existing_name)
                    )
            paths.append((provider.name, local_path))

    def _parse_gateway(self, gateway_data: Dict[str, Any]) -> GatewayConfig:
        host = str(gateway_data.get("host", "127.0.0.1")).strip() or "127.0.0.1"
        try:
            port = int(gateway_data.get("port", 8765))
        except (TypeError, ValueError):
            raise ConfigError("gateway.port must be an integer")
        if not is_loopback_host(host):
            raise ConfigError("gateway.host must be loopback-only")
        if not is_valid_port(port):
            raise ConfigError("gateway.port must be between 1 and 65535")
        return GatewayConfig(host=host, port=port)

    def _parse_secret_runtime(self, value: Dict[str, Any]) -> SecretRuntimeConfig:
        if not value:
            return SecretRuntimeConfig()
        if not isinstance(value, dict):
            raise ConfigError("secret_runtime must be a JSON object")
        mode = str(value.get("mode", "virtual")).strip() or "virtual"
        if mode not in ("strict", "virtual", "compat"):
            raise ConfigError("secret_runtime.mode must be strict, virtual, or compat")
        return SecretRuntimeConfig(mode=mode)

    def _validate_env_name(self, path: str, value: str) -> None:
        if not value:
            raise ConfigError("%s is required" % path)
        if not re.match(r"^[A-Z_][A-Z0-9_]*$", value):
            raise ConfigError("%s must be an uppercase environment variable name" % path)
        blocked = {
            "PATH",
            "HOME",
            "SHELL",
            "PYTHONPATH",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "NO_PROXY",
            "no_proxy",
        }
        if value in blocked:
            raise ConfigError("%s must not override critical process environment" % path)

    def _validate_upstream(self, path: str, upstream: str) -> None:
        parsed = urlsplit(upstream)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ConfigError("%s must be an https URL with a host" % path)
        try:
            port = parsed.port
        except ValueError:
            raise ConfigError("%s port is invalid" % path)
        if port is not None and not is_valid_port(port):
            raise ConfigError("%s port must be between 1 and 65535" % path)

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
