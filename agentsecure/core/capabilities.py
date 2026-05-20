import ipaddress
from typing import Optional
from urllib.parse import quote, urlsplit

from agentsecure.core.models import AgentSecureConfig, BrokerEndpointPlan, Capability, EnvKeyPolicy


BROKER_BASE_PORT = 15432


class BrokerPlanningError(ValueError):
    pass


def broker_url_for_env(
    config: AgentSecureConfig,
    env_name: str,
    real_value: str = "",
) -> str:
    return broker_endpoint_plan(config, env_name, real_value).local_url


def broker_endpoint_plan(
    config: AgentSecureConfig,
    env_name: str,
    real_value: str = "",
) -> BrokerEndpointPlan:
    rule = config.env_policy.rule_for(env_name)
    if rule.mode != "broker":
        raise BrokerPlanningError("env_policy.%s is not configured for broker mode" % env_name)
    if not rule.capability:
        raise BrokerPlanningError("env_policy.%s.capability is required for broker mode" % env_name)
    capability = config.capabilities.get(rule.capability)
    if not capability:
        raise BrokerPlanningError("env_policy.%s.capability references unknown capability %s" % (env_name, rule.capability))
    if not is_loopback_host(capability.local_host):
        raise BrokerPlanningError("capabilities.%s.local_host must be loopback-only" % capability.name)
    database = capability.database or _database_from_url(real_value)
    port = capability.local_port or assigned_local_port(config, capability.name)
    if not is_valid_port(port):
        raise BrokerPlanningError("capabilities.%s.local_port must be between 1 and 65535" % capability.name)
    path = "/" + quote(database.lstrip("/"), safe="") if database else ""
    local_url = "postgres://agentsecure@%s:%s%s" % (_url_host(capability.local_host), port, path)
    return BrokerEndpointPlan(
        env_name=env_name,
        capability=capability.name,
        type=capability.type,
        local_url=local_url,
        local_host=capability.local_host,
        local_port=port,
        target_host=capability.target_host,
        target_port=capability.target_port,
        access=capability.access,
        database=database,
    )


def capability_for_rule(config: AgentSecureConfig, rule: EnvKeyPolicy) -> Optional[Capability]:
    if rule.mode != "broker" or not rule.capability:
        return None
    return config.capabilities.get(rule.capability)


def assigned_local_port(config: AgentSecureConfig, capability_name: str) -> int:
    names = sorted(config.capabilities)
    try:
        offset = names.index(capability_name)
    except ValueError:
        offset = 0
    return BROKER_BASE_PORT + offset


def is_loopback_host(host: str) -> bool:
    host = str(host or "").strip()
    if host == "localhost":
        return True
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_valid_port(port: int, allow_zero: bool = False) -> bool:
    try:
        parsed = int(port)
    except (TypeError, ValueError):
        return False
    if allow_zero and parsed == 0:
        return True
    return 1 <= parsed <= 65535


def _url_host(host: str) -> str:
    host = str(host or "").strip()
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        return "[%s]" % host
    return host


def _database_from_url(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return ""
    return parsed.path.lstrip("/")
