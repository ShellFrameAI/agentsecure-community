from dataclasses import asdict
from typing import Any, Dict, List

from agentsecure.core.capabilities import broker_endpoint_plan
from agentsecure.core.models import AgentSecureConfig, EnvKeyPolicy


class LocalPolicyResponseRenderer:
    """Renders validated local policy state for CLI/API clients."""

    def response(self, config: AgentSecureConfig, changed: bool, applied: bool) -> Dict[str, Any]:
        return {
            "valid": True,
            "changed": bool(changed),
            "applied": bool(applied),
            "env_policy": self._env_policy_payload(config),
            "capabilities": self._capabilities_payload(config),
            "broker_endpoint_plans": self._broker_endpoint_plans(config),
        }

    def _env_policy_payload(self, config: AgentSecureConfig) -> Dict[str, Any]:
        return {
            env_name: self._env_rule_payload(rule)
            for env_name, rule in sorted(config.env_policy.rules.items())
        }

    def _env_rule_payload(self, rule: EnvKeyPolicy) -> Dict[str, Any]:
        payload = {"mode": rule.mode}
        if rule.access:
            payload["access"] = rule.access
        if rule.environment:
            payload["environment"] = rule.environment
        if rule.risk:
            payload["risk"] = rule.risk
        if rule.approved_hosts:
            payload["approved_hosts"] = list(rule.approved_hosts)
        if rule.reason:
            payload["reason"] = rule.reason
        if rule.capability:
            payload["capability"] = rule.capability
        return payload

    def _capabilities_payload(self, config: AgentSecureConfig) -> Dict[str, Any]:
        payload = {}
        for name, capability in sorted(config.capabilities.items()):
            row = {
                "type": capability.type,
                "target_host": capability.target_host,
                "target_port": capability.target_port,
                "local_host": capability.local_host,
                "local_port": capability.local_port,
            }
            if capability.expose_as:
                row["expose_as"] = capability.expose_as
            if capability.access:
                row["access"] = capability.access
            if capability.database:
                row["database"] = capability.database
            payload[name] = row
        return payload

    def _broker_endpoint_plans(self, config: AgentSecureConfig) -> List[Dict[str, Any]]:
        plans = []
        for env_name, rule in sorted(config.env_policy.rules.items()):
            if rule.mode != "broker":
                continue
            plans.append(asdict(broker_endpoint_plan(config, env_name)))
        return plans
