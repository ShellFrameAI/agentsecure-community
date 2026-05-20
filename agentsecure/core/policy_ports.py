from typing import Any, Dict, Set

from agentsecure.core.capabilities import BROKER_BASE_PORT, is_valid_port


class BrokerPortAllocator:
    """Assigns stable local ports to broker capabilities in raw config data."""

    def assign(self, config: Dict[str, Any], mutation: Dict[str, Any]) -> None:
        capabilities = config.get("capabilities", {})
        if not isinstance(capabilities, dict):
            return
        referenced = self._broker_capability_names(config)
        referenced.update([str(name) for name in mutation.get("capabilities", {}).keys()])
        used = self._used_local_ports(capabilities)
        next_port = BROKER_BASE_PORT
        for name in sorted(referenced):
            capability = capabilities.get(name)
            if not isinstance(capability, dict):
                continue
            if self._has_declared_nonzero_local_port(capability):
                continue
            while next_port in used:
                next_port += 1
            capability["local_port"] = next_port
            used.add(next_port)

    def _broker_capability_names(self, config: Dict[str, Any]) -> Set[str]:
        names = set()
        env_policy = config.get("env_policy", {})
        if not isinstance(env_policy, dict):
            return names
        for rule in env_policy.values():
            if not isinstance(rule, dict):
                continue
            if str(rule.get("mode", "")) == "broker" and rule.get("capability"):
                names.add(str(rule.get("capability")))
        return names

    def _used_local_ports(self, capabilities: Dict[str, Any]) -> Set[int]:
        ports = set()
        for capability in capabilities.values():
            if not isinstance(capability, dict):
                continue
            port = self._optional_port(capability.get("local_port", 0))
            if port:
                ports.add(port)
        return ports

    def _optional_port(self, value: Any) -> int:
        try:
            port = int(value or 0)
        except (TypeError, ValueError):
            return 0
        return port if is_valid_port(port) else 0

    def _has_declared_nonzero_local_port(self, capability: Dict[str, Any]) -> bool:
        try:
            return int(capability.get("local_port", 0) or 0) != 0
        except (TypeError, ValueError):
            return True
