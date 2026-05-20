import copy
import json
import os
from typing import Any, Dict

from agentsecure.core.capabilities import is_valid_port
from agentsecure.core.config import JsonConfigLoader, JsonConfigWriter
from agentsecure.core.policy_ports import BrokerPortAllocator
from agentsecure.core.policy_response import LocalPolicyResponseRenderer
from agentsecure.core.policy_validation import CAPABILITY_FIELDS, ENV_POLICY_FIELDS, PolicyMutationValidator


class LocalPolicyMutationService:
    """Applies semantic local policy edits without accepting real secret material."""

    def __init__(
        self,
        config_path: str,
        loader: JsonConfigLoader = None,
        writer: JsonConfigWriter = None,
        validator: PolicyMutationValidator = None,
        port_allocator: BrokerPortAllocator = None,
        renderer: LocalPolicyResponseRenderer = None,
    ) -> None:
        self.config_path = config_path
        self.loader = loader or JsonConfigLoader()
        self.writer = writer or JsonConfigWriter()
        self.validator = validator or PolicyMutationValidator()
        self.port_allocator = port_allocator or BrokerPortAllocator()
        self.renderer = renderer or LocalPolicyResponseRenderer()

    def review(self) -> Dict[str, Any]:
        current = self._load_raw_config()
        config = self.loader.load_data(current)
        return self.renderer.response(config, changed=False, applied=False)

    def preview(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        mutation = self._build_mutation(payload)
        return self.renderer.response(mutation["config"], changed=mutation["changed"], applied=False)

    def apply_local(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        mutation = self._build_mutation(payload)
        if mutation["changed"]:
            self.writer.save(self.config_path, mutation["next_config"])
        return self.renderer.response(mutation["config"], changed=mutation["changed"], applied=mutation["changed"])

    def _build_mutation(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        current = self._load_raw_config()
        next_config = copy.deepcopy(current)
        mutation = self.validator.extract_policy_payload(payload)
        self._merge_env_policy(next_config, mutation)
        self._merge_capabilities(next_config, mutation)
        self.port_allocator.assign(next_config, mutation)
        config = self.loader.load_data(next_config)
        return {
            "next_config": next_config,
            "config": config,
            "changed": self._canonical(current) != self._canonical(next_config),
        }

    def _merge_env_policy(self, config: Dict[str, Any], mutation: Dict[str, Any]) -> None:
        if "env_policy" not in mutation:
            return
        updates = mutation.get("env_policy", {})
        if not isinstance(updates, dict):
            raise ValueError("env_policy must be a JSON object")
        current = config.setdefault("env_policy", {})
        if not isinstance(current, dict):
            raise ValueError("current env_policy must be a JSON object")
        for env_name, rule in updates.items():
            if not isinstance(rule, dict):
                raise ValueError("env_policy.%s must be a JSON object" % env_name)
            self.validator.validate_fields("env_policy.%s" % env_name, rule, ENV_POLICY_FIELDS)
            next_rule = dict(current.get(str(env_name), {})) if isinstance(current.get(str(env_name), {}), dict) else {}
            for field, value in rule.items():
                self.validator.reject_raw_secret_value("env_policy.%s.%s" % (env_name, field), value)
                if field == "approved_hosts":
                    if not isinstance(value, list):
                        raise ValueError("env_policy.%s.approved_hosts must be a list" % env_name)
                    next_rule[field] = [str(item).strip() for item in value if str(item).strip()]
                else:
                    next_rule[field] = "" if value is None else str(value)
            current[str(env_name)] = next_rule

    def _merge_capabilities(self, config: Dict[str, Any], mutation: Dict[str, Any]) -> None:
        if "capabilities" not in mutation:
            return
        updates = mutation.get("capabilities", {})
        if not isinstance(updates, dict):
            raise ValueError("capabilities must be a JSON object")
        current = config.setdefault("capabilities", {})
        if not isinstance(current, dict):
            raise ValueError("current capabilities must be a JSON object")
        for name, capability in updates.items():
            if not isinstance(capability, dict):
                raise ValueError("capabilities.%s must be a JSON object" % name)
            self.validator.validate_fields("capabilities.%s" % name, capability, CAPABILITY_FIELDS)
            next_capability = (
                dict(current.get(str(name), {})) if isinstance(current.get(str(name), {}), dict) else {}
            )
            for field, value in capability.items():
                self.validator.reject_raw_secret_value("capabilities.%s.%s" % (name, field), value)
                if field in ("target_port", "local_port"):
                    try:
                        port = int(value or 0)
                    except (TypeError, ValueError):
                        raise ValueError("capabilities.%s.%s must be an integer" % (name, field))
                    if field == "target_port" and not is_valid_port(port):
                        raise ValueError("capabilities.%s.target_port must be between 1 and 65535" % name)
                    if field == "local_port" and not is_valid_port(port, allow_zero=True):
                        raise ValueError("capabilities.%s.local_port must be between 1 and 65535" % name)
                    next_capability[field] = port
                else:
                    next_capability[field] = "" if value is None else str(value)
            current[str(name)] = next_capability

    def _load_raw_config(self) -> Dict[str, Any]:
        if not os.path.exists(self.config_path):
            return {}
        with open(self.config_path, "r") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise ValueError("config root must be a JSON object")
        return data

    def _canonical(self, data: Dict[str, Any]) -> str:
        return json.dumps(data, sort_keys=True, separators=(",", ":"))
