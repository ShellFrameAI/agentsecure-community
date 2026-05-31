import os
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

from agentsecure.core.capabilities import broker_url_for_env
from agentsecure.core.config import JsonConfigLoader
from agentsecure.core.models import SecretBinding
from agentsecure.core.runtime_bindings import runtime_bindings_from_environment
from agentsecure.implementations.secret_store_factory import encrypted_secret_store_for_config, encrypted_secret_store_for_vault
from agentsecure.interfaces.key_store import SecretStore


@dataclass(frozen=True)
class SecretReplacementMap:
    replacements: Dict[str, str]
    denied_env_names: Set[str]
    denied_values: Set[str]


class SecretOutputSanitizer:
    """Replaces real local secrets with their agent-visible virtual tokens."""

    def __init__(self, replacement_map: SecretReplacementMap) -> None:
        self._replacement_map = replacement_map

    @classmethod
    def from_config_path(cls, config_path: str) -> "SecretOutputSanitizer":
        absolute_config = os.path.abspath(config_path)
        config = JsonConfigLoader().load(absolute_config)
        secret_store = encrypted_secret_store_for_config(absolute_config)
        vault_store = encrypted_secret_store_for_vault()
        replacements = {}
        denied_values = set()
        runtime_bindings = runtime_bindings_from_environment()
        for binding in list(config.secrets) + runtime_bindings:
            store = vault_store if binding.alias_id else secret_store
            real_value = cls._real_value(store, binding)
            if not real_value:
                continue
            rule = config.env_policy.rule_for(binding.env_name)
            if rule.mode == "deny":
                denied_values.add(real_value)
            elif rule.mode == "broker":
                replacements[real_value] = broker_url_for_env(config, binding.env_name, real_value)
            else:
                replacements[real_value] = binding.virtual_token
        denied_env_names = set(
            env_name
            for env_name, rule in config.env_policy.rules.items()
            if rule.mode == "deny"
        )
        return cls(SecretReplacementMap(replacements, denied_env_names, denied_values))

    @staticmethod
    def _real_value(secret_store: SecretStore, binding: SecretBinding) -> str:
        if binding.real_secret_ref.startswith("local:"):
            secret_id = binding.real_secret_ref.split(":", 1)[1]
            return secret_store.get(secret_id) or ""
        if binding.real_secret_env:
            return os.environ.get(binding.real_secret_env, "")
        return ""

    def sanitize_bytes(self, value: bytes) -> bytes:
        if not value:
            return value
        text = value.decode("utf-8", "replace")
        return self.sanitize_text(text).encode("utf-8")

    def sanitize_text(self, value: str) -> str:
        sanitized = self._remove_denied_env_lines(value)
        for denied_value in self._ordered_denied_values():
            sanitized = sanitized.replace(denied_value, "")
        for real_value, virtual_value in self._ordered_replacements():
            sanitized = sanitized.replace(real_value, virtual_value)
        return sanitized

    def _remove_denied_env_lines(self, value: str) -> str:
        if not self._replacement_map.denied_env_names:
            return value
        lines = []
        for line in value.splitlines(True):
            env_name = self._parse_env_assignment_name(line)
            if env_name and env_name in self._replacement_map.denied_env_names:
                continue
            lines.append(line)
        return "".join(lines)

    def _parse_env_assignment_name(self, line: str):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            return None
        name = stripped.split("=", 1)[0].strip()
        if name.startswith("export "):
            name = name[len("export ") :].strip()
        return name or None

    def _ordered_replacements(self) -> List[Tuple[str, str]]:
        return sorted(
            self._replacement_map.replacements.items(),
            key=lambda item: len(item[0]),
            reverse=True,
        )

    def _ordered_denied_values(self) -> List[str]:
        return sorted(
            self._replacement_map.denied_values,
            key=len,
            reverse=True,
        )
