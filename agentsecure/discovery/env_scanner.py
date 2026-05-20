import os
from typing import List, Mapping, Optional

from agentsecure.core.models import DiscoveredSecret
from agentsecure.discovery.patterns import (
    is_discoverable_secret,
    provider_hint_for_name,
)
from agentsecure.discovery.scanner import SecretScanner


class EnvironmentSecretScanner(SecretScanner):
    def __init__(self, environment: Optional[Mapping[str, str]] = None) -> None:
        self._environment = environment if environment is not None else os.environ

    def scan(self) -> List[DiscoveredSecret]:
        results = []
        for name, value in sorted(self._environment.items()):
            if is_discoverable_secret(name, value):
                results.append(
                    DiscoveredSecret(
                        name=name,
                        source="env",
                        value=value,
                        confidence="high",
                        provider_hint=provider_hint_for_name(name),
                    )
                )
        return results
