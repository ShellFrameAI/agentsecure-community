from abc import ABC, abstractmethod
from typing import List

from agentsecure.core.models import DiscoveredSecret


class SecretScanner(ABC):
    @abstractmethod
    def scan(self) -> List[DiscoveredSecret]:
        pass


class CompositeSecretScanner(SecretScanner):
    def __init__(self, scanners: List[SecretScanner]) -> None:
        self._scanners = scanners

    def scan(self) -> List[DiscoveredSecret]:
        results = []
        seen = set()
        for scanner in self._scanners:
            for secret in scanner.scan():
                key = (secret.name, secret.source)
                if key not in seen:
                    seen.add(key)
                    results.append(secret)
        return results

