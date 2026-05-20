from abc import ABC, abstractmethod
from typing import Dict, Optional


class TokenResolver(ABC):
    """Maps virtual tokens to real secret material."""

    @abstractmethod
    def resolve(self, virtual_token: str) -> Optional[str]:
        pass


class VirtualEnvironmentProvider(ABC):
    """Builds the environment exposed to the AI agent."""

    @abstractmethod
    def build_environment(self) -> Dict[str, str]:
        pass

