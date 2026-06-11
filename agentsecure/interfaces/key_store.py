from abc import ABC, abstractmethod
from typing import Optional


class SecretStore(ABC):
    """Stores real secrets outside the agent-visible config."""

    @abstractmethod
    def put(self, secret_id: str, secret_value: str) -> None:
        pass

    @abstractmethod
    def get(self, secret_id: str) -> Optional[str]:
        pass

    def delete(self, secret_id: str) -> bool:
        return False
