from abc import ABC, abstractmethod
from typing import List, Optional

from agentsecure.core.models import SecretGrant


class GrantStore(ABC):
    @abstractmethod
    def put(self, grant: SecretGrant) -> None:
        pass

    @abstractmethod
    def get_by_virtual_token(self, virtual_token: str) -> Optional[SecretGrant]:
        pass

    @abstractmethod
    def list(self) -> List[SecretGrant]:
        pass

    @abstractmethod
    def revoke(self, virtual_token: str) -> bool:
        pass

