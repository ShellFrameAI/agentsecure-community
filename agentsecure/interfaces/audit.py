from abc import ABC, abstractmethod
from typing import Any, Dict


class AuditLogger(ABC):
    """Records security-relevant runtime events."""

    @abstractmethod
    def record(self, event_type: str, details: Dict[str, Any]) -> None:
        pass

