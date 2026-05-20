from abc import ABC, abstractmethod

from agentsecure.core.models import Destination, PolicyDecision, ProcessRequest


class DestinationValidator(ABC):
    """Validates outbound network destinations."""

    @abstractmethod
    def validate(self, destination: Destination) -> PolicyDecision:
        pass


class PolicyEngine(ABC):
    """Evaluates process, network, file, and secret access policy."""

    @abstractmethod
    def evaluate_network(self, destination: Destination) -> PolicyDecision:
        pass

    @abstractmethod
    def evaluate_process(self, request: ProcessRequest) -> PolicyDecision:
        pass

