import ipaddress
import os
import socket
from typing import Iterable

from agentsecure.core.command_metadata import safe_command_metadata
from agentsecure.core.models import (
    Destination,
    NetworkPolicy,
    PolicyDecision,
    ProcessPolicy,
    ProcessRequest,
)
from agentsecure.interfaces.audit import AuditLogger
from agentsecure.interfaces.policy import DestinationValidator, PolicyEngine


class StrictDestinationValidator(DestinationValidator):
    def __init__(self, policy: NetworkPolicy) -> None:
        self._policy = policy

    def validate(self, destination: Destination) -> PolicyDecision:
        host = destination.host.lower().rstrip(".")
        if destination.port not in self._policy.allow_ports:
            return PolicyDecision.deny("port is not allowed", "network.port")
        if self._matches_any(host, self._policy.deny_domains):
            return PolicyDecision.deny("domain is explicitly denied", "network.deny_domain")
        if self._policy.deny_ip_literals and self._is_ip_literal(host):
            return PolicyDecision.deny("IP literal destinations are denied", "network.ip_literal")
        if not self._matches_any(host, self._policy.allow_domains):
            if not destination.credentials_present:
                return PolicyDecision.allow("destination allowed without credentials", "network.no_credentials")
            return PolicyDecision.deny("domain is not allowlisted", "network.allow_domain")
        if self._policy.deny_private_networks and self._resolves_to_private_ip(host):
            return PolicyDecision.deny("domain resolves to private or loopback IP", "network.private_ip")
        return PolicyDecision.allow("destination allowed", "network.allow_domain")

    def _matches_any(self, host: str, patterns: Iterable[str]) -> bool:
        for pattern in patterns:
            normalized = pattern.lower().rstrip(".")
            if normalized.startswith("*."):
                suffix = normalized[1:]
                if host.endswith(suffix) and host != normalized[2:]:
                    return True
            elif host == normalized:
                return True
        return False

    def _is_ip_literal(self, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _resolves_to_private_ip(self, host: str) -> bool:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return True
        for info in infos:
            address = info[4][0]
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                return True
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                return True
        return False


class DefaultPolicyEngine(PolicyEngine):
    def __init__(
        self,
        destination_validator: DestinationValidator,
        process_policy: ProcessPolicy,
        audit_logger: AuditLogger,
    ) -> None:
        self._destination_validator = destination_validator
        self._process_policy = process_policy
        self._audit = audit_logger

    def evaluate_network(self, destination: Destination) -> PolicyDecision:
        decision = self._destination_validator.validate(destination)
        self._audit.record(
            "network_policy",
            {
                "scheme": destination.scheme,
                "host": destination.host,
                "port": destination.port,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "rule_id": decision.rule_id,
            },
        )
        return decision

    def evaluate_process(self, request: ProcessRequest) -> PolicyDecision:
        if not request.argv:
            decision = PolicyDecision.deny("empty command", "process.empty")
        elif not self._process_policy.allowed_commands:
            decision = PolicyDecision.allow("process allowed by default", "process.default")
        elif self._command_allowed(request.argv[0]):
            decision = PolicyDecision.allow("process command allowlisted", "process.allow_command")
        else:
            decision = PolicyDecision.deny("process command is not allowlisted", "process.allow_command")

        command_metadata = safe_command_metadata(request.argv)
        self._audit.record(
            "process_policy",
            {
                "argv": command_metadata["argv"],
                "argc": command_metadata["argc"],
                "cwd": request.cwd,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "rule_id": decision.rule_id,
            },
        )
        return decision

    def _command_allowed(self, command: str) -> bool:
        return (
            command in self._process_policy.allowed_commands
            or os.path.basename(command) in self._process_policy.allowed_commands
        )
