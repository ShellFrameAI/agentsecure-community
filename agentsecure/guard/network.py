from dataclasses import dataclass
import os
from typing import List
from urllib.parse import urlsplit

from agentsecure.core.container import Container
from agentsecure.core.models import Destination


NETWORK_TOOLS = {"curl", "wget"}


@dataclass(frozen=True)
class GuardedNetworkDecision:
    allowed: bool
    reason: str
    host: str
    port: int
    rule_id: str = ""


class GuardedNetworkCommandPolicy:
    """Preflights credential-bearing network CLI commands before TLS hides headers."""

    def __init__(self, config_path: str) -> None:
        self._config_path = config_path

    def validate(self, tool: str, args: List[str]):
        if tool not in NETWORK_TOOLS:
            return None
        if not self._has_visible_credentials(args):
            return None

        container = Container.from_config_path(self._config_path)
        for url in self._urls(args):
            parsed = urlsplit(url)
            scheme = parsed.scheme or "http"
            host = parsed.hostname or ""
            if not host:
                continue
            port = parsed.port or (443 if scheme == "https" else 80)
            decision = container.policy_engine.evaluate_network(
                Destination(scheme, host, port, credentials_present=True)
            )
            if not decision.allowed:
                container.audit_logger.record(
                    "guarded_network_command_blocked",
                    {
                        "tool": tool,
                        "session_id": os.environ.get("AGENTSECURE_SESSION_ID", ""),
                        "host": host,
                        "port": port,
                        "allowed": False,
                        "credentials_present": True,
                        "reason": decision.reason,
                    },
                )
                return GuardedNetworkDecision(
                    allowed=False,
                    reason=decision.reason,
                    host=host,
                    port=port,
                    rule_id=decision.rule_id or "",
                )
        return None

    def _has_visible_credentials(self, args: List[str]) -> bool:
        joined = " ".join(args).lower()
        if "virt_" in joined:
            return True
        markers = [
            "authorization:",
            "x-api-key:",
            "api-key:",
            "apikey:",
            "openai-api-key:",
            "anthropic-api-key:",
            "api_key=",
            "apikey=",
            "access_token=",
            "auth_token=",
            "token=",
        ]
        return any(marker in joined for marker in markers)

    def _urls(self, args: List[str]) -> List[str]:
        urls = []
        for arg in args:
            lowered = arg.lower()
            if lowered.startswith("http://") or lowered.startswith("https://"):
                urls.append(arg)
        return urls
