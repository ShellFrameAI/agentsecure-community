from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Destination:
    scheme: str
    host: str
    port: int
    credentials_present: bool = True


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    rule_id: Optional[str] = None

    @staticmethod
    def allow(reason: str = "allowed", rule_id: Optional[str] = None) -> "PolicyDecision":
        return PolicyDecision(True, reason, rule_id)

    @staticmethod
    def deny(reason: str, rule_id: Optional[str] = None) -> "PolicyDecision":
        return PolicyDecision(False, reason, rule_id)


@dataclass(frozen=True)
class SecretBinding:
    env_name: str
    virtual_token: str
    real_secret_env: str = ""
    real_secret_ref: str = ""
    inject_as: str = "authorization_bearer"
    provider: str = "custom"


@dataclass(frozen=True)
class EnvKeyPolicy:
    mode: str = "virtualize"
    access: str = ""
    environment: str = ""
    risk: str = ""
    approved_hosts: List[str] = field(default_factory=list)
    reason: str = ""
    capability: str = ""

    def __post_init__(self) -> None:
        if self.mode not in ("deny", "virtualize", "broker"):
            raise ValueError("env policy mode must be deny, virtualize, or broker")


@dataclass
class EnvPolicy:
    rules: Dict[str, EnvKeyPolicy] = field(default_factory=dict)

    def rule_for(self, env_name: str) -> EnvKeyPolicy:
        return self.rules.get(env_name, EnvKeyPolicy())


@dataclass(frozen=True)
class DiscoveredSecret:
    name: str
    source: str
    value: str
    confidence: str
    provider_hint: str = "custom"


@dataclass(frozen=True)
class SecretGrant:
    env_name: str
    virtual_token: str
    secret_ref: str
    provider: str
    inject_as: str
    created_at: float
    expires_at: float
    status: str = "active"


@dataclass(frozen=True)
class SecretReplacement:
    source: str
    name: str
    real_value: str
    virtual_value: str
    action: str = "replace"


@dataclass(frozen=True)
class WorkspaceSession:
    session_id: str
    source_root: str
    workspace_root: str
    created_at: float
    expires_at: float
    mode: str = "symlink"


@dataclass(frozen=True)
class WorkspaceRequest:
    source_root: str
    replacements: List[SecretReplacement]
    ttl: str
    mode: str = "symlink"
    protected_write_paths: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ProcessRequest:
    argv: List[str]
    cwd: str


@dataclass
class NetworkPolicy:
    allow_domains: List[str] = field(default_factory=list)
    deny_domains: List[str] = field(default_factory=list)
    allow_ports: List[int] = field(default_factory=lambda: [80, 443])
    deny_ip_literals: bool = True
    deny_private_networks: bool = True


@dataclass
class ProcessPolicy:
    allowed_commands: List[str] = field(default_factory=list)


@dataclass
class FilePolicy:
    protect_write: List[str] = field(default_factory=list)


@dataclass
class AuditConfig:
    path: str = ".agentsecure/audit.log"


@dataclass
class GatewayConfig:
    host: str = "127.0.0.1"
    port: int = 8765


@dataclass(frozen=True)
class Capability:
    name: str
    type: str
    expose_as: str
    target_host: str
    target_port: int
    access: str = ""
    database: str = ""
    local_host: str = "127.0.0.1"
    local_port: int = 0


@dataclass(frozen=True)
class BrokerEndpointPlan:
    env_name: str
    capability: str
    type: str
    local_url: str
    local_host: str
    local_port: int
    target_host: str
    target_port: int
    access: str = ""
    database: str = ""


@dataclass
class AgentSecureConfig:
    secrets: List[SecretBinding] = field(default_factory=list)
    env_policy: EnvPolicy = field(default_factory=EnvPolicy)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    process: ProcessPolicy = field(default_factory=ProcessPolicy)
    files: FilePolicy = field(default_factory=FilePolicy)
    audit: AuditConfig = field(default_factory=AuditConfig)
    gateway: GatewayConfig = field(default_factory=GatewayConfig)
    capabilities: Dict[str, Capability] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)
