import time
from dataclasses import dataclass, field
from typing import Any, Dict, List


def now_ts() -> float:
    return time.time()


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    name: str
    type: str = "coding_agent"
    team: str = ""
    workspace: str = "local"
    trust_level: str = "local"
    allowed_scopes: List[str] = field(default_factory=list)
    owner: str = ""
    last_seen_at: float = field(default_factory=now_ts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "type": self.type,
            "team": self.team,
            "workspace": self.workspace,
            "trust_level": self.trust_level,
            "allowed_scopes": list(self.allowed_scopes),
            "owner": self.owner,
            "last_seen_at": self.last_seen_at,
        }


@dataclass(frozen=True)
class MeshMessage:
    message_id: str
    from_agent: str
    to: str
    type: str
    subject: str
    body: str
    resource: Dict[str, Any] = field(default_factory=dict)
    status: str = "unread"
    thread_id: str = ""
    reply_to: str = ""
    created_at: float = field(default_factory=now_ts)
    read_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "from_agent": self.from_agent,
            "to": self.to,
            "type": self.type,
            "subject": self.subject,
            "body": self.body,
            "resource": dict(self.resource),
            "status": self.status,
            "thread_id": self.thread_id or self.message_id,
            "reply_to": self.reply_to,
            "created_at": self.created_at,
            "read_at": self.read_at,
        }


@dataclass(frozen=True)
class ApprovalRequest:
    approval_id: str
    requested_by: str
    action: str
    resource: Dict[str, Any]
    reason: str
    status: str = "pending"
    required_approver: Dict[str, Any] = field(default_factory=dict)
    decision: str = ""
    decision_reason: str = ""
    decided_by: str = ""
    created_at: float = field(default_factory=now_ts)
    decided_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "requested_by": self.requested_by,
            "action": self.action,
            "resource": dict(self.resource),
            "reason": self.reason,
            "status": self.status,
            "required_approver": dict(self.required_approver),
            "decision": self.decision,
            "decision_reason": self.decision_reason,
            "decided_by": self.decided_by,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
        }
