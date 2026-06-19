import hashlib
import json
import os
import re
import shlex
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional

from agentsecure.cloud import CloudError, CloudRuntimeService
from agentsecure.core.config import JsonConfigLoader
from agentsecure.core.models import AgentSecureConfig
from agentsecure.implementations.audit import JsonLineAuditLogger
from agentsecure.mesh.models import AgentIdentity, ApprovalRequest, MeshMessage, now_ts
from agentsecure.mesh.store import LocalMeshStore


MESSAGE_TYPES = {
    "question",
    "reply",
    "approval_request",
    "approval_decision",
    "policy_denial",
    "system_notice",
    "ownership_request",
    "resource_comment",
    "task_handoff",
}

SENSITIVE_ACTION_MARKERS = (
    "deploy",
    "production",
    "prod",
    "secret",
    "staging",
    "migration",
    "risky",
    "infrastructure",
    "api_contract",
)

SAFE_RESOURCE_KEYS = {
    "action",
    "environment",
    "id",
    "path",
    "provider",
    "repo",
    "team",
    "type",
}


class MeshService:
    def __init__(self, config_path: str) -> None:
        self.config_path = os.path.abspath(config_path)
        self.config = self._load_config()
        mesh_path = self._mesh_path()
        self.store = LocalMeshStore(mesh_path)
        audit_path = self.config.audit.path
        if not os.path.isabs(audit_path):
            audit_path = os.path.join(os.path.dirname(self.config_path) or os.getcwd(), audit_path)
        self.audit = JsonLineAuditLogger(audit_path)
        self.cloud = CloudRuntimeService()

    def register_agent(
        self,
        agent_id: str,
        name: str = "",
        agent_type: str = "coding_agent",
        team: str = "",
        workspace: str = "local",
        trust_level: str = "local",
        allowed_scopes: Optional[List[str]] = None,
        owner: str = "",
    ) -> Dict[str, Any]:
        agent_id = self._required_id(agent_id, "agent_id")
        identity = AgentIdentity(
            agent_id=agent_id,
            name=name or agent_id,
            type=agent_type or "coding_agent",
            team=team,
            workspace=workspace or "local",
            trust_level=trust_level or "local",
            allowed_scopes=allowed_scopes or [],
            owner=owner,
        )
        state = self.store.load()
        state["agents"][agent_id] = identity.to_dict()
        self.store.save(state)
        self._record("mesh.agent_registered", identity.to_dict())
        result = identity.to_dict()
        if self._cloud_enrolled():
            try:
                self.cloud.register_mesh_agent(
                    {
                        "agent_id": agent_id,
                        "name": identity.name,
                        "agent_type": identity.type,
                        "runtime": "agentsecure",
                        "workspace": identity.workspace,
                        "status": "active",
                        "trust_level": identity.trust_level,
                        "capabilities": {
                            "team": identity.team,
                            "owner": identity.owner,
                            "allowed_scopes": identity.allowed_scopes,
                        },
                    }
                )
                result["cloud_registered"] = True
            except CloudError as exc:
                result["cloud_registered"] = False
                result["cloud_error"] = str(exc)
        return result

    def identity(self, agent_id: str = "") -> Dict[str, Any]:
        state = self.store.load()
        if agent_id:
            agent = state["agents"].get(agent_id)
            if not agent:
                return {"exists": False, "agent_id": agent_id}
            return {"exists": True, **agent}
        return {"agents": sorted(state["agents"].values(), key=lambda item: item.get("agent_id", ""))}

    def check_messages(self, agent_id: str) -> Dict[str, Any]:
        agent_id = self._required_id(agent_id, "agent_id")
        message_result = self.list_messages(agent_id, include_read=False)
        messages = message_result["messages"]
        pending = self._pending_approvals_for_agent(agent_id)
        if message_result.get("blocked"):
            return {
                "blocked": True,
                "agent_id": agent_id,
                "unread_count": len(messages),
                "pending_approval_count": len(pending),
                "reason": message_result.get("reason", ""),
                "allowed_next_step": message_result.get("allowed_next_step", ""),
                "notice": "AgentSecure Cloud messages are unavailable. %s" % message_result.get("reason", ""),
            }
        return {
            "agent_id": agent_id,
            "unread_count": len(messages),
            "pending_approval_count": len(pending),
            "notice": (
                "You have %s new AgentSecure message(s). Call agentsecure.list_messages or agentsecure.read_message."
                % len(messages)
            ),
        }

    def list_messages(self, agent_id: str, include_read: bool = False) -> Dict[str, Any]:
        agent_id = self._required_id(agent_id, "agent_id")
        if self._cloud_enrolled():
            try:
                return self.cloud.mesh_messages(agent_id=agent_id, include_read=include_read)
            except CloudError as exc:
                return {
                    "blocked": True,
                    "agent_id": agent_id,
                    "messages": [],
                    "reason": str(exc),
                    "allowed_next_step": "retry after AgentSecure Cloud is reachable",
                }
        state = self.store.load()
        messages = []
        for message in state["messages"].values():
            if message.get("to") != agent_id:
                continue
            if not include_read and message.get("status") == "read":
                continue
            messages.append(message)
        messages.sort(key=lambda item: item.get("created_at", 0), reverse=True)
        return {"agent_id": agent_id, "messages": messages}

    def read_message(self, message_id: str, agent_id: str = "") -> Dict[str, Any]:
        message_id = self._required_id(message_id, "message_id")
        agent_id = self._required_id(agent_id, "agent_id")
        if self._cloud_enrolled():
            try:
                result = self.cloud.read_mesh_message(message_id, agent_id=agent_id)
                message = result.get("message", result)
                if isinstance(message, dict) and message.get("message_id"):
                    self._record("mesh.message_read", {"message_id": message_id, "reader": agent_id})
                    return message
                raise ValueError("cloud read did not return a mesh message")
            except CloudError as exc:
                raise ValueError("cloud message read failed: %s" % exc)
        state = self.store.load()
        message = state["messages"].get(message_id)
        if not message:
            raise ValueError("message not found: %s" % message_id)
        if message.get("to") != agent_id:
            raise ValueError("message %s is not addressed to %s" % (message_id, agent_id))
        if message.get("status") != "read":
            message["status"] = "read"
            message["read_at"] = now_ts()
            state["messages"][message_id] = message
            self.store.save(state)
            self._record("mesh.message_read", {"message_id": message_id, "reader": message.get("to")})
        return message

    def send_message(
        self,
        from_agent: str,
        to: str,
        message_type: str,
        subject: str,
        body: str,
        resource: Optional[Dict[str, Any]] = None,
        reply_to: str = "",
    ) -> Dict[str, Any]:
        from_agent = self._required_id(from_agent, "from_agent")
        to = self._required_id(to, "to")
        message_type = message_type or "question"
        if message_type not in MESSAGE_TYPES:
            raise ValueError("unsupported mesh message type: %s" % message_type)
        policy = self.get_policy_hint(from_agent, "send_message", resource or {}, target=to)
        if policy["blocked"]:
            denial = self._policy_denial(from_agent, "send_message", resource or {}, policy)
            return denial
        if self._cloud_enrolled():
            try:
                result = self.cloud.create_mesh_message(
                    self._cloud_message_payload(
                        from_agent,
                        to,
                        message_type,
                        subject,
                        body,
                        resource or {},
                        reply_to,
                    )
                )
                message = result.get("message", {}) if isinstance(result, dict) else {}
                self._record(
                    "mesh.message_sent",
                    {
                        "message_id": message.get("message_id", ""),
                        "from_agent": from_agent,
                        "to": to,
                        "delivery_status": result.get("delivery_status", ""),
                        "approval_id": result.get("approval_id", ""),
                    },
                )
                return result
            except CloudError as exc:
                return {
                    "blocked": True,
                    "reason": str(exc),
                    "allowed_next_step": "retry after AgentSecure Cloud is reachable",
                }
        message_id = "msg_" + uuid.uuid4().hex[:16]
        thread_id = message_id
        if reply_to:
            original = self.store.load()["messages"].get(reply_to, {})
            thread_id = original.get("thread_id") or reply_to
        message = MeshMessage(
            message_id=message_id,
            from_agent=from_agent,
            to=to,
            type=message_type,
            subject=self._text_summary(subject),
            body="[redacted]",
            resource=self._safe_resource(resource or {}),
            thread_id=thread_id,
            reply_to=reply_to,
        ).to_dict()
        message["body_sha256"] = self._text_hash(body)
        message["body_summary"] = self._text_summary(body)
        message["content_redacted"] = True
        state = self.store.load()
        state["messages"][message_id] = message
        self.store.save(state)
        self._record("mesh.message_sent", message)
        return {"blocked": False, "message": message}

    def reply_message(self, message_id: str, from_agent: str, body: str) -> Dict[str, Any]:
        if self._cloud_enrolled():
            from_agent = self._required_id(from_agent, "from_agent")
            try:
                result = self.cloud.reply_mesh_message(message_id, {"from_agent": from_agent, "body": "[redacted]"})
                message = result.get("message", {}) if isinstance(result, dict) else {}
                self._record(
                    "mesh.message_sent",
                    {
                        "message_id": message.get("message_id", ""),
                        "from_agent": from_agent,
                        "to": message.get("to", ""),
                        "delivery_status": result.get("delivery_status", ""),
                    },
                )
                return result
            except CloudError as exc:
                return {
                    "blocked": True,
                    "reason": str(exc),
                    "allowed_next_step": "retry after AgentSecure Cloud is reachable",
                }
        original = self.read_message(message_id, agent_id=from_agent)
        return self.send_message(
            from_agent=from_agent,
            to=str(original.get("from_agent", "")),
            message_type="reply",
            subject="Re: %s" % original.get("subject", ""),
            body=body,
            resource=original.get("resource") or {},
            reply_to=message_id,
        )

    def request_approval(
        self,
        requested_by: str,
        action: str,
        resource: Optional[Dict[str, Any]],
        reason: str,
        required_approver: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        requested_by = self._required_id(requested_by, "requested_by")
        action = self._required_id(action, "action")
        approval_id = "apr_" + uuid.uuid4().hex[:16]
        approver = required_approver or self._required_approver(action, resource or {})
        approval = ApprovalRequest(
            approval_id=approval_id,
            requested_by=requested_by,
            action=action,
            resource=self._safe_resource(resource or {}),
            reason="[redacted]",
            required_approver=approver,
        ).to_dict()
        approval["reason_sha256"] = self._text_hash(reason)
        approval["reason_summary"] = self._text_summary(reason)
        approval["content_redacted"] = True
        state = self.store.load()
        state["approvals"][approval_id] = approval
        self.store.save(state)
        self._record("mesh.approval_requested", approval)
        return {"approval": approval}

    def get_approval_status(self, approval_id: str) -> Dict[str, Any]:
        approval_id = self._required_id(approval_id, "approval_id")
        state = self.store.load()
        approval = state["approvals"].get(approval_id)
        if not approval:
            raise ValueError("approval not found: %s" % approval_id)
        return {"approval": approval}

    def list_approvals(self, status: str = "", approver: str = "") -> Dict[str, Any]:
        state = self.store.load()
        approvals = []
        for approval in state["approvals"].values():
            if status and approval.get("status") != status:
                continue
            if approver and not self._approval_matches_approver(approval, {approver}):
                continue
            approvals.append(approval)
        approvals.sort(key=lambda item: item.get("created_at", 0), reverse=True)
        return {"approvals": approvals}

    def resolve_approval(self, approval_id: str, decision: str, reason: str, decided_by: str = "human") -> Dict[str, Any]:
        approval_id = self._required_id(approval_id, "approval_id")
        normalized = self._normalize_decision(decision)
        state = self.store.load()
        approval = state["approvals"].get(approval_id)
        if not approval:
            raise ValueError("approval not found: %s" % approval_id)
        approval["status"] = "approved" if normalized == "approve" else "denied"
        if normalized == "comment":
            approval["status"] = "needs_info"
        approval["decision"] = normalized
        approval["decision_reason"] = "[redacted]" if reason else ""
        approval["decision_reason_sha256"] = self._text_hash(reason)
        approval["decision_reason_summary"] = self._text_summary(reason)
        approval["decided_by"] = decided_by or "human"
        approval["decided_at"] = now_ts()
        state["approvals"][approval_id] = approval
        self.store.save(state)
        self._record("mesh.approval_decided", approval)
        return {"approval": approval}

    def get_policy_hint(
        self,
        agent_id: str,
        action: str,
        resource: Optional[Dict[str, Any]] = None,
        target: str = "",
    ) -> Dict[str, Any]:
        agent_id = self._required_id(agent_id, "agent_id")
        action = self._required_id(action, "action")
        mesh_policy = self.config.raw.get("mesh", {}) if isinstance(self.config.raw.get("mesh", {}), dict) else {}
        agents = mesh_policy.get("agents", {}) if isinstance(mesh_policy.get("agents", {}), dict) else {}
        policy = agents.get(agent_id, {}) if isinstance(agents.get(agent_id, {}), dict) else {}
        cannot = set(str(item) for item in policy.get("cannot", []))
        if action in cannot:
            return self._hint(False, "action is denied by local mesh policy", action, resource or {})
        if action == "send_message" and target:
            allowed_targets = [str(item) for item in policy.get("can_message", [])]
            if allowed_targets and target not in allowed_targets:
                return self._hint(False, "agent is not allowed to message %s" % target, action, resource or {})
        required = set(str(item) for item in policy.get("requires_human_for", []))
        if action in required or self._resource_requires_approval(action, resource or {}):
            return self._hint(
                False,
                "action requires human approval",
                action,
                resource or {},
                allowed_next_step="call agentsecure.request_approval",
            )
        return self._hint(True, "allowed by local mesh policy", action, resource or {})

    def audit_context(self, resource: Optional[Dict[str, Any]] = None, limit: int = 50) -> Dict[str, Any]:
        audit_path = self.config.audit.path
        if not os.path.isabs(audit_path):
            audit_path = os.path.join(os.path.dirname(self.config_path) or os.getcwd(), audit_path)
        events = []
        if os.path.exists(audit_path):
            with open(audit_path, "r") as handle:
                for line in handle:
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    if not str(event.get("type", "")).startswith("mesh."):
                        continue
                    if resource and not self._resource_matches(resource, event.get("details", {})):
                        continue
                    events.append(event)
        return {"events": events[-int(limit):]}

    def set_launch_profile(
        self,
        agent_id: str,
        command: List[str],
        cwd: str = "",
        env: Optional[Dict[str, str]] = None,
        wake_mode: str = "notify",
    ) -> Dict[str, Any]:
        agent_id = self._required_id(agent_id, "agent_id")
        if not command:
            raise ValueError("launch command is required")
        profile = {
            "agent_id": agent_id,
            "command": [str(item) for item in command],
            "cwd": os.path.abspath(os.path.expanduser(cwd or os.getcwd())),
            "env": {str(key): str(value) for key, value in (env or {}).items()},
            "wake_mode": wake_mode if wake_mode in ("notify", "launch") else "notify",
            "updated_at": now_ts(),
        }
        profile["env"].setdefault("AGENTSECURE_AGENT_ID", agent_id)
        state = self.store.load()
        state["launch_profiles"][agent_id] = profile
        self.store.save(state)
        self._record("mesh.launch_profile_saved", {"agent_id": agent_id, "wake_mode": profile["wake_mode"]})
        return {"profile": profile}

    def launch_profiles(self, agent_id: str = "") -> Dict[str, Any]:
        state = self.store.load()
        profiles = state.get("launch_profiles", {})
        if agent_id:
            return {"profile": profiles.get(agent_id)}
        return {"profiles": sorted(profiles.values(), key=lambda item: item.get("agent_id", ""))}

    def wake(self, agent_id: str, reason: str = "", launch: bool = False) -> Dict[str, Any]:
        agent_id = self._required_id(agent_id, "agent_id")
        check = self.check_messages(agent_id)
        blocked = bool(check.get("blocked"))
        unread_count = int(check.get("unread_count", 0) or 0)
        details = {
            "agent_id": agent_id,
            "reason": self._text_summary(reason),
            "unread_count": unread_count,
            "blocked": blocked,
        }
        self._record("mesh.wake_requested", details)
        if blocked:
            self._record("mesh.wake_denied", details)
            return {"blocked": True, **details, "allowed_next_step": check.get("allowed_next_step", "")}
        if unread_count <= 0:
            self._record("mesh.wake_notified", {**details, "status": "no_unread_messages"})
            return {"blocked": False, **details, "launched": False, "notice": "No unread messages for %s." % agent_id}
        self._record("mesh.wake_allowed", details)
        profile = (self.launch_profiles(agent_id).get("profile") or {})
        should_launch = launch or profile.get("wake_mode") == "launch"
        if should_launch and profile:
            launch_result = self.launch_agent(agent_id)
            return {"blocked": False, **details, **launch_result}
        self._record("mesh.wake_notified", {**details, "status": "notified"})
        return {
            "blocked": False,
            **details,
            "launched": False,
            "notice": "Agent %s has %s unread AgentSecure message(s)." % (agent_id, unread_count),
        }

    def launch_agent(self, agent_id: str) -> Dict[str, Any]:
        agent_id = self._required_id(agent_id, "agent_id")
        profile = self.launch_profiles(agent_id).get("profile")
        if not profile:
            return {
                "launched": False,
                "reason": "no launch profile configured",
                "allowed_next_step": "agentsecure mesh launch-profile set --agent-id %s --cmd <command>" % shlex.quote(agent_id),
            }
        command = [str(item) for item in profile.get("command", []) if str(item)]
        if not command:
            raise ValueError("launch profile for %s has no command" % agent_id)
        cwd = str(profile.get("cwd") or os.getcwd())
        env = os.environ.copy()
        env.update({str(key): str(value) for key, value in (profile.get("env") or {}).items()})
        env["AGENTSECURE_AGENT_ID"] = agent_id
        self._record("mesh.agent_launch_requested", {"agent_id": agent_id, "cwd": cwd})
        try:
            process = subprocess.Popen(command, cwd=cwd, env=env)
        except OSError as exc:
            self._record("mesh.agent_launch_failed", {"agent_id": agent_id, "cwd": cwd, "error": str(exc)})
            return {"launched": False, "agent_id": agent_id, "reason": str(exc)}
        self._record("mesh.agent_launched", {"agent_id": agent_id, "pid": process.pid})
        return {"launched": True, "pid": process.pid, "agent_id": agent_id}

    def watch(self, agent_id: str, once: bool = False, interval_seconds: float = 5.0, launch: bool = False) -> Dict[str, Any]:
        agent_id = self._required_id(agent_id, "agent_id")
        interval_seconds = max(1.0, float(interval_seconds))
        while True:
            check = self.check_messages(agent_id)
            if int(check.get("unread_count", 0) or 0) > 0 or check.get("blocked"):
                result = self.wake(agent_id, reason="watch detected unread AgentSecure messages", launch=launch)
                return {"agent_id": agent_id, "check": check, **result}
            if once:
                return {"agent_id": agent_id, "check": check, "woke": False}
            time.sleep(interval_seconds)

    def _load_config(self) -> AgentSecureConfig:
        if not os.path.exists(self.config_path):
            return AgentSecureConfig()
        return JsonConfigLoader().load(self.config_path)

    def _mesh_path(self) -> str:
        mesh = self.config.raw.get("mesh", {}) if isinstance(self.config.raw.get("mesh", {}), dict) else {}
        path = str(mesh.get("path", ".agentsecure/mesh.json"))
        if os.path.isabs(path):
            return path
        return os.path.join(os.path.dirname(self.config_path) or os.getcwd(), path)

    def _record(self, event_type: str, details: Dict[str, Any]) -> None:
        self.audit.record(event_type, self._safe_details(details))

    def _cloud_enrolled(self) -> bool:
        try:
            return bool(self.cloud.status().get("enrolled"))
        except CloudError:
            return False

    def _policy_denial(
        self,
        agent_id: str,
        action: str,
        resource: Dict[str, Any],
        hint: Dict[str, Any],
    ) -> Dict[str, Any]:
        details = {
            "agent_id": agent_id,
            "action": action,
            "resource": self._safe_resource(resource),
            "reason": hint.get("reason", ""),
            "allowed_next_step": hint.get("allowed_next_step", "call agentsecure.get_policy_hint"),
        }
        self._record("mesh.policy_denied", details)
        return {"blocked": True, **details}

    def _cloud_message_payload(
        self,
        from_agent: str,
        to: str,
        message_type: str,
        subject: str,
        body: str,
        resource: Dict[str, Any],
        reply_to: str = "",
    ) -> Dict[str, Any]:
        return {
            "from_agent": from_agent,
            "to": to,
            "type": message_type,
            "subject": "[redacted]" if subject else "",
            "body": "[redacted]" if body else "",
            "resource": self._safe_resource(resource),
            "reply_to": reply_to,
        }

    def _hint(
        self,
        allowed: bool,
        reason: str,
        action: str,
        resource: Dict[str, Any],
        allowed_next_step: str = "",
    ) -> Dict[str, Any]:
        if not allowed_next_step and not allowed:
            allowed_next_step = "call agentsecure.request_approval"
        return {
            "allowed": allowed,
            "blocked": not allowed,
            "reason": reason,
            "action": action,
            "resource": self._safe_resource(resource),
            "allowed_next_step": allowed_next_step,
        }

    def _required_approver(self, action: str, resource: Dict[str, Any]) -> Dict[str, Any]:
        if resource.get("team"):
            return {"type": "team", "id": resource.get("team")}
        if "security" in action or "secret" in action:
            return {"type": "team", "id": "security"}
        return {"type": "human", "id": "local-owner"}

    def _resource_requires_approval(self, action: str, resource: Dict[str, Any]) -> bool:
        text = " ".join([action, json.dumps(resource, sort_keys=True)]).lower()
        return any(
            re.search(r"(?<![a-z0-9])%s(?![a-z0-9])" % re.escape(marker), text)
            for marker in SENSITIVE_ACTION_MARKERS
        )

    def _pending_approvals_for_agent(self, agent_id: str) -> List[Dict[str, Any]]:
        state = self.store.load()
        agent = state["agents"].get(agent_id) or {}
        approver_ids = {agent_id}
        if agent.get("team"):
            approver_ids.add(str(agent["team"]))
        approvals = [
            approval
            for approval in state["approvals"].values()
            if approval.get("status") == "pending"
            and self._approval_matches_approver(approval, approver_ids)
        ]
        approvals.sort(key=lambda item: item.get("created_at", 0), reverse=True)
        return approvals

    def _approval_matches_approver(self, approval: Dict[str, Any], approver_ids: set) -> bool:
        required = approval.get("required_approver") or {}
        return any(
            str(value) in approver_ids
            for value in (required.get("id"), required.get("agent_id"), required.get("team"))
            if value is not None
        )

    def _resource_matches(self, expected: Dict[str, Any], value: Any) -> bool:
        text = json.dumps(value, sort_keys=True)
        for key, item in expected.items():
            if str(key) not in text or str(item) not in text:
                return False
        return True

    def _normalize_decision(self, decision: str) -> str:
        normalized = str(decision).strip().lower()
        if normalized in ("approved", "approve", "allow", "yes"):
            return "approve"
        if normalized in ("rejected", "reject", "deny", "denied", "no"):
            return "deny"
        if normalized in ("comment", "needs_info", "request_more_info"):
            return "comment"
        raise ValueError("decision must be approve, reject, or comment")

    def _safe_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        if "resource" in details and isinstance(details.get("resource"), dict):
            details = dict(details)
            details["resource"] = self._safe_resource(details["resource"])
        for text_key in ("body", "reason", "decision_reason"):
            if text_key in details and details[text_key] not in ("", "[redacted]"):
                text = str(details[text_key])
                details[text_key] = "[redacted]"
                details[text_key + "_sha256"] = self._text_hash(text)
                details[text_key + "_summary"] = self._text_summary(text)
        return details

    def _safe_resource(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        safe: Dict[str, Any] = {}
        for key, value in (resource or {}).items():
            key_text = str(key)
            if key_text not in SAFE_RESOURCE_KEYS:
                continue
            if isinstance(value, (str, int, float, bool)) or value is None:
                safe[key_text] = self._safe_scalar(value)
            elif isinstance(value, list):
                safe[key_text] = [self._safe_scalar(item) for item in value[:20]]
        return safe

    def _safe_scalar(self, value: Any) -> Any:
        if value is None or isinstance(value, (int, float, bool)):
            return value
        text = str(value).strip()
        if "\n" in text or "=" in text:
            return "[redacted]"
        return text[:300]

    def _text_hash(self, value: str) -> str:
        return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest() if value else ""

    def _text_summary(self, value: str) -> str:
        text = " ".join(str(value or "").split())
        if not text:
            return ""
        if "=" in text:
            return "[redacted]"
        return text[:120]

    def _required_id(self, value: str, name: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("%s is required" % name)
        return text
