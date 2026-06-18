from typing import Any, Dict

from agentsecure.mesh import MeshService


def call_mesh_tool(config_path: str, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    service = MeshService(config_path)
    if name == "agentsecure.identity":
        agent_id = str(args.get("agent_id", ""))
        if args.get("register"):
            return service.register_agent(
                agent_id=agent_id,
                name=str(args.get("name", "")),
                agent_type=str(args.get("type", "coding_agent")),
                team=str(args.get("team", "")),
                workspace=str(args.get("workspace", "local")),
                trust_level=str(args.get("trust_level", "local")),
                allowed_scopes=[str(item) for item in args.get("allowed_scopes", [])],
                owner=str(args.get("owner", "")),
            )
        return service.identity(agent_id)
    if name == "agentsecure.check_messages":
        return service.check_messages(str(args.get("agent_id", "")))
    if name == "agentsecure.list_messages":
        return service.list_messages(str(args.get("agent_id", "")), include_read=bool(args.get("include_read", False)))
    if name == "agentsecure.read_message":
        return service.read_message(str(args.get("message_id", "")), agent_id=str(args.get("agent_id", "")))
    if name == "agentsecure.send_message":
        return service.send_message(
            from_agent=str(args.get("from_agent", "")),
            to=str(args.get("to", "")),
            message_type=str(args.get("type", "question")),
            subject=str(args.get("subject", "")),
            body=str(args.get("body", "")),
            resource=_object_arg(args.get("resource", {}), "resource"),
        )
    if name == "agentsecure.reply_message":
        return service.reply_message(
            message_id=str(args.get("message_id", "")),
            from_agent=str(args.get("from_agent", "")),
            body=str(args.get("body", "")),
        )
    if name == "agentsecure.request_approval":
        return service.request_approval(
            requested_by=str(args.get("requested_by", "")),
            action=str(args.get("action", "")),
            resource=_object_arg(args.get("resource", {}), "resource"),
            reason=str(args.get("reason", "")),
            required_approver=_object_arg(args.get("required_approver", {}), "required_approver") or None,
        )
    if name == "agentsecure.get_approval_status":
        return service.get_approval_status(str(args.get("approval_id", "")))
    if name == "agentsecure.resolve_approval":
        return service.resolve_approval(
            approval_id=str(args.get("approval_id", "")),
            decision=str(args.get("decision", "")),
            reason=str(args.get("reason", "")),
            decided_by=str(args.get("decided_by", "human")),
        )
    if name == "agentsecure.get_policy_hint":
        return service.get_policy_hint(
            agent_id=str(args.get("agent_id", "")),
            action=str(args.get("action", "")),
            resource=_object_arg(args.get("resource", {}), "resource"),
            target=str(args.get("target", "")),
        )
    if name == "agentsecure.audit_context":
        return service.audit_context(resource=_object_arg(args.get("resource", {}), "resource"), limit=int(args.get("limit", 50)))
    raise ValueError("unknown AgentSecure mesh MCP tool: %s" % name)


def mesh_tools():
    object_schema = {"type": "object", "additionalProperties": True}
    return [
        {
            "name": "agentsecure.identity",
            "description": "Read or register the current AgentSecure Mesh agent identity.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string"},
                    "register": {"type": "boolean"},
                    "name": {"type": "string"},
                    "type": {"type": "string"},
                    "team": {"type": "string"},
                    "workspace": {"type": "string"},
                    "trust_level": {"type": "string"},
                    "allowed_scopes": {"type": "array", "items": {"type": "string"}},
                    "owner": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        _tool("agentsecure.check_messages", {"agent_id": {"type": "string"}}, ["agent_id"]),
        _tool(
            "agentsecure.list_messages",
            {"agent_id": {"type": "string"}, "include_read": {"type": "boolean"}},
            ["agent_id"],
        ),
        _tool(
            "agentsecure.read_message",
            {"message_id": {"type": "string"}, "agent_id": {"type": "string"}},
            ["message_id", "agent_id"],
        ),
        _tool(
            "agentsecure.send_message",
            {
                "from_agent": {"type": "string"},
                "to": {"type": "string"},
                "type": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
                "resource": object_schema,
            },
            ["from_agent", "to", "body"],
        ),
        _tool(
            "agentsecure.reply_message",
            {"message_id": {"type": "string"}, "from_agent": {"type": "string"}, "body": {"type": "string"}},
            ["message_id", "from_agent", "body"],
        ),
        _tool(
            "agentsecure.request_approval",
            {
                "requested_by": {"type": "string"},
                "action": {"type": "string"},
                "resource": object_schema,
                "reason": {"type": "string"},
                "required_approver": object_schema,
            },
            ["requested_by", "action", "reason"],
        ),
        _tool("agentsecure.get_approval_status", {"approval_id": {"type": "string"}}, ["approval_id"]),
        _tool(
            "agentsecure.resolve_approval",
            {
                "approval_id": {"type": "string"},
                "decision": {"type": "string"},
                "reason": {"type": "string"},
                "decided_by": {"type": "string"},
            },
            ["approval_id", "decision"],
        ),
        _tool(
            "agentsecure.get_policy_hint",
            {
                "agent_id": {"type": "string"},
                "action": {"type": "string"},
                "resource": object_schema,
                "target": {"type": "string"},
            },
            ["agent_id", "action"],
        ),
        _tool(
            "agentsecure.audit_context",
            {"resource": object_schema, "limit": {"type": "number"}},
            [],
        ),
    ]


def _tool(name: str, properties: Dict[str, Any], required):
    return {
        "name": name,
        "description": "AgentSecure Mesh tool: %s" % name,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
    }


def _object_arg(value: Any, label: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("%s must be an object" % label)
    return value
