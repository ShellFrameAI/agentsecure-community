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
    object_schema = {
        "type": "object",
        "additionalProperties": True,
        "description": (
            "Optional resource metadata; defaults to {}. Stored/returned fields are limited to action, environment, "
            "id, path, provider, repo, team, and type. Use non-secret scalar values or lists; other keys and "
            "top-level object-valued fields are dropped; list items are converted to scalars, and strings are truncated/redacted. "
            "Example: {\"type\": \"code_file\", \"path\": \"src/app.py\"}. "
            "For policy checks, the entire supplied object is examined for sensitive-action markers."
        ),
    }
    agent_id_schema = {
        "type": "string",
        "description": (
            "Non-empty Mesh agent ID, e.g. backend-agent. Pass this session's AGENTSECURE_AGENT_ID value when set; "
            "it is not read automatically. IDs are caller-supplied local labels, not authentication credentials."
        ),
    }
    return [
        {
            "name": "agentsecure.identity",
            "description": (
                "Look up or register identities in the local Community Mesh store. By default, agent_id returns "
                "exists plus that identity's metadata (or exists=false if unknown); omitting agent_id returns an "
                "agents array sorted by ID. Set register=true with a non-empty agent_id to create or overwrite "
                "its record and write an audit event; returns the saved identity. Registration replaces rather "
                "than merges metadata. Identity labels, trust_level, and allowed_scopes do not authenticate callers "
                "or grant permissions. Example: {\"agent_id\": \"backend-agent\"}."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Local Mesh ID to look up or register. Omit/empty to list identities when register=false; non-empty required when register=true. Not inferred from the environment or authenticated.",
                    },
                    "register": {
                        "type": "boolean",
                        "description": "Defaults to false (lookup only). True creates or overwrites the agent_id record using the metadata below, including defaults for omitted fields.",
                    },
                    "name": {"type": "string", "description": "Display name for registration; defaults to agent_id. Ignored on lookup."},
                    "type": {"type": "string", "description": "Agent classification for registration; defaults to coding_agent. Metadata only; ignored on lookup."},
                    "team": {"type": "string", "description": "Team label for registration; defaults to empty. Used when counting approvals assigned to this team; ignored on lookup."},
                    "workspace": {"type": "string", "description": "Workspace label for registration; defaults to local. Does not select a filesystem directory; ignored on lookup."},
                    "trust_level": {"type": "string", "description": "Trust label for registration; defaults to local. Metadata only, not a security boundary; ignored on lookup."},
                    "allowed_scopes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Scope labels to store at registration; defaults to []. Informational only, not enforced by Mesh policy; ignored on lookup.",
                    },
                    "owner": {"type": "string", "description": "Owner label for registration; defaults to empty. Does not verify ownership; ignored on lookup."},
                },
                "additionalProperties": False,
            },
        },
        _tool(
            "agentsecure.check_messages",
            {"agent_id": agent_id_schema},
            ["agent_id"],
            "Check local inbox counts before answering whether this agent has messages or approvals. Returns "
            "agent_id, unread_count, pending_approval_count, and a notice, not message content. Pending approvals "
            "are those assigned to the agent or its registered team, not all requests created by it. Does not mark "
            "messages read. Use agentsecure.list_messages for records and agentsecure.read_message to acknowledge "
            "one. Example: {\"agent_id\": \"backend-agent\"}.",
        ),
        _tool(
            "agentsecure.list_messages",
            {
                "agent_id": agent_id_schema,
                "include_read": {"type": "boolean", "description": "Defaults to false (unread only). True includes already-read messages as well; neither setting marks messages read."},
            },
            ["agent_id"],
            "List messages addressed to one agent in the local Community Mesh store. Returns agent_id and a "
            "messages array, newest first (empty if none). Each record includes message_id, sender/recipient, "
            "subject, resource, status, thread IDs, and timestamps. Body is [redacted]; body_summary may retain "
            "up to 120 characters and body_sha256 is a digest, not recoverable full content. Does not mark "
            "messages read. Use agentsecure.check_messages for counts only or agentsecure.read_message to mark "
            "a specific record read. Example: {\"agent_id\": \"backend-agent\", \"include_read\": true}.",
        ),
        _tool(
            "agentsecure.read_message",
            {
                "message_id": {"type": "string", "description": "Exact message_id returned by list_messages or send_message. Unknown IDs cause an error."},
                "agent_id": agent_id_schema,
            },
            ["message_id", "agent_id"],
            "Retrieve and acknowledge one local Mesh message after listing the inbox. Requires agent_id to match "
            "the record's recipient; an unknown ID or a different recipient causes an error. Returns the message "
            "record with status=read and read_at; the first read updates local state and audit. Re-reading returns "
            "the same acknowledged record. Body remains [redacted], with only body_summary/body_sha256 available; "
            "this does not recover original text. Use agentsecure.list_messages to inspect without marking read. "
            "The recipient check compares caller-supplied IDs, not authenticated identities.",
        ),
        _tool(
            "agentsecure.send_message",
            {
                "from_agent": agent_id_schema,
                "to": {"type": "string", "description": "Non-empty recipient Mesh agent ID, not an email address. Local registration is not required; delivery means a record in the shared local store."},
                "type": {
                    "type": "string",
                    "description": "Message category; defaults to question. Supported: question, reply, approval_request, approval_decision, policy_denial, system_notice, ownership_request, resource_comment, task_handoff. A category alone does not create or resolve an approval.",
                },
                "subject": {"type": "string", "description": "Optional subject, default empty. Whitespace is collapsed and text is truncated to 120 characters or redacted by heuristics. Do not include secrets."},
                "body": {"type": "string", "description": "Message text to summarize/hash. The body field is stored as [redacted], but a heuristic summary of up to 120 characters may remain. Do not include secrets; full text cannot later be retrieved."},
                "resource": object_schema,
            },
            ["from_agent", "to", "body"],
            "Create a new unread message in the local Community Mesh store for another agent. Checks the sender's "
            "send_message policy and resource approval requirements. Returns blocked=false and message (including "
            "message_id/thread_id), or blocked=true with reason and allowed_next_step. Stores/audits a redacted "
            "body, digest, and heuristic summary, not the full text; never put secrets in the input. Does not "
            "launch/wake the recipient, contact a remote service, or prove the recipient read it. Use "
            "agentsecure.reply_message to respond in an existing thread. Example: {\"from_agent\": \"frontend-agent\", "
            "\"to\": \"backend-agent\", \"body\": \"Please review src/app.py.\"}.",
        ),
        _tool(
            "agentsecure.reply_message",
            {
                "message_id": {"type": "string", "description": "Existing message_id addressed to from_agent. The reply goes to its original sender and reuses its thread and resource."},
                "from_agent": agent_id_schema,
                "body": {"type": "string", "description": "Reply text to summarize/hash; stored as [redacted] plus a heuristic summary of up to 120 characters and a digest. Do not include secrets."},
            },
            ["message_id", "from_agent", "body"],
            "Reply to a local Mesh message addressed to from_agent. Marks the original read first, then checks "
            "send_message policy and creates a type=reply message to the original sender, preserving thread_id "
            "and resource and setting reply_to. Returns blocked=false and message, or a policy denial with "
            "blocked=true, reason, and allowed_next_step; the original can remain read even if sending is blocked. "
            "Unknown messages or recipient mismatches cause an error. Reply body is redacted with a summary/hash, "
            "not full-text delivery. Use agentsecure.send_message for a new thread.",
        ),
        _tool(
            "agentsecure.request_approval",
            {
                "requested_by": agent_id_schema,
                "action": {"type": "string", "description": "Non-empty proposed action label, e.g. deploy_preview; use the same action supplied to get_policy_hint. Records intent only and does not execute it."},
                "resource": object_schema,
                "reason": {"type": "string", "description": "Justification to summarize/hash. Stored reason is [redacted], but up to 120 characters can remain in a heuristic summary. Do not include secrets."},
                "required_approver": {
                    "type": "object",
                    "additionalProperties": True,
                    "description": "Optional approver metadata, e.g. {\"type\": \"team\", \"id\": \"platform\"}. Omitted/empty selects resource.team, then security team for a case-sensitive action containing security/secret, else human local-owner. Stored as supplied; use only non-secret labels. Does not authenticate an approver.",
                },
            },
            ["requested_by", "action", "reason"],
            "Create a local pending approval record when a Mesh policy hint requires human review. Returns an "
            "approval object with approval_id, status=pending, requested_by, action, resource, required_approver, "
            "and timestamps; reason is redacted with a summary/hash. Writes local state and audit but does not "
            "send a message, notify a human, execute the action, or change policy. Repeated calls create separate "
            "requests. Use agentsecure.get_approval_status with the returned ID; approval decisions are made "
            "outside these MCP tools. An approved record does not automatically unblock policy. "
            "Example: {\"requested_by\": \"frontend-agent\", \"action\": \"deploy_preview\", \"reason\": \"Please review the preview deployment.\"}.",
        ),
        _tool(
            "agentsecure.get_approval_status",
            {"approval_id": {"type": "string", "description": "Exact approval_id returned by request_approval (apr_...); non-empty and must exist in the local Mesh store."}},
            ["approval_id"],
            "Read a previously created local approval without changing it. Returns an approval object with "
            "status (pending, approved, denied, or needs_info), action/resource, required_approver, and recorded "
            "decision details/timestamps. Reason text remains redacted with summary/hash metadata. Unknown IDs "
            "cause an error. This tool neither requests nor grants approval, and an approved record does not "
            "execute an action or automatically lift policy restrictions. Use agentsecure.request_approval "
            "to create a request and agentsecure.get_policy_hint to inspect current action policy.",
        ),
        _tool(
            "agentsecure.get_policy_hint",
            {
                "agent_id": agent_id_schema,
                "action": {"type": "string", "description": "Non-empty action label matched against mesh.agents policy, e.g. send_message or deploy_preview. Action/resource text is also checked for sensitive markers such as deploy or secret."},
                "resource": object_schema,
                "target": {"type": "string", "description": "Recipient agent ID for a send_message check; defaults to empty. Only used with action=send_message to check can_message restrictions; not a hostname or URL."},
            },
            ["agent_id", "action"],
            "Evaluate a proposed Mesh action against the current local agent policy without executing it. Checks "
            "cannot, can_message (when a send_message target is supplied), requires_human_for, and sensitive "
            "markers in action/resource. Returns allowed, blocked, reason, action, sanitized resource, and "
            "allowed_next_step. This is guidance, not an authorization token or a guarantee about external "
            "permissions; existing approval records are not consulted. Use agentsecure.request_approval to "
            "record a review request, or agentsecure.policy.describe for HTTP network/secret configuration. "
            "Example: {\"agent_id\": \"frontend-agent\", \"action\": \"send_message\", \"target\": \"backend-agent\"}.",
        ),
        _tool(
            "agentsecure.audit_context",
            {
                "resource": {
                    "type": "object",
                    "additionalProperties": True,
                    "description": "Optional filter, e.g. {\"path\": \"src/app.py\"}; defaults to {} (all Mesh events). Each key and stringified value must occur in serialized event details. This is substring matching, not exact structured matching.",
                },
                "limit": {"type": "number", "description": "Number of most recent matching events to return; defaults to 50. Use a positive integer (values are converted with int); 0 returns all matches, not zero events."},
            },
            [],
            "Inspect recent local Mesh history for troubleshooting messages, registrations, approvals, or policy "
            "denials. Returns an events array containing only mesh.* records from the configured audit log, "
            "optionally filtered by resource, with the last limit matches in log order (oldest first within "
            "that slice). A missing log returns an empty array and malformed JSON lines are skipped. Does not "
            "change state or include non-Mesh HTTP/secret audit events. Text fields may be redacted with "
            "summary/hash metadata; this is not an immutable audit service. Example: {\"limit\": 10}.",
        ),
    ]


def _tool(name: str, properties: Dict[str, Any], required, description: str):
    return {
        "name": name,
        "description": description,
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
