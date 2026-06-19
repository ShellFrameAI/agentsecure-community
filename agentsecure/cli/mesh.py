import argparse
import json
import os
import shlex
import sys
from typing import Any, Dict

from agentsecure.mesh import MeshService


def add_mesh_subparser(subparsers) -> None:
    mesh_parser = subparsers.add_parser("mesh", help="Agent Mesh identity, inbox, approvals, and audit")
    mesh_subparsers = mesh_parser.add_subparsers(dest="mesh_command")

    register = mesh_subparsers.add_parser("register-agent", help="Register or update a local agent identity")
    register.add_argument("--agent-id", required=True)
    register.add_argument("--name", default="")
    register.add_argument("--type", default="coding_agent")
    register.add_argument("--team", default="")
    register.add_argument("--workspace", default="local")
    register.add_argument("--trust-level", default="local")
    register.add_argument("--scope", action="append", default=[])
    register.add_argument("--owner", default="")

    run_profile = mesh_subparsers.add_parser("use-agent", help="Print shell exports for an Agent Mesh identity")
    run_profile.add_argument("agent_id")

    identity = mesh_subparsers.add_parser("identity", help="Show one or all local agent identities")
    identity.add_argument("--agent-id", default="")

    agents = mesh_subparsers.add_parser("agents", help="List local mesh agents")
    agents.add_argument("--json", action="store_true", help="Accepted for desktop compatibility; output is always JSON")

    check = mesh_subparsers.add_parser("check-messages", help="Show unread mesh message counts for an agent")
    check.add_argument("--agent-id", required=True)

    list_messages = mesh_subparsers.add_parser("list-messages", help="List mesh inbox messages")
    list_messages.add_argument("--agent-id", required=True)
    list_messages.add_argument("--include-read", action="store_true")

    messages = mesh_subparsers.add_parser("messages", help="List mesh messages across local inboxes")
    messages.add_argument("--agent-id", default="")
    messages.add_argument("--unread", action="store_true")
    messages.add_argument("--json", action="store_true", help="Accepted for desktop compatibility; output is always JSON")

    read = mesh_subparsers.add_parser("read-message", help="Read a mesh message")
    read.add_argument("message_id")
    read.add_argument("--agent-id", default="")

    send = mesh_subparsers.add_parser("send-message", help="Send a controlled mesh message")
    send.add_argument("--from-agent", required=True)
    send.add_argument("--to", required=True)
    send.add_argument("--type", default="question")
    send.add_argument("--subject", default="")
    send.add_argument("--body", required=True)
    send.add_argument("--resource-json", default="{}")

    reply = mesh_subparsers.add_parser("reply-message", help="Reply to a mesh message")
    reply.add_argument("message_id")
    reply.add_argument("--from-agent", required=True)
    reply.add_argument("--body", required=True)

    request = mesh_subparsers.add_parser("request-approval", help="Request human or team approval")
    request.add_argument("--requested-by", required=True)
    request.add_argument("--action", required=True)
    request.add_argument("--resource-json", default="{}")
    request.add_argument("--reason", required=True)
    request.add_argument("--required-approver-json", default="{}")

    list_approvals = mesh_subparsers.add_parser("list-approvals", help="List mesh approval requests")
    list_approvals.add_argument("--status", default="")
    list_approvals.add_argument("--approver", default="")

    approvals = mesh_subparsers.add_parser("approvals", help="List or resolve mesh approval requests")
    approvals.add_argument("--pending", action="store_true")
    approvals.add_argument("--status", default="")
    approvals.add_argument("--approver", default="")
    approvals.add_argument("--json", action="store_true", help="Accepted for desktop compatibility; output is always JSON")
    approvals_subparsers = approvals.add_subparsers(dest="approval_action")
    for action in ("approve", "reject", "comment"):
        action_parser = approvals_subparsers.add_parser(action, help="%s an approval request" % action)
        action_parser.add_argument("approval_id")
        action_parser.add_argument("--comment", default="")
        action_parser.add_argument("--json", action="store_true", help="Accepted for desktop compatibility; output is always JSON")

    status = mesh_subparsers.add_parser("approval-status", help="Show approval status")
    status.add_argument("approval_id")

    resolve = mesh_subparsers.add_parser("resolve-approval", help="Resolve an approval request")
    resolve.add_argument("approval_id")
    resolve.add_argument("--decision", required=True, choices=["approve", "reject", "comment"])
    resolve.add_argument("--reason", default="")
    resolve.add_argument("--decided-by", default="human")

    hint = mesh_subparsers.add_parser("policy-hint", help="Explain whether a mesh action is allowed")
    hint.add_argument("--agent-id", required=True)
    hint.add_argument("--action", required=True)
    hint.add_argument("--resource-json", default="{}")
    hint.add_argument("--target", default="")

    audit = mesh_subparsers.add_parser("audit-context", help="Show recent mesh audit events")
    audit.add_argument("--resource-json", default="{}")
    audit.add_argument("--limit", type=int, default=50)

    denials = mesh_subparsers.add_parser("denials", help="List recent mesh policy denials")
    denials.add_argument("--recent", action="store_true")
    denials.add_argument("--limit", type=int, default=50)
    denials.add_argument("--json", action="store_true", help="Accepted for desktop compatibility; output is always JSON")

    audit_alias = mesh_subparsers.add_parser("audit", help="List recent mesh audit events")
    audit_alias.add_argument("--recent", action="store_true")
    audit_alias.add_argument("--limit", type=int, default=50)
    audit_alias.add_argument("--json", action="store_true", help="Accepted for desktop compatibility; output is always JSON")

    wake = mesh_subparsers.add_parser("wake", help="Wake or notify a mesh agent when messages are waiting")
    wake.add_argument("--to", required=True)
    wake.add_argument("--reason", default="")
    wake.add_argument("--launch", action="store_true")

    watch = mesh_subparsers.add_parser("watch", help="Watch an agent inbox and wake on unread messages")
    watch.add_argument("--agent-id", required=True)
    watch.add_argument("--once", action="store_true")
    watch.add_argument("--interval", type=float, default=5.0)
    watch.add_argument("--launch", action="store_true")

    launch = mesh_subparsers.add_parser("launch-agent", help="Launch an agent from its mesh launch profile")
    launch.add_argument("--agent-id", required=True)

    launch_profile = mesh_subparsers.add_parser("launch-profile", help="Manage local agent launch profiles")
    launch_profile_subparsers = launch_profile.add_subparsers(dest="launch_profile_action")
    set_profile = launch_profile_subparsers.add_parser("set", help="Set a launch profile")
    set_profile.add_argument("--agent-id", required=True)
    set_profile.add_argument("--cwd", default="")
    set_profile.add_argument("--wake-mode", choices=["notify", "launch"], default="notify")
    set_profile.add_argument("--env", action="append", default=[], help="Extra KEY=VALUE environment entry")
    set_profile.add_argument("--cmd", nargs=argparse.REMAINDER, required=True)
    show_profile = launch_profile_subparsers.add_parser("show", help="Show launch profiles")
    show_profile.add_argument("--agent-id", default="")


def handle_mesh(args: argparse.Namespace) -> int:
    command = getattr(args, "mesh_command", "")
    service = MeshService(args.config)
    try:
        if command == "register-agent":
            return _print(
                service.register_agent(
                    agent_id=args.agent_id,
                    name=args.name,
                    agent_type=args.type,
                    team=args.team,
                    workspace=args.workspace,
                    trust_level=args.trust_level,
                    allowed_scopes=args.scope,
                    owner=args.owner,
                )
            )
        if command == "use-agent":
            agent_id = str(args.agent_id).strip()
            if not agent_id:
                raise ValueError("agent_id is required")
            print("export AGENTSECURE_AGENT_ID=%s" % shlex.quote(agent_id))
            return 0
        if command == "identity":
            return _print(service.identity(args.agent_id))
        if command == "agents":
            return _print(service.identity(""))
        if command == "check-messages":
            return _print(service.check_messages(args.agent_id))
        if command == "list-messages":
            return _print(service.list_messages(args.agent_id, include_read=args.include_read))
        if command == "messages":
            return _print(_all_messages(service, agent_id=args.agent_id, unread_only=args.unread))
        if command == "read-message":
            return _print(service.read_message(args.message_id, agent_id=args.agent_id))
        if command == "send-message":
            return _print(
                service.send_message(
                    from_agent=args.from_agent,
                    to=args.to,
                    message_type=args.type,
                    subject=args.subject,
                    body=args.body,
                    resource=_json_arg(args.resource_json, "resource-json"),
                )
            )
        if command == "reply-message":
            return _print(service.reply_message(args.message_id, args.from_agent, args.body))
        if command == "request-approval":
            required_approver = _json_arg(args.required_approver_json, "required-approver-json")
            return _print(
                service.request_approval(
                    requested_by=args.requested_by,
                    action=args.action,
                    resource=_json_arg(args.resource_json, "resource-json"),
                    reason=args.reason,
                    required_approver=required_approver or None,
                )
            )
        if command == "list-approvals":
            return _print(service.list_approvals(status=args.status, approver=args.approver))
        if command == "approvals":
            action = getattr(args, "approval_action", "")
            if action:
                return _print(
                    service.resolve_approval(
                        args.approval_id,
                        action,
                        getattr(args, "comment", ""),
                        decided_by="desktop-human",
                    )
                )
            status = "pending" if args.pending else args.status
            return _print(service.list_approvals(status=status, approver=args.approver))
        if command == "approval-status":
            return _print(service.get_approval_status(args.approval_id))
        if command == "resolve-approval":
            return _print(service.resolve_approval(args.approval_id, args.decision, args.reason, args.decided_by))
        if command == "policy-hint":
            return _print(
                service.get_policy_hint(
                    agent_id=args.agent_id,
                    action=args.action,
                    resource=_json_arg(args.resource_json, "resource-json"),
                    target=args.target,
                )
            )
        if command == "audit-context":
            return _print(service.audit_context(resource=_json_arg(args.resource_json, "resource-json"), limit=args.limit))
        if command == "denials":
            return _print(_recent_denials(service, limit=args.limit))
        if command == "audit":
            return _print(service.audit_context(limit=args.limit))
        if command == "wake":
            return _print(service.wake(args.to, reason=args.reason, launch=args.launch))
        if command == "watch":
            return _print(service.watch(args.agent_id, once=args.once, interval_seconds=args.interval, launch=args.launch))
        if command == "launch-agent":
            return _print(service.launch_agent(args.agent_id))
        if command == "launch-profile":
            action = getattr(args, "launch_profile_action", "")
            if action == "set":
                command_parts = list(args.cmd)
                if command_parts and command_parts[0] == "--":
                    command_parts = command_parts[1:]
                return _print(
                    service.set_launch_profile(
                        args.agent_id,
                        command_parts,
                        cwd=args.cwd or os.getcwd(),
                        env=_env_args(args.env),
                        wake_mode=args.wake_mode,
                    )
                )
            if action == "show":
                return _print(service.launch_profiles(args.agent_id))
    except ValueError as exc:
        sys.stderr.write("agentsecure mesh: %s\n" % exc)
        return 2
    sys.stderr.write("agentsecure: missing mesh subcommand\n")
    return 2


def _json_arg(value: str, label: str) -> Dict[str, Any]:
    try:
        payload = json.loads(value or "{}")
    except ValueError as exc:
        raise ValueError("%s must be valid JSON: %s" % (label, exc))
    if not isinstance(payload, dict):
        raise ValueError("%s must be a JSON object" % label)
    return payload


def _print(payload: Dict[str, Any]) -> int:
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _all_messages(service: MeshService, agent_id: str = "", unread_only: bool = False) -> Dict[str, Any]:
    state = service.store.load()
    messages = []
    for message in state["messages"].values():
        if agent_id and message.get("to") != agent_id:
            continue
        if unread_only and message.get("status") == "read":
            continue
        messages.append(message)
    messages.sort(key=lambda item: item.get("created_at", 0), reverse=True)
    return {"messages": messages}


def _recent_denials(service: MeshService, limit: int = 50) -> Dict[str, Any]:
    events = service.audit_context(limit=limit).get("events", [])
    denials = []
    for event in events:
        if event.get("type") != "mesh.policy_denied":
            continue
        details = event.get("details", {}) if isinstance(event.get("details", {}), dict) else {}
        denials.append(
            {
                "id": str(event.get("ts", "")),
                "agent": details.get("agent_id", ""),
                "action": details.get("action", ""),
                "resource": details.get("resource", {}),
                "reason": details.get("reason", ""),
                "denied_at": event.get("ts", 0),
            }
        )
    return {"denials": denials[-int(limit):]}


def _env_args(values) -> Dict[str, str]:
    env = {}
    for value in values or []:
        if "=" not in str(value):
            raise ValueError("env entries must be KEY=VALUE")
        key, raw = str(value).split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError("env key is required")
        env[key] = raw
    return env
