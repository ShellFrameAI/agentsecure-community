import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

from agentsecure.cli.main import main
from agentsecure.mcp.server import McpServer
from agentsecure.mesh import MeshService


class MeshTest(unittest.TestCase):
    def test_local_message_reply_approval_and_audit_flow(self):
        with _ProjectContext() as project:
            service = MeshService(project["config_path"])
            service.register_agent("frontend-agent", name="Frontend Agent", team="product")
            service.register_agent("backend-agent", name="Backend Agent", team="platform")

            sent = service.send_message(
                from_agent="frontend-agent",
                to="backend-agent",
                message_type="question",
                subject="API contract",
                body="Can I rename fullName to name?",
                resource={"type": "code_file", "provider": "local", "path": "src/api/users.ts"},
            )
            self.assertFalse(sent["blocked"])
            message_id = sent["message"]["message_id"]

            inbox = service.list_messages("backend-agent")
            self.assertEqual(1, len(inbox["messages"]))
            self.assertEqual("unread", inbox["messages"][0]["status"])

            read = service.read_message(message_id, agent_id="backend-agent")
            self.assertEqual("read", read["status"])

            reply = service.reply_message(message_id, "backend-agent", "Use a migration first.")
            self.assertFalse(reply["blocked"])
            self.assertEqual("frontend-agent", reply["message"]["to"])

            approval = service.request_approval(
                requested_by="frontend-agent",
                action="change_api_contract",
                resource={"type": "code_change", "repo": "company/app", "path": "src/api/users.ts", "team": "platform"},
                reason="Frontend needs a simpler user object shape.",
            )["approval"]
            self.assertEqual("pending", approval["status"])

            decided = service.resolve_approval(
                approval["approval_id"],
                "reject",
                "Breaking change needs backend migration first.",
                decided_by="amichai",
            )["approval"]
            self.assertEqual("denied", decided["status"])
            self.assertEqual("deny", decided["decision"])

            events = service.audit_context(resource={"path": "src/api/users.ts"})["events"]
            event_types = [event["type"] for event in events]
            self.assertIn("mesh.message_sent", event_types)
            self.assertIn("mesh.approval_decided", event_types)

    def test_mesh_requires_reader_identity_and_redacts_free_text(self):
        with _ProjectContext() as project:
            service = MeshService(project["config_path"])
            service.register_agent("frontend-agent")
            service.register_agent("backend-agent")
            secret_text = "TOKEN=super-sensitive-value"

            sent = service.send_message(
                from_agent="frontend-agent",
                to="backend-agent",
                message_type="question",
                subject=secret_text,
                body=secret_text,
                resource={"type": "code_file", "path": "src/api/users.ts", "payload": secret_text},
            )
            message_id = sent["message"]["message_id"]
            self.assertEqual("[redacted]", sent["message"]["body"])
            self.assertTrue(sent["message"]["content_redacted"])
            with self.assertRaises(ValueError):
                service.read_message(message_id)

            approval = service.request_approval(
                requested_by="frontend-agent",
                action="change_api_contract",
                resource={"type": "code_change", "path": "src/api/users.ts", "payload": secret_text},
                reason=secret_text,
            )["approval"]
            self.assertEqual("[redacted]", approval["reason"])
            self.assertTrue(approval["content_redacted"])

            mesh_path = os.path.join(project["project_dir"], ".agentsecure", "mesh.json")
            audit_path = os.path.join(project["project_dir"], ".agentsecure", "audit.log")
            with open(mesh_path, "r") as handle:
                mesh_text = handle.read()
            with open(audit_path, "r") as handle:
                audit_text = handle.read()
            self.assertNotIn(secret_text, mesh_text)
            self.assertNotIn(secret_text, audit_text)

    def test_policy_hint_blocks_sensitive_action_with_next_step(self):
        with _ProjectContext() as project:
            service = MeshService(project["config_path"])
            hint = service.get_policy_hint(
                "frontend-agent",
                "deploy_production",
                {"type": "deployment", "environment": "production"},
            )

            self.assertTrue(hint["blocked"])
            self.assertIn("request_approval", hint["allowed_next_step"])

    def test_policy_hint_does_not_match_prod_inside_product(self):
        with _ProjectContext() as project:
            service = MeshService(project["config_path"])
            hint = service.get_policy_hint(
                "frontend-agent",
                "send_message",
                {"type": "code_file", "team": "product", "path": "src/product/catalog.ts"},
            )

            self.assertFalse(hint["blocked"])

    def test_check_messages_counts_team_assigned_approvals(self):
        with _ProjectContext() as project:
            service = MeshService(project["config_path"])
            service.register_agent("backend-agent", name="Backend Agent", team="platform")
            service.request_approval(
                requested_by="frontend-agent",
                action="change_api_contract",
                resource={"type": "code_change", "team": "platform"},
                reason="Need platform review.",
            )

            inbox = service.check_messages("backend-agent")

            self.assertEqual(1, inbox["pending_approval_count"])

    def test_cli_mesh_commands_print_json(self):
        with _ProjectContext() as project:
            with redirect_stdout(StringIO()):
                self.assertEqual(
                    0,
                    main(
                        [
                            "--config",
                            project["config_path"],
                            "mesh",
                            "register-agent",
                            "--agent-id",
                            "backend-agent",
                            "--name",
                            "Backend Agent",
                        ]
                    ),
                )
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    0,
                    main(["--config", project["config_path"], "mesh", "identity", "--agent-id", "backend-agent"]),
                )
            payload = json.loads(output.getvalue())
            self.assertTrue(payload["exists"])
            self.assertEqual("Backend Agent", payload["name"])

    def test_cli_desktop_compatibility_aliases_print_json(self):
        with _ProjectContext() as project:
            with redirect_stdout(StringIO()):
                self.assertEqual(
                    0,
                    main(
                        [
                            "--config",
                            project["config_path"],
                            "mesh",
                            "register-agent",
                            "--agent-id",
                            "backend-agent",
                        ]
                    ),
                )
            commands = [
                ["mesh", "agents", "--json"],
                ["mesh", "messages", "--unread", "--json"],
                ["mesh", "approvals", "--pending", "--json"],
                ["mesh", "denials", "--recent", "--json"],
                ["mesh", "audit", "--recent", "--json"],
            ]
            for command in commands:
                output = StringIO()
                with redirect_stdout(output):
                    self.assertEqual(0, main(["--config", project["config_path"]] + command))
                json.loads(output.getvalue())

    def test_mcp_mesh_tools_are_listed_and_callable(self):
        with _ProjectContext() as project:
            server = McpServer(project["config_path"])
            listed = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            serialized = json.dumps(listed)
            self.assertIn("agentsecure.request_approval", serialized)
            self.assertIn("agentsecure.check_messages", serialized)
            self.assertNotIn("agentsecure.resolve_approval", serialized)

            called = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "agentsecure.identity",
                        "arguments": {
                            "register": True,
                            "agent_id": "security-agent",
                            "name": "Security Agent",
                        },
                    },
                }
            )
            self.assertIn("content", called["result"])
            self.assertIn("security-agent", called["result"]["content"][0]["text"])


class _ProjectContext:
    def __enter__(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.old_cwd = os.getcwd()
        self.project_dir = os.path.join(self.temp_dir.name, "project")
        os.makedirs(self.project_dir)
        self.config_path = os.path.join(self.project_dir, "agentsecure.json")
        with open(self.config_path, "w") as handle:
            json.dump({"audit": {"path": ".agentsecure/audit.log"}}, handle)
        os.chdir(self.project_dir)
        return {"config_path": self.config_path, "project_dir": self.project_dir}

    def __exit__(self, exc_type, exc, tb):
        os.chdir(self.old_cwd)
        self.temp_dir.cleanup()
