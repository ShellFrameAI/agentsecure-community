"""Keep caller-facing MCP documentation aligned with observable local behavior."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from agentsecure.mcp.server import McpServer
from agentsecure.mesh import MeshService


class McpToolDescriptionsTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.config_path = os.path.join(self.temp_dir.name, "agentsecure.json")
        self.config = {"audit": {"path": ".agentsecure/audit.log"}}
        self._save_config()
        self.server = McpServer(self.config_path)
        self.tools = {tool["name"]: tool for tool in self.server._tools()}

    def _save_config(self):
        with open(self.config_path, "w") as handle:
            json.dump(self.config, handle)

    def _call(self, name, **arguments):
        response = self.server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
        self.assertNotIn("error", response, response)
        result = response["result"]
        payload = json.loads(result["content"][0]["text"])
        self.assertEqual(bool(payload.get("blocked")), result["isError"])
        return payload

    def _example(self, name):
        description = self.tools[name]["description"]
        example = description.split("Example: ", 1)[1]
        return json.JSONDecoder().raw_decode(example)[0]

    def test_all_existing_tools_and_arguments_have_specific_descriptions(self):
        self.assertEqual(
            {
                "agentsecure.policy.describe", "agentsecure.secret.status", "agentsecure.http.request",
                "agentsecure.identity", "agentsecure.check_messages", "agentsecure.list_messages",
                "agentsecure.read_message", "agentsecure.send_message", "agentsecure.reply_message",
                "agentsecure.request_approval", "agentsecure.get_approval_status",
                "agentsecure.get_policy_hint", "agentsecure.audit_context",
            },
            set(self.tools),
        )
        for name, tool in self.tools.items():
            with self.subTest(tool=name):
                self.assertTrue(tool["description"].strip())
                self.assertNotIn("AgentSecure Mesh tool:", tool["description"])
                for argument, schema in tool["inputSchema"]["properties"].items():
                    self.assertTrue(schema.get("description", "").strip(), (name, argument))

    def test_identity_example_and_registration_replace_metadata(self):
        example = self._example("agentsecure.identity")
        self.assertEqual(
            {"exists": False, "agent_id": "backend-agent"},
            self._call("agentsecure.identity", **example),
        )
        self._call("agentsecure.identity", register=True, team="platform", **example)
        replaced = self._call("agentsecure.identity", register=True, **example)
        self.assertEqual("", replaced["team"])
        self.assertEqual("coding_agent", replaced["type"])
        self.assertEqual("local", replaced["workspace"])
        self.assertEqual([], replaced["allowed_scopes"])
        self.assertEqual([replaced], self._call("agentsecure.identity")["agents"])

    def test_message_examples_distinguish_count_list_and_acknowledgement(self):
        sent = self._call("agentsecure.send_message", **self._example("agentsecure.send_message"))
        message = sent["message"]
        self.assertFalse(sent["blocked"])
        self.assertEqual("question", message["type"])
        self.assertEqual("[redacted]", message["body"])
        self.assertEqual("Please review src/app.py.", message["body_summary"])
        self.assertEqual(64, len(message["body_sha256"]))

        checked = self._call("agentsecure.check_messages", **self._example("agentsecure.check_messages"))
        self.assertEqual(1, checked["unread_count"])
        self.assertNotIn("messages", checked)
        listed = self._call("agentsecure.list_messages", **self._example("agentsecure.list_messages"))
        self.assertEqual([message], listed["messages"])
        self.assertEqual(1, self._call("agentsecure.check_messages", agent_id="backend-agent")["unread_count"])

        read = self._call("agentsecure.read_message", message_id=message["message_id"], agent_id="backend-agent")
        self.assertEqual("read", read["status"])
        self.assertGreater(read["read_at"], 0)
        self.assertEqual("[redacted]", read["body"])
        self.assertEqual([], self._call("agentsecure.list_messages", agent_id="backend-agent")["messages"])
        self.assertEqual(
            read,
            self._call("agentsecure.read_message", message_id=message["message_id"], agent_id="backend-agent"),
        )

    def test_reply_acknowledges_original_even_when_sending_is_denied(self):
        sent = self._call("agentsecure.send_message", **self._example("agentsecure.send_message"))
        self.config["mesh"] = {"agents": {"backend-agent": {"cannot": ["send_message"]}}}
        self._save_config()
        reply = self._call(
            "agentsecure.reply_message", message_id=sent["message"]["message_id"],
            from_agent="backend-agent", body="Please check the unit tests.",
        )
        self.assertTrue(reply["blocked"])
        self.assertIn("allowed_next_step", reply)
        self.assertEqual([], self._call("agentsecure.list_messages", agent_id="backend-agent")["messages"])
        self.assertEqual([], self._call("agentsecure.list_messages", agent_id="frontend-agent")["messages"])

    def test_approval_example_creates_record_without_message_or_policy_override(self):
        arguments = self._example("agentsecure.request_approval")
        approval = self._call("agentsecure.request_approval", **arguments)["approval"]
        self.assertEqual("pending", approval["status"])
        self.assertEqual({"type": "human", "id": "local-owner"}, approval["required_approver"])
        self.assertEqual("[redacted]", approval["reason"])
        self.assertEqual([], self._call("agentsecure.list_messages", agent_id="local-owner")["messages"])
        repeated = self._call("agentsecure.request_approval", **arguments)["approval"]
        self.assertNotEqual(approval["approval_id"], repeated["approval_id"])

        # Decisions exist in the service/CLI, not in the exposed MCP tool set.
        MeshService(self.config_path).resolve_approval(approval["approval_id"], "approve", "Reviewed locally")
        status = self._call("agentsecure.get_approval_status", approval_id=approval["approval_id"])
        self.assertEqual("approved", status["approval"]["status"])
        hint = self._call("agentsecure.get_policy_hint", agent_id=arguments["requested_by"], action=arguments["action"])
        self.assertTrue(hint["blocked"])
        self.assertEqual("call agentsecure.request_approval", hint["allowed_next_step"])
        self.assertTrue(self._call("agentsecure.get_policy_hint", **self._example("agentsecure.get_policy_hint"))["allowed"])

    def test_resource_and_summary_documentation_matches_storage(self):
        body = "A harmless review note. " * 10
        result = self._call(
            "agentsecure.send_message", from_agent="frontend-agent", to="backend-agent", body=body,
            resource={"path": "src/app.py", "id": {"nested": "omitted"}, "unrecognized": "omitted"},
        )
        message = result["message"]
        self.assertEqual({"path": "src/app.py"}, message["resource"])
        self.assertEqual(" ".join(body.split())[:120], message["body_summary"])
        self.assertNotIn(body, json.dumps(message))

    def test_audit_example_filter_order_and_zero_limit(self):
        self.assertEqual([], self._call("agentsecure.audit_context", **self._example("agentsecure.audit_context"))["events"])
        path = os.path.join(self.temp_dir.name, ".agentsecure", "audit.log")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        events = [
            {"type": "mesh.message_sent", "details": {"resource": {"path": "src/app.py"}}, "timestamp": 1},
            {"type": "mcp_http_request", "details": {}, "timestamp": 2},
            {"type": "mesh.message_read", "details": {"resource": {"path": "src/app.py"}}, "timestamp": 3},
        ]
        with open(path, "w") as handle:
            handle.write("not JSON\n")
            for event in events:
                handle.write(json.dumps(event) + "\n")
        self.assertEqual([events[2]], self._call("agentsecure.audit_context", limit=1)["events"])
        self.assertEqual([events[0], events[2]], self._call("agentsecure.audit_context", limit=0)["events"])
        self.assertEqual(
            [events[0], events[2]],
            self._call("agentsecure.audit_context", resource={"path": "app.py"})["events"],
        )

    def test_secret_status_is_config_only_and_http_requires_placeholders(self):
        self.config["secret_aliases"] = [{"alias_id": "demo-missing-vault-entry", "env_name": "API_KEY"}]
        self._save_config()
        # These metadata calls must not attempt to resolve the nonexistent vault entry.
        with patch("agentsecure.mcp.runtime.secret_alias_service", side_effect=AssertionError("vault lookup")):
            status = self._call("agentsecure.secret.status", **self._example("agentsecure.secret.status"))
            self.assertTrue(status["exists"])
            self.assertEqual("vault_alias", status["source"])
            policy = self._call("agentsecure.policy.describe")
            self.assertEqual({"network", "secret_aliases", "project_bindings", "instructions"}, set(policy))
        result = self._call("agentsecure.http.request", url="https://api.example.com/me")
        self.assertTrue(result["blocked"])
        self.assertEqual("mcp.no_secret_placeholders", result["rule_id"])


if __name__ == "__main__":
    unittest.main()
