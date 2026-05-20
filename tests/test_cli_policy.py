import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from agentsecure.cli.main import build_parser, main
from agentsecure.cli.policy import read_policy_mutation_payload


class CliPolicyTest(unittest.TestCase):
    def test_policy_parser_wires_preview_json_file(self):
        args = build_parser().parse_args(["--config", "custom.json", "policy", "preview", "--json-file", "payload.json"])

        self.assertEqual("policy", args.command)
        self.assertEqual("preview", args.policy_command)
        self.assertEqual("custom.json", args.config)
        self.assertEqual("payload.json", args.json_file)

    def test_policy_reader_rejects_non_object_json(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("[]")
            payload_path = handle.name
        try:
            with self.assertRaises(ValueError):
                read_policy_mutation_payload(argparse.Namespace(json_file=payload_path))
        finally:
            os.unlink(payload_path)

    def test_policy_review_command_outputs_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "agentsecure.json")
            with open(config_path, "w") as handle:
                json.dump({"env_policy": {"DATABASE_URL_PROD": {"mode": "deny"}}}, handle)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(["--config", config_path, "policy", "review"])

        self.assertEqual(0, code)
        payload = json.loads(stdout.getvalue())
        self.assertEqual("deny", payload["env_policy"]["DATABASE_URL_PROD"]["mode"])

    def test_policy_preview_missing_json_file_returns_cli_error(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = main(["policy", "preview", "--json-file", "/tmp/agentsecure-missing-policy.json"])

        self.assertEqual(2, code)
        self.assertIn("agentsecure:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
