import argparse
import json
import sys

from agentsecure.core.config import ConfigError
from agentsecure.core.policy_mutation import LocalPolicyMutationService


def add_policy_subparser(subparsers) -> None:
    policy_parser = subparsers.add_parser("policy", help="Review and apply local env/capability policy")
    policy_subparsers = policy_parser.add_subparsers(dest="policy_command")
    policy_subparsers.add_parser("review", help="Print current local policy review payload")
    policy_preview_parser = policy_subparsers.add_parser("preview", help="Preview local policy changes from JSON")
    policy_preview_parser.add_argument("--json-file", help="Read mutation JSON from this file instead of stdin")
    policy_apply_parser = policy_subparsers.add_parser("apply-local", help="Apply local policy changes from JSON")
    policy_apply_parser.add_argument("--json-file", help="Read mutation JSON from this file instead of stdin")


def handle_policy(args: argparse.Namespace) -> int:
    service = LocalPolicyMutationService(args.config)
    try:
        if args.policy_command == "review":
            payload = service.review()
        elif args.policy_command == "preview":
            payload = service.preview(read_policy_mutation_payload(args))
        elif args.policy_command == "apply-local":
            payload = service.apply_local(read_policy_mutation_payload(args))
        else:
            sys.stderr.write("agentsecure: missing policy subcommand\n")
            return 2
    except (ConfigError, OSError, ValueError, json.JSONDecodeError) as exc:
        sys.stderr.write("agentsecure: %s\n" % exc)
        return 2
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def read_policy_mutation_payload(args: argparse.Namespace):
    if getattr(args, "json_file", ""):
        with open(args.json_file, "r") as handle:
            data = json.load(handle)
    else:
        text = sys.stdin.read()
        data = json.loads(text) if text.strip() else {}
    if not isinstance(data, dict):
        raise ValueError("policy mutation payload must be a JSON object")
    return data
