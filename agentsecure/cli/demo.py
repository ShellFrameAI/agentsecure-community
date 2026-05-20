import argparse
import os
import shutil
import subprocess
import tempfile

from agentsecure.cli.common import load_config_data, scanner
from agentsecure.core.config import JsonConfigWriter
from agentsecure.core.key_service import KeyManagementService
from agentsecure.core.product import ProductService
from agentsecure.guard.sanitizer import SecretOutputSanitizer
from agentsecure.implementations.audit import JsonLineAuditLogger
from agentsecure.implementations.grant_store import LocalJsonGrantStore
from agentsecure.implementations.secret_store_factory import encrypted_secret_store_for_config
from agentsecure.workspace.materializer import make_tree_writable


def run_demo(args: argparse.Namespace) -> int:
    demo_dir = tempfile.mkdtemp(prefix="agentsecure-demo-")
    current = os.getcwd()
    try:
        os.chdir(demo_dir)
        config_path = os.path.join(demo_dir, "agentsecure.json")
        env_path = os.path.join(demo_dir, ".env")
        openai_secret = "sk-demo-local-secret-do-not-use"
        database_secret = "postgres://demo:demo-password@production.example/app"
        with open(env_path, "w") as handle:
            handle.write("OPENAI_API_KEY=%s\n" % openai_secret)
            handle.write("DATABASE_URL_PROD=%s\n" % database_secret)

        ProductService(config_path, scanner()).init_project(force=True)
        service = KeyManagementService(
            config_path,
            encrypted_secret_store_for_config(config_path),
            LocalJsonGrantStore(os.path.join(demo_dir, ".agentsecure", "grants.json")),
            JsonLineAuditLogger(os.path.join(demo_dir, ".agentsecure", "audit.log")),
        )
        openai_result = service.create_key(
            env_name="OPENAI_API_KEY",
            real_secret=openai_secret,
            provider="openai",
            ttl="2h",
        )
        service.create_key(
            env_name="DATABASE_URL_PROD",
            real_secret=database_secret,
            provider="database",
            ttl="2h",
        )
        config = load_config_data(config_path)
        config.setdefault("env_policy", {})["DATABASE_URL_PROD"] = {
            "mode": "deny",
            "environment": "production",
            "risk": "high",
            "reason": "production database credentials are not exposed to local agents",
        }
        JsonConfigWriter().save(config_path, config)

        raw_output = _demo_read_dotenv(demo_dir)
        sanitizer = SecretOutputSanitizer.from_config_path(config_path)
        agent_visible = sanitizer.sanitize_text(raw_output)

        print("AgentSecure community demo (local only)")
        print("Project: %s" % demo_dir)
        print("Command: cat .env")
        print("Decision: mask OPENAI_API_KEY and block DATABASE_URL_PROD")
        print("")
        print("Agent-visible output:")
        print(agent_visible, end="" if agent_visible.endswith("\n") else "\n")
        print("")
        print("Why:")
        print("  OPENAI_API_KEY was replaced with %s" % openai_result["virtual_token"])
        print("  DATABASE_URL_PROD was removed because env_policy sets mode=deny")
        print("  Real secret values stayed local in the demo project")
        print("  No cloud service, billing service, or enterprise policy sync was used")
        if args.keep:
            print("")
            print("Kept demo project: %s" % demo_dir)
        return 0
    finally:
        os.chdir(current)
        if not args.keep:
            make_tree_writable(demo_dir)
            shutil.rmtree(demo_dir, ignore_errors=True)


def _demo_read_dotenv(demo_dir: str) -> str:
    try:
        return subprocess.check_output(
            ["cat", ".env"],
            cwd=demo_dir,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
    except (OSError, subprocess.SubprocessError):
        with open(os.path.join(demo_dir, ".env"), "r") as handle:
            return handle.read()
