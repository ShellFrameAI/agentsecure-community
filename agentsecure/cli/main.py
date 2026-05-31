import argparse
import hashlib
import getpass
import ipaddress
import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen

from agentsecure import __version__
from agentsecure.cloud import CloudError, CloudRuntimeService
from agentsecure.api.server import LocalApiServer
from agentsecure.api.services import ApiServices
from agentsecure.cli.common import (
    cloud_features_disabled as _cloud_features_disabled,
    cloud_features_enabled as _cloud_features_enabled,
    scanner as _scanner,
)
from agentsecure.cli.demo import run_demo
from agentsecure.cli.policy import add_policy_subparser, handle_policy
from agentsecure.cli.project import (
    _profile_label,
    cleanup_project,
    init_project,
    run_doctor,
    show_status,
    uninstall_agentsecure,
)
from agentsecure.cli.proxy import add_proxy_subparser, handle_proxy
from agentsecure.cli.receipts import handle_receipts
from agentsecure.cli.secrets import (
    _read_real_secret,
    discover_secrets,
    handle_keys,
    print_env,
    protect_secrets,
    suggest_policy,
)
from agentsecure.cli.settings import (
    apply_workspace,
    diff_workspace,
    handle_files,
    handle_network,
    handle_setup,
)
from agentsecure.client.wrappers import AgentWrapperInstaller, SUPPORTED_AGENTS
from agentsecure.core.agentsecure_md import AGENTSECURE_MD, agentsecure_md_status
from agentsecure.core.command_metadata import safe_command_metadata
from agentsecure.core.config import ConfigError, JsonConfigLoader, JsonConfigWriter
from agentsecure.core.config_profiles import (
    profile_metadata_from_response,
    profile_policy_body_from_response,
)
from agentsecure.core.capabilities import broker_url_for_env
from agentsecure.core.container import Container
from agentsecure.core.key_service import KeyManagementError, KeyManagementService
from agentsecure.core.models import AgentSecureConfig, DiscoveredSecret, ProcessRequest, SecretBinding, SecretReplacement
from agentsecure.core.provider_proxy import configured_provider_base_url, provider_base_local_path
from agentsecure.core.product import ProductService
from agentsecure.core.runtime_bindings import ENV_RUNTIME_BINDINGS, serialize_runtime_bindings
from agentsecure.core.secret_aliases import (
    SecretAliasError,
    SecretAliasService,
    local_secret_alias_store_for_home,
    project_id_for_path,
)
from agentsecure.core.time import DurationError
from agentsecure.daemon.commands import CommandExecutor, CommandPoller
from agentsecure.daemon.policies import PolicyApplier
from agentsecure.daemon.sessions import SessionRegistry
from agentsecure.daemon.supervisor import AgentProcessSupervisor
from agentsecure.discovery.dotenv_scanner import DotenvSecretScanner
from agentsecure.discovery.env_scanner import EnvironmentSecretScanner
from agentsecure.discovery.patterns import mask_secret
from agentsecure.discovery.scanner import CompositeSecretScanner
from agentsecure.discovery.suggestions import PolicySuggestionService
from agentsecure.guard.command import GuardedCommandRunner
from agentsecure.guard.sanitizer import SecretOutputSanitizer
from agentsecure.guard.wrappers import CommandGuardWrapperInstaller
from agentsecure.gateway.proxy import LocalGateway
from agentsecure.implementations.audit import JsonLineAuditLogger
from agentsecure.implementations.grant_store import LocalJsonGrantStore, local_grant_store_for_config
from agentsecure.implementations.secret_store_factory import (
    agentsecure_home,
    encrypted_secret_store_for_config,
    encrypted_secret_store_for_vault,
)
from agentsecure.workspace.apply import WorkspaceApplier
from agentsecure.workspace.diff import WorkspaceDiff
from agentsecure.workspace.materializer import WorkspaceMaterializer, make_tree_writable


INTERACTIVE_AGENT_COMMANDS = set(SUPPORTED_AGENTS)


class LocalGatewayHandle:
    def __init__(self, gateway: LocalGateway, thread: threading.Thread) -> None:
        self.gateway = gateway
        self.thread = thread

    def shutdown(self) -> None:
        self.gateway.shutdown()
        self.thread.join(timeout=2)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        return run_agent(args)
    if args.command == "gateway":
        return run_gateway(args)
    if args.command == "daemon":
        return run_daemon(args)
    if args.command == "env":
        return print_env(args)
    if args.command == "keys":
        return handle_keys(args)
    if args.command == "secrets":
        return handle_secret_aliases(args)
    if args.command == "discover":
        return discover_secrets(args)
    if args.command == "suggest":
        return suggest_policy(args)
    if args.command == "protect":
        result = protect_secrets(args)
        return result if isinstance(result, int) else 0
    if args.command == "api":
        return run_api(args)
    if args.command == "init":
        return init_project(args)
    if args.command == "status":
        return show_status(args)
    if args.command == "doctor":
        return run_doctor(args)
    if args.command == "cleanup":
        return cleanup_project(args)
    if args.command == "uninstall":
        return uninstall_agentsecure(args)
    if args.command == "files":
        return handle_files(args)
    if args.command == "network":
        return handle_network(args)
    if args.command == "proxy":
        return handle_proxy(args)
    if args.command == "receipts":
        return handle_receipts(args)
    if args.command == "policy":
        return handle_policy(args)
    if args.command == "setup":
        return handle_setup(args)
    if args.command == "enroll":
        return enroll_cloud(args)
    if args.command == "cloud":
        return handle_cloud(args)
    if args.command == "diff":
        return diff_workspace(args)
    if args.command == "apply":
        return apply_workspace(args)
    if args.command == "guard":
        return guard_command(args)
    if args.command == "demo":
        return run_demo(args)
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentsecure")
    parser.add_argument("--version", action="version", version="agentsecure %s" % __version__)
    parser.add_argument(
        "--config",
        default="agentsecure.json",
        help="Path to AgentSecure JSON config",
    )
    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser("run", help="Run an agent under AgentSecure")
    run_parser.add_argument("--no-discover", action="store_true", help="Skip pre-run secret discovery prompt")
    run_parser.add_argument("--protect-all", action="store_true", default=True, help="Virtualize all discovered secrets without prompting")
    run_parser.add_argument("--prompt-secrets", dest="protect_all", action="store_false", help="Prompt before virtualizing discovered secrets")
    run_parser.add_argument(
        "--runtime",
        choices=["workspace", "command-guard"],
        default="command-guard",
        help="Runtime mode. command-guard runs in place and sanitizes common read commands; workspace materializes sanitized files.",
    )
    run_parser.add_argument("--no-workspace", action="store_true", help="Run in the real project directory")
    run_parser.add_argument("--workspace-keep", action="store_true", help="Keep the safe workspace after the agent exits")
    run_parser.add_argument("--read-only-workspace", action="store_true", help="Make the safe workspace read-only")
    run_parser.add_argument("--no-new-files", action="store_true", help="Block creating, deleting, or renaming files in the safe workspace")
    run_parser.add_argument(
        "--allow-loopback-proxy-bypass",
        action="store_true",
        help="Allow direct 127.0.0.1/localhost connections when strict proxy is enabled",
    )
    run_parser.add_argument(
        "--allow-private-proxy-bypass",
        action="append",
        default=[],
        metavar="PRIVATE_IP",
        help="Allow direct connections to one private IP when strict proxy is enabled",
    )
    run_parser.add_argument(
        "--strict-proxy",
        action="store_true",
        help="Route general HTTP(S) traffic through the AgentSecure gateway. Command-guard leaves general traffic direct by default.",
    )
    run_parser.add_argument(
        "--workspace-mode",
        choices=["symlink", "copy"],
        default="symlink",
        help="Workspace strategy. symlink is fast and lets normal edits hit the real project; copy is safer review mode.",
    )
    run_parser.add_argument("--ttl", default="2h", help="Grant duration for protected discovered secrets")
    run_parser.add_argument("agent_command", nargs=argparse.REMAINDER)

    subparsers.add_parser("gateway", help="Run only the local gateway")
    subparsers.add_parser("env", help="Print virtual environment variables")

    keys_parser = subparsers.add_parser("keys", help="Manage virtual keys")
    keys_subparsers = keys_parser.add_subparsers(dest="keys_command")
    create_parser = keys_subparsers.add_parser("create", help="Create a virtual key")
    create_parser.add_argument("--env-name", required=True, help="Agent-visible environment variable name")
    create_parser.add_argument("--provider", default="custom", help="Provider label, such as openai")
    create_parser.add_argument("--inject-as", default="authorization_bearer", help="Credential injection mode")
    create_parser.add_argument("--name", default="", help="Optional human-readable key name")
    create_parser.add_argument("--real-secret-env", help="Read the real secret from this local environment variable")
    create_parser.add_argument("--real-secret-stdin", action="store_true", help="Read the real secret from stdin")
    create_parser.add_argument("--ttl", default="2h", help="Grant duration, default 2h, max 24h")
    keys_subparsers.add_parser("list", help="List virtual key grants")
    revoke_parser = keys_subparsers.add_parser("revoke", help="Revoke a virtual key")
    revoke_parser.add_argument("virtual_token")

    secrets_parser = subparsers.add_parser("secrets", help="Manage central local secret aliases")
    secrets_subparsers = secrets_parser.add_subparsers(dest="secrets_command")
    add_secret_parser = secrets_subparsers.add_parser("add", help="Store a real secret once under a local alias")
    add_secret_parser.add_argument("alias_id", help="Stable local alias, such as dev_db or facebook_app")
    add_secret_parser.add_argument("--env-name", required=True, help="Environment variable exposed during runs")
    add_secret_parser.add_argument("--provider", default="custom", help="Provider label")
    add_secret_parser.add_argument("--inject-as", default="authorization_bearer", help="Credential injection mode")
    add_secret_parser.add_argument("--name", default="", help="Human-readable alias label")
    add_secret_parser.add_argument("--approved-host", action="append", default=[], help="Host allowed to receive this alias")
    add_secret_parser.add_argument("--real-secret-env", help="Read the real secret from this local environment variable")
    add_secret_parser.add_argument("--real-secret-stdin", action="store_true", help="Read the real secret from stdin")
    secrets_subparsers.add_parser("list", help="List local secret aliases without printing secret values")
    use_secret_parser = secrets_subparsers.add_parser("use", help="Assign aliases to this project")
    use_secret_parser.add_argument("alias_ids", nargs="+")
    use_secret_parser.add_argument("--project", default="", help="Project name for audit metadata")

    subparsers.add_parser("discover", help="Discover likely local secrets")
    subparsers.add_parser("suggest", help="Suggest env and network policy for discovered secrets")
    protect_parser = subparsers.add_parser("protect", help="Interactively virtualize discovered secrets")
    protect_parser.add_argument("--protect-all", action="store_true", help="Virtualize all discovered secrets without prompting")
    protect_parser.add_argument("--ttl", default="2h", help="Grant duration, default 2h, max 24h")

    init_parser = subparsers.add_parser("init", help="Initialize AgentSecure in this project")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing AgentSecure config")
    init_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    status_parser = subparsers.add_parser("status", help="Show AgentSecure project status")
    status_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    doctor_parser = subparsers.add_parser("doctor", help="Check AgentSecure project setup")
    doctor_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    cleanup_parser = subparsers.add_parser("cleanup", help="Remove local AgentSecure trial state from this project")
    cleanup_parser.add_argument("--yes", action="store_true", help="Confirm removal without prompting")
    cleanup_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    uninstall_parser = subparsers.add_parser("uninstall", help="Remove AgentSecure from this project and user bin")
    uninstall_parser.add_argument("--yes", action="store_true", help="Confirm removal without prompting")
    uninstall_parser.add_argument("--install-dir", default=os.path.expanduser("~/.agentsecure/bin"), help="AgentSecure user bin directory")

    files_parser = subparsers.add_parser("files", help="Manage write-protected files")
    files_subparsers = files_parser.add_subparsers(dest="files_command")
    files_subparsers.add_parser("list", help="List paths protected from writes in safe workspaces")
    protect_file_parser = files_subparsers.add_parser("protect", help="Protect paths from writes")
    protect_file_parser.add_argument("paths", nargs="+")
    unprotect_file_parser = files_subparsers.add_parser("unprotect", help="Remove write protection for paths")
    unprotect_file_parser.add_argument("paths", nargs="+")

    network_parser = subparsers.add_parser("network", help="Manage network allowlist")
    network_subparsers = network_parser.add_subparsers(dest="network_command")
    network_subparsers.add_parser("list", help="List allowed credential destinations")
    network_allow_parser = network_subparsers.add_parser("allow", help="Allow credential use for domains")
    network_allow_parser.add_argument("domains", nargs="+")
    network_remove_parser = network_subparsers.add_parser("remove", help="Remove domains from credential allowlist")
    network_remove_parser.add_argument("domains", nargs="+")

    add_proxy_subparser(subparsers)
    receipts_parser = subparsers.add_parser("receipts", help="Run replayable AgentSecure proof receipts")
    receipts_parser.add_argument("--proxy", action="store_true", help="Run provider proxy receipts")
    add_policy_subparser(subparsers)

    setup_parser = subparsers.add_parser("setup", help="Install local protected agent command wrappers")
    setup_parser.add_argument("--bin-dir", default=os.path.expanduser("~/.agentsecure/bin"), help="Directory for wrapper commands")
    setup_subparsers = setup_parser.add_subparsers(dest="setup_command")
    setup_install_parser = setup_subparsers.add_parser("install", help="Install wrapper commands")
    setup_install_parser.add_argument("agents", nargs="+", choices=SUPPORTED_AGENTS)
    setup_remove_parser = setup_subparsers.add_parser("remove", help="Remove wrapper commands")
    setup_remove_parser.add_argument("agents", nargs="+", choices=SUPPORTED_AGENTS)
    setup_subparsers.add_parser("list", help="List wrapper commands")

    diff_parser = subparsers.add_parser("diff", help="Show changes in a kept safe workspace")
    diff_parser.add_argument("--workspace", help="Workspace path. Defaults to latest kept workspace")
    diff_parser.add_argument("--include-protected", action="store_true", help="Include protected files such as .env")

    apply_parser = subparsers.add_parser("apply", help="Apply safe changes from a kept workspace")
    apply_parser.add_argument("--workspace", help="Workspace path. Defaults to latest kept workspace")
    apply_parser.add_argument("--dry-run", action="store_true", help="Show what would be applied without copying files")

    guard_parser = subparsers.add_parser("guard", help="Run the local command-guard wrapper")
    guard_parser.add_argument("tool")
    guard_parser.add_argument("tool_args", nargs=argparse.REMAINDER)

    demo_parser = subparsers.add_parser("demo", help="Run a local-only community .env masking demo")
    demo_parser.add_argument("--keep", action="store_true", help="Keep the temporary demo project")
    return parser


def run_agent(args: argparse.Namespace) -> int:
    run_id = "run_" + uuid.uuid4().hex[:16]
    project_id = project_id_for_path(args.config)
    policy_doc = agentsecure_md_status(AGENTSECURE_MD)
    if policy_doc.get("exists"):
        state = "valid" if policy_doc.get("ok") else "needs review"
        print("AgentSecure policy guidance: %s (%s)" % (AGENTSECURE_MD, state), flush=True)
    cloud = CloudRuntimeService() if _cloud_features_enabled() else None
    if cloud:
        _apply_cloud_runtime_defaults(args, cloud)
        _pull_cloud_policy(args.config, cloud)
    project_name = getattr(args, "project", "") or os.path.basename(os.getcwd()) or "default"
    task_label = getattr(args, "task", "") or "Untitled session"
    replacements = []
    if not args.no_discover:
        replacements = protect_secrets(args)
        if isinstance(replacements, int):
            return replacements
    if not os.path.exists(args.config):
        ProductService(args.config, _scanner()).init_project()
    try:
        initial_config = JsonConfigLoader().load(args.config)
    except FileNotFoundError:
        initial_config = AgentSecureConfig()
    alias_runtime_bindings = []
    if initial_config.secret_aliases:
        try:
            alias_runtime_bindings = _secret_alias_service(args.config).prepare_run_bindings(
                initial_config.secret_aliases,
                args.ttl,
                project_id,
                run_id,
            )
        except (DurationError, SecretAliasError) as exc:
            sys.stderr.write("agentsecure: %s\n" % exc)
            return 2
    runtime_bindings = alias_runtime_bindings
    container = Container.from_config_path(args.config, runtime_bindings=runtime_bindings, run_id=run_id)
    replacements.extend(_configured_secret_replacements(container, replacements))
    run_cwd = os.getcwd()
    workspace_session = None
    materializer = WorkspaceMaterializer(_workspace_base_for_runtime(run_cwd, args.runtime))
    should_create_workspace = bool(replacements or container.config.files.protect_write)
    if args.runtime == "command-guard":
        print("AgentSecure runtime: command-guard", flush=True)
        print("No workspace created. Common secret reads are sanitized through command wrappers.", flush=True)
    elif should_create_workspace and not args.no_workspace:
        try:
            workspace_mode = "copy" if args.read_only_workspace else args.workspace_mode
            workspace_session = materializer.create_workspace(
                run_cwd,
                replacements,
                args.ttl,
                mode=workspace_mode,
                protected_write_paths=container.config.files.protect_write,
            )
            if args.read_only_workspace:
                materializer.make_read_only(workspace_session.workspace_root)
            else:
                materializer.protect_write_paths(
                    workspace_session.workspace_root,
                    container.config.files.protect_write,
                )
                if args.no_new_files:
                    materializer.prevent_new_files(workspace_session.workspace_root)
            run_cwd = workspace_session.workspace_root
            print("AgentSecure safe workspace: %s" % workspace_session.workspace_root, flush=True)
            print("AgentSecure workspace mode: %s" % workspace_session.mode, flush=True)
            if workspace_session.mode == "symlink":
                print("Secrets are virtualized. Normal file edits may affect the real project.", flush=True)
            else:
                print("Real project files were not modified.", flush=True)
            if args.read_only_workspace:
                print("Safe workspace is read-only.", flush=True)
            elif args.no_new_files:
                print("Safe workspace blocks new files.", flush=True)
        except (DurationError, OSError) as exc:
            sys.stderr.write("agentsecure: failed to create safe workspace: %s\n" % exc)
            return 1
    argv = list(args.agent_command)
    if argv and argv[0] == "--":
        argv = argv[1:]
    argv = _apply_read_only_agent_mode(argv, args.read_only_workspace)
    decision = container.policy_engine.evaluate_process(ProcessRequest(argv=argv, cwd=run_cwd))
    if not decision.allowed:
        sys.stderr.write("agentsecure: blocked process: " + decision.reason + "\n")
        return 126
    if not argv:
        sys.stderr.write("agentsecure: missing agent command\n")
        return 2

    daemon = None if runtime_bindings else _running_daemon()
    daemon_session = None
    gateway_handle = None
    if daemon:
        daemon_session = _daemon_create_session(
            daemon,
            {
                "agent": os.path.basename(argv[0]) if argv else "",
                "argv": argv,
                "project": project_name,
                "task": task_label,
                "runtime": args.runtime,
                "cwd": run_cwd,
                "config_profile": cloud.config_profile() if cloud else {},
            },
        )
        gateway_host = str(daemon.get("gateway_host", container.config.gateway.host))
        gateway_port = int(daemon.get("gateway_port", container.config.gateway.port))
    else:
        gateway_host = container.config.gateway.host
        gateway_port = _available_gateway_port(gateway_host, container.config.gateway.port)
        gateway_handle = _start_local_gateway_thread(container, gateway_host, gateway_port)
        if isinstance(gateway_handle, int):
            return gateway_handle

    env = os.environ.copy()
    for env_name in container.config.env_policy.rules:
        env.pop(env_name, None)
    _strip_backing_secret_environment(env, container)
    env.update(container.virtual_env_provider.build_environment())
    if runtime_bindings:
        env[ENV_RUNTIME_BINDINGS] = serialize_runtime_bindings(runtime_bindings)
        env["AGENTSECURE_RUN_ID"] = run_id
        env["AGENTSECURE_PROJECT_ID"] = project_id
    if args.runtime == "command-guard":
        CommandGuardWrapperInstaller(args.config).install(env)
    session_id = daemon_session.get("session_id", "") if daemon_session else ""
    if session_id:
        env["AGENTSECURE_SESSION_ID"] = session_id
    proxy_url = _proxy_url(gateway_host, gateway_port, session_id)
    proxy_enabled = bool(getattr(args, "strict_proxy", False) or args.runtime == "workspace")
    if proxy_enabled:
        try:
            _apply_proxy_environment(
                env,
                proxy_url,
                allow_loopback_bypass=getattr(args, "allow_loopback_proxy_bypass", False),
                private_bypass_hosts=getattr(args, "allow_private_proxy_bypass", []),
            )
        except ValueError as exc:
            sys.stderr.write("agentsecure: %s\n" % exc)
            return 2
    else:
        try:
            _validate_private_proxy_bypass_hosts(getattr(args, "allow_private_proxy_bypass", []))
        except ValueError as exc:
            sys.stderr.write("agentsecure: %s\n" % exc)
            return 2
    _apply_provider_proxy_environment(env, container, gateway_host, gateway_port)
    command_metadata = safe_command_metadata(argv)
    container.audit_logger.record(
        "agent_started",
        {
            "argv": command_metadata["argv"],
            "argc": command_metadata["argc"],
            "proxy": proxy_url if proxy_enabled else "",
            "cwd": run_cwd,
            "workspace": workspace_session.workspace_root if workspace_session else "",
            "project": project_name,
            "task": task_label,
            "session_id": session_id,
            "daemon": bool(daemon),
        },
    )
    cloud_session = None
    cloud_stop = threading.Event()
    cloud_thread = None
    command_poller = None
    command_executor = None
    if cloud and cloud.status().get("enrolled"):
        cloud_session = cloud.session_payload(
            argv,
            project_name,
            task_label,
            args.runtime,
            run_cwd,
            workspace_session.workspace_root if workspace_session else "",
            config_profile=cloud.config_profile(),
        )
        if session_id:
            cloud_session["session_id"] = session_id
        if getattr(args, "cloud_debug", False):
            os.environ["AGENTSECURE_CLOUD_DEBUG"] = "true"
    session_finished = False
    try:
        output_sanitizer = SecretOutputSanitizer.from_config_path(args.config)
        preserve_tty = _should_preserve_interactive_tty(argv)
        if preserve_tty:
            print(
                "AgentSecure interactive terminal mode: command output is not post-processed.",
                flush=True,
            )
        process = _start_agent_process(argv, env, run_cwd, sanitize_output=not preserve_tty)
        process_group_id = _process_group_id(process)
        if cloud_session and cloud and cloud.status().get("enrolled"):
            command_executor = _run_command_executor(
                args.config,
                container.audit_logger,
                cloud_session,
                process.pid,
            )
            start_response = _try_cloud_sync(cloud, cloud_session, "running", force=True)
            _execute_cloud_response_commands(cloud, command_executor, start_response)
            cloud_thread = _start_cloud_report_thread(cloud, cloud_session, cloud_stop, command_executor)
        if daemon and daemon_session:
            _daemon_update_session(
                daemon,
                session_id,
                {
                    "pid": process.pid,
                    "pgid": os.getpgid(process.pid) if os.name == "posix" else process.pid,
                    "status": "running",
                },
            )
        elif command_executor:
            command_poller = CommandPoller(cloud, command_executor)
            command_poller.start()
        exit_code = _wait_for_agent_process(process, output_sanitizer)
        if exit_code is None or exit_code >= 0:
            _wait_for_process_group_exit(process_group_id)
        final_status = "killed" if exit_code is not None and exit_code < 0 else "finished"
        if daemon and daemon_session:
            _daemon_finish_session(daemon, session_id, final_status, exit_code)
            session_finished = True
        if cloud_session:
            container.audit_logger.record(
                "agent_killed" if final_status == "killed" else "agent_finished",
                {
                    "session_id": cloud_session.get("session_id", ""),
                    "project": project_name,
                    "task": task_label,
                    "exit_code": exit_code,
                },
            )
            finish_response = _try_cloud_sync(cloud, cloud_session, final_status, exit_code, force=True)
            if command_executor:
                _execute_cloud_response_commands(cloud, command_executor, finish_response)
        return exit_code
    finally:
        if runtime_bindings:
            _revoke_runtime_bindings(args.config, runtime_bindings, run_id)
        if command_poller:
            command_poller.stop()
        if daemon and daemon_session and not session_finished:
            _daemon_finish_session(daemon, session_id, "finished", None)
        cloud_stop.set()
        if cloud_thread:
            cloud_thread.join(timeout=2)
        if gateway_handle:
            gateway_handle.shutdown()
        if workspace_session and not args.workspace_keep:
            materializer.make_writable(workspace_session.workspace_root)
            shutil.rmtree(workspace_session.workspace_root, ignore_errors=True)
            container.audit_logger.record(
                "workspace_removed",
                {"workspace": workspace_session.workspace_root},
            )


def _workspace_base_for_runtime(source_root: str, runtime: str) -> str:
    if runtime != "workspace":
        return ".agentsecure/workspaces"
    digest = hashlib.sha256(os.path.abspath(source_root).encode("utf-8")).hexdigest()[:16]
    return os.path.join(tempfile.gettempdir(), "agentsecure-workspaces", digest)


def _revoke_runtime_bindings(config_path: str, bindings: List[SecretBinding], run_id: str) -> None:
    grant_store = local_grant_store_for_config(config_path)
    revoked = []
    for binding in bindings:
        if grant_store.revoke(binding.virtual_token):
            revoked.append(binding.alias_id or binding.env_name)
    if revoked:
        JsonLineAuditLogger(".agentsecure/audit.log").record(
            "run_secret_revoked",
            {"run_id": run_id, "secrets": revoked},
        )


def _start_agent_process(argv: List[str], env, cwd: str, sanitize_output: bool = False):
    stdout = subprocess.PIPE if sanitize_output else None
    stderr = subprocess.PIPE if sanitize_output else None
    if os.name == "posix":
        return subprocess.Popen(argv, env=env, cwd=cwd, stdout=stdout, stderr=stderr, preexec_fn=os.setsid)
    return subprocess.Popen(argv, env=env, cwd=cwd, stdout=stdout, stderr=stderr)


def _should_preserve_interactive_tty(argv: List[str]) -> bool:
    if not argv or not _stdio_is_tty():
        return False
    command = os.path.basename(argv[0])
    if command == "ollama" and len(argv) >= 2 and argv[1] == "launch":
        return not any(arg in ("-h", "--help") for arg in argv[2:])
    if command not in INTERACTIVE_AGENT_COMMANDS:
        return False
    return len(argv) == 1


def _stdio_is_tty() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty() and sys.stderr.isatty()


def _wait_for_agent_process(process, sanitizer: SecretOutputSanitizer) -> int:
    if process.stdout is None and process.stderr is None:
        return process.wait()

    stdout_thread = _start_output_forwarder(process.stdout, sys.stdout.buffer, sanitizer)
    stderr_thread = _start_output_forwarder(process.stderr, sys.stderr.buffer, sanitizer)
    exit_code = process.wait()
    if stdout_thread:
        stdout_thread.join()
    if stderr_thread:
        stderr_thread.join()
    return int(exit_code)


def _start_output_forwarder(source, target, sanitizer: SecretOutputSanitizer):
    if source is None:
        return None

    def forward() -> None:
        while True:
            chunk = source.readline()
            if not chunk:
                break
            target.write(sanitizer.sanitize_bytes(chunk))
            target.flush()

    thread = threading.Thread(target=forward)
    thread.daemon = True
    thread.start()
    return thread


def _process_group_id(process) -> int:
    if os.name != "posix":
        return 0
    try:
        return os.getpgid(process.pid)
    except OSError:
        return 0


def _wait_for_process_group_exit(process_group_id: int) -> None:
    if os.name != "posix" or not process_group_id:
        return
    while _process_group_alive(process_group_id):
        time.sleep(0.5)


def _process_group_alive(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _run_command_executor(
    config_path: str,
    audit_logger: JsonLineAuditLogger,
    cloud_session,
    pid: int,
):
    session_id = str(cloud_session.get("session_id", ""))
    if not session_id:
        return None
    project_root = os.path.dirname(os.path.abspath(config_path)) or os.getcwd()
    sessions = SessionRegistry(project_root)
    supervisor = AgentProcessSupervisor(sessions)
    supervisor.attach_process(session_id, pid)
    executor = CommandExecutor(
        supervisor,
        PolicyApplier(config_path),
        config_path,
        audit_logger,
    )
    return executor


def _apply_cloud_runtime_defaults(args: argparse.Namespace, cloud: CloudRuntimeService) -> None:
    defaults = cloud.runtime_defaults()
    if not defaults:
        return
    if "protect_all_by_default" in defaults:
        args.protect_all = bool(defaults.get("protect_all_by_default"))
    runtime_mode = defaults.get("runtime_mode")
    if runtime_mode in ("command-guard", "workspace"):
        args.runtime = runtime_mode
    workspace_mode = defaults.get("workspace_mode")
    if workspace_mode in ("symlink", "copy"):
        args.workspace_mode = workspace_mode
    if defaults.get("reporting_debug"):
        args.cloud_debug = True


def _pull_cloud_policy(config_path: str, cloud: CloudRuntimeService) -> bool:
    if not cloud.status().get("enrolled"):
        return False
    try:
        response = cloud.sync(session={}, status="idle", force=True)
    except CloudError:
        return False
    try:
        return _apply_cloud_policy_response(config_path, response)
    except (OSError, ValueError, TypeError):
        return False


def _apply_cloud_policy_response(config_path: str, response) -> bool:
    if not isinstance(response, dict):
        return False
    policy = response.get("policy", {}) if isinstance(response.get("policy", {}), dict) else {}
    profile_body = profile_policy_body_from_response(response)
    selected_policy = policy if policy else profile_body
    selected_profile = profile_metadata_from_response(
        response,
        source="sync",
    )
    if not selected_policy and not selected_profile:
        return False
    current = {}
    if os.path.exists(config_path):
        with open(config_path, "r") as handle:
            loaded = json.load(handle)
            current = loaded if isinstance(loaded, dict) else {}
    version = _cloud_policy_version(response, selected_profile)
    PolicyApplier(config_path).apply(current, selected_policy, version, selected_profile)
    return True


def _cloud_policy_version(response: Dict[str, Any], selected_profile: Dict[str, Any]) -> int:
    for key in ("policy_version", "version", "profile_version"):
        try:
            value = int(response.get(key, 0) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
    try:
        return int(selected_profile.get("version", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _start_local_gateway_thread(container: Container, host: str, port: int):
    gateway_events = queue.Queue()
    gateway = LocalGateway(
        host,
        port,
        container.policy_engine,
        container.token_resolver,
        container.audit_logger,
        container.bindings,
        container.config.provider_proxy,
    )

    def run_gateway_thread() -> None:
        try:
            gateway.serve_forever(lambda: gateway_events.put("ready"))
        except Exception as exc:
            gateway_events.put(exc)

    gateway_thread = threading.Thread(target=run_gateway_thread)
    gateway_thread.daemon = True
    gateway_thread.start()
    try:
        gateway_status = gateway_events.get(timeout=5)
    except queue.Empty:
        sys.stderr.write("agentsecure: gateway did not start within 5 seconds\n")
        return 1
    if isinstance(gateway_status, Exception):
        sys.stderr.write("agentsecure: gateway failed to start: %s\n" % gateway_status)
        return 1
    return LocalGatewayHandle(gateway, gateway_thread)


def _proxy_url(host: str, port: int, session_id: str = "") -> str:
    if session_id:
        return "http://%s@%s:%s" % (session_id, host, port)
    return "http://%s:%s" % (host, port)


def _available_gateway_port(host: str, preferred_port: int) -> int:
    for port in [preferred_port] + list(range(8766, 8899)):
        if _can_bind(host, port):
            return port
    return preferred_port


def _can_bind(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _running_daemon():
    state = _read_daemon_state()
    if not state:
        return None
    try:
        daemon = _http_json("GET", _daemon_url(state, "/daemon"))
    except Exception:
        return None
    if daemon.get("running"):
        return daemon
    return None


def _read_daemon_state():
    path = os.path.join(".agentsecure", "daemon.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as handle:
            data = json.load(handle)
    except (ValueError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _write_daemon_state(state) -> None:
    os.makedirs(".agentsecure", exist_ok=True)
    with open(os.path.join(".agentsecure", "daemon.json"), "w") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)


def _daemon_url(state, path: str) -> str:
    return "http://%s:%s%s" % (state.get("api_host", "127.0.0.1"), state.get("api_port", 8787), path)


def _daemon_create_session(daemon, payload):
    return _http_json("POST", _daemon_url(daemon, "/sessions"), payload)


def _daemon_finish_session(daemon, session_id: str, status: str, exit_code) -> None:
    if not session_id:
        return
    try:
        _http_json(
            "POST",
            _daemon_url(daemon, "/sessions/finish"),
            {"session_id": session_id, "status": status, "exit_code": exit_code},
        )
    except Exception:
        return


def _daemon_update_session(daemon, session_id: str, fields) -> None:
    if not session_id:
        return
    try:
        _http_json(
            "POST",
            _daemon_url(daemon, "/sessions/update"),
            {"session_id": session_id, "fields": fields},
        )
    except Exception:
        return


def _http_json(method: str, url: str, payload=None):
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urlopen(request, timeout=2) as response:
        raw = response.read().decode("utf-8")
    return json.loads(raw) if raw else {}


def _start_cloud_report_thread(cloud: CloudRuntimeService, session, stop_event, command_executor=None):
    def run() -> None:
        while not stop_event.is_set():
            if cloud.has_reportable_events():
                response = _try_cloud_sync(cloud, session, "running")
                if command_executor:
                    _execute_cloud_response_commands(cloud, command_executor, response)
            interval = 5 if cloud.status().get("debug_reporting") else 15
            stop_event.wait(interval)

    thread = threading.Thread(target=run)
    thread.daemon = True
    thread.start()
    return thread


def _execute_cloud_response_commands(cloud: CloudRuntimeService, executor: CommandExecutor, response) -> None:
    if not isinstance(response, dict):
        return
    commands = response.get("commands", [])
    if not isinstance(commands, list):
        return
    for command in commands:
        if not isinstance(command, dict):
            continue
        result = executor.execute(command)
        command_id = str(command.get("id", ""))
        if command_id:
            try:
                cloud.command_result(command_id, result)
            except CloudError:
                pass


def _try_cloud_sync(
    cloud: CloudRuntimeService,
    session,
    status: str,
    exit_code: Optional[int] = None,
    force: bool = False,
) -> None:
    try:
        return cloud.sync(session=session, status=status, exit_code=exit_code, force=force)
    except CloudError:
        return {}


def _apply_proxy_environment(
    env,
    proxy_url: str,
    allow_loopback_bypass: bool = False,
    private_bypass_hosts: Optional[List[str]] = None,
) -> None:
    env["HTTP_PROXY"] = proxy_url
    env["HTTPS_PROXY"] = proxy_url
    env["http_proxy"] = proxy_url
    env["https_proxy"] = proxy_url
    no_proxy = _merge_no_proxy(
        env.get("NO_PROXY") or env.get("no_proxy") or "",
        include_defaults=allow_loopback_bypass,
        private_bypass_hosts=private_bypass_hosts,
    )
    env["NO_PROXY"] = no_proxy
    env["no_proxy"] = no_proxy


def _validate_private_proxy_bypass_hosts(private_bypass_hosts: Optional[List[str]] = None) -> None:
    for host in private_bypass_hosts or []:
        _normalize_private_proxy_bypass_host(host)


def _apply_provider_proxy_environment(env, container: Container, gateway_host: str, gateway_port: int) -> None:
    if not container.config.provider_proxy.enabled:
        return
    raw = dict(container.config.raw)
    gateway = dict(raw.get("gateway", {}))
    gateway["host"] = gateway_host
    gateway["port"] = gateway_port
    raw["gateway"] = gateway
    for provider in container.config.provider_proxy.providers.values():
        provider_data = {
            "local_path": provider_base_local_path(provider.local_path, provider.allow_paths),
        }
        env[provider.base_url_env] = configured_provider_base_url(raw, provider_data)


def _strip_backing_secret_environment(env, container: Container) -> None:
    for binding in container.config.secrets:
        if binding.real_secret_env:
            env.pop(binding.real_secret_env, None)


def _configured_secret_replacements(container: Container, existing: List[SecretReplacement]) -> List[SecretReplacement]:
    existing_names = set(replacement.name for replacement in existing)
    replacements = []
    for binding in container.config.secrets:
        if binding.env_name in existing_names:
            continue
        real_value = container.token_resolver.resolve(binding.virtual_token) or ""
        if not real_value:
            continue
        rule = container.config.env_policy.rule_for(binding.env_name)
        if rule.mode == "deny":
            replacements.append(
                SecretReplacement(
                    source="configured",
                    name=binding.env_name,
                    real_value=real_value,
                    virtual_value="",
                    action="remove",
                )
            )
        elif rule.mode != "broker":
            replacements.append(
                SecretReplacement(
                    source="configured",
                    name=binding.env_name,
                    real_value=real_value,
                    virtual_value=binding.virtual_token,
                )
            )
    return replacements


def _merge_no_proxy(
    existing: str,
    include_defaults: bool = True,
    private_bypass_hosts: Optional[List[str]] = None,
) -> str:
    defaults = [
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        ".local",
        "host.docker.internal",
    ]
    values = []
    seen = set()
    extras = defaults if include_defaults else []
    extras = list(extras)
    for host in private_bypass_hosts or []:
        extras.append(_normalize_private_proxy_bypass_host(host))
    for raw in existing.split(",") + extras:
        value = raw.strip()
        if not value:
            continue
        key = value.lower()
        if key == "*":
            continue
        if key not in seen:
            values.append(value)
            seen.add(key)
    return ",".join(values)


def _normalize_private_proxy_bypass_host(value: str) -> str:
    host = str(value).strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if host.startswith("[") and "]" in host:
        host = host[1:].split("]", 1)[0]
    elif ":" in host:
        host = host.split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("private proxy bypass must be a private IP address")
    if not (ip.is_private or ip.is_loopback or ip.is_link_local):
        raise ValueError("private proxy bypass host must be private, loopback, or link-local")
    return str(ip)


def run_gateway(args: argparse.Namespace) -> int:
    container = Container.from_config_path(args.config)
    container.gateway().serve_forever()
    return 0


def run_daemon(args: argparse.Namespace) -> int:
    if args.host not in ("127.0.0.1", "localhost"):
        sys.stderr.write("agentsecure: daemon must bind to localhost\n")
        return 2
    host = "127.0.0.1" if args.host == "localhost" else args.host
    container = Container.from_config_path(args.config)
    gateway_port = _available_gateway_port(host, args.gateway_port)
    daemon_info = {
        "api_host": host,
        "api_port": args.api_port,
        "gateway_host": host,
        "gateway_port": gateway_port,
        "started_at": time.time(),
    }
    gateway_thread = _start_local_gateway_thread(container, host, gateway_port)
    if isinstance(gateway_thread, int):
        return gateway_thread
    _write_daemon_state(daemon_info)
    services = ApiServices(args.config, _scanner(), daemon_info=daemon_info)
    sessions = SessionRegistry(os.getcwd())
    supervisor = AgentProcessSupervisor(sessions)
    executor = CommandExecutor(
        supervisor,
        PolicyApplier(args.config),
        args.config,
        container.audit_logger,
    )
    poller = None
    if _cloud_features_enabled():
        poller = CommandPoller(CloudRuntimeService(), executor)
        poller.start()
    server = LocalApiServer(host, args.api_port, services)
    print("AgentSecure daemon API: http://%s:%s" % (host, args.api_port), flush=True)
    print("AgentSecure daemon gateway: http://%s:%s" % (host, gateway_port), flush=True)
    try:
        server.serve_forever()
    finally:
        if poller:
            poller.stop()
    return 0


def guard_command(args: argparse.Namespace) -> int:
    runner = GuardedCommandRunner(args.config)
    return runner.run(args.tool, list(args.tool_args))


def handle_secret_aliases(args: argparse.Namespace) -> int:
    if args.secrets_command == "add":
        return add_secret_alias(args)
    if args.secrets_command == "list":
        return list_secret_aliases(args)
    if args.secrets_command == "use":
        return use_secret_aliases(args)
    sys.stderr.write("agentsecure: missing secrets subcommand\n")
    return 2


def add_secret_alias(args: argparse.Namespace) -> int:
    try:
        real_secret = _read_real_secret(args)
        alias = _secret_alias_service(args.config).add_alias(
            alias_id=args.alias_id,
            real_secret=real_secret,
            env_name=args.env_name,
            provider=args.provider,
            inject_as=args.inject_as,
            name=args.name,
            approved_hosts=args.approved_host,
        )
    except (KeyManagementError, SecretAliasError) as exc:
        sys.stderr.write("agentsecure: %s\n" % exc)
        return 2
    print(
        json.dumps(
            {
                "alias_id": alias.alias_id,
                "name": alias.name,
                "env_name": alias.env_name,
                "provider": alias.provider,
                "inject_as": alias.inject_as,
                "approved_hosts": alias.approved_hosts,
                "has_local_secret": True,
                "local_only": True,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def list_secret_aliases(args: argparse.Namespace) -> int:
    aliases = _secret_alias_service(args.config).list_aliases()
    print(
        json.dumps(
            [
                {
                    "alias_id": alias.alias_id,
                    "name": alias.name,
                    "env_name": alias.env_name,
                    "provider": alias.provider,
                    "inject_as": alias.inject_as,
                    "approved_hosts": alias.approved_hosts,
                    "has_local_secret": bool(alias.secret_ref),
                    "local_only": True,
                }
                for alias in aliases
            ],
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def use_secret_aliases(args: argparse.Namespace) -> int:
    try:
        assigned = _secret_alias_service(args.config).assign_to_project(
            args.config,
            args.alias_ids,
            project=args.project or os.path.basename(os.getcwd()) or "default",
        )
    except SecretAliasError as exc:
        sys.stderr.write("agentsecure: %s\n" % exc)
        return 2
    print(
        json.dumps(
            {
                "assigned": [
                    {
                        "alias_id": item.alias_id,
                        "env_name": item.env_name,
                        "provider": item.provider,
                        "approved_hosts": item.approved_hosts,
                    }
                    for item in assigned
                ],
                "config_path": args.config,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _secret_alias_service(config_path: str) -> SecretAliasService:
    home = agentsecure_home()
    return SecretAliasService(
        local_secret_alias_store_for_home(home),
        encrypted_secret_store_for_vault(),
        local_grant_store_for_config(config_path),
        JsonLineAuditLogger(".agentsecure/audit.log"),
    )


def run_api(args: argparse.Namespace) -> int:
    services = ApiServices(args.config, _scanner())
    server = LocalApiServer(args.host, args.port, services)
    print("AgentSecure API listening on http://%s:%s" % (server.host, server.port))
    server.serve_forever()
    return 0


def _apply_read_only_agent_mode(argv: List[str], read_only_workspace: bool) -> List[str]:
    if not read_only_workspace or not argv:
        return argv
    command = os.path.basename(argv[0])
    if command != "codex":
        return argv
    if "--sandbox" in argv or "-s" in argv:
        return argv
    return [argv[0], "--sandbox", "read-only"] + argv[1:]


def enroll_cloud(args: argparse.Namespace) -> int:
    if not _cloud_features_enabled():
        return _cloud_features_disabled()
    try:
        result = CloudRuntimeService().enroll(
            args.api_base,
            args.token,
            args.project,
        )
    except CloudError as exc:
        sys.stderr.write("agentsecure: %s\n" % exc)
        return 1
    print("AgentSecure Cloud enrolled.")
    print("Device: %s" % result.get("device_id", ""))
    print("Project: %s" % result.get("project_id", ""))
    if result.get("config_profile"):
        print("Config profile: %s" % _profile_label(result.get("config_profile", {})))
    print("Sync interval: %ss" % result.get("sync_interval_seconds", 30))
    return 0


def handle_cloud(args: argparse.Namespace) -> int:
    if not _cloud_features_enabled():
        return _cloud_features_disabled()
    service = CloudRuntimeService()
    if args.cloud_command == "status":
        print(json.dumps(service.status(), indent=2, sort_keys=True))
        return 0
    if args.cloud_command == "sync":
        try:
            response = service.sync(
                status="manual",
                force=True,
            )
            try:
                _apply_cloud_policy_response(args.config, response)
            except (OSError, ValueError, TypeError) as exc:
                sys.stderr.write("agentsecure: failed to apply cloud policy: %s\n" % exc)
                return 1
            print(json.dumps(response, indent=2, sort_keys=True))
        except CloudError as exc:
            sys.stderr.write("agentsecure: %s\n" % exc)
            return 1
        return 0
    sys.stderr.write("agentsecure: missing cloud subcommand\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
