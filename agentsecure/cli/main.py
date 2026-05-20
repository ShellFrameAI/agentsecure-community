import argparse
import getpass
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
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen

from agentsecure.cloud import CloudError, CloudRuntimeService
from agentsecure.api.server import LocalApiServer
from agentsecure.api.services import ApiServices
from agentsecure.cli.policy import add_policy_subparser, handle_policy
from agentsecure.client.wrappers import AgentWrapperInstaller, SUPPORTED_AGENTS
from agentsecure.core.command_metadata import safe_command_metadata
from agentsecure.core.config import ConfigError, JsonConfigLoader, JsonConfigWriter
from agentsecure.core.config_profiles import (
    profile_metadata_from_response,
    profile_policy_body_from_response,
)
from agentsecure.core.capabilities import broker_url_for_env
from agentsecure.core.container import Container
from agentsecure.core.key_service import KeyManagementError, KeyManagementService
from agentsecure.core.models import AgentSecureConfig, DiscoveredSecret, ProcessRequest, SecretReplacement
from agentsecure.core.product import ProductService
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
from agentsecure.implementations.grant_store import LocalJsonGrantStore
from agentsecure.implementations.secret_store_factory import encrypted_secret_store_for_config
from agentsecure.workspace.apply import WorkspaceApplier
from agentsecure.workspace.diff import WorkspaceDiff
from agentsecure.workspace.materializer import WorkspaceMaterializer, make_tree_writable


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
    container = Container.from_config_path(args.config)
    run_cwd = os.getcwd()
    workspace_session = None
    materializer = WorkspaceMaterializer()
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

    daemon = _running_daemon()
    daemon_session = None
    gateway_thread = None
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
        gateway_thread = _start_local_gateway_thread(container, gateway_host, gateway_port)
        if isinstance(gateway_thread, int):
            return gateway_thread

    env = os.environ.copy()
    for env_name in container.config.env_policy.rules:
        env.pop(env_name, None)
    env.update(container.virtual_env_provider.build_environment())
    if args.runtime == "command-guard":
        CommandGuardWrapperInstaller(args.config).install(env)
    session_id = daemon_session.get("session_id", "") if daemon_session else ""
    if session_id:
        env["AGENTSECURE_SESSION_ID"] = session_id
    proxy_url = _proxy_url(gateway_host, gateway_port, session_id)
    _apply_proxy_environment(env, proxy_url)
    command_metadata = safe_command_metadata(argv)
    container.audit_logger.record(
        "agent_started",
        {
            "argv": command_metadata["argv"],
            "argc": command_metadata["argc"],
            "proxy": proxy_url,
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
        process = _start_agent_process(argv, env, run_cwd)
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
        exit_code = process.wait()
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
        if command_poller:
            command_poller.stop()
        if daemon and daemon_session and not session_finished:
            _daemon_finish_session(daemon, session_id, "finished", None)
        cloud_stop.set()
        if cloud_thread:
            cloud_thread.join(timeout=2)
        if workspace_session and not args.workspace_keep:
            materializer.make_writable(workspace_session.workspace_root)
            shutil.rmtree(workspace_session.workspace_root, ignore_errors=True)
            container.audit_logger.record(
                "workspace_removed",
                {"workspace": workspace_session.workspace_root},
            )


def _start_agent_process(argv: List[str], env, cwd: str):
    if os.name == "posix":
        return subprocess.Popen(argv, env=env, cwd=cwd, preexec_fn=os.setsid)
    return subprocess.Popen(argv, env=env, cwd=cwd)


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
    return gateway_thread


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


def _apply_proxy_environment(env, proxy_url: str) -> None:
    env["HTTP_PROXY"] = proxy_url
    env["HTTPS_PROXY"] = proxy_url
    env["http_proxy"] = proxy_url
    env["https_proxy"] = proxy_url
    no_proxy = _merge_no_proxy(env.get("NO_PROXY") or env.get("no_proxy") or "")
    env["NO_PROXY"] = no_proxy
    env["no_proxy"] = no_proxy


def _merge_no_proxy(existing: str) -> str:
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
    for raw in existing.split(",") + defaults:
        value = raw.strip()
        if not value:
            continue
        key = value.lower()
        if key not in seen:
            values.append(value)
            seen.add(key)
    return ",".join(values)


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

        ProductService(config_path, _scanner()).init_project(force=True)
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
        config = _load_config_data(config_path)
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


def run_api(args: argparse.Namespace) -> int:
    services = ApiServices(args.config, _scanner())
    server = LocalApiServer(args.host, args.port, services)
    print("AgentSecure API listening on http://%s:%s" % (server.host, server.port))
    server.serve_forever()
    return 0


def init_project(args: argparse.Namespace) -> int:
    result = ProductService(args.config, _scanner()).init_project(args.force)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if result["config_created"]:
        print("Initialized AgentSecure in this project.")
    else:
        print("AgentSecure is already initialized.")
    print("Config: %s" % result["config_path"])
    print("Local secret data: .agentsecure/")
    print("Next:")
    for step in result["next_steps"]:
        print("  %s" % step)
    return 0


def show_status(args: argparse.Namespace) -> int:
    result = ProductService(args.config, _scanner()).status()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    print("AgentSecure status")
    print("Config: %s (%s)" % (result["config_path"], "found" if result["config_exists"] else "missing"))
    print("Configured secrets: %s" % result["configured_secrets"])
    print("Discovered secrets: %s" % result["discovered_secrets"])
    grants = result["grants"]
    print(
        "Grants: %s active, %s expired, %s revoked"
        % (grants["active"], grants["expired"], grants["revoked"])
    )
    print("Safe workspaces: %s" % result["workspaces"])
    if result.get("configuration_profile"):
        print("Config profile: %s" % _profile_label(result["configuration_profile"]))
    print("Gateway: %s:%s" % (result["gateway"].get("host", ""), result["gateway"].get("port", "")))
    print("API: %s:%s" % (result["api"]["host"], result["api"]["port"]))
    return 0


def run_doctor(args: argparse.Namespace) -> int:
    result = ProductService(args.config, _scanner()).doctor()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["ok"] else 1
    print("AgentSecure doctor")
    for check in result["checks"]:
        status = "OK" if check["ok"] else "FAIL"
        print("[%s] %s - %s" % (status, check["name"], check["detail"]))
    return 0 if result["ok"] else 1


def cleanup_project(args: argparse.Namespace) -> int:
    targets = [
        args.config,
        ".agentsecure",
    ]
    existing = [target for target in targets if os.path.exists(target)]
    if not args.yes and existing:
        print("AgentSecure will remove:")
        for target in existing:
            print("  %s" % target)
        answer = input("Continue? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            print("Cleanup cancelled.")
            return 1
    removed = []
    for target in existing:
        if os.path.isdir(target):
            make_tree_writable(target)
            shutil.rmtree(target)
        else:
            os.unlink(target)
        removed.append(target)
    result = {"removed": removed}
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if removed:
            print("Removed AgentSecure local state:")
            for target in removed:
                print("  %s" % target)
        else:
            print("No AgentSecure local state found.")
    return 0


def uninstall_agentsecure(args: argparse.Namespace) -> int:
    cleanup_args = argparse.Namespace(config="agentsecure.json", yes=args.yes, json=False)
    if not args.yes:
        print("AgentSecure will clean this project and remove the user-level CLI.")
        answer = input("Continue? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            print("Uninstall cancelled.")
            return 1
        cleanup_args.yes = True
    cleanup_project(cleanup_args)
    install_dir = os.path.expanduser(args.install_dir)
    targets = [
        os.path.join(install_dir, "agentsecure"),
        os.path.join(install_dir, "agentsecure.pyz"),
    ]
    removed = []
    for target in targets:
        if os.path.exists(target):
            os.unlink(target)
            removed.append(target)
    if removed:
        print("Removed AgentSecure CLI:")
        for target in removed:
            print("  %s" % target)
    else:
        print("No AgentSecure CLI files found in %s." % install_dir)
    print("Optional PATH cleanup: remove this entry from your shell profile if present:")
    print('  export PATH="%s:$PATH"' % install_dir)
    return 0


def handle_files(args: argparse.Namespace) -> int:
    if args.files_command == "list":
        config = _load_config_data(args.config)
        for path in config.get("files", {}).get("protect_write", []):
            print(path)
        return 0
    if args.files_command == "protect":
        return _update_protected_files(args.config, args.paths, add=True)
    if args.files_command == "unprotect":
        return _update_protected_files(args.config, args.paths, add=False)
    sys.stderr.write("agentsecure: missing files subcommand\n")
    return 2


def handle_network(args: argparse.Namespace) -> int:
    if args.network_command == "list":
        config = _load_config_data(args.config)
        for domain in config.get("network", {}).get("allow_domains", []):
            print(domain)
        return 0
    if args.network_command == "allow":
        return _update_allowed_domains(args.config, args.domains, add=True)
    if args.network_command == "remove":
        return _update_allowed_domains(args.config, args.domains, add=False)
    sys.stderr.write("agentsecure: missing network subcommand\n")
    return 2


def handle_setup(args: argparse.Namespace) -> int:
    installer = AgentWrapperInstaller(args.bin_dir)
    if args.setup_command == "install":
        for agent in args.agents:
            info = installer.install(agent)
            print("Installed %s wrapper: %s" % (info.agent, info.path))
        print("Make sure this directory is first in PATH:")
        print("  %s" % os.path.expanduser(args.bin_dir))
        return 0
    if args.setup_command == "remove":
        for agent in args.agents:
            info = installer.remove(agent)
            print("Removed %s wrapper: %s" % (info.agent, info.path))
        return 0
    if args.setup_command == "list":
        for info in installer.list():
            status = "installed" if info.installed else "not installed"
            print("%s\t%s\t%s" % (info.agent, status, info.path))
        return 0
    sys.stderr.write("agentsecure: missing setup subcommand\n")
    return 2


def diff_workspace(args: argparse.Namespace) -> int:
    source_root = os.getcwd()
    differ = WorkspaceDiff()
    workspace = args.workspace or differ.latest_workspace(source_root)
    if not workspace:
        sys.stderr.write("agentsecure: no kept workspace found. Run with --workspace-keep first.\n")
        return 1
    if not os.path.isdir(workspace):
        sys.stderr.write("agentsecure: workspace not found: %s\n" % workspace)
        return 1
    skip_paths = []
    if not args.include_protected:
        config = _load_config_data(args.config)
        skip_paths = list(config.get("files", {}).get("protect_write", []))
    output = differ.unified_diff(source_root, workspace, skip_paths)
    if output:
        print(output, end="")
    else:
        print("No workspace changes.")
    return 0


def apply_workspace(args: argparse.Namespace) -> int:
    source_root = os.getcwd()
    applier = WorkspaceApplier()
    workspace = args.workspace or applier.latest_workspace(source_root)
    if not workspace:
        sys.stderr.write("agentsecure: no kept workspace found. Run with --runtime workspace --workspace-keep first.\n")
        return 1
    if not os.path.isdir(workspace):
        sys.stderr.write("agentsecure: workspace not found: %s\n" % workspace)
        return 1
    config = _load_config_data(args.config)
    protected_paths = list(config.get("files", {}).get("protect_write", []))
    result = applier.apply(source_root, workspace, protected_paths, dry_run=args.dry_run)
    verb = "Would apply" if args.dry_run else "Applied"
    if result.copied:
        print("%s files:" % verb)
        for path in result.copied:
            print("  %s" % path)
    else:
        print("No safe workspace changes to apply.")
    if result.skipped:
        print("Skipped files:")
        for change in result.skipped:
            print("  %s (%s)" % (change.path, change.reason))
    return 0


def _update_protected_files(config_path: str, paths: List[str], add: bool) -> int:
    config = _load_config_data(config_path)
    files = config.setdefault("files", {})
    protected = list(files.get("protect_write", []))
    if add:
        for path in paths:
            normalized = _normalize_policy_path(path)
            if normalized not in protected:
                protected.append(normalized)
    else:
        remove = set(_normalize_policy_path(path) for path in paths)
        protected = [path for path in protected if path not in remove]
    files["protect_write"] = protected
    JsonConfigWriter().save(config_path, config)
    print("Protected write paths:")
    for path in protected:
        print("  %s" % path)
    return 0


def _update_allowed_domains(config_path: str, domains: List[str], add: bool) -> int:
    config = _load_config_data(config_path)
    network = config.setdefault("network", {})
    allowed = list(network.get("allow_domains", []))
    if add:
        for domain in domains:
            normalized = _normalize_domain(domain)
            if normalized and normalized not in allowed:
                allowed.append(normalized)
    else:
        remove = set(_normalize_domain(domain) for domain in domains)
        allowed = [domain for domain in allowed if domain not in remove]
    network["allow_domains"] = allowed
    JsonConfigWriter().save(config_path, config)
    print("Allowed credential domains:")
    for domain in allowed:
        print("  %s" % domain)
    return 0


def _load_config_data(config_path: str):
    if not os.path.exists(config_path):
        ProductService(config_path, _scanner()).init_project()
    with open(config_path, "r") as handle:
        return json.load(handle)


def _normalize_policy_path(path: str) -> str:
    return os.path.normpath(path).lstrip(os.sep)


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def _apply_read_only_agent_mode(argv: List[str], read_only_workspace: bool) -> List[str]:
    if not read_only_workspace or not argv:
        return argv
    command = os.path.basename(argv[0])
    if command != "codex":
        return argv
    if "--sandbox" in argv or "-s" in argv:
        return argv
    return [argv[0], "--sandbox", "read-only"] + argv[1:]


def _cloud_features_enabled() -> bool:
    return os.environ.get("AGENTSECURE_ENABLE_CLOUD", "").strip() == "1"


def _cloud_features_disabled() -> int:
    sys.stderr.write(
        "agentsecure: cloud features are not enabled in community mode "
        "(set AGENTSECURE_ENABLE_CLOUD=1 in private builds)\n"
    )
    return 2


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


def _profile_label(config_profile: Dict[str, Any]) -> str:
    name = str(config_profile.get("name", ""))
    profile_id = str(config_profile.get("id", ""))
    version = config_profile.get("version")
    label = name or profile_id
    if name and profile_id:
        label = "%s (%s)" % (name, profile_id)
    if version:
        label = "%s v%s" % (label, version)
    return label


def print_env(args: argparse.Namespace) -> int:
    container = Container.from_config_path(args.config)
    for key, value in sorted(container.virtual_env_provider.build_environment().items()):
        print("%s=%s" % (key, value))
    return 0


def handle_keys(args: argparse.Namespace) -> int:
    if args.keys_command == "create":
        return create_key(args)
    if args.keys_command == "list":
        return list_keys(args)
    if args.keys_command == "revoke":
        return revoke_key(args)
    sys.stderr.write("agentsecure: missing keys subcommand\n")
    return 2


def create_key(args: argparse.Namespace) -> int:
    try:
        real_secret = _read_real_secret(args)
        service = KeyManagementService(
            args.config,
            encrypted_secret_store_for_config(args.config),
            LocalJsonGrantStore(),
            JsonLineAuditLogger(".agentsecure/audit.log"),
        )
        result = service.create_key(
            env_name=args.env_name,
            real_secret=real_secret,
            provider=args.provider,
            inject_as=args.inject_as,
            name=args.name,
            ttl=args.ttl,
        )
    except (DurationError, KeyManagementError) as exc:
        sys.stderr.write("agentsecure: %s\n" % exc)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _read_real_secret(args: argparse.Namespace) -> str:
    if args.real_secret_env:
        value = os.environ.get(args.real_secret_env)
        if not value:
            raise KeyManagementError("environment variable %s is empty or unset" % args.real_secret_env)
        return value
    if args.real_secret_stdin:
        return sys.stdin.read().strip()
    return getpass.getpass("Real secret: ").strip()


def discover_secrets(args: argparse.Namespace) -> int:
    discovered = _scanner().scan()
    _print_discovered(discovered)
    return 0


def suggest_policy(args: argparse.Namespace) -> int:
    try:
        config = JsonConfigLoader().load(args.config) if os.path.exists(args.config) else AgentSecureConfig()
    except ConfigError as exc:
        sys.stderr.write("agentsecure: %s\n" % exc)
        return 2
    discovered = _scanner().scan()
    suggestions = PolicySuggestionService(config, discovered).suggest()
    print(json.dumps(_redact_suggestion_values(suggestions, discovered), indent=2, sort_keys=True))
    return 0


def _redact_suggestion_values(payload, discovered: List[DiscoveredSecret]):
    text = json.dumps(payload)
    for secret in discovered:
        if secret.value:
            text = text.replace(secret.value, mask_secret(secret.value))
    return json.loads(text)


def protect_secrets(args: argparse.Namespace):
    discovered = _scanner().scan()
    if not discovered:
        return []
    env_policy = JsonConfigLoader().load(args.config).env_policy if os.path.exists(args.config) else None
    policy_rules = env_policy.rules if env_policy else {}
    configured = [secret for secret in discovered if secret.name in policy_rules]
    unconfigured = [secret for secret in discovered if secret.name not in policy_rules]
    replacements = []
    for secret in configured:
        rule = policy_rules[secret.name]
        result = _replacement_from_env_policy(args, secret, rule)
        if isinstance(result, int):
            return result
        replacements.append(result)
    if configured:
        print("AgentSecure applied local env_policy for %s secret(s)." % len(configured), flush=True)
    if not unconfigured:
        return replacements
    _print_discovered(unconfigured)
    if getattr(args, "protect_all", False):
        selected = "all"
    elif not sys.stdin.isatty():
        return replacements
    else:
        selected = input("Select secrets to virtualize [all/none/1,2]: ").strip().lower()
    if selected in ("", "none", "n", "no"):
        return replacements
    try:
        indexes = _selected_indexes(selected, len(unconfigured))
    except (KeyManagementError, ValueError) as exc:
        sys.stderr.write("agentsecure: %s\n" % exc)
        return 2
    for index in indexes:
        secret = unconfigured[index]
        result = _replacement_from_prompt(args, secret)
        if isinstance(result, int):
            return result
        replacements.append(result)
    return replacements


def _replacement_from_env_policy(args: argparse.Namespace, secret: DiscoveredSecret, rule):
    if rule.mode == "deny":
        print("Denied %s by env_policy" % secret.name, flush=True)
        return SecretReplacement(
            source=secret.source,
            name=secret.name,
            real_value=secret.value,
            virtual_value="",
            action="remove",
        )
    if rule.mode == "broker":
        return _create_broker_secret_replacement(args, secret, rule)
    return _create_virtual_secret_replacement(
        args,
        secret,
        secret.name,
        secret.provider_hint,
    )


def _create_broker_secret_replacement(args: argparse.Namespace, secret: DiscoveredSecret, rule):
    created = _store_secret_binding(args, secret, secret.name, secret.provider_hint)
    if isinstance(created, int):
        return created
    config = JsonConfigLoader().load(args.config)
    broker_url = broker_url_for_env(config, secret.name, secret.value)
    audit = JsonLineAuditLogger(".agentsecure/audit.log")
    capability = config.capabilities.get(rule.capability)
    if capability:
        audit.record(
            "capability.registered",
            {
                "capability": capability.name,
                "type": capability.type,
                "expose_as": capability.expose_as or secret.name,
                "target_host": capability.target_host,
                "target_port": capability.target_port,
                "access": capability.access,
            },
        )
    audit.record(
        "secret.brokered",
        {
            "env_name": secret.name,
            "capability": rule.capability,
            "broker_url": broker_url,
        },
    )
    print("Brokered %s via capability %s" % (secret.name, rule.capability), flush=True)
    return SecretReplacement(
        source=secret.source,
        name=secret.name,
        real_value=secret.value,
        virtual_value=broker_url,
    )


def _replacement_from_prompt(args: argparse.Namespace, secret: DiscoveredSecret):
    if getattr(args, "protect_all", False):
        env_name = secret.name
        provider = secret.provider_hint
    else:
        env_name = input("Expose %s as env var [%s]: " % (secret.name, secret.name)).strip() or secret.name
        provider = input("Provider for %s [%s]: " % (secret.name, secret.provider_hint)).strip() or secret.provider_hint
    return _create_virtual_secret_replacement(args, secret, env_name, provider)


def _create_virtual_secret_replacement(
    args: argparse.Namespace,
    secret: DiscoveredSecret,
    env_name: str,
    provider: str,
):
    result = _store_secret_binding(args, secret, env_name, provider)
    if isinstance(result, int):
        return result
    ttl = getattr(args, "ttl", "2h")
    print("Created %s=%s expires in %s" % (env_name, result["virtual_token"], ttl), flush=True)
    return SecretReplacement(
        source=secret.source,
        name=secret.name,
        real_value=secret.value,
        virtual_value=result["virtual_token"],
    )


def _store_secret_binding(
    args: argparse.Namespace,
    secret: DiscoveredSecret,
    env_name: str,
    provider: str,
):
    ttl = getattr(args, "ttl", "2h")
    service = KeyManagementService(
        args.config,
        encrypted_secret_store_for_config(args.config),
        LocalJsonGrantStore(),
        JsonLineAuditLogger(".agentsecure/audit.log"),
    )
    try:
        result = service.create_key(
            env_name=env_name,
            real_secret=secret.value,
            provider=provider,
            ttl=ttl,
        )
    except (DurationError, KeyManagementError) as exc:
        sys.stderr.write("agentsecure: %s\n" % exc)
        return 2
    return result


def list_keys(args: argparse.Namespace) -> int:
    grants = LocalJsonGrantStore().list()
    now = time.time()
    rows = []
    for grant in grants:
        remaining = int(grant.expires_at - now)
        if grant.status != "active":
            state = grant.status
        elif remaining <= 0:
            state = "expired"
        else:
            state = "active"
        rows.append(
            {
                "env_name": grant.env_name,
                "provider": grant.provider,
                "virtual_token": grant.virtual_token,
                "status": state,
                "expires_at": grant.expires_at,
                "seconds_remaining": max(0, remaining),
            }
        )
    print(json.dumps(rows, indent=2, sort_keys=True))
    return 0


def revoke_key(args: argparse.Namespace) -> int:
    revoked = LocalJsonGrantStore().revoke(args.virtual_token)
    if not revoked:
        sys.stderr.write("agentsecure: virtual token not found\n")
        return 1
    JsonLineAuditLogger(".agentsecure/audit.log").record(
        "key_revoked",
        {"virtual_token": args.virtual_token},
    )
    print(json.dumps({"revoked": True, "virtual_token": args.virtual_token}, indent=2, sort_keys=True))
    return 0


def _scanner() -> CompositeSecretScanner:
    return CompositeSecretScanner(
        [
            EnvironmentSecretScanner(),
            DotenvSecretScanner(os.getcwd()),
        ]
    )


def _print_discovered(discovered) -> None:
    if not discovered:
        print("No likely secrets found.", flush=True)
        return
    print("AgentSecure found possible secrets:", flush=True)
    for index, secret in enumerate(discovered, 1):
        print(
            "[%s] %s from %s provider=%s value=%s"
            % (index, secret.name, secret.source, secret.provider_hint, mask_secret(secret.value)),
            flush=True,
        )


def _selected_indexes(value: str, count: int) -> List[int]:
    if value == "all":
        return list(range(count))
    indexes = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        number = int(part)
        if number < 1 or number > count:
            raise KeyManagementError("selection out of range: %s" % number)
        indexes.append(number - 1)
    return indexes


if __name__ == "__main__":
    raise SystemExit(main())
