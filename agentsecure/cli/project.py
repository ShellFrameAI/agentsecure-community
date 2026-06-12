import argparse
import json
import os
import shutil

from agentsecure.cli.common import scanner
from agentsecure.core.agentsecure_md import AGENTSECURE_MD
from agentsecure.core.dotenv_backups import latest_dotenv_backup, restore_dotenv_backup
from agentsecure.core.product import ProductService
from agentsecure.workspace.materializer import make_tree_writable


def init_project(args: argparse.Namespace) -> int:
    result = ProductService(args.config, scanner()).init_project(args.force)
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
    result = ProductService(args.config, scanner()).status()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    print("AgentSecure status")
    print("Config: %s (%s)" % (result["config_path"], "found" if result["config_exists"] else "missing"))
    agentsecure_md = result.get("agentsecure_md", {})
    print(
        "AGENTSECURE.md: %s (%s)"
        % (
            agentsecure_md.get("path", AGENTSECURE_MD),
            "valid" if agentsecure_md.get("exists") and agentsecure_md.get("ok") else "missing" if not agentsecure_md.get("exists") else "needs review",
        )
    )
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
    secret_runtime = result.get("secret_runtime", {})
    print("Secret runtime: %s" % secret_runtime.get("mode", "virtual"))
    print("Gateway: %s:%s" % (result["gateway"].get("host", ""), result["gateway"].get("port", "")))
    print("API: %s:%s" % (result["api"]["host"], result["api"]["port"]))
    return 0


def run_doctor(args: argparse.Namespace) -> int:
    result = ProductService(args.config, scanner()).doctor()
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
    cleanup_args = argparse.Namespace(config=args.config, yes=args.yes, json=False)
    if not args.yes:
        print("AgentSecure will clean this project and remove the user-level CLI.")
        answer = input("Continue? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            print("Uninstall cancelled.")
            return 1
        cleanup_args.yes = True
    restore_code = _restore_dotenv_during_uninstall(args)
    if restore_code != 0:
        return restore_code
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


def _restore_dotenv_during_uninstall(args: argparse.Namespace) -> int:
    if getattr(args, "no_restore_dotenv", False):
        print("Dotenv: restore skipped.")
        return 0

    dotenv_path = os.path.abspath(getattr(args, "dotenv", ".env"))
    backup_path = latest_dotenv_backup(dotenv_path, args.config)
    if not backup_path:
        if getattr(args, "restore_dotenv", False):
            print("Dotenv: no AgentSecure backup found for %s." % getattr(args, "dotenv", ".env"))
        return 0

    should_restore = bool(getattr(args, "restore_dotenv", False))
    if not should_restore and not args.yes:
        print("AgentSecure can restore %s from this private backup:" % getattr(args, "dotenv", ".env"))
        print("  %s" % backup_path)
        answer = input("Restore dotenv before uninstall? [y/N]: ").strip().lower()
        should_restore = answer in ("y", "yes")

    if not should_restore:
        print("Dotenv: restore skipped.")
        return 0

    try:
        restore_dotenv_backup(dotenv_path, backup_path)
    except OSError as exc:
        print("Dotenv: failed to restore %s: %s" % (getattr(args, "dotenv", ".env"), exc))
        return 1
    print("Dotenv: restored %s from %s" % (getattr(args, "dotenv", ".env"), backup_path))
    return 0


def _profile_label(config_profile) -> str:
    name = str(config_profile.get("name", ""))
    profile_id = str(config_profile.get("id", ""))
    version = config_profile.get("version")
    label = name or profile_id
    if name and profile_id:
        label = "%s (%s)" % (name, profile_id)
    if version:
        label = "%s v%s" % (label, version)
    return label
