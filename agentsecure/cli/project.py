import argparse
import json
import os
import shutil

from agentsecure.cli.common import scanner
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
