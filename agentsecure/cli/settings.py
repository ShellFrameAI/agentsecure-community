import argparse
import os
import sys

from agentsecure.cli.common import (
    load_config_data,
    update_allowed_domains,
    update_protected_files,
)
from agentsecure.client.wrappers import AgentWrapperInstaller
from agentsecure.workspace.apply import WorkspaceApplier
from agentsecure.workspace.diff import WorkspaceDiff


def handle_files(args: argparse.Namespace) -> int:
    if args.files_command == "list":
        config = load_config_data(args.config)
        for path in config.get("files", {}).get("protect_write", []):
            print(path)
        return 0
    if args.files_command == "protect":
        return update_protected_files(args.config, args.paths, add=True)
    if args.files_command == "unprotect":
        return update_protected_files(args.config, args.paths, add=False)
    sys.stderr.write("agentsecure: missing files subcommand\n")
    return 2


def handle_network(args: argparse.Namespace) -> int:
    if args.network_command == "list":
        config = load_config_data(args.config)
        for domain in config.get("network", {}).get("allow_domains", []):
            print(domain)
        return 0
    if args.network_command == "allow":
        return update_allowed_domains(args.config, args.domains, add=True)
    if args.network_command == "remove":
        return update_allowed_domains(args.config, args.domains, add=False)
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
        config = load_config_data(args.config)
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
    config = load_config_data(args.config)
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
