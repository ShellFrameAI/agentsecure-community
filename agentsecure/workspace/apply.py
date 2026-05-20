import filecmp
import os
import shutil
from dataclasses import dataclass, field
from typing import Iterable, List, Set

from agentsecure.workspace.diff import WorkspaceDiff


DEFAULT_APPLY_SKIP_DIRS = {".agentsecure", ".git", ".venv", "venv", "node_modules", "__pycache__"}
DEFAULT_PROTECTED_PATHS = {".env", ".env.local", ".env.development", "agentsecure.json"}


@dataclass(frozen=True)
class ApplyChange:
    action: str
    path: str
    reason: str = ""


@dataclass(frozen=True)
class ApplyResult:
    copied: List[str] = field(default_factory=list)
    skipped: List[ApplyChange] = field(default_factory=list)


class WorkspaceApplyPlanner:
    """Plans safe file copies from a kept workspace back to the source tree."""

    def plan(
        self,
        source_root: str,
        workspace_root: str,
        protected_paths: Iterable[str],
    ) -> List[ApplyChange]:
        source_root = os.path.abspath(source_root)
        workspace_root = os.path.abspath(workspace_root)
        protected = self._protected_set(protected_paths)
        changes = []
        paths = self._collect_paths(source_root, workspace_root, protected)
        for relative_path in paths:
            source_path = os.path.join(source_root, relative_path)
            workspace_path = os.path.join(workspace_root, relative_path)
            if self._is_protected(relative_path, protected):
                changes.append(ApplyChange("skip", relative_path, "protected path"))
            elif not os.path.exists(workspace_path):
                changes.append(ApplyChange("skip", relative_path, "delete not applied"))
            elif os.path.isdir(workspace_path):
                continue
            elif os.path.islink(workspace_path):
                changes.append(ApplyChange("skip", relative_path, "workspace symlink"))
            elif os.path.exists(source_path) and os.path.isdir(source_path):
                changes.append(ApplyChange("skip", relative_path, "source path is directory"))
            elif self._same_file(source_path, workspace_path):
                continue
            else:
                changes.append(ApplyChange("copy", relative_path))
        return changes

    def _collect_paths(self, source_root: str, workspace_root: str, protected: Set[str]) -> List[str]:
        paths = set()
        for root in (source_root, workspace_root):
            for current_root, dirnames, filenames in os.walk(root):
                dirnames[:] = [
                    dirname
                    for dirname in dirnames
                    if dirname not in DEFAULT_APPLY_SKIP_DIRS
                    and not self._is_protected(self._relative(root, os.path.join(current_root, dirname)), protected)
                ]
                for filename in filenames:
                    relative_path = self._relative(root, os.path.join(current_root, filename))
                    paths.add(relative_path)
        return sorted(paths)

    def _protected_set(self, protected_paths: Iterable[str]) -> Set[str]:
        protected = set(self._normalize(path) for path in protected_paths)
        protected.update(DEFAULT_PROTECTED_PATHS)
        protected.add(".agentsecure")
        return protected

    def _same_file(self, source_path: str, workspace_path: str) -> bool:
        if not os.path.exists(source_path):
            return False
        if not os.path.isfile(source_path) or not os.path.isfile(workspace_path):
            return False
        return filecmp.cmp(source_path, workspace_path, shallow=False)

    def _relative(self, root: str, path: str) -> str:
        return self._normalize(os.path.relpath(path, root))

    def _normalize(self, path: str) -> str:
        return os.path.normpath(path).replace(os.sep, "/").lstrip("/")

    def _is_protected(self, relative_path: str, protected: Set[str]) -> bool:
        normalized = self._normalize(relative_path)
        for item in protected:
            if normalized == item or normalized.startswith(item.rstrip("/") + "/"):
                return True
        return False


class WorkspaceApplier:
    def __init__(self, planner: WorkspaceApplyPlanner = None) -> None:
        self._planner = planner or WorkspaceApplyPlanner()

    def latest_workspace(self, source_root: str) -> str:
        return WorkspaceDiff().latest_workspace(source_root)

    def apply(
        self,
        source_root: str,
        workspace_root: str,
        protected_paths: Iterable[str],
        dry_run: bool = False,
    ) -> ApplyResult:
        changes = self._planner.plan(source_root, workspace_root, protected_paths)
        copied = []
        skipped = []
        for change in changes:
            if change.action != "copy":
                skipped.append(change)
                continue
            if not dry_run:
                self._copy_file(source_root, workspace_root, change.path)
            copied.append(change.path)
        return ApplyResult(copied=copied, skipped=skipped)

    def _copy_file(self, source_root: str, workspace_root: str, relative_path: str) -> None:
        source_path = os.path.abspath(os.path.join(source_root, relative_path))
        workspace_path = os.path.abspath(os.path.join(workspace_root, relative_path))
        source_root = os.path.abspath(source_root)
        workspace_root = os.path.abspath(workspace_root)
        if not source_path.startswith(source_root + os.sep) and source_path != source_root:
            raise ValueError("source path escapes project: %s" % relative_path)
        if not workspace_path.startswith(workspace_root + os.sep) and workspace_path != workspace_root:
            raise ValueError("workspace path escapes workspace: %s" % relative_path)
        directory = os.path.dirname(source_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        shutil.copy2(workspace_path, source_path)

