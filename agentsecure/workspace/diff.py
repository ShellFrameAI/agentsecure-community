import difflib
import os
from typing import Iterable, List, Optional, Set


DEFAULT_SKIP_DIRS = {".agentsecure", ".git", ".venv", "venv", "node_modules", "__pycache__"}


class WorkspaceDiff:
    def latest_workspace(self, source_root: str) -> Optional[str]:
        base = os.path.join(source_root, ".agentsecure", "workspaces")
        if not os.path.isdir(base):
            return None
        sessions = []
        for name in os.listdir(base):
            path = os.path.join(base, name)
            if name.startswith("session_") and os.path.isdir(path):
                sessions.append((os.path.getmtime(path), path))
        if not sessions:
            return None
        sessions.sort()
        return sessions[-1][1]

    def unified_diff(
        self,
        source_root: str,
        workspace_root: str,
        skip_paths: Iterable[str],
    ) -> str:
        source_root = os.path.abspath(source_root)
        workspace_root = os.path.abspath(workspace_root)
        skip = set(self._normalize(path) for path in skip_paths)
        paths = self._collect_paths(source_root, workspace_root, skip)
        chunks = []
        for relative_path in paths:
            source_path = os.path.join(source_root, relative_path)
            workspace_path = os.path.join(workspace_root, relative_path)
            chunk = self._diff_file(source_path, workspace_path, relative_path)
            if chunk:
                chunks.append(chunk)
        return "".join(chunks)

    def _collect_paths(self, source_root: str, workspace_root: str, skip: Set[str]) -> List[str]:
        paths = set()
        for root in (source_root, workspace_root):
            for current_root, dirnames, filenames in os.walk(root):
                dirnames[:] = [
                    dirname
                    for dirname in dirnames
                    if dirname not in DEFAULT_SKIP_DIRS
                    and not self._is_skipped(self._relative(root, os.path.join(current_root, dirname)), skip)
                ]
                for filename in filenames:
                    relative_path = self._relative(root, os.path.join(current_root, filename))
                    if not self._is_skipped(relative_path, skip):
                        paths.add(relative_path)
        return sorted(paths)

    def _diff_file(self, source_path: str, workspace_path: str, relative_path: str) -> str:
        source_exists = os.path.exists(source_path)
        workspace_exists = os.path.exists(workspace_path)
        if not source_exists and not workspace_exists:
            return ""
        if source_exists and os.path.isdir(source_path):
            return ""
        if workspace_exists and os.path.isdir(workspace_path):
            return ""
        source_lines = self._read_text_lines(source_path) if source_exists else []
        workspace_lines = self._read_text_lines(workspace_path) if workspace_exists else []
        if source_lines is None or workspace_lines is None:
            return ""
        if source_lines == workspace_lines:
            return ""
        fromfile = "real/%s" % relative_path if source_exists else "/dev/null"
        tofile = "workspace/%s" % relative_path if workspace_exists else "/dev/null"
        return "\n".join(
            difflib.unified_diff(
                source_lines,
                workspace_lines,
                fromfile=fromfile,
                tofile=tofile,
                lineterm="",
            )
        ) + "\n"

    def _read_text_lines(self, path: str):
        try:
            with open(path, "r") as handle:
                return handle.read().splitlines()
        except UnicodeDecodeError:
            return None

    def _relative(self, root: str, path: str) -> str:
        return self._normalize(os.path.relpath(path, root))

    def _normalize(self, path: str) -> str:
        return os.path.normpath(path).replace(os.sep, "/").lstrip("/")

    def _is_skipped(self, relative_path: str, skip: Set[str]) -> bool:
        normalized = self._normalize(relative_path)
        for item in skip:
            if normalized == item or normalized.startswith(item.rstrip("/") + "/"):
                return True
        return False
