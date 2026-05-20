import os
from typing import Iterable, List

from agentsecure.core.models import SecretReplacement, WorkspaceRequest, WorkspaceSession
from agentsecure.workspace.strategies import DEFAULT_SKIP_DIRS, WorkspaceStrategyFactory
from agentsecure.workspace.rewriter import DotenvFileRewriter


class WorkspaceMaterializer:
    """Creates an agent-visible workspace with virtualized secret files."""

    def __init__(
        self,
        workspace_base: str = ".agentsecure/workspaces",
        rewriter: DotenvFileRewriter = None,
    ) -> None:
        self._workspace_base = workspace_base
        self._rewriter = rewriter or DotenvFileRewriter()
        self._factory = WorkspaceStrategyFactory(workspace_base, self._rewriter)

    def create_workspace(
        self,
        source_root: str,
        replacements: List[SecretReplacement],
        ttl: str = "2h",
        mode: str = "symlink",
        protected_write_paths: List[str] = None,
    ) -> WorkspaceSession:
        request = WorkspaceRequest(
            source_root=os.path.abspath(source_root),
            replacements=replacements,
            ttl=ttl,
            mode=mode,
            protected_write_paths=protected_write_paths or [],
        )
        return self._factory.get(mode).create(request)

    def make_read_only(self, workspace_root: str) -> None:
        for current_root, dirnames, filenames in os.walk(workspace_root):
            for filename in filenames:
                path = os.path.join(current_root, filename)
                if not os.path.islink(path):
                    os.chmod(path, 0o444)
            for dirname in dirnames:
                path = os.path.join(current_root, dirname)
                if not os.path.islink(path):
                    os.chmod(path, 0o555)
        os.chmod(workspace_root, 0o555)

    def protect_write_paths(self, workspace_root: str, paths: Iterable[str]) -> None:
        for relative_path in paths:
            target = self._safe_workspace_path(workspace_root, relative_path)
            if not target or not os.path.exists(target):
                continue
            if os.path.islink(target):
                continue
            if os.path.isdir(target):
                self._chmod_tree(target, 0o555, 0o444)
            else:
                os.chmod(target, 0o444)

    def prevent_new_files(self, workspace_root: str) -> None:
        for current_root, dirnames, _ in os.walk(workspace_root):
            for dirname in dirnames:
                os.chmod(os.path.join(current_root, dirname), 0o555)
        os.chmod(workspace_root, 0o555)

    def make_writable(self, workspace_root: str) -> None:
        if not os.path.exists(workspace_root):
            return
        for current_root, dirnames, filenames in os.walk(workspace_root):
            os.chmod(current_root, 0o755)
            for dirname in dirnames:
                os.chmod(os.path.join(current_root, dirname), 0o755)
            for filename in filenames:
                path = os.path.join(current_root, filename)
                if not os.path.islink(path):
                    os.chmod(path, 0o644)

    def _safe_workspace_path(self, workspace_root: str, relative_path: str):
        normalized = os.path.normpath(relative_path).lstrip(os.sep)
        if normalized.startswith(".."):
            return None
        target = os.path.abspath(os.path.join(workspace_root, normalized))
        workspace_abs = os.path.abspath(workspace_root)
        if target != workspace_abs and not target.startswith(workspace_abs + os.sep):
            return None
        return target

    def _chmod_tree(self, root: str, dir_mode: int, file_mode: int) -> None:
        for current_root, dirnames, filenames in os.walk(root):
            for filename in filenames:
                path = os.path.join(current_root, filename)
                if not os.path.islink(path):
                    os.chmod(path, file_mode)
            for dirname in dirnames:
                os.chmod(os.path.join(current_root, dirname), dir_mode)
        os.chmod(root, dir_mode)


def make_tree_writable(path: str) -> None:
    if not os.path.exists(path):
        return
    if os.path.isdir(path):
        for current_root, dirnames, filenames in os.walk(path):
            os.chmod(current_root, 0o755)
            for dirname in dirnames:
                os.chmod(os.path.join(current_root, dirname), 0o755)
            for filename in filenames:
                path = os.path.join(current_root, filename)
                if not os.path.islink(path):
                    os.chmod(path, 0o644)
