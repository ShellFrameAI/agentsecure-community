import os
import shutil
import uuid
from abc import ABC, abstractmethod

from agentsecure.core.models import WorkspaceRequest, WorkspaceSession
from agentsecure.core.time import now_seconds, parse_duration_seconds
from agentsecure.workspace.rewriter import DotenvFileRewriter


DEFAULT_SKIP_DIRS = (
    ".git",
    ".agentsecure",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
)


class WorkspaceStrategy(ABC):
    def __init__(self, workspace_base: str, rewriter: DotenvFileRewriter = None) -> None:
        self._workspace_base = workspace_base
        self._rewriter = rewriter or DotenvFileRewriter()

    @abstractmethod
    def create(self, request: WorkspaceRequest) -> WorkspaceSession:
        pass

    def _new_session(self, request: WorkspaceRequest) -> WorkspaceSession:
        created_at = now_seconds()
        expires_at = created_at + parse_duration_seconds(request.ttl)
        session_id = "session_%s" % uuid.uuid4().hex[:16]
        if os.path.isabs(self._workspace_base):
            workspace_root = os.path.abspath(os.path.join(self._workspace_base, session_id))
        else:
            workspace_root = os.path.abspath(
                os.path.join(request.source_root, self._workspace_base, session_id)
            )
        os.makedirs(workspace_root, exist_ok=False)
        if os.path.isabs(self._workspace_base):
            self._write_external_workspace_marker(request.source_root, session_id, workspace_root)
        return WorkspaceSession(
            session_id=session_id,
            source_root=os.path.abspath(request.source_root),
            workspace_root=workspace_root,
            created_at=created_at,
            expires_at=expires_at,
            mode=request.mode,
        )

    def _write_external_workspace_marker(self, source_root: str, session_id: str, workspace_root: str) -> None:
        marker_base = os.path.join(os.path.abspath(source_root), ".agentsecure", "workspaces")
        os.makedirs(marker_base, exist_ok=True)
        marker_path = os.path.join(marker_base, session_id + ".path")
        with open(marker_path, "w") as handle:
            handle.write(os.path.abspath(workspace_root) + "\n")

    def _filtered_dirnames(self, rel_root: str, dirnames):
        return [
            dirname
            for dirname in dirnames
            if dirname not in DEFAULT_SKIP_DIRS
            and not self._is_inside_workspace_base(os.path.join(rel_root, dirname))
        ]

    def _is_inside_workspace_base(self, relative_path: str) -> bool:
        normalized = relative_path.replace(os.sep, "/").strip("/")
        return normalized == ".agentsecure" or normalized.startswith(".agentsecure/")

    def _must_copy(self, relative_path: str, request: WorkspaceRequest) -> bool:
        normalized = self._normalize(relative_path)
        if self._rewriter.should_rewrite(normalized):
            return True
        for path in request.protected_write_paths:
            protected = self._normalize(path)
            if normalized == protected or normalized.startswith(protected.rstrip("/") + "/"):
                return True
        return False

    def _copy_or_rewrite(self, source_path: str, dest_path: str, relative_path: str, request: WorkspaceRequest) -> None:
        if self._rewriter.should_rewrite(relative_path):
            self._rewriter.rewrite_file(source_path, dest_path, request.replacements)
        else:
            shutil.copy2(source_path, dest_path)

    def _normalize(self, path: str) -> str:
        return os.path.normpath(path).replace(os.sep, "/").lstrip("/")


class CopyWorkspaceStrategy(WorkspaceStrategy):
    def create(self, request: WorkspaceRequest) -> WorkspaceSession:
        session = self._new_session(request)
        source_root = os.path.abspath(request.source_root)
        self._copy_tree(source_root, session.workspace_root, request)
        return session

    def _copy_tree(self, source_root: str, workspace_root: str, request: WorkspaceRequest) -> None:
        for current_root, dirnames, filenames in os.walk(source_root):
            rel_root = os.path.relpath(current_root, source_root)
            if rel_root == ".":
                rel_root = ""
            dirnames[:] = self._filtered_dirnames(rel_root, dirnames)
            dest_root = os.path.join(workspace_root, rel_root)
            os.makedirs(dest_root, exist_ok=True)
            for filename in filenames:
                source_path = os.path.join(current_root, filename)
                relative_path = os.path.join(rel_root, filename)
                dest_path = os.path.join(dest_root, filename)
                self._copy_or_rewrite(source_path, dest_path, relative_path, request)


class SymlinkWorkspaceStrategy(WorkspaceStrategy):
    def create(self, request: WorkspaceRequest) -> WorkspaceSession:
        session = self._new_session(request)
        source_root = os.path.abspath(request.source_root)
        self._link_tree(source_root, session.workspace_root, request)
        return session

    def _link_tree(self, source_root: str, workspace_root: str, request: WorkspaceRequest) -> None:
        for current_root, dirnames, filenames in os.walk(source_root):
            rel_root = os.path.relpath(current_root, source_root)
            if rel_root == ".":
                rel_root = ""
            dirnames[:] = self._filtered_dirnames(rel_root, dirnames)
            dest_root = os.path.join(workspace_root, rel_root)
            os.makedirs(dest_root, exist_ok=True)
            for filename in filenames:
                source_path = os.path.join(current_root, filename)
                relative_path = os.path.join(rel_root, filename)
                dest_path = os.path.join(dest_root, filename)
                if self._must_copy(relative_path, request):
                    self._copy_or_rewrite(source_path, dest_path, relative_path, request)
                else:
                    os.symlink(source_path, dest_path)


class WorkspaceStrategyFactory:
    def __init__(self, workspace_base: str, rewriter: DotenvFileRewriter = None) -> None:
        self._workspace_base = workspace_base
        self._rewriter = rewriter or DotenvFileRewriter()

    def get(self, mode: str) -> WorkspaceStrategy:
        normalized = (mode or "symlink").lower()
        if normalized == "copy":
            return CopyWorkspaceStrategy(self._workspace_base, self._rewriter)
        if normalized == "symlink":
            return SymlinkWorkspaceStrategy(self._workspace_base, self._rewriter)
        raise ValueError("unsupported workspace mode: %s" % mode)
