import os
import subprocess
import sys
from typing import List, Optional

from agentsecure.guard.network import GuardedNetworkCommandPolicy
from agentsecure.guard.sanitizer import SecretOutputSanitizer


class GuardedCommandRunner:
    """Runs a real command and sanitizes its output before the agent sees it."""

    def __init__(self, config_path: str) -> None:
        self._config_path = config_path

    def run(self, tool: str, args: List[str]) -> int:
        denied = GuardedNetworkCommandPolicy(self._config_path).validate(tool, args)
        if denied is not None:
            sys.stderr.write(
                "agentsecure: blocked credential-bearing request: %s\n" % denied.reason
            )
            sys.stderr.write("agentsecure: allow with: agentsecure network allow %s\n" % denied.host)
            return 126

        real_tool = self._find_real_tool(tool)
        if not real_tool:
            sys.stderr.write("agentsecure: guarded command not found: %s\n" % tool)
            return 127

        env = os.environ.copy()
        original_path = env.get("AGENTSECURE_ORIGINAL_PATH")
        if original_path:
            env["PATH"] = original_path

        process = subprocess.Popen(
            [real_tool] + args,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        sanitizer = SecretOutputSanitizer.from_config_path(self._config_path)
        if stdout:
            sys.stdout.write(sanitizer.sanitize_bytes(stdout).decode("utf-8", "replace"))
        if stderr:
            sys.stderr.write(sanitizer.sanitize_bytes(stderr).decode("utf-8", "replace"))
        return int(process.returncode)

    def _find_real_tool(self, tool: str) -> Optional[str]:
        if os.path.isabs(tool) or os.sep in tool:
            return tool if self._is_executable(tool) else None
        path = os.environ.get("AGENTSECURE_ORIGINAL_PATH") or os.environ.get("PATH", "")
        for directory in path.split(os.pathsep):
            if not directory:
                continue
            candidate = os.path.join(directory, tool)
            if self._is_executable(candidate):
                return candidate
        return None

    def _is_executable(self, path: str) -> bool:
        return os.path.isfile(path) and os.access(path, os.X_OK)
