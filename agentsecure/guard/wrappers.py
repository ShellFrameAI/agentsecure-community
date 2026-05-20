import os
import stat
import sys
from typing import Dict, List


DEFAULT_GUARDED_TOOLS = ["cat", "head", "tail", "grep", "rg", "curl", "wget"]


class CommandGuardWrapperInstaller:
    """Installs PATH-first wrappers for common read/search commands."""

    def __init__(self, config_path: str, tools: List[str] = None) -> None:
        self._config_path = config_path
        self._tools = tools or list(DEFAULT_GUARDED_TOOLS)

    def install(self, env: Dict[str, str]) -> str:
        wrapper_dir = os.path.abspath(os.path.join(".agentsecure", "bin"))
        os.makedirs(wrapper_dir, exist_ok=True)
        original_path = env.get("PATH", "")
        env["AGENTSECURE_CONFIG"] = os.path.abspath(self._config_path)
        env["AGENTSECURE_ENTRYPOINT"] = os.path.abspath(sys.argv[0])
        env["AGENTSECURE_ORIGINAL_PATH"] = original_path
        env["AGENTSECURE_PYTHON"] = sys.executable
        env["AGENTSECURE_WRAPPER_DIR"] = wrapper_dir
        for tool in self._tools:
            self._write_wrapper(wrapper_dir, tool)
        env["PATH"] = wrapper_dir + os.pathsep + original_path
        return wrapper_dir

    def _write_wrapper(self, wrapper_dir: str, tool: str) -> None:
        path = os.path.join(wrapper_dir, tool)
        with open(path, "w") as handle:
            handle.write(self._wrapper_source(tool))
        mode = os.stat(path).st_mode
        os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def _wrapper_source(self, tool: str) -> str:
        return """#!/usr/bin/env python3
import os
import subprocess
import sys

python = os.environ.get("AGENTSECURE_PYTHON", sys.executable)
entrypoint = os.environ["AGENTSECURE_ENTRYPOINT"]
config = os.environ["AGENTSECURE_CONFIG"]
tool = %r
argv = [python, entrypoint, "--config", config, "guard", tool] + sys.argv[1:]
raise SystemExit(subprocess.call(argv))
""" % tool
