import os
import stat
from dataclasses import dataclass
from typing import List


DEFAULT_BIN_DIR = os.path.expanduser("~/.agentsecure/bin")
SUPPORTED_AGENTS = ("claude", "codex", "cursor")


@dataclass(frozen=True)
class WrapperInfo:
    agent: str
    path: str
    installed: bool


class AgentWrapperInstaller:
    """Installs PATH-first wrappers that run agents through AgentSecure."""

    def __init__(self, bin_dir: str = DEFAULT_BIN_DIR, agentsecure_path: str = "") -> None:
        self.bin_dir = os.path.expanduser(bin_dir)
        self.agentsecure_path = agentsecure_path or os.path.join(self.bin_dir, "agentsecure")

    def install(self, agent: str) -> WrapperInfo:
        self._validate_agent(agent)
        os.makedirs(self.bin_dir, exist_ok=True)
        path = self._wrapper_path(agent)
        with open(path, "w") as handle:
            handle.write(self._wrapper_source(agent))
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        return WrapperInfo(agent=agent, path=path, installed=True)

    def remove(self, agent: str) -> WrapperInfo:
        self._validate_agent(agent)
        path = self._wrapper_path(agent)
        if os.path.exists(path):
            os.unlink(path)
        return WrapperInfo(agent=agent, path=path, installed=False)

    def list(self) -> List[WrapperInfo]:
        return [
            WrapperInfo(agent=agent, path=self._wrapper_path(agent), installed=os.path.exists(self._wrapper_path(agent)))
            for agent in SUPPORTED_AGENTS
        ]

    def _wrapper_path(self, agent: str) -> str:
        return os.path.join(self.bin_dir, agent)

    def _validate_agent(self, agent: str) -> None:
        if agent not in SUPPORTED_AGENTS:
            raise ValueError("unsupported agent: %s" % agent)

    def _wrapper_source(self, agent: str) -> str:
        return """#!/usr/bin/env bash
set -e

AGENTSECURE_BIN="${AGENTSECURE_BIN:-__AGENTSECURE_PATH__}"
AGENTSECURE_WRAPPER_DIR="${AGENTSECURE_WRAPPER_DIR:-__BIN_DIR__}"

if [ ! -x "$AGENTSECURE_BIN" ]; then
  echo "agentsecure: AgentSecure CLI not found at $AGENTSECURE_BIN" >&2
  exit 127
fi

ORIGINAL_PATH="$PATH"
FILTERED_PATH=""
IFS=':'
for part in $ORIGINAL_PATH; do
  if [ "$part" != "$AGENTSECURE_WRAPPER_DIR" ]; then
    if [ -z "$FILTERED_PATH" ]; then
      FILTERED_PATH="$part"
    else
      FILTERED_PATH="$FILTERED_PATH:$part"
    fi
  fi
done
unset IFS

REAL_AGENT="$(PATH="$FILTERED_PATH" command -v __AGENT__ || true)"
if [ -z "$REAL_AGENT" ]; then
  echo "agentsecure: real __AGENT__ command not found outside $AGENTSECURE_WRAPPER_DIR" >&2
  exit 127
fi

exec "$AGENTSECURE_BIN" run -- "$REAL_AGENT" "$@"
""".replace("__AGENT__", agent).replace("__AGENTSECURE_PATH__", self.agentsecure_path).replace("__BIN_DIR__", self.bin_dir)
