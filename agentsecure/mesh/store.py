import json
import os
import tempfile
from typing import Any, Dict


EMPTY_STATE = {
    "version": 1,
    "agents": {},
    "messages": {},
    "approvals": {},
}


class LocalMeshStore:
    def __init__(self, path: str) -> None:
        self.path = path
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def load(self) -> Dict[str, Any]:
        if not os.path.exists(self.path):
            return json.loads(json.dumps(EMPTY_STATE))
        with open(self.path, "r") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            return json.loads(json.dumps(EMPTY_STATE))
        state = json.loads(json.dumps(EMPTY_STATE))
        state.update(data)
        for key in ("agents", "messages", "approvals"):
            if not isinstance(state.get(key), dict):
                state[key] = {}
        return state

    def save(self, state: Dict[str, Any]) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".mesh-", suffix=".json", dir=directory)
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(state, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.replace(temp_path, self.path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
