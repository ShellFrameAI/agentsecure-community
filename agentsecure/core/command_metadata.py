import os
from typing import Any, Dict, List


def safe_command_metadata(argv: List[str]) -> Dict[str, Any]:
    if not isinstance(argv, list):
        argv = []
    command = os.path.basename(str(argv[0])) if argv else ""
    return {
        "agent": command,
        "argv": [command] if command else [],
        "argc": len(argv),
    }
