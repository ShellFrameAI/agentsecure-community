import os
from typing import Iterable, List

from agentsecure.core.models import DiscoveredSecret
from agentsecure.discovery.patterns import (
    is_discoverable_secret,
    provider_hint_for_name,
)
from agentsecure.discovery.scanner import SecretScanner


DEFAULT_DOTENV_FILES = (".env", ".env.local", ".env.development")


class DotenvSecretScanner(SecretScanner):
    def __init__(self, root: str = ".", filenames: Iterable[str] = DEFAULT_DOTENV_FILES) -> None:
        self._root = root
        self._filenames = list(filenames)

    def scan(self) -> List[DiscoveredSecret]:
        results = []
        for filename in self._filenames:
            path = os.path.join(self._root, filename)
            if not os.path.exists(path):
                continue
            results.extend(self._scan_file(path, filename))
        return results

    def _scan_file(self, path: str, source: str) -> List[DiscoveredSecret]:
        results = []
        with open(path, "r") as handle:
            for line in handle:
                parsed = self._parse_line(line)
                if not parsed:
                    continue
                name, value = parsed
                if is_discoverable_secret(name, value):
                    results.append(
                        DiscoveredSecret(
                            name=name,
                            source=source,
                            value=value,
                            confidence="medium",
                            provider_hint=provider_hint_for_name(name),
                        )
                    )
        return results

    def _parse_line(self, line: str):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            return None
        name, value = stripped.split("=", 1)
        name = name.strip()
        value = value.strip().strip("'").strip('"')
        if name.startswith("export "):
            name = name[len("export ") :].strip()
        if not name:
            return None
        return name, value
