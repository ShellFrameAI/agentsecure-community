import os
from typing import Dict, Iterable

from agentsecure.core.models import SecretReplacement


DOTENV_REWRITE_NAMES = (
    ".env",
    ".env.local",
    ".env.development",
)


class DotenvFileRewriter:
    """Rewrites copied dotenv files by replacing real secret values."""

    def should_rewrite(self, relative_path: str) -> bool:
        name = os.path.basename(relative_path)
        return name in DOTENV_REWRITE_NAMES or name.endswith(".env")

    def rewrite_file(
        self,
        source_path: str,
        dest_path: str,
        replacements: Iterable[SecretReplacement],
    ) -> None:
        with open(source_path, "r") as handle:
            content = handle.read()
        rewritten = content
        rewritten = self._remove_denied_lines(rewritten, {replacement.name: replacement for replacement in replacements})
        for replacement in replacements:
            if replacement.action != "remove" and replacement.real_value:
                rewritten = rewritten.replace(replacement.real_value, replacement.virtual_value)
        with open(dest_path, "w") as handle:
            handle.write(rewritten)

    def _remove_denied_lines(self, content: str, replacements: Dict[str, SecretReplacement]) -> str:
        lines = []
        for line in content.splitlines(True):
            parsed_name = self._parse_name(line)
            replacement = replacements.get(parsed_name) if parsed_name else None
            if replacement and replacement.action == "remove":
                continue
            lines.append(line)
        return "".join(lines)

    def _parse_name(self, line: str):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            return None
        name = stripped.split("=", 1)[0].strip()
        if name.startswith("export "):
            name = name[len("export ") :].strip()
        return name or None
