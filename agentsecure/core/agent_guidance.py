import os
from typing import Iterable, List

from agentsecure.core.models import SecretBinding


AGENT_GUIDE_FILENAME = "AGENTSECURE_AGENT_GUIDE.md"
ENV_AGENT_GUIDE = "AGENTSECURE_AGENT_GUIDE"
ENV_SKILL_FILE = "AGENTSECURE_SKILL_FILE"


def write_agent_guidance(source_root: str, run_id: str, bindings: Iterable[SecretBinding]) -> str:
    guide_dir = os.path.abspath(os.path.join(source_root, ".agentsecure", "runs", run_id))
    os.makedirs(guide_dir, exist_ok=True)
    os.chmod(guide_dir, 0o700)
    guide_path = os.path.join(guide_dir, AGENT_GUIDE_FILENAME)
    fd = os.open(guide_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(render_agent_guidance(bindings))
    os.chmod(guide_path, 0o600)
    return guide_path


def render_agent_guidance(bindings: Iterable[SecretBinding]) -> str:
    binding_list = sorted(list(bindings), key=lambda item: (item.env_name, item.provider, item.alias_id))
    lines: List[str] = [
        "# AgentSecure Run Guidance",
        "",
        "- Use the environment variables AgentSecure injected for this run.",
        "- Treat values beginning with `virt_` as virtual tokens, not raw secrets.",
        "- Do not read `.env` files to recover secrets.",
        "- Do not ask a human to paste secrets into chat, terminal, logs, or files.",
        "- If a required secret environment variable is missing, ask the user to run `agentsecure secrets import .env` or `agentsecure secrets use <alias>` before retrying.",
        "",
    ]
    if binding_list:
        lines.extend(["## Managed Secret Environment", ""])
        for binding in binding_list:
            details = [
                "env=%s" % _safe_text(binding.env_name),
                "provider=%s" % _safe_text(binding.provider or "custom"),
            ]
            if binding.approved_hosts:
                details.append("approved_hosts=%s" % ", ".join(_safe_text(host) for host in binding.approved_hosts))
            else:
                details.append("approved_hosts=not specified")
            lines.append("- " + "; ".join(details))
        lines.append("")
    else:
        lines.extend(
            [
                "## Managed Secret Environment",
                "",
                "- No runtime alias bindings were provided for this run.",
                "",
            ]
        )
    return "\n".join(lines)


def relative_agent_guidance_path(source_root: str, guide_path: str) -> str:
    try:
        return os.path.relpath(guide_path, os.path.abspath(source_root))
    except ValueError:
        return guide_path


def _safe_text(value: str) -> str:
    return str(value).replace("\n", " ").replace("\r", " ").strip()
