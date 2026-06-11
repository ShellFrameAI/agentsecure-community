import json
import os
from typing import Iterable, List, Optional

from agentsecure.core.models import SecretBinding


ENV_RUNTIME_BINDINGS = "AGENTSECURE_RUNTIME_BINDINGS"


def serialize_runtime_bindings(bindings: Iterable[SecretBinding]) -> str:
    payload = []
    for binding in bindings:
        payload.append(
            {
                "env_name": binding.env_name,
                "virtual_token": binding.virtual_token,
                "real_secret_ref": binding.real_secret_ref,
                "real_secret_env": binding.real_secret_env,
                "inject_as": binding.inject_as,
                "provider": binding.provider,
                "expires_at": binding.expires_at,
                "alias_id": binding.alias_id,
                "approved_hosts": list(binding.approved_hosts or []),
            }
        )
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def runtime_bindings_from_environment(environ: Optional[dict] = None) -> List[SecretBinding]:
    env = environ if environ is not None else os.environ
    raw = env.get(ENV_RUNTIME_BINDINGS, "")
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    if not isinstance(data, list):
        return []
    bindings = []
    for item in data:
        if not isinstance(item, dict):
            continue
        bindings.append(
            SecretBinding(
                env_name=str(item.get("env_name", "")),
                virtual_token=str(item.get("virtual_token", "")),
                real_secret_ref=str(item.get("real_secret_ref", "")),
                real_secret_env=str(item.get("real_secret_env", "")),
                inject_as=str(item.get("inject_as", "authorization_bearer")),
                provider=str(item.get("provider", "custom")),
                expires_at=_optional_float(item.get("expires_at")),
                alias_id=str(item.get("alias_id", "")),
                approved_hosts=[str(host) for host in item.get("approved_hosts", [])],
            )
        )
    return bindings


def _optional_float(value):
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
