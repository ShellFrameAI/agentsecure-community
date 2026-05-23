from typing import Any, Dict
from urllib.parse import urlsplit


def configured_provider_base_url(config: Dict[str, Any], provider: Dict[str, Any]) -> str:
    gateway = config.get("gateway", {})
    host = str(gateway.get("host", "127.0.0.1"))
    port = int(gateway.get("port", 8765))
    local_path = "/" + str(provider.get("local_path", "")).strip().strip("/")
    return "http://%s:%s%s" % (host, port, local_path)


def provider_base_local_path(local_path: str, allow_paths) -> str:
    if not allow_paths:
        return local_path
    first = str(allow_paths[0])
    if first == "/":
        return local_path
    return local_path.rstrip("/") + "/" + first.strip("/").rstrip("/")


def upstream_host(provider: Dict[str, Any]) -> str:
    return urlsplit(str(provider.get("upstream", ""))).hostname or ""
