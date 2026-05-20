import json
import os
import sys
from typing import List

from agentsecure.core.config import JsonConfigWriter
from agentsecure.core.key_service import KeyManagementError
from agentsecure.core.product import ProductService
from agentsecure.discovery.dotenv_scanner import DotenvSecretScanner
from agentsecure.discovery.env_scanner import EnvironmentSecretScanner
from agentsecure.discovery.patterns import mask_secret
from agentsecure.discovery.scanner import CompositeSecretScanner


def scanner() -> CompositeSecretScanner:
    return CompositeSecretScanner(
        [
            EnvironmentSecretScanner(),
            DotenvSecretScanner(os.getcwd()),
        ]
    )


def load_config_data(config_path: str):
    if not os.path.exists(config_path):
        ProductService(config_path, scanner()).init_project()
    with open(config_path, "r") as handle:
        return json.load(handle)


def normalize_policy_path(path: str) -> str:
    return os.path.normpath(path).lstrip(os.sep)


def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def print_discovered(discovered) -> None:
    if not discovered:
        print("No likely secrets found.", flush=True)
        return
    print("AgentSecure found possible secrets:", flush=True)
    for index, secret in enumerate(discovered, 1):
        print(
            "[%s] %s from %s provider=%s value=%s"
            % (index, secret.name, secret.source, secret.provider_hint, mask_secret(secret.value)),
            flush=True,
        )


def selected_indexes(value: str, count: int) -> List[int]:
    if value == "all":
        return list(range(count))
    indexes = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        number = int(part)
        if number < 1 or number > count:
            raise KeyManagementError("selection out of range: %s" % number)
        indexes.append(number - 1)
    return indexes


def update_protected_files(config_path: str, paths: List[str], add: bool) -> int:
    config = load_config_data(config_path)
    files = config.setdefault("files", {})
    protected = list(files.get("protect_write", []))
    if add:
        for path in paths:
            normalized = normalize_policy_path(path)
            if normalized not in protected:
                protected.append(normalized)
    else:
        remove = set(normalize_policy_path(path) for path in paths)
        protected = [path for path in protected if path not in remove]
    files["protect_write"] = protected
    JsonConfigWriter().save(config_path, config)
    print("Protected write paths:")
    for path in protected:
        print("  %s" % path)
    return 0


def update_allowed_domains(config_path: str, domains: List[str], add: bool) -> int:
    config = load_config_data(config_path)
    network = config.setdefault("network", {})
    allowed = list(network.get("allow_domains", []))
    if add:
        for domain in domains:
            normalized = normalize_domain(domain)
            if normalized and normalized not in allowed:
                allowed.append(normalized)
    else:
        remove = set(normalize_domain(domain) for domain in domains)
        allowed = [domain for domain in allowed if domain not in remove]
    network["allow_domains"] = allowed
    JsonConfigWriter().save(config_path, config)
    print("Allowed credential domains:")
    for domain in allowed:
        print("  %s" % domain)
    return 0


def cloud_features_enabled() -> bool:
    return os.environ.get("AGENTSECURE_ENABLE_CLOUD", "").strip() == "1"


def cloud_features_disabled() -> int:
    sys.stderr.write(
        "agentsecure: cloud features are not enabled in community mode "
        "(set AGENTSECURE_ENABLE_CLOUD=1 in private builds)\n"
    )
    return 2
