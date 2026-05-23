import argparse
import os
import re
import socket
import sys
from typing import Any, Dict
from urllib.parse import urlsplit

from agentsecure.cli.common import load_config_data, normalize_domain
from agentsecure.core.config import ConfigError, JsonConfigLoader, JsonConfigWriter
from agentsecure.core.models import Destination
from agentsecure.core.provider_proxy import configured_provider_base_url, provider_base_local_path, upstream_host
from agentsecure.core.product import default_config
from agentsecure.implementations.policy import StrictDestinationValidator


def add_proxy_subparser(subparsers) -> None:
    proxy_parser = subparsers.add_parser("proxy", help="Configure local provider proxy")
    proxy_subparsers = proxy_parser.add_subparsers(dest="proxy_command")

    setup_parser = proxy_subparsers.add_parser("setup", help="Configure a provider proxy")
    setup_subparsers = setup_parser.add_subparsers(dest="provider")
    openai_parser = setup_subparsers.add_parser("openai", help="Activate provider_catalog.openai")
    openai_parser.add_argument(
        "--trust-local-catalog",
        action="store_true",
        help="Allow provider_catalog.openai values that differ from the packaged default",
    )

    custom_parser = setup_subparsers.add_parser("custom", help="Configure a custom provider proxy")
    custom_parser.add_argument("--name", required=True, help="Provider name used in the local path")
    custom_parser.add_argument("--upstream", required=True, help="Provider upstream, for example https://api.example.com")
    custom_parser.add_argument("--env", required=True, help="Environment variable that contains the provider key")
    custom_parser.add_argument("--base-url-env", required=True, help="Environment variable used by the SDK for base URL")
    custom_parser.add_argument("--allow-path", action="append", default=[], help="Allowed upstream path prefix")

    proxy_subparsers.add_parser("doctor", help="Check provider proxy setup")


def handle_proxy(args: argparse.Namespace) -> int:
    if args.proxy_command == "setup":
        return setup_proxy(args)
    if args.proxy_command == "doctor":
        return doctor_proxy(args)
    sys.stderr.write("agentsecure: missing proxy subcommand\n")
    return 2


def setup_proxy(args: argparse.Namespace) -> int:
    if args.provider == "openai":
        return _activate_catalog_provider(args.config, "openai", args.trust_local_catalog)
    if args.provider == "custom":
        return _activate_custom_provider(args)
    sys.stderr.write("agentsecure: missing proxy provider\n")
    return 2


def doctor_proxy(args: argparse.Namespace) -> int:
    try:
        config = JsonConfigLoader().load(args.config)
    except (ConfigError, OSError, ValueError) as exc:
        sys.stderr.write("agentsecure: invalid config: %s\n" % exc)
        return 1

    if not config.provider_proxy.enabled:
        print("Provider proxy: disabled")
        return 1

    ok = True
    if _can_bind(config.gateway.host, config.gateway.port):
        print("Gateway bind: ok (%s:%s)" % (config.gateway.host, config.gateway.port))
    else:
        print("Gateway bind: blocked or busy (%s:%s)" % (config.gateway.host, config.gateway.port))
        ok = False

    bindings = {(binding.env_name, binding.provider): binding for binding in config.secrets}
    network_validator = StrictDestinationValidator(config.network)
    for provider in config.provider_proxy.providers.values():
        host = normalize_domain(urlsplit(provider.upstream).hostname or "")
        print("Provider %s:" % provider.name)
        local_path = provider_base_local_path(provider.local_path, provider.allow_paths)
        print("  local: http://%s:%s%s" % (config.gateway.host, config.gateway.port, local_path))
        print("  upstream: %s" % provider.upstream)
        print("  env: %s" % provider.env_name)
        print("  base url env: %s" % provider.base_url_env)
        if (provider.env_name, provider.name) in bindings:
            print("  binding: ok")
        else:
            print("  binding: missing (run with --protect-all after adding the key for provider %s)" % provider.name)
            ok = False
        parsed = urlsplit(provider.upstream)
        port = parsed.port or 443
        decision = network_validator.validate(Destination("https", host, port, credentials_present=True))
        if decision.allowed:
            print("  network allowlist: ok")
        else:
            print("  network policy: blocked (%s)" % decision.reason)
            ok = False
    return 0 if ok else 1


def _activate_catalog_provider(config_path: str, provider_name: str, trust_local_catalog: bool = False) -> int:
    config = load_config_data(config_path)
    catalog = config.get("provider_catalog", {})
    provider = catalog.get(provider_name)
    if not isinstance(provider, dict):
        sys.stderr.write(
            "agentsecure: provider_catalog.%s is missing from %s\n" % (provider_name, config_path)
        )
        return 1
    default_provider = default_config().get("provider_catalog", {}).get(provider_name)
    if default_provider and not trust_local_catalog and _canonical_provider(provider) != _canonical_provider(default_provider):
        sys.stderr.write(
            "agentsecure: provider_catalog.%s differs from the packaged default; "
            "use proxy setup custom or pass --trust-local-catalog\n" % provider_name
        )
        return 2
    return _activate_provider(config_path, config, provider_name, provider)


def _activate_custom_provider(args: argparse.Namespace) -> int:
    config = load_config_data(args.config)
    name = _slug(args.name)
    upstream = str(args.upstream).rstrip("/")
    parsed = urlsplit(upstream)
    try:
        parsed_port = parsed.port
    except ValueError:
        sys.stderr.write("agentsecure: custom upstream port is invalid\n")
        return 2
    if parsed.scheme != "https" or not parsed.hostname:
        sys.stderr.write("agentsecure: custom upstream must be https and include a host\n")
        return 2
    _ = parsed_port
    provider = {
        "env_name": args.env,
        "base_url_env": args.base_url_env,
        "upstream": upstream,
        "local_path": "/providers/%s" % name,
        "inject_as": "authorization_bearer",
        "allow_paths": args.allow_path or ["/"],
        "allow_domains": [parsed.hostname],
    }
    config.setdefault("provider_catalog", {})[name] = dict(provider)
    return _activate_provider(args.config, config, name, provider)


def _activate_provider(
    config_path: str,
    config: Dict[str, Any],
    provider_name: str,
    provider: Dict[str, Any],
) -> int:
    error = _validate_provider(provider_name, provider)
    if error:
        sys.stderr.write("agentsecure: %s\n" % error)
        return 2

    provider_proxy = config.setdefault("provider_proxy", {})
    provider_proxy["enabled"] = True
    providers = provider_proxy.setdefault("providers", {})
    providers[provider_name] = {
        "env_name": str(provider["env_name"]),
        "base_url_env": str(provider["base_url_env"]),
        "upstream": str(provider["upstream"]).rstrip("/"),
        "local_path": _normalize_path(str(provider["local_path"])),
        "inject_as": "authorization_bearer",
        "allow_paths": [_normalize_allow_path(path) for path in provider.get("allow_paths", ["/"])],
    }

    env_name = str(provider["env_name"])
    env_policy = config.setdefault("env_policy", {})
    rule = dict(env_policy.get(env_name, {}))
    rule.setdefault("mode", "virtualize")
    rule.setdefault(
        "reason",
        "Agent sees a virtual token; AgentSecure injects the real key only at the configured provider proxy.",
    )
    rule["approved_hosts"] = list(provider.get("allow_domains") or [upstream_host(provider)])
    env_policy[env_name] = rule

    network = config.setdefault("network", {})
    allowed = list(network.get("allow_domains", []))
    for domain in provider.get("allow_domains") or [upstream_host(provider)]:
        normalized = normalize_domain(str(domain))
        if normalized and normalized not in allowed:
            allowed.append(normalized)
    network["allow_domains"] = allowed

    JsonConfigWriter().save(config_path, config)
    active_provider = dict(providers[provider_name])
    active_provider["local_path"] = provider_base_local_path(
        str(active_provider["local_path"]),
        list(active_provider.get("allow_paths") or []),
    )
    print("Configured provider proxy: %s" % provider_name)
    print("  %s=%s" % (provider["base_url_env"], configured_provider_base_url(config, active_provider)))
    print("  %s stays virtualized" % provider["env_name"])
    print("  upstream: %s" % provider["upstream"])
    return 0


def _validate_provider(provider_name: str, provider: Dict[str, Any]) -> str:
    for key in ("env_name", "base_url_env", "upstream", "local_path"):
        if not str(provider.get(key, "")).strip():
            return "provider_catalog.%s.%s is required" % (provider_name, key)
    upstream = str(provider.get("upstream", "")).strip()
    parsed = urlsplit(upstream)
    try:
        parsed_port = parsed.port
    except ValueError:
        return "provider_catalog.%s.upstream port is invalid" % provider_name
    if parsed.scheme != "https" or not parsed.hostname:
        return "provider_catalog.%s.upstream must be an https URL with a host" % provider_name
    _ = parsed_port
    if _normalize_path(str(provider.get("local_path", ""))) == "/":
        return "provider_catalog.%s.local_path must not be /" % provider_name
    if not isinstance(provider.get("allow_paths", []), list):
        return "provider_catalog.%s.allow_paths must be a list" % provider_name
    for key in ("env_name", "base_url_env"):
        error = _validate_env_name(str(provider[key]), "provider_catalog.%s.%s" % (provider_name, key))
        if error:
            return error
    if str(provider.get("inject_as", "authorization_bearer")) != "authorization_bearer":
        return "provider_catalog.%s.inject_as must be authorization_bearer" % provider_name
    return ""


def _validate_env_name(value: str, path: str) -> str:
    if not re.match(r"^[A-Z_][A-Z0-9_]*$", value):
        return "%s must be an uppercase environment variable name" % path
    blocked = {
        "PATH",
        "HOME",
        "SHELL",
        "PYTHONPATH",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
    }
    if value in blocked:
        return "%s must not override critical process environment" % path
    return ""


def _canonical_provider(provider: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "env_name": str(provider.get("env_name", "")),
        "base_url_env": str(provider.get("base_url_env", "")),
        "upstream": str(provider.get("upstream", "")).rstrip("/"),
        "local_path": _normalize_path(str(provider.get("local_path", ""))),
        "inject_as": str(provider.get("inject_as", "authorization_bearer")),
        "allow_paths": [_normalize_allow_path(path) for path in provider.get("allow_paths", [])],
        "allow_domains": [normalize_domain(str(domain)) for domain in provider.get("allow_domains", [])],
    }


def _normalize_path(path: str) -> str:
    return "/" + path.strip().strip("/")


def _normalize_allow_path(path: str) -> str:
    normalized = "/" + str(path).strip().strip("/")
    return "/" if normalized == "/" else normalized.rstrip("/") + "/"


def _slug(value: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in value).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "custom"


def _can_bind(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()
