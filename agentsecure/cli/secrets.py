import argparse
import getpass
import json
import os
import sys
import time
from typing import List

from agentsecure.cli.common import print_discovered, scanner, selected_indexes
from agentsecure.core.capabilities import broker_url_for_env
from agentsecure.core.config import ConfigError, JsonConfigLoader
from agentsecure.core.key_service import KeyManagementError, KeyManagementService
from agentsecure.core.models import AgentSecureConfig, DiscoveredSecret, SecretReplacement
from agentsecure.core.time import DurationError
from agentsecure.discovery.patterns import mask_secret
from agentsecure.discovery.suggestions import PolicySuggestionService
from agentsecure.implementations.audit import JsonLineAuditLogger
from agentsecure.implementations.grant_store import LocalJsonGrantStore
from agentsecure.implementations.secret_store_factory import encrypted_secret_store_for_config


def print_env(args: argparse.Namespace) -> int:
    from agentsecure.core.container import Container

    container = Container.from_config_path(args.config)
    for key, value in sorted(container.virtual_env_provider.build_environment().items()):
        print("%s=%s" % (key, value))
    return 0


def handle_keys(args: argparse.Namespace) -> int:
    if args.keys_command == "create":
        return create_key(args)
    if args.keys_command == "list":
        return list_keys(args)
    if args.keys_command == "revoke":
        return revoke_key(args)
    sys.stderr.write("agentsecure: missing keys subcommand\n")
    return 2


def create_key(args: argparse.Namespace) -> int:
    try:
        real_secret = _read_real_secret(args)
        service = KeyManagementService(
            args.config,
            encrypted_secret_store_for_config(args.config),
            LocalJsonGrantStore(),
            JsonLineAuditLogger(".agentsecure/audit.log"),
        )
        result = service.create_key(
            env_name=args.env_name,
            real_secret=real_secret,
            provider=args.provider,
            inject_as=args.inject_as,
            name=args.name,
            ttl=args.ttl,
        )
    except (DurationError, KeyManagementError) as exc:
        sys.stderr.write("agentsecure: %s\n" % exc)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _read_real_secret(args: argparse.Namespace) -> str:
    if args.real_secret_env:
        value = os.environ.get(args.real_secret_env)
        if not value:
            raise KeyManagementError("environment variable %s is empty or unset" % args.real_secret_env)
        return value
    if args.real_secret_stdin:
        return sys.stdin.read().strip()
    return getpass.getpass("Real secret: ").strip()


def discover_secrets(args: argparse.Namespace) -> int:
    discovered = scanner().scan()
    print_discovered(discovered)
    return 0


def suggest_policy(args: argparse.Namespace) -> int:
    try:
        config = JsonConfigLoader().load(args.config) if os.path.exists(args.config) else AgentSecureConfig()
    except ConfigError as exc:
        sys.stderr.write("agentsecure: %s\n" % exc)
        return 2
    discovered = scanner().scan()
    suggestions = PolicySuggestionService(config, discovered).suggest()
    print(json.dumps(_redact_suggestion_values(suggestions, discovered), indent=2, sort_keys=True))
    return 0


def _redact_suggestion_values(payload, discovered: List[DiscoveredSecret]):
    text = json.dumps(payload)
    for secret in discovered:
        if secret.value:
            text = text.replace(secret.value, mask_secret(secret.value))
    return json.loads(text)


def protect_secrets(args: argparse.Namespace):
    discovered = scanner().scan()
    if not discovered:
        return []
    env_policy = JsonConfigLoader().load(args.config).env_policy if os.path.exists(args.config) else None
    policy_rules = env_policy.rules if env_policy else {}
    configured = [secret for secret in discovered if secret.name in policy_rules]
    unconfigured = [secret for secret in discovered if secret.name not in policy_rules]
    replacements = []
    for secret in configured:
        rule = policy_rules[secret.name]
        result = _replacement_from_env_policy(args, secret, rule)
        if isinstance(result, int):
            return result
        replacements.append(result)
    if configured:
        print("AgentSecure applied local env_policy for %s secret(s)." % len(configured), flush=True)
    if not unconfigured:
        return replacements
    print_discovered(unconfigured)
    if getattr(args, "protect_all", False):
        selected = "all"
    elif not sys.stdin.isatty():
        return replacements
    else:
        selected = input("Select secrets to virtualize [all/none/1,2]: ").strip().lower()
    if selected in ("", "none", "n", "no"):
        return replacements
    try:
        indexes = selected_indexes(selected, len(unconfigured))
    except (KeyManagementError, ValueError) as exc:
        sys.stderr.write("agentsecure: %s\n" % exc)
        return 2
    for index in indexes:
        secret = unconfigured[index]
        result = _replacement_from_prompt(args, secret)
        if isinstance(result, int):
            return result
        replacements.append(result)
    return replacements


def _replacement_from_env_policy(args: argparse.Namespace, secret: DiscoveredSecret, rule):
    if rule.mode == "deny":
        print("Denied %s by env_policy" % secret.name, flush=True)
        return SecretReplacement(
            source=secret.source,
            name=secret.name,
            real_value=secret.value,
            virtual_value="",
            action="remove",
        )
    if rule.mode == "broker":
        return _create_broker_secret_replacement(args, secret, rule)
    return _create_virtual_secret_replacement(
        args,
        secret,
        secret.name,
        secret.provider_hint,
    )


def _create_broker_secret_replacement(args: argparse.Namespace, secret: DiscoveredSecret, rule):
    created = _store_secret_binding(args, secret, secret.name, secret.provider_hint)
    if isinstance(created, int):
        return created
    config = JsonConfigLoader().load(args.config)
    broker_url = broker_url_for_env(config, secret.name, secret.value)
    audit = JsonLineAuditLogger(".agentsecure/audit.log")
    capability = config.capabilities.get(rule.capability)
    if capability:
        audit.record(
            "capability.registered",
            {
                "capability": capability.name,
                "type": capability.type,
                "expose_as": capability.expose_as or secret.name,
                "target_host": capability.target_host,
                "target_port": capability.target_port,
                "access": capability.access,
            },
        )
    audit.record(
        "secret.brokered",
        {
            "env_name": secret.name,
            "capability": rule.capability,
            "broker_url": broker_url,
        },
    )
    print("Brokered %s via capability %s" % (secret.name, rule.capability), flush=True)
    return SecretReplacement(
        source=secret.source,
        name=secret.name,
        real_value=secret.value,
        virtual_value=broker_url,
    )


def _replacement_from_prompt(args: argparse.Namespace, secret: DiscoveredSecret):
    if getattr(args, "protect_all", False):
        env_name = secret.name
        provider = secret.provider_hint
    else:
        env_name = input("Expose %s as env var [%s]: " % (secret.name, secret.name)).strip() or secret.name
        provider = input("Provider for %s [%s]: " % (secret.name, secret.provider_hint)).strip() or secret.provider_hint
    return _create_virtual_secret_replacement(args, secret, env_name, provider)


def _create_virtual_secret_replacement(
    args: argparse.Namespace,
    secret: DiscoveredSecret,
    env_name: str,
    provider: str,
):
    result = _store_secret_binding(args, secret, env_name, provider)
    if isinstance(result, int):
        return result
    ttl = getattr(args, "ttl", "2h")
    print("Created %s=%s expires in %s" % (env_name, result["virtual_token"], ttl), flush=True)
    return SecretReplacement(
        source=secret.source,
        name=secret.name,
        real_value=secret.value,
        virtual_value=result["virtual_token"],
    )


def _store_secret_binding(
    args: argparse.Namespace,
    secret: DiscoveredSecret,
    env_name: str,
    provider: str,
):
    ttl = getattr(args, "ttl", "2h")
    service = KeyManagementService(
        args.config,
        encrypted_secret_store_for_config(args.config),
        LocalJsonGrantStore(),
        JsonLineAuditLogger(".agentsecure/audit.log"),
    )
    try:
        result = service.create_key(
            env_name=env_name,
            real_secret=secret.value,
            provider=provider,
            ttl=ttl,
        )
    except (DurationError, KeyManagementError) as exc:
        sys.stderr.write("agentsecure: %s\n" % exc)
        return 2
    return result


def list_keys(args: argparse.Namespace) -> int:
    grants = LocalJsonGrantStore().list()
    now = time.time()
    rows = []
    for grant in grants:
        remaining = int(grant.expires_at - now)
        if grant.status != "active":
            state = grant.status
        elif remaining <= 0:
            state = "expired"
        else:
            state = "active"
        rows.append(
            {
                "env_name": grant.env_name,
                "provider": grant.provider,
                "virtual_token": grant.virtual_token,
                "status": state,
                "expires_at": grant.expires_at,
                "seconds_remaining": max(0, remaining),
            }
        )
    print(json.dumps(rows, indent=2, sort_keys=True))
    return 0


def revoke_key(args: argparse.Namespace) -> int:
    revoked = LocalJsonGrantStore().revoke(args.virtual_token)
    if not revoked:
        sys.stderr.write("agentsecure: virtual token not found\n")
        return 1
    JsonLineAuditLogger(".agentsecure/audit.log").record(
        "key_revoked",
        {"virtual_token": args.virtual_token},
    )
    print(json.dumps({"revoked": True, "virtual_token": args.virtual_token}, indent=2, sort_keys=True))
    return 0
