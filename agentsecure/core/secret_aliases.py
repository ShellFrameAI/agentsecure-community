import hashlib
import json
import os
import secrets
import string
from dataclasses import asdict
from typing import Dict, Iterable, List, Optional

from agentsecure.core.config import JsonConfigWriter
from agentsecure.core.models import ProjectSecretAlias, SecretAlias, SecretBinding
from agentsecure.core.secure_files import write_private_json
from agentsecure.core.time import DEFAULT_TTL_SECONDS, now_seconds, parse_duration_seconds
from agentsecure.interfaces.audit import AuditLogger
from agentsecure.interfaces.grants import GrantStore
from agentsecure.interfaces.key_store import SecretStore


DEFAULT_ALIAS_STORE_PATH = "vault/aliases.json"
SECRET_ALIAS_POLICY_FIELDS = set(
    [
        "alias",
        "alias_id",
        "description",
        "label",
        "name",
        "env_name",
        "provider",
        "inject_as",
        "approved_hosts",
        "required",
        "mode",
    ]
)


class SecretAliasError(ValueError):
    pass


class LocalSecretAliasStore:
    def __init__(self, path: str) -> None:
        self._path = path

    def put(self, alias: SecretAlias) -> None:
        aliases = self._read()
        aliases[alias.alias_id] = alias
        self._write(aliases)

    def get(self, alias_id: str) -> Optional[SecretAlias]:
        return self._read().get(alias_id)

    def list(self) -> List[SecretAlias]:
        return sorted(self._read().values(), key=lambda item: item.alias_id)

    def _read(self) -> Dict[str, SecretAlias]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path, "r") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            return {}
        aliases = {}
        for alias_id, item in data.items():
            if not isinstance(item, dict):
                continue
            aliases[str(alias_id)] = SecretAlias(
                alias_id=str(item.get("alias_id", alias_id)),
                name=str(item.get("name", "")),
                env_name=str(item.get("env_name", "")),
                provider=str(item.get("provider", "custom")),
                inject_as=str(item.get("inject_as", "authorization_bearer")),
                secret_ref=str(item.get("secret_ref", "")),
                approved_hosts=list(item.get("approved_hosts", [])),
            )
        return aliases

    def _write(self, aliases: Dict[str, SecretAlias]) -> None:
        data = {key: asdict(value) for key, value in aliases.items()}
        write_private_json(self._path, data, ".aliases-")


class SecretAliasService:
    def __init__(
        self,
        alias_store: LocalSecretAliasStore,
        secret_store: SecretStore,
        grant_store: GrantStore,
        audit_logger: AuditLogger,
    ) -> None:
        self._aliases = alias_store
        self._secret_store = secret_store
        self._grant_store = grant_store
        self._audit = audit_logger

    def add_alias(
        self,
        alias_id: str,
        real_secret: str,
        env_name: str,
        provider: str = "custom",
        inject_as: str = "authorization_bearer",
        name: str = "",
        approved_hosts: Optional[List[str]] = None,
    ) -> SecretAlias:
        alias_id = self._normalize_alias_id(alias_id)
        if not real_secret:
            raise SecretAliasError("real_secret is required")
        if not env_name:
            raise SecretAliasError("env_name is required")
        existing = self._aliases.get(alias_id)
        provider = self._slug(provider or "custom")
        secret_id = "alias_%s_%s" % (provider, secrets.token_urlsafe(18))
        secret_ref = "local:" + secret_id
        self._secret_store.put(secret_id, real_secret)
        alias = SecretAlias(
            alias_id=alias_id,
            name=name or alias_id,
            env_name=env_name,
            provider=provider,
            inject_as=inject_as or "authorization_bearer",
            secret_ref=secret_ref,
            approved_hosts=list(approved_hosts or []),
        )
        self._aliases.put(alias)
        revoked_count = 0
        if existing:
            revoked_count = self._revoke_alias_grants(alias_id)
            self._delete_secret_ref(existing.secret_ref)
            self._audit.record(
                "secret_alias_rotated",
                {
                    "alias_id": alias.alias_id,
                    "env_name": alias.env_name,
                    "provider": alias.provider,
                    "revoked_grants": revoked_count,
                },
            )
        self._audit.record(
            "secret_alias_created",
            {
                "alias_id": alias.alias_id,
                "env_name": alias.env_name,
                "provider": alias.provider,
                "approved_hosts": alias.approved_hosts,
            },
        )
        return alias

    def list_aliases(self) -> List[SecretAlias]:
        return self._aliases.list()

    def assign_to_project(
        self,
        config_path: str,
        alias_ids: Iterable[str],
        project: str = "",
    ) -> List[ProjectSecretAlias]:
        config = self._load_config(config_path)
        existing = {
            str(item.get("alias_id", "")): dict(item)
            for item in config.get("secret_aliases", [])
            if isinstance(item, dict)
        }
        assigned = []
        for raw_alias_id in alias_ids:
            alias_id = self._normalize_alias_id(raw_alias_id)
            alias = self._aliases.get(alias_id)
            if not alias:
                raise SecretAliasError("secret alias not found: %s" % alias_id)
            item = {
                "alias_id": alias.alias_id,
                "env_name": alias.env_name,
                "provider": alias.provider,
                "inject_as": alias.inject_as,
                "approved_hosts": list(alias.approved_hosts),
                "required": True,
                "mode": "virtualize",
            }
            existing[alias.alias_id] = item
            assigned.append(ProjectSecretAlias(**item))
            self._merge_env_policy(config, alias)
            self._merge_network_allow_domains(config, alias.approved_hosts)
        config["secret_aliases"] = sorted(existing.values(), key=lambda item: item["alias_id"])
        JsonConfigWriter().save(config_path, config)
        self._audit.record(
            "project_secret_assigned",
            {
                "project": project,
                "aliases": [item.alias_id for item in assigned],
                "config_path": os.path.abspath(config_path),
            },
        )
        return assigned

    def prepare_run_bindings(
        self,
        project_aliases: Iterable[ProjectSecretAlias],
        ttl: str,
        project_id: str,
        run_id: str,
        selected_alias_ids: Optional[Iterable[str]] = None,
    ) -> List[SecretBinding]:
        selected = set(self._normalize_alias_id(item) for item in selected_alias_ids or [])
        bindings = []
        for assignment in project_aliases:
            if selected and assignment.alias_id not in selected:
                continue
            if assignment.mode != "virtualize":
                self._audit.record(
                    "run_secret_skipped",
                    {
                        "alias_id": assignment.alias_id,
                        "mode": assignment.mode,
                        "project_id": project_id,
                        "run_id": run_id,
                    },
                )
                continue
            alias = self._aliases.get(assignment.alias_id)
            if not alias:
                if assignment.required:
                    raise SecretAliasError("required secret alias is missing locally: %s" % assignment.alias_id)
                continue
            env_name = assignment.env_name or alias.env_name
            provider = self._slug(assignment.provider or alias.provider)
            inject_as = assignment.inject_as or alias.inject_as
            approved_hosts = list(assignment.approved_hosts or alias.approved_hosts)
            virtual_token = "virt_%s_%s" % (provider, secrets.token_urlsafe(24))
            ttl_seconds = parse_duration_seconds(ttl) if ttl else DEFAULT_TTL_SECONDS
            created_at = now_seconds()
            expires_at = created_at + ttl_seconds
            from agentsecure.core.models import SecretGrant

            self._grant_store.put(
                SecretGrant(
                    env_name=env_name,
                    virtual_token=virtual_token,
                    secret_ref=alias.secret_ref,
                    provider=provider,
                    inject_as=inject_as,
                    created_at=created_at,
                    expires_at=expires_at,
                    alias_id=alias.alias_id,
                    scope="run",
                    project_id=project_id,
                    run_id=run_id,
                )
            )
            bindings.append(
                SecretBinding(
                    env_name=env_name,
                    virtual_token=virtual_token,
                    real_secret_ref=alias.secret_ref,
                    inject_as=inject_as,
                    provider=provider,
                    expires_at=expires_at,
                    alias_id=alias.alias_id,
                    approved_hosts=approved_hosts,
                )
            )
            self._audit.record(
                "run_secret_granted",
                {
                    "alias_id": alias.alias_id,
                    "env_name": env_name,
                    "provider": provider,
                    "expires_at": expires_at,
                    "project_id": project_id,
                    "run_id": run_id,
                    "approved_hosts": approved_hosts,
                },
            )
        return bindings

    def revoke_run_bindings(self, bindings: Iterable[SecretBinding], run_id: str) -> None:
        revoked = []
        for binding in bindings:
            if self._grant_store.revoke(binding.virtual_token):
                revoked.append(binding.alias_id or binding.env_name)
        if revoked:
            self._audit.record("run_secret_revoked", {"run_id": run_id, "aliases": revoked})

    def _load_config(self, config_path: str) -> Dict:
        if not os.path.exists(config_path):
            return {
                "secrets": [],
                "secret_aliases": [],
                "env_policy": {},
                "network": {"allow_domains": [], "deny_domains": [], "allow_ports": [80, 443]},
            }
        with open(config_path, "r") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise SecretAliasError("config root must be an object")
        return data

    def _merge_env_policy(self, config: Dict, alias: SecretAlias) -> None:
        env_policy = config.setdefault("env_policy", {})
        rule = dict(env_policy.get(alias.env_name, {})) if isinstance(env_policy.get(alias.env_name, {}), dict) else {}
        rule.setdefault("mode", "virtualize")
        if alias.approved_hosts:
            rule["approved_hosts"] = list(alias.approved_hosts)
        rule.setdefault("reason", "AgentSecure secret alias %s" % alias.alias_id)
        env_policy[alias.env_name] = rule

    def _merge_network_allow_domains(self, config: Dict, approved_hosts: List[str]) -> None:
        if not approved_hosts:
            return
        network = config.setdefault("network", {})
        allow_domains = list(network.get("allow_domains", []))
        existing = {str(item).lower().rstrip(".") for item in allow_domains}
        for host in approved_hosts:
            normalized = str(host).strip()
            if normalized and normalized.lower().rstrip(".") not in existing:
                allow_domains.append(normalized)
                existing.add(normalized.lower().rstrip("."))
        network["allow_domains"] = allow_domains
        network.setdefault("allow_ports", [80, 443])
        network.setdefault("deny_ip_literals", True)
        network.setdefault("deny_private_networks", True)

    def _normalize_alias_id(self, value: str) -> str:
        alias_id = str(value or "").strip()
        if not alias_id:
            raise SecretAliasError("alias_id is required")
        allowed = string.ascii_letters + string.digits + "._-"
        if any(ch not in allowed for ch in alias_id):
            raise SecretAliasError("alias_id may contain only letters, numbers, '.', '_' and '-'")
        return alias_id

    def _slug(self, value: str) -> str:
        allowed = string.ascii_lowercase + string.digits + "_"
        lowered = str(value).lower().replace("-", "_")
        slug = "".join(ch for ch in lowered if ch in allowed)
        return slug or "custom"

    def _revoke_alias_grants(self, alias_id: str) -> int:
        count = 0
        for grant in self._grant_store.list():
            if grant.alias_id == alias_id and grant.status == "active":
                if self._grant_store.revoke(grant.virtual_token):
                    count += 1
        return count

    def _delete_secret_ref(self, secret_ref: str) -> None:
        if not secret_ref.startswith("local:"):
            return
        self._secret_store.delete(secret_ref.split(":", 1)[1])


def project_id_for_path(path: str) -> str:
    root = os.path.dirname(os.path.abspath(path)) if path else os.getcwd()
    return hashlib.sha256(root.encode("utf-8")).hexdigest()[:16]


def local_secret_alias_store_for_home(agentsecure_home: str) -> LocalSecretAliasStore:
    return LocalSecretAliasStore(os.path.join(agentsecure_home, DEFAULT_ALIAS_STORE_PATH))


def normalize_project_secret_alias_updates(updates, validator=None) -> List[Dict]:
    if not isinstance(updates, list):
        raise ValueError("secret_aliases must be a list")
    if validator is None:
        from agentsecure.core.policy_validation import PolicyMutationValidator

        validator = PolicyMutationValidator()
    aliases = []
    for index, item in enumerate(updates):
        path = "secret_aliases.%s" % index
        if not isinstance(item, dict):
            raise ValueError("%s must be a JSON object" % path)
        for field, field_value in item.items():
            if field not in SECRET_ALIAS_POLICY_FIELDS:
                if validator.looks_like_raw_secret_field(field):
                    raise ValueError("%s must not include raw secrets" % path)
                raise ValueError("unsupported %s field: %s" % (path, field))
            validator.reject_raw_secret_value("%s.%s" % (path, field), field_value)
        alias_id = str(item.get("alias_id", item.get("alias", ""))).strip()
        if not alias_id:
            raise ValueError("%s.alias_id is required" % path)
        env_name = str(item.get("env_name", "")).strip()
        mode = str(item.get("mode", "virtualize") or "virtualize")
        if mode not in ("deny", "virtualize"):
            raise ValueError("%s.mode must be deny or virtualize" % path)
        alias = {
            "alias_id": alias_id,
            "env_name": env_name,
            "provider": str(item.get("provider", "")).strip(),
            "inject_as": str(item.get("inject_as", "authorization_bearer") or "authorization_bearer"),
            "approved_hosts": _strings(item.get("approved_hosts", [])),
            "required": bool(item.get("required", True)),
            "mode": mode,
        }
        label = str(item.get("label", item.get("name", ""))).strip()
        if label:
            alias["label"] = label
        description = str(item.get("description", "")).strip()
        if description:
            alias["description"] = description[:160]
        aliases.append(alias)
    return aliases


def _strings(value) -> list:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]
