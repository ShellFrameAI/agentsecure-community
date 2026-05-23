import json
import os
import secrets
import string
from typing import Any, Dict

from agentsecure.core.config import JsonConfigWriter
from agentsecure.core.models import SecretGrant
from agentsecure.core.product import default_config
from agentsecure.core.time import DEFAULT_TTL_SECONDS, now_seconds, parse_duration_seconds
from agentsecure.interfaces.audit import AuditLogger
from agentsecure.interfaces.grants import GrantStore
from agentsecure.interfaces.key_store import SecretStore


class KeyManagementError(Exception):
    pass


class KeyManagementService:
    """Creates virtual keys and stores mappings to real local secrets."""

    def __init__(
        self,
        config_path: str,
        secret_store: SecretStore,
        grant_store: GrantStore,
        audit_logger: AuditLogger,
    ) -> None:
        self._config_path = config_path
        self._secret_store = secret_store
        self._grant_store = grant_store
        self._audit = audit_logger
        self._writer = JsonConfigWriter()

    def create_key(
        self,
        env_name: str,
        real_secret: str,
        provider: str = "custom",
        inject_as: str = "authorization_bearer",
        name: str = "",
        ttl: str = "",
    ) -> Dict[str, Any]:
        if not env_name:
            raise KeyManagementError("env_name is required")
        if not real_secret:
            raise KeyManagementError("real_secret is required")
        provider_slug = self._slug(provider or "custom")
        virtual_token = self._generate_virtual_token(provider_slug)
        secret_id = self._generate_secret_id(provider_slug)
        secret_ref = "local:" + secret_id
        ttl_seconds = parse_duration_seconds(ttl) if ttl else DEFAULT_TTL_SECONDS
        created_at = now_seconds()
        expires_at = created_at + ttl_seconds

        self._secret_store.put(secret_id, real_secret)
        grant = SecretGrant(
            env_name=env_name,
            virtual_token=virtual_token,
            secret_ref=secret_ref,
            provider=provider_slug,
            inject_as=inject_as,
            created_at=created_at,
            expires_at=expires_at,
        )
        self._grant_store.put(grant)
        config = self._load_or_default_config()
        secrets_list = config.setdefault("secrets", [])
        secrets_list.append(
            {
                "env_name": env_name,
                "virtual_token": virtual_token,
                "real_secret_ref": secret_ref,
                "inject_as": inject_as,
                "provider": provider_slug,
                "name": name,
                "expires_at": expires_at,
            }
        )
        self._writer.save(self._config_path, config)
        self._audit.record(
            "key_created",
            {
                "env_name": env_name,
                "provider": provider_slug,
                "secret_ref": secret_ref,
                "virtual_token": virtual_token,
                "expires_at": expires_at,
            },
        )
        return {
            "env_name": env_name,
            "provider": provider_slug,
            "inject_as": inject_as,
            "virtual_token": virtual_token,
            "secret_ref": secret_ref,
            "config_path": self._config_path,
            "created_at": created_at,
            "expires_at": expires_at,
            "ttl_seconds": ttl_seconds,
        }

    def _load_or_default_config(self) -> Dict[str, Any]:
        if not os.path.exists(self._config_path):
            return default_config()
        with open(self._config_path, "r") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise KeyManagementError("config root must be an object")
        return data

    def _generate_virtual_token(self, provider_slug: str) -> str:
        return "virt_%s_%s" % (provider_slug, secrets.token_urlsafe(24))

    def _generate_secret_id(self, provider_slug: str) -> str:
        return "%s_%s" % (provider_slug, secrets.token_urlsafe(18))

    def _slug(self, value: str) -> str:
        allowed = string.ascii_lowercase + string.digits + "_"
        lowered = value.lower().replace("-", "_")
        slug = "".join(ch for ch in lowered if ch in allowed)
        return slug or "custom"
