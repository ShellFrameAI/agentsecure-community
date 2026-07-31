import json
import os
from dataclasses import asdict
from typing import Dict, List, Optional

from agentsecure.core.models import SecretGrant
from agentsecure.core.secure_files import write_private_json
from agentsecure.interfaces.grants import GrantStore


DEFAULT_GRANT_STORE_PATH = ".agentsecure/grants.json"


class LocalJsonGrantStore(GrantStore):
    def __init__(self, path: str = DEFAULT_GRANT_STORE_PATH) -> None:
        self._path = path

    def put(self, grant: SecretGrant) -> None:
        grants = self._read()
        grants[grant.virtual_token] = grant
        self._write(grants)

    def get_by_virtual_token(self, virtual_token: str) -> Optional[SecretGrant]:
        return self._read().get(virtual_token)

    def list(self) -> List[SecretGrant]:
        return sorted(self._read().values(), key=lambda grant: grant.created_at)

    def revoke(self, virtual_token: str) -> bool:
        grants = self._read()
        grant = grants.get(virtual_token)
        if not grant:
            return False
        grants[virtual_token] = SecretGrant(
            env_name=grant.env_name,
            virtual_token=grant.virtual_token,
            secret_ref=grant.secret_ref,
            provider=grant.provider,
            inject_as=grant.inject_as,
            created_at=grant.created_at,
            expires_at=grant.expires_at,
            status="revoked",
            alias_id=grant.alias_id,
            scope=grant.scope,
            project_id=grant.project_id,
            run_id=grant.run_id,
        )
        self._write(grants)
        return True

    def _read(self) -> Dict[str, SecretGrant]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path, "r") as handle:
            data = json.load(handle)
        result = {}
        if not isinstance(data, dict):
            return result
        for token, item in data.items():
            if not isinstance(item, dict):
                continue
            result[str(token)] = SecretGrant(
                env_name=str(item["env_name"]),
                virtual_token=str(item["virtual_token"]),
                secret_ref=str(item["secret_ref"]),
                provider=str(item.get("provider", "custom")),
                inject_as=str(item.get("inject_as", "authorization_bearer")),
                created_at=float(item["created_at"]),
                expires_at=float(item["expires_at"]),
                status=str(item.get("status", "active")),
                alias_id=str(item.get("alias_id", "")),
                scope=str(item.get("scope", "project")),
                project_id=str(item.get("project_id", "")),
                run_id=str(item.get("run_id", "")),
            )
        return result

    def _write(self, grants: Dict[str, SecretGrant]) -> None:
        data = {}
        for token, grant in grants.items():
            data[token] = asdict(grant)
        write_private_json(self._path, data, ".grants-")


def local_grant_store_for_project(project_root: str = ".") -> LocalJsonGrantStore:
    base = os.path.abspath(project_root)
    return LocalJsonGrantStore(os.path.join(base, DEFAULT_GRANT_STORE_PATH))


def local_grant_store_for_config(config_path: str) -> LocalJsonGrantStore:
    config_dir = os.path.dirname(os.path.abspath(config_path)) or "."
    return local_grant_store_for_project(config_dir)
