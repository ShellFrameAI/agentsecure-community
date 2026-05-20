import json
import os
import tempfile
from dataclasses import asdict
from typing import Dict, List, Optional

from agentsecure.core.models import SecretGrant
from agentsecure.interfaces.grants import GrantStore


class LocalJsonGrantStore(GrantStore):
    def __init__(self, path: str = ".agentsecure/grants.json") -> None:
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
            )
        return result

    def _write(self, grants: Dict[str, SecretGrant]) -> None:
        directory = os.path.dirname(self._path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".grants-", dir=directory)
        try:
            os.fchmod(fd, 0o600)
            data = {}
            for token, grant in grants.items():
                data[token] = asdict(grant)
            with os.fdopen(fd, "w") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.replace(temp_path, self._path)
            os.chmod(self._path, 0o600)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

