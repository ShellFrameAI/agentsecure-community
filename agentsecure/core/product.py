import json
import os
import socket
import stat
from typing import Any, Dict, List

from agentsecure.core.config import JsonConfigWriter
from agentsecure.core.config_profiles import profile_metadata
from agentsecure.core.time import now_seconds
from agentsecure.crypto.key_provider import LocalDeviceKeyProvider
from agentsecure.discovery.scanner import SecretScanner
from agentsecure.implementations.grant_store import LocalJsonGrantStore


DEFAULT_CONFIG = {
    "secrets": [],
    "env_policy": {},
    "network": {
        "allow_domains": [
            "api.openai.com",
            "api.anthropic.com",
            "chatgpt.com",
            "*.chatgpt.com",
        ],
        "deny_domains": [],
        "allow_ports": [80, 443],
        "deny_ip_literals": True,
        "deny_private_networks": True,
    },
    "process": {
        "allowed_commands": [],
    },
    "files": {
        "protect_write": [
            ".env",
            ".env.local",
            ".env.development",
            "agentsecure.json",
        ],
    },
    "gateway": {
        "host": "127.0.0.1",
        "port": 8765,
    },
    "audit": {
        "path": ".agentsecure/audit.log",
    },
}


class ProductService:
    def __init__(
        self,
        config_path: str,
        scanner: SecretScanner,
        grant_store: LocalJsonGrantStore = None,
    ) -> None:
        self.config_path = config_path
        self.scanner = scanner
        self.grant_store = grant_store or LocalJsonGrantStore()
        self.writer = JsonConfigWriter()

    def init_project(self, force: bool = False) -> Dict[str, Any]:
        created = []
        if os.path.exists(self.config_path) and not force:
            config_created = False
        else:
            config = json.loads(json.dumps(DEFAULT_CONFIG))
            config["gateway"]["port"] = self._available_port(config["gateway"]["port"])
            self.writer.save(self.config_path, config)
            created.append(self.config_path)
            config_created = True

        os.makedirs(".agentsecure", exist_ok=True)
        key_provider = LocalDeviceKeyProvider(os.path.join(".agentsecure", "device.key"))
        if not os.path.exists(key_provider.path):
            key_provider.get_or_create_key()
            created.append(key_provider.path)
        gitignore_path = os.path.join(".agentsecure", ".gitignore")
        if not os.path.exists(gitignore_path) or force:
            with open(gitignore_path, "w") as handle:
                handle.write("*\n!.gitignore\n")
            created.append(gitignore_path)

        return {
            "config_path": self.config_path,
            "config_created": config_created,
            "created": created,
            "next_steps": [
                "agentsecure discover",
                "agentsecure run --protect-all -- <agent-command>",
                "agentsecure api",
            ],
        }

    def status(self) -> Dict[str, Any]:
        config = self._load_config()
        grants = self.grant_store.list()
        now = now_seconds()
        active = 0
        expired = 0
        revoked = 0
        for grant in grants:
            if grant.status != "active":
                revoked += 1
            elif grant.expires_at <= now:
                expired += 1
            else:
                active += 1
        discoveries = self.scanner.scan()
        workspaces = self._workspace_count()
        configuration_profile = self._configuration_profile(config)
        return {
            "config_path": self.config_path,
            "config_exists": os.path.exists(self.config_path),
            "configured_secrets": len(config.get("secrets", [])) if config else 0,
            "discovered_secrets": len(discoveries),
            "grants": {
                "active": active,
                "expired": expired,
                "revoked": revoked,
                "total": len(grants),
            },
            "workspaces": workspaces,
            "gateway": config.get("gateway", {}) if config else {},
            "api": {
                "host": "127.0.0.1",
                "port": 8787,
            },
            "configuration_profile": configuration_profile,
            "config_profile": configuration_profile,
        }

    def doctor(self) -> Dict[str, Any]:
        checks = []
        checks.append(self._check("config_exists", os.path.exists(self.config_path), self.config_path))
        checks.append(self._check("agentsecure_dir_exists", os.path.isdir(".agentsecure"), ".agentsecure"))
        checks.append(
            self._check(
                "device_key_exists",
                os.path.exists(os.path.join(".agentsecure", "device.key")),
                ".agentsecure/device.key encrypts local secrets",
            )
        )
        checks.append(
            self._check(
                "device_key_private",
                self._has_private_permissions(os.path.join(".agentsecure", "device.key")),
                ".agentsecure/device.key should be readable only by the owner",
            )
        )
        checks.append(
            self._check(
                "agentsecure_dir_ignored",
                os.path.exists(os.path.join(".agentsecure", ".gitignore")),
                ".agentsecure/.gitignore protects local secrets from git",
            )
        )
        config = self._load_config()
        checks.append(self._check("config_valid_json", config is not None, self.config_path))
        if config:
            gateway = config.get("gateway", {})
            checks.append(
                self._check(
                    "gateway_localhost",
                    gateway.get("host", "127.0.0.1") == "127.0.0.1",
                    "gateway should bind to 127.0.0.1",
                )
            )
            network = config.get("network", {})
            checks.append(
                self._check(
                    "deny_ip_literals",
                    bool(network.get("deny_ip_literals", True)),
                    "IP literal destinations should be denied",
                )
            )
        ok = all(check["ok"] for check in checks)
        return {"ok": ok, "checks": checks}

    def _load_config(self):
        if not os.path.exists(self.config_path):
            return None
        try:
            with open(self.config_path, "r") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                return data
        except (IOError, ValueError):
            return None
        return None

    def _workspace_count(self) -> int:
        path = os.path.join(".agentsecure", "workspaces")
        if not os.path.isdir(path):
            return 0
        return len([name for name in os.listdir(path) if name.startswith("session_")])

    def _configuration_profile(self, config: Dict[str, Any]) -> Dict[str, Any]:
        local_profile = {}
        if isinstance(config, dict):
            cloud = config.get("cloud", {})
            if isinstance(cloud, dict):
                local_profile = profile_metadata(cloud.get("config_profile", {}))
        assigned_profile = profile_metadata(self._cloud_state().get("config_profile", {}))
        metadata = {}
        metadata.update(local_profile)
        metadata.update(assigned_profile)
        if local_profile.get("applied_version"):
            metadata["applied_version"] = local_profile["applied_version"]
        elif local_profile.get("version"):
            metadata["applied_version"] = local_profile["version"]
        if local_profile.get("last_applied_at"):
            metadata["last_applied_at"] = local_profile["last_applied_at"]
        assigned_version = self._safe_int(metadata.get("assigned_version", 0) or metadata.get("version", 0) or 0)
        applied_version = self._safe_int(metadata.get("applied_version", 0) or 0)
        if assigned_version and applied_version and applied_version < assigned_version:
            metadata["status"] = "pending"
            metadata["pending_version"] = assigned_version
        elif applied_version:
            metadata["status"] = "applied"
            metadata.pop("pending_version", None)
        elif assigned_version and not metadata.get("status"):
            metadata["status"] = "assigned"
        return metadata

    def _cloud_state(self) -> Dict[str, Any]:
        path = os.path.join(".agentsecure", "cloud.json")
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r") as handle:
                data = json.load(handle)
        except (IOError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _safe_int(self, value) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    def _check(self, name: str, ok: bool, detail: str) -> Dict[str, Any]:
        return {"name": name, "ok": bool(ok), "detail": detail}

    def _available_port(self, preferred_port: int) -> int:
        for port in [preferred_port] + list(range(8766, 8790)):
            if self._can_bind(port):
                return port
        return preferred_port

    def _can_bind(self, port: int) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False
        finally:
            sock.close()

    def _has_private_permissions(self, path: str) -> bool:
        if not os.path.exists(path):
            return False
        mode = stat.S_IMODE(os.stat(path).st_mode)
        return mode & 0o077 == 0
