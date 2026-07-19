import hashlib
import json
import os
import shutil
import tempfile
import time
import uuid
from typing import Dict, List

from agentsecure.crypto.aead_cipher import AeadSecretCipher
from agentsecure.implementations.secret_store_factory import (
    agentsecure_home,
    detected_vault_format,
    local_ciphers_for_vault,
)


VAULT_CIPHERS = {
    1: "agentsecure-local-v1",
    2: AeadSecretCipher.NAME,
}


class VaultMigrationError(RuntimeError):
    pass


class VaultMigrationLock:
    def __init__(self, path: str) -> None:
        self.path = path
        self._held = False

    def __enter__(self):
        directory = os.path.dirname(self.path) or "."
        _ensure_private_directory(directory)
        for attempt in range(2):
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                if attempt == 0 and self._remove_stale_lock():
                    continue
                raise VaultMigrationError(
                    "another vault operation is active; if it was interrupted, run `agentsecure vault status`"
                )
            with os.fdopen(fd, "w") as handle:
                json.dump({"pid": os.getpid(), "created_at": int(time.time())}, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._held = True
            return self
        raise VaultMigrationError("failed to acquire vault migration lock")

    def __exit__(self, exc_type, exc_value, traceback):
        if self._held:
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
            self._held = False

    def _remove_stale_lock(self) -> bool:
        try:
            with open(self.path, "r") as handle:
                data = json.load(handle)
            pid = int(data.get("pid", 0))
        except (OSError, ValueError, TypeError):
            try:
                stale = time.time() - os.path.getmtime(self.path) > 300
            except OSError:
                return False
            if not stale:
                return False
            pid = 0
        if pid > 0 and _pid_is_running(pid):
            return False
        try:
            os.unlink(self.path)
            return True
        except OSError:
            return False


class VaultMigrationService:
    def __init__(self, home: str = "") -> None:
        self.home = os.path.abspath(home or agentsecure_home())
        self.vault_dir = os.path.join(self.home, "vault")
        self.store_path = os.path.join(self.vault_dir, "secrets.enc.json")
        self.key_path = os.path.join(self.vault_dir, "device.key")
        self.aliases_path = os.path.join(self.vault_dir, "aliases.json")
        self.manifest_path = os.path.join(self.vault_dir, "manifest.json")
        self.lock_path = os.path.join(self.vault_dir, "migration.lock")
        self.recovery_dir = os.path.join(self.vault_dir, "recovery")

    def status(self) -> Dict:
        format_version = detected_vault_format(self.store_path)
        data = self._load_store(required=False)
        manifest = self._load_json(self.manifest_path, required=False)
        lock_status = _migration_lock_status(self.lock_path)
        return {
            "cipher": VAULT_CIPHERS.get(format_version, "unknown"),
            "format_version": format_version,
            "key_exists": os.path.isfile(self.key_path) and not os.path.islink(self.key_path),
            "key_provider": "local_file",
            "manifest": manifest,
            "migration_lock": lock_status,
            "migration_locked": lock_status["exists"],
            "records": len(data),
            "store_exists": os.path.isfile(self.store_path) and not os.path.islink(self.store_path),
            "vault_directory": self.vault_dir,
        }

    def verify(self) -> Dict:
        data = self._load_store(required=False)
        format_version = detected_vault_format(self.store_path)
        if data and format_version not in VAULT_CIPHERS:
            raise VaultMigrationError("vault contains an unsupported or mixed record format")
        errors = self._verify_records(data, format_version) if data else []
        errors.extend(self._verify_alias_references(data))
        return {
            "errors": errors,
            "format_version": format_version,
            "ok": not errors,
            "records": len(data),
            "verified_secret_ids": sorted(data.keys()) if not errors else [],
        }

    def migrate(self, target_format: int = 2, dry_run: bool = False) -> Dict:
        return self._convert(target_format, "migrate", dry_run)

    def rollback(self, target_format: int = 1, dry_run: bool = False) -> Dict:
        return self._convert(target_format, "rollback", dry_run)

    def _convert(self, target_format: int, operation: str, dry_run: bool) -> Dict:
        if target_format not in VAULT_CIPHERS:
            raise VaultMigrationError("unsupported target vault format: %s" % target_format)
        source_data = self._load_store(required=False)
        source_format = detected_vault_format(self.store_path)
        if source_data and source_format not in VAULT_CIPHERS:
            raise VaultMigrationError("vault contains an unsupported or mixed record format")
        if not source_data:
            alias_errors = self._verify_alias_references(source_data)
            if alias_errors:
                raise VaultMigrationError("vault verification failed before %s: %s" % (operation, "; ".join(alias_errors)))
            return self._result(operation, source_format, target_format, dry_run, 0, "no_secrets", "")
        source_errors = self._verify_records(source_data, source_format)
        source_errors.extend(self._verify_alias_references(source_data))
        if source_errors:
            raise VaultMigrationError("vault verification failed before %s: %s" % (operation, "; ".join(source_errors)))
        if source_format == target_format:
            return self._result(operation, source_format, target_format, dry_run, len(source_data), "already_current", "")
        if dry_run:
            return self._result(operation, source_format, target_format, True, len(source_data), "planned", "")

        _ensure_private_directory(self.vault_dir)
        with VaultMigrationLock(self.lock_path):
            current_data = self._load_store(required=True)
            current_format = detected_vault_format(self.store_path)
            if current_format != source_format or current_data != source_data:
                raise VaultMigrationError("vault changed after the migration plan was created; retry the command")
            converted, expected_hashes = self._convert_records(current_data, source_format, target_format)
            candidate_path = self._write_candidate(converted)
            recovery_path = ""
            replaced = False
            try:
                candidate_data = self._load_json(candidate_path, required=True)
                candidate_errors = self._verify_records(candidate_data, target_format, expected_hashes)
                if candidate_errors:
                    raise VaultMigrationError("candidate vault verification failed: %s" % "; ".join(candidate_errors))
                recovery_path = self._write_recovery_snapshot(source_format, operation)
                os.replace(candidate_path, self.store_path)
                replaced = True
                os.chmod(self.store_path, 0o600)
                _fsync_directory(self.vault_dir)
                self._write_manifest(
                    target_format,
                    operation,
                    source_format,
                    len(converted),
                    recovery_path,
                )
            except Exception:
                if replaced and recovery_path:
                    self._restore_recovery_snapshot(recovery_path)
                raise
            finally:
                if os.path.exists(candidate_path):
                    os.unlink(candidate_path)
        return self._result(
            operation,
            source_format,
            target_format,
            False,
            len(source_data),
            "completed",
            recovery_path,
        )

    def _convert_records(self, data: Dict, source_format: int, target_format: int):
        ciphers = local_ciphers_for_vault(create=False)
        if VAULT_CIPHERS[source_format] not in ciphers or VAULT_CIPHERS[target_format] not in ciphers:
            raise VaultMigrationError(
                "vault format conversion requires AES-256-GCM support; install AgentSecure from PyPI"
            )
        source_cipher = ciphers[VAULT_CIPHERS[source_format]]
        target_cipher = ciphers[VAULT_CIPHERS[target_format]]
        converted = {}
        expected_hashes = {}
        for secret_id, item in sorted(data.items()):
            try:
                plaintext = source_cipher.decrypt(str(item["ciphertext"]))
            except Exception as exc:
                raise VaultMigrationError("failed to decrypt secret %s: %s" % (secret_id, exc))
            expected_hashes[secret_id] = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
            converted[secret_id] = {
                "cipher": VAULT_CIPHERS[target_format],
                "ciphertext": target_cipher.encrypt(plaintext),
                "version": target_format,
            }
        return converted, expected_hashes

    def _verify_records(self, data: Dict, format_version: int, expected_hashes: Dict = None) -> List[str]:
        errors = []
        if not data:
            return errors
        if format_version not in VAULT_CIPHERS:
            return ["unsupported or mixed vault format"]
        try:
            ciphers = local_ciphers_for_vault(create=False)
            cipher = ciphers[VAULT_CIPHERS[format_version]]
        except Exception as exc:
            return ["could not load vault key: %s" % exc]
        for secret_id, item in sorted(data.items()):
            if not isinstance(item, dict):
                errors.append("%s is not a record" % secret_id)
                continue
            if item.get("cipher") != VAULT_CIPHERS[format_version] or item.get("version") != format_version:
                errors.append("%s has inconsistent format metadata" % secret_id)
                continue
            try:
                plaintext = cipher.decrypt(str(item.get("ciphertext", "")))
            except Exception:
                errors.append("%s failed authentication or decryption" % secret_id)
                continue
            if expected_hashes is not None:
                actual_hash = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
                if actual_hash != expected_hashes.get(secret_id):
                    errors.append("%s changed during conversion" % secret_id)
        return errors

    def _verify_alias_references(self, data: Dict) -> List[str]:
        if not os.path.exists(self.aliases_path):
            return []
        aliases = self._load_json(self.aliases_path, required=True)
        errors = []
        for alias_id, item in sorted(aliases.items()):
            if not isinstance(item, dict):
                errors.append("alias %s is not an object" % alias_id)
                continue
            secret_ref = str(item.get("secret_ref", ""))
            if not secret_ref.startswith("local:"):
                errors.append("alias %s has an unsupported secret reference" % alias_id)
                continue
            secret_id = secret_ref.split(":", 1)[1]
            if secret_id not in data:
                errors.append("alias %s references a missing local secret" % alias_id)
        return errors

    def _load_store(self, required: bool) -> Dict:
        if os.path.islink(self.store_path):
            raise VaultMigrationError("vault store must not be a symbolic link")
        return self._load_json(self.store_path, required)

    def _load_json(self, path: str, required: bool) -> Dict:
        if not os.path.exists(path):
            if required:
                raise VaultMigrationError("required vault file is missing: %s" % path)
            return {}
        if os.path.islink(path) or not os.path.isfile(path):
            raise VaultMigrationError("vault path must be a regular file: %s" % path)
        try:
            with open(path, "r") as handle:
                data = json.load(handle)
        except (OSError, ValueError) as exc:
            raise VaultMigrationError("failed to read vault file %s: %s" % (path, exc))
        if not isinstance(data, dict):
            raise VaultMigrationError("vault file must contain a JSON object: %s" % path)
        return data

    def _write_candidate(self, data: Dict) -> str:
        fd, path = tempfile.mkstemp(prefix=".vault-candidate-", dir=self.vault_dir)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            if os.path.exists(path):
                os.unlink(path)
            raise
        return path

    def _write_recovery_snapshot(self, source_format: int, operation: str) -> str:
        name = "%s-%s-v%s" % (time.strftime("%Y%m%d%H%M%S"), uuid.uuid4().hex[:8], source_format)
        directory = os.path.join(self.recovery_dir, name)
        _ensure_private_directory(directory)
        snapshot_path = os.path.join(directory, "secrets.enc.json")
        _atomic_copy_private(self.store_path, snapshot_path)
        metadata = {
            "created_at": int(time.time()),
            "format_version": source_format,
            "operation": operation,
            "source_store": "vault/secrets.enc.json",
        }
        _atomic_write_json(os.path.join(directory, "snapshot.json"), metadata)
        return snapshot_path

    def _restore_recovery_snapshot(self, snapshot_path: str) -> None:
        _atomic_copy_private(snapshot_path, self.store_path)

    def _write_manifest(
        self,
        target_format: int,
        operation: str,
        source_format: int,
        records: int,
        recovery_path: str,
    ) -> None:
        manifest = {
            "cipher": VAULT_CIPHERS[target_format],
            "format_version": target_format,
            "key_provider": "local_file",
            "last_operation": operation,
            "migrated_from": source_format,
            "records": records,
            "recovery_snapshot": os.path.relpath(recovery_path, self.vault_dir),
            "updated_at": int(time.time()),
        }
        _atomic_write_json(self.manifest_path, manifest)

    def _result(
        self,
        operation: str,
        source_format: int,
        target_format: int,
        dry_run: bool,
        records: int,
        status: str,
        recovery_path: str,
    ) -> Dict:
        return {
            "dry_run": bool(dry_run),
            "operation": operation,
            "records": records,
            "recovery_snapshot": recovery_path,
            "source_format": source_format,
            "status": status,
            "target_format": target_format,
        }


def _atomic_write_json(path: str, data: Dict) -> None:
    directory = os.path.dirname(path) or "."
    _ensure_private_directory(directory)
    fd, temp_path = tempfile.mkstemp(prefix=".vault-json-", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        os.chmod(path, 0o600)
        _fsync_directory(directory)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _atomic_copy_private(source: str, target: str) -> None:
    directory = os.path.dirname(target) or "."
    _ensure_private_directory(directory)
    fd, temp_path = tempfile.mkstemp(prefix=".vault-copy-", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with open(source, "rb") as source_handle:
            with os.fdopen(fd, "wb") as target_handle:
                shutil.copyfileobj(source_handle, target_handle)
                target_handle.flush()
                os.fsync(target_handle.fileno())
        os.replace(temp_path, target)
        os.chmod(target, 0o600)
        _fsync_directory(directory)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _ensure_private_directory(path: str) -> None:
    if os.path.islink(path):
        raise VaultMigrationError("vault directory must not be a symbolic link: %s" % path)
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def _fsync_directory(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _pid_is_running(pid: int) -> bool:
    if pid == os.getpid():
        return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _migration_lock_status(path: str) -> Dict:
    if not os.path.exists(path):
        return {"exists": False, "pid": 0, "stale": False}
    pid = 0
    created_at = 0
    try:
        with open(path, "r") as handle:
            data = json.load(handle)
        pid = int(data.get("pid", 0))
        created_at = int(data.get("created_at", 0))
    except (OSError, ValueError, TypeError):
        pass
    try:
        age_seconds = max(0, int(time.time() - os.path.getmtime(path)))
    except OSError:
        age_seconds = 0
    stale = bool((pid > 0 and not _pid_is_running(pid)) or (pid <= 0 and age_seconds > 300))
    return {
        "age_seconds": age_seconds,
        "created_at": created_at,
        "exists": True,
        "pid": pid,
        "stale": stale,
    }
