import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time
from typing import Dict, List

from agentsecure.core.dotenv_backups import BACKUP_FORMAT, BACKUP_VERSION, ENCRYPTED_BACKUP_SUFFIX
from agentsecure.core.vault_migration import (
    VAULT_CIPHERS,
    VaultMigrationLock,
    _atomic_write_json,
    _ensure_private_directory,
    _fsync_directory,
)
from agentsecure.crypto.aead_cipher import AeadSecretCipher
from agentsecure.crypto.cipher import LocalSecretCipher
from agentsecure.crypto.wrapped_key_provider import (
    StaticDeviceKeyProvider,
    unwrap_device_key,
    wrap_device_key,
)
from agentsecure.implementations.secret_store_factory import (
    agentsecure_home,
    clear_vault_key_provider_cache,
    detected_vault_format,
)


MINIMUM_PASSPHRASE_LENGTH = 12


class VaultKeyMigrationError(RuntimeError):
    pass


class VaultKeyMigrationService:
    """Moves the vault device key between raw and passphrase-wrapped storage."""

    def __init__(self, home: str = "") -> None:
        self.home = os.path.abspath(home or agentsecure_home())
        self.vault_dir = os.path.join(self.home, "vault")
        self.store_path = os.path.join(self.vault_dir, "secrets.enc.json")
        self.raw_key_path = os.path.join(self.vault_dir, "device.key")
        self.wrapped_key_path = os.path.join(self.vault_dir, "device.key.wrap.json")
        self.manifest_path = os.path.join(self.vault_dir, "manifest.json")
        self.lock_path = os.path.join(self.vault_dir, "migration.lock")
        self.backups_dir = os.path.join(self.home, "backups")

    def status(self) -> Dict:
        raw_state = self._path_state(self.raw_key_path)
        wrapped_state = self._path_state(self.wrapped_key_path)
        if "invalid" in (raw_state, wrapped_state):
            provider = "invalid"
            action = "Replace symbolic links or non-regular key paths with verified regular files."
        elif raw_state == "regular" and wrapped_state == "regular":
            provider = "ambiguous"
            action = "Re-run the intended `vault key protect` or `vault key unprotect` command to recover safely."
        elif wrapped_state == "regular":
            provider = "passphrase_wrapped"
            action = "Run `agentsecure vault key unprotect` before downgrading to AgentSecure 0.1.22."
        elif raw_state == "regular":
            provider = "local_file"
            action = "Run `agentsecure vault key protect` to remove the unwrapped device key."
        elif self._encrypted_material_exists():
            provider = "missing"
            action = "Restore the original device key; creating a replacement cannot decrypt existing data."
        else:
            provider = "uninitialized"
            action = "No vault key exists yet; protect now or let the first secret write create a compatible raw key."
        return {
            "action": action,
            "provider": provider,
            "raw_key_exists": raw_state == "regular",
            "raw_key_invalid": raw_state == "invalid",
            "wrapped_key_exists": wrapped_state == "regular",
            "wrapped_key_invalid": wrapped_state == "invalid",
            "vault_format": detected_vault_format(self.store_path),
        }

    def protect(self, passphrase: str = "", confirmation: str = "", dry_run: bool = False) -> Dict:
        status = self.status()
        if status["provider"] == "passphrase_wrapped":
            return self._result("protect", dry_run, "already_current", self._empty_verification())
        if status["provider"] == "uninitialized":
            if dry_run:
                return self._result("protect", True, "planned", self._empty_verification())
            self._validate_new_passphrase(passphrase, confirmation)
            return self._protect_new_key(passphrase)
        if status["provider"] not in ("local_file", "ambiguous"):
            raise VaultKeyMigrationError("cannot protect vault key while provider state is %s" % status["provider"])
        encoded_key = self._read_raw_key()
        verification = self._verify_everything(encoded_key)
        if dry_run:
            return self._result("protect", True, "planned", verification)
        self._validate_new_passphrase(passphrase, confirmation)

        _ensure_private_directory(self.vault_dir)
        with VaultMigrationLock(self.lock_path):
            current_key = self._read_raw_key()
            if not _keys_equal(encoded_key, current_key):
                raise VaultKeyMigrationError("vault device key changed after the protection plan was created; retry")
            created_wrapped = False
            raw_removed = False
            try:
                if os.path.exists(self.wrapped_key_path):
                    existing = self._read_wrapped_envelope()
                    unwrapped = unwrap_device_key(existing, passphrase)
                    if not _keys_equal(current_key, unwrapped):
                        raise VaultKeyMigrationError("existing wrapped key does not match the active device key")
                else:
                    envelope = wrap_device_key(current_key, passphrase)
                    _atomic_write_json(self.wrapped_key_path, envelope)
                    created_wrapped = True
                verified_key = unwrap_device_key(self._read_wrapped_envelope(), passphrase)
                if not _keys_equal(current_key, verified_key):
                    raise VaultKeyMigrationError("wrapped key round-trip verification failed")
                verification = self._verify_everything(verified_key)
                if not _keys_equal(current_key, self._read_raw_key()):
                    raise VaultKeyMigrationError("raw vault key changed during protection; no key file was removed")
                os.unlink(self.raw_key_path)
                raw_removed = True
                _fsync_directory(self.vault_dir)
                self._write_manifest("passphrase_wrapped", "protect")
            except Exception:
                if raw_removed:
                    _atomic_write_bytes_private(self.raw_key_path, current_key + b"\n")
                if created_wrapped and os.path.exists(self.wrapped_key_path):
                    os.unlink(self.wrapped_key_path)
                    _fsync_directory(self.vault_dir)
                clear_vault_key_provider_cache()
                raise
        clear_vault_key_provider_cache()
        return self._result("protect", False, "completed", verification)

    def unprotect(self, passphrase: str = "", dry_run: bool = False) -> Dict:
        status = self.status()
        if status["provider"] == "uninitialized":
            return self._result("unprotect", dry_run, "not_required", self._empty_verification())
        if status["provider"] == "local_file":
            verification = self._verify_everything(self._read_raw_key())
            return self._result("unprotect", dry_run, "already_current", verification)
        if status["provider"] not in ("passphrase_wrapped", "ambiguous"):
            raise VaultKeyMigrationError("cannot unprotect vault key while provider state is %s" % status["provider"])
        if dry_run:
            return self._result("unprotect", True, "passphrase_required", self._empty_verification())
        if not passphrase:
            raise VaultKeyMigrationError("vault passphrase cannot be empty")
        wrapped_bytes = self._read_bytes(self.wrapped_key_path)
        encoded_key = unwrap_device_key(json.loads(wrapped_bytes.decode("utf-8")), passphrase)
        verification = self._verify_everything(encoded_key)

        _ensure_private_directory(self.vault_dir)
        with VaultMigrationLock(self.lock_path):
            if self._read_bytes(self.wrapped_key_path) != wrapped_bytes:
                raise VaultKeyMigrationError("wrapped vault key changed after the rollback plan was created; retry")
            created_raw = False
            wrapped_removed = False
            try:
                if os.path.exists(self.raw_key_path):
                    current_key = self._read_raw_key()
                    if not _keys_equal(current_key, encoded_key):
                        raise VaultKeyMigrationError("existing raw key does not match the wrapped device key")
                else:
                    _atomic_write_bytes_private(self.raw_key_path, encoded_key + b"\n")
                    created_raw = True
                verification = self._verify_everything(self._read_raw_key())
                if self._read_bytes(self.wrapped_key_path) != wrapped_bytes:
                    raise VaultKeyMigrationError("wrapped vault key changed during rollback; no key file was removed")
                os.unlink(self.wrapped_key_path)
                wrapped_removed = True
                _fsync_directory(self.vault_dir)
                self._write_manifest("local_file", "unprotect")
            except Exception:
                if wrapped_removed:
                    _atomic_write_bytes_private(self.wrapped_key_path, wrapped_bytes)
                if created_raw and os.path.exists(self.raw_key_path):
                    os.unlink(self.raw_key_path)
                    _fsync_directory(self.vault_dir)
                clear_vault_key_provider_cache()
                raise
        clear_vault_key_provider_cache()
        return self._result("unprotect", False, "completed", verification)

    def _protect_new_key(self, passphrase: str) -> Dict:
        encoded_key = base64.urlsafe_b64encode(secrets.token_bytes(32))
        _ensure_private_directory(self.vault_dir)
        with VaultMigrationLock(self.lock_path):
            if self.status()["provider"] != "uninitialized":
                raise VaultKeyMigrationError("vault key state changed while protection was being prepared; retry")
            created_wrapped = False
            try:
                _atomic_write_json(self.wrapped_key_path, wrap_device_key(encoded_key, passphrase))
                created_wrapped = True
                verified_key = unwrap_device_key(self._read_wrapped_envelope(), passphrase)
                if not _keys_equal(encoded_key, verified_key):
                    raise VaultKeyMigrationError("wrapped key round-trip verification failed")
                self._write_manifest("passphrase_wrapped", "protect")
            except Exception:
                if created_wrapped and os.path.exists(self.wrapped_key_path):
                    os.unlink(self.wrapped_key_path)
                    _fsync_directory(self.vault_dir)
                clear_vault_key_provider_cache()
                raise
        clear_vault_key_provider_cache()
        return self._result("protect", False, "completed", self._empty_verification())

    def _verify_everything(self, encoded_key: bytes) -> Dict:
        encoded_key = _validated_encoded_key(encoded_key)
        provider = StaticDeviceKeyProvider(encoded_key)
        ciphers = {
            1: LocalSecretCipher(provider),
            2: AeadSecretCipher(provider),
        }
        data = self._load_json(self.store_path, required=False)
        format_version = detected_vault_format(self.store_path)
        if data and format_version not in VAULT_CIPHERS:
            raise VaultKeyMigrationError("vault contains an unsupported or mixed record format")
        cipher = ciphers.get(format_version)
        for secret_id, record in sorted(data.items()):
            if not isinstance(record, dict):
                raise VaultKeyMigrationError("vault record %s is invalid" % secret_id)
            if record.get("version") != format_version or record.get("cipher") != VAULT_CIPHERS[format_version]:
                raise VaultKeyMigrationError("vault record %s has inconsistent format metadata" % secret_id)
            try:
                cipher.decrypt(str(record.get("ciphertext", "")))
            except Exception:
                raise VaultKeyMigrationError("vault record %s failed authentication or decryption" % secret_id)

        backup_paths = self._encrypted_backup_paths()
        backup_cipher = LocalSecretCipher(provider)
        for backup_path in backup_paths:
            envelope = self._load_json(backup_path, required=True)
            if envelope.get("format") != BACKUP_FORMAT or envelope.get("version") != BACKUP_VERSION:
                raise VaultKeyMigrationError("encrypted dotenv backup has an unsupported format: %s" % backup_path)
            try:
                payload = json.loads(backup_cipher.decrypt(str(envelope.get("ciphertext", ""))))
            except Exception:
                raise VaultKeyMigrationError("encrypted dotenv backup failed authentication: %s" % backup_path)
            if not isinstance(payload, dict) or not isinstance(payload.get("dotenv_content"), str):
                raise VaultKeyMigrationError("encrypted dotenv backup payload is invalid: %s" % backup_path)
        return {
            "encrypted_backups_verified": len(backup_paths),
            "vault_records_verified": len(data),
        }

    def _encrypted_backup_paths(self) -> List[str]:
        if not os.path.exists(self.backups_dir):
            return []
        if os.path.islink(self.backups_dir) or not os.path.isdir(self.backups_dir):
            raise VaultKeyMigrationError("backup root must be a regular directory")
        paths = []
        for root, directories, filenames in os.walk(self.backups_dir, followlinks=False):
            invalid_directories = [name for name in directories if os.path.islink(os.path.join(root, name))]
            if invalid_directories:
                raise VaultKeyMigrationError("backup directory tree must not contain symbolic links")
            for filename in filenames:
                if not filename.endswith(ENCRYPTED_BACKUP_SUFFIX):
                    continue
                path = os.path.join(root, filename)
                if os.path.islink(path) or not os.path.isfile(path):
                    raise VaultKeyMigrationError("encrypted backup must be a regular file: %s" % path)
                paths.append(path)
        return sorted(paths)

    def _read_raw_key(self) -> bytes:
        if self._path_state(self.raw_key_path) != "regular":
            raise VaultKeyMigrationError("raw vault device key is missing or is not a regular file")
        return _validated_encoded_key(self._read_bytes(self.raw_key_path))

    def _read_wrapped_envelope(self) -> Dict:
        return self._load_json(self.wrapped_key_path, required=True)

    def _read_bytes(self, path: str) -> bytes:
        if os.path.islink(path) or not os.path.isfile(path):
            raise VaultKeyMigrationError("vault key path must be a regular file: %s" % path)
        try:
            with open(path, "rb") as handle:
                return handle.read()
        except OSError as exc:
            raise VaultKeyMigrationError("failed to read vault key file: %s" % exc)

    def _load_json(self, path: str, required: bool) -> Dict:
        if not os.path.exists(path):
            if required:
                raise VaultKeyMigrationError("required file is missing: %s" % path)
            return {}
        if os.path.islink(path) or not os.path.isfile(path):
            raise VaultKeyMigrationError("path must be a regular file: %s" % path)
        try:
            with open(path, "r") as handle:
                data = json.load(handle)
        except (OSError, ValueError, UnicodeError) as exc:
            raise VaultKeyMigrationError("failed to read JSON file %s: %s" % (path, exc))
        if not isinstance(data, dict):
            raise VaultKeyMigrationError("JSON file must contain an object: %s" % path)
        return data

    def _write_manifest(self, key_provider: str, operation: str) -> None:
        manifest = self._load_json(self.manifest_path, required=False)
        format_version = detected_vault_format(self.store_path)
        data = self._load_json(self.store_path, required=False)
        manifest.update(
            {
                "cipher": VAULT_CIPHERS.get(format_version, "unknown"),
                "format_version": format_version,
                "key_provider": key_provider,
                "last_key_operation": operation,
                "records": len(data),
                "updated_at": int(time.time()),
            }
        )
        _atomic_write_json(self.manifest_path, manifest)

    def _validate_new_passphrase(self, passphrase: str, confirmation: str) -> None:
        if passphrase != confirmation:
            raise VaultKeyMigrationError("vault passphrase confirmation does not match")
        if len(passphrase) < MINIMUM_PASSPHRASE_LENGTH:
            raise VaultKeyMigrationError(
                "vault passphrase must contain at least %s characters" % MINIMUM_PASSPHRASE_LENGTH
            )

    def _path_state(self, path: str) -> str:
        if not os.path.lexists(path):
            return "missing"
        if os.path.islink(path) or not os.path.isfile(path):
            return "invalid"
        return "regular"

    def _encrypted_material_exists(self) -> bool:
        if os.path.lexists(self.store_path):
            return True
        recovery_dir = os.path.join(self.vault_dir, "recovery")
        for root in (self.backups_dir, recovery_dir):
            if not os.path.lexists(root):
                continue
            if os.path.islink(root) or not os.path.isdir(root):
                return True
            for current_root, directories, filenames in os.walk(root, followlinks=False):
                if any(os.path.islink(os.path.join(current_root, name)) for name in directories):
                    return True
                if root == self.backups_dir and any(name.endswith(ENCRYPTED_BACKUP_SUFFIX) for name in filenames):
                    return True
                if root == recovery_dir and "secrets.enc.json" in filenames:
                    return True
        return False

    def _result(self, operation: str, dry_run: bool, status: str, verification: Dict) -> Dict:
        return {
            "dry_run": bool(dry_run),
            "operation": operation,
            "provider": self.status()["provider"],
            "status": status,
            "verification": verification,
        }

    @staticmethod
    def _empty_verification() -> Dict:
        return {"encrypted_backups_verified": 0, "vault_records_verified": 0}


def _validated_encoded_key(encoded_key: bytes) -> bytes:
    encoded_key = bytes(encoded_key).strip()
    try:
        raw_key = base64.b64decode(encoded_key, altchars=b"-_", validate=True)
    except Exception:
        raise VaultKeyMigrationError("vault device key is not valid base64")
    if len(raw_key) != 32:
        raise VaultKeyMigrationError("vault device key must decode to 32 bytes")
    return encoded_key


def _keys_equal(left: bytes, right: bytes) -> bool:
    left_hash = hashlib.sha256(bytes(left).strip()).digest()
    right_hash = hashlib.sha256(bytes(right).strip()).digest()
    return hmac.compare_digest(left_hash, right_hash)


def _atomic_write_bytes_private(path: str, data: bytes) -> None:
    directory = os.path.dirname(path) or "."
    _ensure_private_directory(directory)
    fd, temp_path = tempfile.mkstemp(prefix=".vault-key-", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        os.chmod(path, 0o600)
        _fsync_directory(directory)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
