import json
import os
import secrets
import tempfile
import time
from typing import Dict

from agentsecure.core.secret_aliases import project_id_for_path
from agentsecure.implementations.secret_store_factory import agentsecure_home, local_cipher_for_vault


BACKUP_FORMAT = "agentsecure-dotenv-backup"
BACKUP_VERSION = 1
ENCRYPTED_BACKUP_SUFFIX = ".asbak"
LEGACY_BACKUP_SUFFIX = ".bak"


class DotenvBackupError(OSError):
    pass


def dotenv_backup_directory(config_path: str) -> str:
    return os.path.join(agentsecure_home(), "backups", project_id_for_path(config_path))


def backup_dotenv_to_vault(dotenv_path: str, config_path: str) -> str:
    backup_dir = dotenv_backup_directory(config_path)
    _ensure_private_directory(backup_dir)
    timestamp = time.strftime("%Y%m%d%H%M%S")
    backup_path = os.path.join(
        backup_dir,
        "%s.%s-%s%s"
        % (os.path.basename(dotenv_path), timestamp, secrets.token_hex(4), ENCRYPTED_BACKUP_SUFFIX),
    )
    try:
        with open(dotenv_path, "r") as handle:
            dotenv_content = handle.read()
    except (OSError, UnicodeError) as exc:
        raise DotenvBackupError("failed to read dotenv file: %s" % exc)
    _write_encrypted_backup(
        backup_path,
        dotenv_content,
        os.path.basename(dotenv_path),
        project_id_for_path(config_path),
    )
    return backup_path


def latest_dotenv_backup(dotenv_path: str, config_path: str) -> str:
    backup_dir = dotenv_backup_directory(config_path)
    if not os.path.isdir(backup_dir):
        return ""
    prefix = os.path.basename(dotenv_path) + "."
    candidates = []
    for filename in os.listdir(backup_dir):
        if filename.startswith(prefix) and _is_supported_backup_name(filename):
            path = os.path.join(backup_dir, filename)
            if os.path.isfile(path) and not os.path.islink(path):
                candidates.append(path)
    if not candidates:
        return ""
    candidates.sort(key=lambda path: (os.path.getmtime(path), path), reverse=True)
    return candidates[0]


def restore_dotenv_backup(dotenv_path: str, backup_path: str) -> None:
    if os.path.islink(backup_path) or not os.path.isfile(backup_path):
        raise DotenvBackupError("backup must be a regular file")
    if backup_path.endswith(ENCRYPTED_BACKUP_SUFFIX):
        dotenv_content = _read_encrypted_backup(backup_path)
    elif backup_path.endswith(LEGACY_BACKUP_SUFFIX):
        try:
            with open(backup_path, "r") as handle:
                dotenv_content = handle.read()
        except (OSError, UnicodeError) as exc:
            raise DotenvBackupError("failed to read legacy dotenv backup: %s" % exc)
    else:
        raise DotenvBackupError("unsupported dotenv backup file type")
    _atomic_write_dotenv(dotenv_path, dotenv_content)


def dotenv_backup_status(config_path: str) -> Dict:
    backup_dir = dotenv_backup_directory(config_path)
    encrypted = []
    invalid_encrypted = []
    legacy_plaintext = []
    if os.path.isdir(backup_dir):
        for filename in sorted(os.listdir(backup_dir)):
            path = os.path.join(backup_dir, filename)
            if not os.path.isfile(path) or os.path.islink(path):
                continue
            if filename.endswith(ENCRYPTED_BACKUP_SUFFIX):
                if is_encrypted_dotenv_backup(path):
                    encrypted.append(path)
                else:
                    invalid_encrypted.append(path)
            elif filename.endswith(LEGACY_BACKUP_SUFFIX):
                legacy_plaintext.append(path)
    return {
        "backup_directory": backup_dir,
        "encrypted": encrypted,
        "invalid_encrypted": invalid_encrypted,
        "legacy_plaintext": legacy_plaintext,
        "encrypted_count": len(encrypted),
        "invalid_encrypted_count": len(invalid_encrypted),
        "legacy_plaintext_count": len(legacy_plaintext),
        "ok": not legacy_plaintext and not invalid_encrypted,
    }


def migrate_legacy_dotenv_backups(config_path: str, dry_run: bool = False) -> Dict:
    status = dotenv_backup_status(config_path)
    planned = []
    migrated = []
    removed_plaintext = []
    for legacy_path in status["legacy_plaintext"]:
        encrypted_path = legacy_path[: -len(LEGACY_BACKUP_SUFFIX)] + ENCRYPTED_BACKUP_SUFFIX
        planned.append({"source": legacy_path, "target": encrypted_path})
        if dry_run:
            continue
        try:
            with open(legacy_path, "r") as handle:
                dotenv_content = handle.read()
        except (OSError, UnicodeError) as exc:
            raise DotenvBackupError("failed to read legacy dotenv backup: %s" % exc)
        if os.path.exists(encrypted_path):
            if not is_encrypted_dotenv_backup(encrypted_path):
                raise DotenvBackupError("migration target is not an encrypted AgentSecure backup: %s" % encrypted_path)
            if _read_encrypted_backup(encrypted_path) != dotenv_content:
                raise DotenvBackupError("migration target does not match legacy backup: %s" % encrypted_path)
        else:
            _write_encrypted_backup(
                encrypted_path,
                dotenv_content,
                _source_name_from_legacy_backup(legacy_path),
                project_id_for_path(config_path),
            )
        if _read_encrypted_backup(encrypted_path) != dotenv_content:
            raise DotenvBackupError("encrypted backup verification failed: %s" % encrypted_path)
        os.unlink(legacy_path)
        migrated.append(encrypted_path)
        removed_plaintext.append(legacy_path)
    return {
        "dry_run": bool(dry_run),
        "planned": planned,
        "migrated": migrated,
        "removed_plaintext": removed_plaintext,
        "legacy_plaintext_count": len(status["legacy_plaintext"]),
    }


def is_encrypted_dotenv_backup(backup_path: str) -> bool:
    if not backup_path.endswith(ENCRYPTED_BACKUP_SUFFIX):
        return False
    try:
        with open(backup_path, "r") as handle:
            envelope = json.load(handle)
    except (OSError, ValueError, UnicodeError):
        return False
    return bool(
        isinstance(envelope, dict)
        and envelope.get("format") == BACKUP_FORMAT
        and envelope.get("version") == BACKUP_VERSION
        and isinstance(envelope.get("ciphertext"), str)
    )


def _write_encrypted_backup(
    backup_path: str,
    dotenv_content: str,
    source_name: str,
    project_id: str,
) -> None:
    directory = os.path.dirname(backup_path) or "."
    _ensure_private_directory(directory)
    created_at = int(time.time())
    protected_payload = json.dumps(
        {
            "created_at": created_at,
            "dotenv_content": dotenv_content,
            "project_id": project_id,
            "source_name": source_name,
        },
        sort_keys=True,
    )
    try:
        ciphertext = local_cipher_for_vault().encrypt(protected_payload)
    except Exception as exc:
        raise DotenvBackupError("failed to encrypt dotenv backup: %s" % exc)
    envelope = {
        "cipher": "agentsecure-local-v1",
        "ciphertext": ciphertext,
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
    }
    _atomic_write_json(backup_path, envelope)


def _read_encrypted_backup(backup_path: str) -> str:
    try:
        with open(backup_path, "r") as handle:
            envelope = json.load(handle)
    except (OSError, ValueError, UnicodeError) as exc:
        raise DotenvBackupError("failed to read encrypted dotenv backup: %s" % exc)
    if not isinstance(envelope, dict) or envelope.get("format") != BACKUP_FORMAT:
        raise DotenvBackupError("unsupported dotenv backup format")
    if envelope.get("version") != BACKUP_VERSION:
        raise DotenvBackupError("unsupported dotenv backup version: %s" % envelope.get("version"))
    ciphertext = envelope.get("ciphertext")
    if not isinstance(ciphertext, str) or not ciphertext:
        raise DotenvBackupError("encrypted dotenv backup is missing ciphertext")
    try:
        plaintext = local_cipher_for_vault().decrypt(ciphertext)
        payload = json.loads(plaintext)
    except Exception as exc:
        raise DotenvBackupError("dotenv backup authentication or decryption failed: %s" % exc)
    if not isinstance(payload, dict) or not isinstance(payload.get("dotenv_content"), str):
        raise DotenvBackupError("decrypted dotenv backup payload is invalid")
    return payload["dotenv_content"]


def _atomic_write_json(path: str, data: Dict) -> None:
    directory = os.path.dirname(path) or "."
    fd, temp_path = tempfile.mkstemp(prefix=".dotenv-backup-", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _atomic_write_dotenv(path: str, dotenv_content: str) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".agentsecure-restore-", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(dotenv_content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _ensure_private_directory(path: str) -> None:
    if os.path.islink(path):
        raise DotenvBackupError("backup directory must not be a symbolic link: %s" % path)
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def _is_supported_backup_name(filename: str) -> bool:
    return filename.endswith(ENCRYPTED_BACKUP_SUFFIX) or filename.endswith(LEGACY_BACKUP_SUFFIX)


def _source_name_from_legacy_backup(backup_path: str) -> str:
    filename = os.path.basename(backup_path)
    stem = filename[: -len(LEGACY_BACKUP_SUFFIX)] if filename.endswith(LEGACY_BACKUP_SUFFIX) else filename
    if "." not in stem:
        return stem
    return stem.rsplit(".", 1)[0] or ".env"
