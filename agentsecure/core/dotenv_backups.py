import os
import shutil
import time

from agentsecure.core.secret_aliases import project_id_for_path
from agentsecure.implementations.secret_store_factory import agentsecure_home


def backup_dotenv_to_vault(dotenv_path: str, config_path: str) -> str:
    backup_dir = os.path.join(agentsecure_home(), "backups", project_id_for_path(config_path))
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(
        backup_dir,
        "%s.%s.bak" % (os.path.basename(dotenv_path), time.strftime("%Y%m%d%H%M%S")),
    )
    shutil.copy2(dotenv_path, backup_path)
    os.chmod(backup_path, 0o600)
    return backup_path


def latest_dotenv_backup(dotenv_path: str, config_path: str) -> str:
    backup_dir = os.path.join(agentsecure_home(), "backups", project_id_for_path(config_path))
    if not os.path.isdir(backup_dir):
        return ""
    prefix = os.path.basename(dotenv_path) + "."
    candidates = []
    for filename in os.listdir(backup_dir):
        if filename.startswith(prefix) and filename.endswith(".bak"):
            path = os.path.join(backup_dir, filename)
            if os.path.isfile(path):
                candidates.append(path)
    if not candidates:
        return ""
    candidates.sort(key=lambda path: (os.path.getmtime(path), path), reverse=True)
    return candidates[0]


def restore_dotenv_backup(dotenv_path: str, backup_path: str) -> None:
    shutil.copy2(backup_path, dotenv_path)
