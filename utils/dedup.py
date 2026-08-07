# /var/ossec/integrations/security_events/utils/dedup.py

import json
import os
import time
import logging
import fcntl

from security_events.config import DEDUP_CACHE_PATH, DEDUP_TTL

logger = logging.getLogger(__name__)

_LOCK_PATH = DEDUP_CACHE_PATH + ".lock"


def _load_cache() -> dict:
    if not os.path.exists(DEDUP_CACHE_PATH):
        return {}  # normal on first run — no cache yet, not an error
    try:
        with open(DEDUP_CACHE_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        # A cache file that exists but can't be read/parsed is a real
        # problem worth surfacing — previously this was silently treated
        # as "no cache," meaning dedup history could vanish (and every
        # previously-suppressed key could re-alert) without any log
        # trace explaining why.
        logger.warning(f"[dedup] Cache file exists but failed to load, treating as empty: {e}")
        return {}


def _save_cache(cache: dict):
    tmp_path = DEDUP_CACHE_PATH + ".tmp"
    try:
        with open(tmp_path, "w") as f:
            json.dump(cache, f)
        # chmod the temp file BEFORE the atomic rename, not after — this
        # file's permissions have already caused real incidents this
        # session (wazuh-user ownership mismatches). Doing chmod first
        # means the final path is never observable with the wrong
        # (default/umask) permissions, even if the process is killed
        # between these two lines.
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, DEDUP_CACHE_PATH)  # atomic on POSIX
    except Exception as e:
        logger.warning(f"[dedup] Failed to save cache: {e}")


def is_duplicate(key: str, category: str = "default") -> bool:
    """
    Returns True if this key was seen within the TTL window for its category.
    Side-effect: records the key (with its category) if not duplicate.

    Cross-process safe via an exclusive file lock, since Wazuh may invoke
    this integration concurrently for multiple alerts.
    """
    ttl = DEDUP_TTL.get(category, DEDUP_TTL["default"])
    now = time.time()

    # Ensure the lock file exists with safe perms before opening.
    if not os.path.exists(_LOCK_PATH):
        try:
            fd = os.open(_LOCK_PATH, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        except FileExistsError:
            pass

    try:
        lock_fd = open(_LOCK_PATH, "w")
    except OSError as e:
        logger.error(f"[dedup] Could not open lock file {_LOCK_PATH}: {e}")
        return False  # fail open — never silently swallow a real alert

    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        cache = _load_cache()

        # Purge entries that have outlived *their own* category's TTL
        # (stored alongside each entry, not guessed from the global max).
        expired = [
            k for k, entry in cache.items()
            if now - entry.get("ts", 0) >
               DEDUP_TTL.get(entry.get("cat", "default"), DEDUP_TTL["default"])
        ]
        for k in expired:
            del cache[k]

        existing = cache.get(key)
        if existing and (now - existing["ts"]) < ttl:
            return True

        cache[key] = {"ts": now, "cat": category}
        _save_cache(cache)
        return False
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()