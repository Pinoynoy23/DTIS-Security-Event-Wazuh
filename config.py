# /var/ossec/integrations/security_events/config.py
"""Configuration loader for the Wazuh -> Telegram integration.

Loads secrets from /etc/wazuh-telegram.env (never hardcoded), validates
file permissions, and exposes typed, validated config values.
"""
import json
import logging
import os
import pwd
import stat

logger = logging.getLogger("config")

_ENV_FILE = "/etc/wazuh-telegram.env"

# wazuh-integratord (the process that actually invokes this integration for
# real alerts) runs as the 'wazuh' service account, not root. Manual testing
# as root will always have read access regardless of this check, which is
# why a root-only check can look correct in manual tests but still break
# the live pipeline. Accept ownership by root OR this service account.
_EXPECTED_OWNER = os.environ.get("WAZUH_INTEGRATION_USER", "wazuh")


def _resolve_expected_uids() -> set:
    uids = {0}  # root is always acceptable
    try:
        uids.add(pwd.getpwnam(_EXPECTED_OWNER).pw_uid)
    except KeyError:
        # Service account not found on this system — fall back to root-only.
        logger.warning(f"User '{_EXPECTED_OWNER}' not found; only root-owned env file will be accepted")
    return uids


def _load_env_file(path: str) -> None:
    if not os.path.exists(path):
        return

    st = os.stat(path)
    expected_uids = _resolve_expected_uids()

    # Refuse to trust a secrets file that isn't owned by root or the
    # integration's service account, or that's readable/writable beyond
    # its owner.
    if st.st_uid not in expected_uids or (st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
        raise PermissionError(
            f"{path} must be owned by root or '{_EXPECTED_OWNER}' with mode 0600 "
            f"(found uid={st.st_uid}, mode={oct(st.st_mode)}; "
            f"acceptable uids={sorted(expected_uids)})"
        )

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"'))


try:
    _load_env_file(_ENV_FILE)
except PermissionError as e:
    logger.critical(str(e))
    raise

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
TELEGRAM_THREAD_ID = os.environ.get("TELEGRAM_THREAD_ID", "")

if not TELEGRAM_BOT_TOKEN:
    logger.critical("TELEGRAM_BOT_TOKEN is not set — refusing to start")
    raise RuntimeError("TELEGRAM_BOT_TOKEN missing")

if not TELEGRAM_CHAT_ID:
    logger.critical("TELEGRAM_CHAT_ID is not set — refusing to start")
    raise RuntimeError("TELEGRAM_CHAT_ID missing")

# Dedup cache: root-owned, private directory, not world-writable /tmp
DEDUP_CACHE_PATH = os.environ.get(
    "DEDUP_CACHE_PATH", "/var/ossec/var/run/wazuh_telegram_dedup.json"
)

try:
    MIN_LEVEL = int(os.environ.get("MIN_LEVEL", "3"))
except ValueError:
    logger.warning("Invalid MIN_LEVEL env value, defaulting to 3")
    MIN_LEVEL = 3

MAX_ALERT_FILE_BYTES = 5 * 1024 * 1024  # 5MB guard against runaway/malformed alerts

# generic.py's minimum level for forwarding low-priority/uncategorized rules.
# Kept here (not hardcoded in the handler) so it's visible alongside MIN_LEVEL.
GENERIC_FORWARD_MIN_LEVEL = int(os.environ.get("GENERIC_FORWARD_MIN_LEVEL", "7"))

DEDUP_TTL = {
    "registry": 3600,
    "fim": 60,
    "default": 10,
    "network": 300,
}

SUPPRESSED_AGENTS = {
    "597": ["011"],
}

FIM_NOISE_PATHS = [
    "/proc/", "/sys/", "/run/", "/tmp/",
    "/var/ossec/integrations/__pycache__/",
    "/var/ossec/integrations/security_events/__pycache__/",
    "/var/ossec/integrations/security_events/handlers/__pycache__/",
    "/var/ossec/integrations/.agent-",
    "/var/ossec/integrations/.watcher",
    "/var/ossec/integrations/.wazuh_telegram_dedup.json",
    "/var/ossec/integrations/.wazuh_telegram_dedup.json.lock",
    "/var/ossec/integrations/.test-write",
    "c:\\windows\\prefetch",
    "c:\\windows\\temp",
]

# Explicit whitelist — the only modules import_module is ever allowed to load.
# main.py checks every RULE_CATEGORY_MAP value against this before importing,
# so the map can never become an arbitrary-module-import primitive even if
# it's extended later from an external config file.
VALID_HANDLER_CATEGORIES = {
    "auth", "privilege", "user_mgmt", "fim", "malware",
    "evasion", "network", "web", "hardware", "registry", "generic",
    "agent_dis_connect.py",
}

RULE_CATEGORY_MAP = {
    # ── Built-in Wazuh ───────────────────────────────
    "5710": "auth", "5711": "auth", "5712": "auth",
    "2501": "auth", "2502": "auth",
    "5400": "privilege", "5401": "privilege", "5402": "privilege", "5403": "privilege",
    "5901": "user_mgmt", "5902": "user_mgmt",
    "550": "fim", "553": "fim", "554": "fim",
    "594": "fim", "597": "fim", "598": "fim", "750": "fim",

    # ── Authentication & Brute Force ─────────────────
    "100001": "auth",
    "100002": "auth",
    "100003": "auth",
    "100004": "auth",
    "100300": "auth",

    # ── Privilege Escalation ─────────────────────────
    "100005": "privilege",
    "100050": "privilege",
    "100051": "privilege",
    "100070": "privilege",
    "100071": "privilege",

    # ── User / Account Management ────────────────────
    "100006": "user_mgmt",
    "100007": "user_mgmt",
    "5903": "user_mgmt",

    # ── Persistence ──────────────────────────────────
    "100008": "generic",
    "100015": "generic",

    # ── Malware / Suspicious Execution ───────────────
    "100009": "malware",

    # ── FIM ──────────────────────────────────────────
    "100010": "fim",
    "100040": "fim",
    "100041": "fim",
    "100042": "fim",

    # ── Defense Evasion ──────────────────────────────
    "100011": "evasion",
    "100016": "evasion",
    "100017": "evasion",   # security-tooling stop (local_rules.xml)
    "100018": "evasion",   # security-tooling start (local_rules.xml)

    # ── Network ──────────────────────────────────────
    "100012": "network",

    # ── Web Attacks ──────────────────────────────────
    "100013": "web",

    # ── Ransomware ───────────────────────────────────
    "100014": "malware",

    # ── Correlation ──────────────────────────────────
    "100020": "auth",
    "100021": "user_mgmt",
    "100022": "network",
    "100023": "evasion",
    "100024": "malware",

    # ── USB / Hardware ───────────────────────────────
    "100060": "hardware", "100061": "hardware", "100062": "hardware",
    "100063": "hardware", "100064": "hardware",
    "100080": "hardware", "100081": "hardware", "100082": "hardware",
    "100083": "hardware",
    "100084": "hardware", "100085": "hardware", "100086": "hardware",
    "100087": "hardware", "100088": "hardware", "100089": "hardware",

    # ── Registry ─────────────────────────────────────
    "199008": "registry",
    "199009": "registry",
    "199010": "registry",
    "199011": "registry",
    "199012": "registry",

    # ── Agent Status & Management ────────────────────
    # FIXED 2026-07-06: these six rule IDs previously had no entry here
    # at all, meaning they fell through to "generic", whose
    # GENERIC_FORWARD_MIN_LEVEL=7 threshold silently dropped 100030
    # (level 5), 100031 (level 6), 100033 (level 3), 100500 (level 3),
    # and 100501 (level 3) — only 100032 (level 7) happened to pass.
    # The entire "agent registered/disconnected" alerting story was
    # non-functional. Now routed to a dedicated handler; see
    # handlers/agent_dis_connect.py.py for which of these actually alert vs.
    # are intentionally suppressed (100033, 100500 — routine
    # reconnect/connect, covered separately by agent_monitor.py).
  "100030": "agent_dis_connect",
  "100031": "agent_dis_connect",
  "100032": "agent_dis_connect",
  "100033": "agent_dis_connect",
  "100500": "agent_dis_connect",
  "100501": "agent_dis_connect",
}

# Fail loudly at import time if the map ever drifts from the whitelist,
# instead of discovering an unsafe import_module target at runtime.
_unknown = set(RULE_CATEGORY_MAP.values()) - VALID_HANDLER_CATEGORIES
if _unknown:
    raise RuntimeError(f"RULE_CATEGORY_MAP references unknown categories: {_unknown}")


def load_alert(alert_file_path: str) -> dict:
    """Load and minimally validate a Wazuh alert JSON file."""
    size = os.path.getsize(alert_file_path)
    if size > MAX_ALERT_FILE_BYTES:
        raise ValueError(f"Alert file too large ({size} bytes): {alert_file_path}")

    with open(alert_file_path, "r") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Alert JSON root must be an object")

    return data