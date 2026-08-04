# /var/ossec/integrations/security_events/handlers/generic.py
from __future__ import annotations

from security_events.config import GENERIC_FORWARD_MIN_LEVEL
from security_events.utils.formatter import header, divider, esc
from security_events.utils.dedup import is_duplicate

# Suppressed rules - these will be completely ignored
SUPPRESSED_RULES = {
    "52501",  # ClamAV daemon started
    "52502",  # ClamAV daemon stopped
    "52503",  # Clamd error
    "52504",  # ClamAV virus detected
    "52505",  # ClamAV virus detected (file)
    "52506",  # ClamAV virus detected (infected)
    "52507",  # ClamAV database update
    "52508",  # ClamAV database outdated
}

# Suppressed patterns - any alert containing these will be ignored
SUPPRESSED_PATTERNS = [
    "clamav",
    "ClamAV",
    "clamd",
    "freshclam",
    "Clam AntiVirus",
    "virus database",
]


def _is_suppressed(alert: dict) -> bool:
    """Check if this alert should be suppressed."""
    rule = alert.get("rule", {})
    rule_id = rule.get("id", "")
    full_log = alert.get("full_log", "")
    description = rule.get("description", "")
    
    # Check if rule ID is in suppressed list
    if rule_id in SUPPRESSED_RULES:
        return True
    
    # Check if any suppressed pattern matches
    combined = f"{full_log} {description}".lower()
    for pattern in SUPPRESSED_PATTERNS:
        if pattern.lower() in combined:
            return True
    
    return False


def handle(alert: dict) -> str | None:
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    agent = alert.get("agent", {}).get("id", "000")
    rule_id = rule.get("id", "?")
    desc = rule.get("description", "Security event")
    level = int(rule.get("level", 0))
    full_log = alert.get("full_log", "")

    # Check if this alert should be suppressed (ClamAV, etc.)
    if _is_suppressed(alert):
        return None

    # Only forward if level is high enough to warrant attention.
    if level < GENERIC_FORWARD_MIN_LEVEL:
        return None

    # Include a snippet of full_log in the dedup key
    key = f"generic:{agent}:{rule_id}:{full_log[:120]}"
    if is_duplicate(key, "default"):
        return None

    groups = ", ".join(rule.get("groups", []))
    package = data.get("package", "")
    version = data.get("version", "")
    package_line = f"📦 Package: <code>{esc(package)} ({esc(version)})</code>\n" if package else ""

    msg = (
        f"{header('SECURITY EVENT', '⚠️', alert)}\n"
        f"📝 INCIDENT ANALYSIS\n"
        f"📋 {esc(desc)}\n"
        f"{package_line}"
        f"🏷️ Groups: <code>{esc(groups) if groups else 'N/A'}</code>\n"
        f"{divider()}\n"
        f"🛡️ RECOMMENDED REMEDIATION\n"
        f"Review Wazuh dashboard for full context on rule {esc(rule_id)}."
    )
    return msg