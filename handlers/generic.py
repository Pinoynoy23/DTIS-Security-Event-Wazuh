# /var/ossec/integrations/security_events/handlers/generic.py
from __future__ import annotations

from security_events.config import GENERIC_FORWARD_MIN_LEVEL
from security_events.utils.formatter import header, divider, esc
from security_events.utils.dedup import is_duplicate


def handle(alert: dict) -> str | None:
    rule    = alert.get("rule",  {})
    agent   = alert.get("agent", {}).get("id", "000")
    rule_id = rule.get("id", "?")
    desc    = rule.get("description", "Security event")
    level   = int(rule.get("level", 0))
    full_log = alert.get("full_log", "")

    # Only forward if level is high enough to warrant attention.
    # Threshold lives in config.py (GENERIC_FORWARD_MIN_LEVEL) rather than
    # hardcoded here, so it's visible alongside MIN_LEVEL and overridable
    # via env without a code change.
    if level < GENERIC_FORWARD_MIN_LEVEL:
        return None

    # Include a snippet of full_log in the dedup key: without any
    # event-specific content, the key had no way to distinguish two
    # genuinely different events that happen to share a rule ID on the
    # same agent (e.g. rule 592 "Log file size reduced" firing for two
    # different files back-to-back). This is the catch-all fallback
    # handler for anything not explicitly mapped elsewhere, so its dedup
    # precision matters more than any other handler's.
    key = f"generic:{agent}:{rule_id}:{full_log[:120]}"
    if is_duplicate(key, "default"):
        return None

    groups = ", ".join(rule.get("groups", []))

    msg = (
        f"{header('SECURITY EVENT', '⚠️', alert)}\n"
        f"📝 INCIDENT ANALYSIS\n"
        f"📋 {esc(desc)}\n"
        f"🏷️ Groups: <code>{esc(groups) if groups else 'N/A'}</code>\n"
        f"{divider()}\n"
        f"🛡️ RECOMMENDED REMEDIATION\n"
        f"Review Wazuh dashboard for full context on rule {esc(rule_id)}."
    )
    return msg