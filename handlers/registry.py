# /var/ossec/integrations/security_events/handlers/registry.py
from __future__ import annotations

from security_events.utils.formatter import header, divider, esc
from security_events.utils.dedup import is_duplicate


def handle(alert: dict) -> str | None:
    syscheck = alert.get("syscheck", {})
    data     = alert.get("data",     {})
    agent    = alert.get("agent",    {}).get("id", "000")

    reg_key   = syscheck.get("path") or data.get("registry_key", "Unknown")
    reg_value = syscheck.get("value_name") or data.get("value_name", "")
    action    = syscheck.get("event", "modified").lower()

    # Include action in the key: with a 1-hour TTL for the "registry"
    # category, omitting this meant an add-then-delete (or similar
    # sequence) on the same key within that hour would silently collapse
    # into a single alert for whichever action fired first — losing
    # visibility into a potentially significant persistence
    # establish/remove sequence on the same registry key.
    key = f"registry:{agent}:{reg_key}:{reg_value}:{action}"
    if is_duplicate(key, "registry"):
        return None

    msg = (
        f"{header('WINDOWS REGISTRY CHANGE', '🗝️', alert)}\n"
        f"📝 INCIDENT ANALYSIS\n"
        f"🗝️ Registry Modification Detected\n"
        f"📂 Key: <code>{esc(reg_key)}</code>\n"
        f"📋 Value: <code>{esc(reg_value) if reg_value else '(default)'}</code>\n"
        f"🔧 Action: <b>{esc(action.upper())}</b>\n"
        f"{divider()}\n"
        f"🛡️ RECOMMENDED REMEDIATION\n"
        f"Check if this registry change is from a known application or user activity."
    )
    return msg