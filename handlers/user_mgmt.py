# /var/ossec/integrations/security_events/handlers/user_mgmt.py
from __future__ import annotations

from security_events.utils.formatter import header, divider, esc
from security_events.utils.dedup import is_duplicate


def handle(alert: dict) -> str | None:
    data    = alert.get("data",  {})
    agent   = alert.get("agent", {}).get("id", "000")
    rule    = alert.get("rule",  {})
    rule_id = rule.get("id", "?")
    desc    = rule.get("description", "User management event")

    user   = data.get("dstuser") or data.get("srcuser") or "Unknown"
    action = _guess_action(desc)

    key = f"usermgmt:{agent}:{user}:{rule_id}"
    if is_duplicate(key, "default"):
        return None

    msg = (
        f"{header('USER MANAGEMENT EVENT', '👤', alert)}\n"
        f"📝 INCIDENT ANALYSIS\n"
        f"👤 {esc(desc)}\n"
        f"🔑 Target User: <code>{esc(user)}</code>\n"
        f"⚡ Action: {esc(action)}\n"
        f"{divider()}\n"
        f"🛡️ RECOMMENDED REMEDIATION\n"
        f"Confirm this account change was authorized by an administrator."
    )
    return msg


def _guess_action(desc: str) -> str:
    desc_l = desc.lower()
    if "creat" in desc_l or "add" in desc_l:
        return "Account Created"
    if "delet" in desc_l or "remov" in desc_l:
        return "Account Deleted"
    if "modif" in desc_l or "chang" in desc_l:
        return "Account Modified"
    if "lock" in desc_l or "disabl" in desc_l:
        return "Account Locked/Disabled"
    return "Account Event"