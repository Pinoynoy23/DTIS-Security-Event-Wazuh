# /var/ossec/integrations/security_events/handlers/fim.py
from __future__ import annotations

from security_events.config import FIM_NOISE_PATHS, SUPPRESSED_AGENTS
from security_events.utils.formatter import header, divider, esc
from security_events.utils.dedup import is_duplicate


ACTION_MAP = {
    "added":    ("📄 File Created",   "➕"),
    "modified": ("📝 File Modified",  "✏️"),
    "deleted":  ("🗑️ File Deleted",   "🗑️"),
}


def handle(alert: dict) -> str | None:
    rule    = alert.get("rule", {})
    agent   = alert.get("agent", {}).get("id", "000")
    rule_id = rule.get("id", "?")

    # Agent-level suppression
    if rule_id in SUPPRESSED_AGENTS and agent in SUPPRESSED_AGENTS[rule_id]:
        return None

    syscheck = alert.get("syscheck", {})
    path     = syscheck.get("path", alert.get("data", {}).get("path", "Unknown"))
    action   = syscheck.get("event", "modified").lower()
    user     = syscheck.get("uname_after") or syscheck.get("uname", "Unknown")
    perms    = syscheck.get("perm_after", "")

    # Noise suppression
    if _is_noisy(path):
        return None

    key = f"fim:{agent}:{path}:{action}"
    if is_duplicate(key, "fim"):
        return None

    label, icon = ACTION_MAP.get(action, ("📁 FIM Event", "📁"))

    lines = [
        f"{header('FILE INTEGRITY EVENT', icon, alert)}",
        f"📝 INCIDENT ANALYSIS",
        f"{label}",
        f"📂 Path: <code>{esc(path)}</code>",
        f"👤 User: <code>{esc(user)}</code>",
        f"🔧 Action: <b>{esc(action.upper())}</b>",
    ]
    if perms:
        lines.append(f"🔒 Permissions: <code>{esc(perms)}</code>")
    lines += [
        divider(),
        "🛡️ RECOMMENDED REMEDIATION",
        "Verify this change is authorized. If unexpected, investigate immediately.",
    ]
    return "\n".join(lines)


def _is_noisy(path: str) -> bool:
    for noise in FIM_NOISE_PATHS:
        if noise.endswith("*"):
            if path.startswith(noise[:-1]):
                return True
        elif path.startswith(noise):
            return True
    return False