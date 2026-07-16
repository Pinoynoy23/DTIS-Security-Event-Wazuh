# /var/ossec/integrations/security_events/utils/formatter.py
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from html import escape

ICT = timezone(timedelta(hours=7))

LEVEL_MAP = {
    range(0, 4): ("LOW", "🔵"),
    range(4, 7): ("MEDIUM", "🟡"),
    range(7, 13): ("HIGH", "🟠"),
    range(13, 16): ("CRITICAL", "🔴"),
}


def esc(value) -> str:
    """Escape a value for safe interpolation into Telegram HTML messages.

    Every handler must route untrusted alert-derived fields through this
    before placing them inside <code>/<b> tags — alert data (usernames,
    paths, commands, URLs, log text) is attacker-influenceable and
    Telegram's HTML parse_mode will render unescaped '<'/'>'/'&' as markup,
    which can be used to inject fake links into alerts your team trusts.
    """
    if value is None or value == "":
        return "Unknown"
    return escape(str(value), quote=False)


def severity(level: int) -> tuple[str, str]:
    """Returns (label, emoji) for a Wazuh rule level."""
    for r, (label, emoji) in LEVEL_MAP.items():
        if level in r:
            return label, emoji
    # Level is outside the normal 0-15 range (negative, or 16+) — this
    # means the alert's level field is malformed or corrupted, not that
    # it's genuinely critical. Previously this silently returned
    # CRITICAL/🔴, which could mislead an analyst into treating a broken
    # alert as the highest possible severity. Flag it as unknown instead.
    return "UNKNOWN", "⚪"


def timestamp_now() -> str:
    return datetime.now(ICT).strftime("%b %d, %Y %H:%M ICT")


def agent_line(alert: dict) -> str:
    name = alert.get("agent", {}).get("name", "Unknown")
    aid = alert.get("agent", {}).get("id", "???")
    return f"🖥️ {esc(name)} (ID {esc(aid)})"


def rule_line(alert: dict) -> str:
    rule = alert.get("rule", {})
    rule_id = rule.get("id", "?")
    level = int(rule.get("level", 0))
    label, emoji = severity(level)
    lines = [f"⚡ {label} ({level}) ·  {esc(rule_id)}"]
    mitre = _mitre(alert)
    if mitre:
        lines.append(f"🎯 {esc(mitre)}")
    return "\n".join(lines)


def _mitre(alert: dict) -> str:
    """Best-effort MITRE ATT&CK tactic/technique string."""
    mitre = alert.get("rule", {}).get("mitre", {})
    if not mitre:
        return ""
    ids = mitre.get("id", [])
    tactic = mitre.get("tactic", [])
    tech = mitre.get("technique", [])
    parts = []
    if ids:
        parts.append(ids[0])
    if tech:
        parts.append(tech[0])
    elif tactic:
        parts.append(tactic[0])
    return " — ".join(parts)


def divider() -> str:
    return "─────────────────"


def header(title: str, icon: str, alert: dict) -> str:
    level = int(alert.get("rule", {}).get("level", 0))
    _, emoji = severity(level)
    return (
        f"{emoji} <b>{esc(title)}</b>\n"
        f"{agent_line(alert)}\n"
        f"{rule_line(alert)}\n"
        f"📅 {timestamp_now()}\n"
        f"{divider()}"
    )