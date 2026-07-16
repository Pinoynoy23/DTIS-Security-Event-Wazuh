# /var/ossec/integrations/security_events/handlers/auth.py
from __future__ import annotations

import re
from security_events.utils.formatter import header, divider, esc
from security_events.utils.dedup import is_duplicate


def handle(alert: dict) -> str | None:
    data     = alert.get("data", {})
    rule     = alert.get("rule", {})
    agent    = alert.get("agent", {})
    full_log = alert.get("full_log", "")
    rule_id  = rule.get("id", "?")
    desc     = rule.get("description", "Authentication event")

    if not alert.get("full_log") and not alert.get("decoder"):
        return None

    user = (
        data.get("dstuser") or
        data.get("srcuser") or
        _extract_su_user(full_log) or
        "Unknown"
    )

    src_ip = data.get("srcip") or agent.get("ip")
    # Only classify as "Local (TTY)" when there is genuinely no source IP
    # anywhere in the alert. Previously this also matched whenever the log
    # line merely contained the substring "tty" (e.g. "tty=ssh" in a normal
    # remote SSH auth failure), which could mislabel a real remote attack
    # as local if a decoder ever failed to populate data.srcip — hiding the
    # attacker's actual origin from the analyst. "su" in the log text is
    # still a reasonable local-session signal on its own, since su sessions
    # never have a remote source IP by definition.
    is_local = not src_ip or "su" in full_log.lower()
    src_ip = src_ip or ("Local (TTY)" if is_local else "Unknown")

    agent_id   = agent.get("id", "000")
    agent_name = agent.get("name", "Unknown")

    key = f"auth:{agent_id}:{src_ip}:{user}:{rule_id}"
    if is_duplicate(key, "default"):
        return None

    icon  = "🔐" if "success" in desc.lower() else "🚨"
    title = "AUTHENTICATION FAILURE" if "fail" in desc.lower() else "AUTHENTICATION EVENT"

    msg = (
        f"{header(title, icon, alert)}\n"
        f"📝 INCIDENT ANALYSIS\n"
        f"🔑 {esc(desc)}\n"
        f"🖥️ Endpoint: <code>{esc(agent_name)}</code>\n"
        f"👤 User: <code>{esc(user)}</code>\n"
        f"🌐 Source: <code>{esc(src_ip)}</code>\n"
        f"{divider()}\n"
        f"🛡️ RECOMMENDED REMEDIATION\n"
        f"Check /var/log/auth.log. If repeated, verify this isn't a brute-force attempt."
    )
    return msg


def _extract_su_user(full_log: str) -> str:
    # "FAILED SU (to root) rathana on pts/0"
    m = re.search(r'\(to \S+\)\s+(\S+)', full_log)
    if m:
        return m.group(1)
    # "authentication failure; logname=rathana ..."
    m = re.search(r'logname=(\S+)', full_log)
    if m:
        return m.group(1)
    return ""