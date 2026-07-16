# /var/ossec/integrations/security_events/handlers/web.py
from __future__ import annotations

from security_events.utils.formatter import header, divider, esc
from security_events.utils.dedup import is_duplicate


def handle(alert: dict) -> str | None:
    data   = alert.get("data",  {})
    agent  = alert.get("agent", {}).get("id", "000")
    rule   = alert.get("rule",  {})
    desc   = rule.get("description", "Web attack detected")

    src_ip = data.get("srcip", "Unknown")
    url    = data.get("url") or data.get("request", {}).get("uri", "Unknown")
    method = data.get("method", "GET")

    key = f"web:{agent}:{src_ip}:{url}"
    if is_duplicate(key, "default"):
        return None

    # NOTE: url/method/src_ip here are attacker-supplied — this is the
    # single highest-risk handler for HTML injection, since it's echoing
    # back the payload that triggered the alert. Always esc() these.
    msg = (
        f"{header('WEB ATTACK DETECTED', '🌐', alert)}\n"
        f"📝 INCIDENT ANALYSIS\n"
        f"⚠️ {esc(desc)}\n"
        f"🌐 Source IP: <code>{esc(src_ip)}</code>\n"
        f"🔗 URL: <code>{esc(url)}</code>\n"
        f"📡 Method: <code>{esc(method)}</code>\n"
        f"{divider()}\n"
        f"🛡️ RECOMMENDED REMEDIATION\n"
        f"Block <code>{esc(src_ip)}</code> at firewall/WAF. Review web server logs."
    )
    return msg