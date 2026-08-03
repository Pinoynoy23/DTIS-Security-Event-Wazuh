from __future__ import annotations

from security_events.utils.formatter import header, divider, esc
from security_events.utils.dedup import is_duplicate


def handle(alert: dict) -> str | None:
    data   = alert.get("data",  {})
    agent  = alert.get("agent", {}).get("id", "000")
    rule   = alert.get("rule",  {})
    desc   = rule.get("description", "Network anomaly")

    src_ip   = data.get("srcip",   "Unknown")
    dst_ip   = data.get("dstip",   "Unknown")
    src_port = data.get("srcport", "?")
    dst_port = data.get("dstport", "?")
    proto    = data.get("protocol", "?")

    key = f"net:{agent}:{src_ip}:{rule.get('id', '?')}"
    if is_duplicate(key, "network"):
        return None

    msg = (
        f"{header('NETWORK ANOMALY', '🌍', alert)}\n"
        f"📝 INCIDENT ANALYSIS\n"
        f"🔍 {esc(desc)}\n"
        f"📤 Src: <code>{esc(src_ip)}:{esc(src_port)}</code>\n"
        f"📥 Dst: <code>{esc(dst_ip)}:{esc(dst_port)}</code>\n"
        f"🔗 Protocol: <code>{esc(proto)}</code>\n"
        f"{divider()}\n"
        f"🛡️ RECOMMENDED REMEDIATION\n"
        f"Investigate this connection. Block if unauthorized."
    )
    return msg
