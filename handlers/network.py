from __future__ import annotations

import re
import socket
import time
from collections import defaultdict
from security_events.utils.formatter import header, esc
from security_events.utils.dedup import is_duplicate

# Rate limiting - track alerts per source IP
_rate_limit = defaultdict(list)
_RATE_LIMIT_WINDOW = 300  # 5 minutes
_RATE_LIMIT_MAX = 2       # Max 2 alerts per IP per window

# Global dedup for network alerts (in-memory, faster than file-based)
_network_dedup = {}
_NETWORK_DEDUP_TTL = 3600  # 1 hour

# Common port mappings
PORT_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 123: "NTP",
    135: "MSRPC", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP", 631: "CUPS", 636: "LDAPS", 873: "rsync",
    990: "FTPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 27017: "MongoDB", 9200: "Elasticsearch",
    # Development/Web ports
    3000: "Node.js", 5000: "Flask", 5173: "Vite", 4200: "Angular",
    8000: "Dev/HTTP", 8008: "HTTP-alt", 8081: "HTTP-alt", 8082: "HTTP-alt",
    8088: "HTTP-alt", 8090: "HTTP-alt", 9000: "Jetty", 9001: "Weblogic",
    9090: "Web/Admin", 9443: "HTTPS-alt", 9999: "Web/Admin",
}

# Suppressed IPs (add any internal/known scanners here)
SUPPRESSED_IPS = {
    # "192.168.142.42",  # Uncomment to suppress your Kali IP
}


def _get_service_name(port: str) -> str:
    try:
        port_num = int(port)
        if port_num in PORT_SERVICES:
            return PORT_SERVICES[port_num]
        try:
            return socket.getservbyport(port_num)
        except:
            return "unknown"
    except:
        return "unknown"


def _is_rate_limited(src_ip: str) -> bool:
    """Check if this source IP is rate limited."""
    if src_ip in SUPPRESSED_IPS:
        return True

    if src_ip == "Unknown":
        return False

    now = time.time()
    timestamps = _rate_limit[src_ip]
    valid_until = now - _RATE_LIMIT_WINDOW
    _rate_limit[src_ip] = [t for t in timestamps if t > valid_until]

    if len(_rate_limit[src_ip]) >= _RATE_LIMIT_MAX:
        return True

    _rate_limit[src_ip].append(now)
    return False


def _is_network_dedup(src_ip: str, dst_ip: str, rule_id: str) -> bool:
    """In-memory dedup for network alerts."""
    key = f"{src_ip}:{dst_ip}:{rule_id}"
    now = time.time()

    for k in list(_network_dedup.keys()):
        if _network_dedup[k] < now - _NETWORK_DEDUP_TTL:
            del _network_dedup[k]

    if key in _network_dedup:
        return True

    _network_dedup[key] = now
    return False


def _extract_ip(log: str, field: str) -> str | None:
    if not log:
        return None
    patterns = [
        rf'{field}=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        rf'{field}\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
    ]
    for pattern in patterns:
        m = re.search(pattern, log, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _extract_port(log: str, field: str) -> str | None:
    if not log:
        return None
    patterns = [rf'{field}=([0-9]+)', rf'{field}\s+([0-9]+)']
    for pattern in patterns:
        m = re.search(pattern, log, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _extract_proto(log: str) -> str | None:
    if not log:
        return None
    if " TCP " in log or "TCP" in log:
        return "TCP"
    elif " UDP " in log or "UDP" in log:
        return "UDP"
    elif "ICMP" in log:
        return "ICMP"
    return None


def handle(alert: dict) -> str | None:
    """Main handler for network alerts."""
    data = alert.get("data", {})
    agent_info = alert.get("agent", {})
    agent_id = agent_info.get("id", "000")
    rule = alert.get("rule", {})
    rule_id = rule.get("id", "unknown")
    desc = rule.get("description", "Network anomaly")
    full_log = alert.get("full_log", "")

    # Extract network info
    src_ip = data.get("srcip") or data.get("src_ip") or _extract_ip(full_log, "SRC") or "Unknown"
    dst_ip = data.get("dstip") or data.get("dst_ip") or _extract_ip(full_log, "DST") or "Unknown"
    src_port = data.get("srcport") or data.get("src_port") or _extract_port(full_log, "SPT") or "?"
    dst_port = data.get("dstport") or data.get("dst_port") or _extract_port(full_log, "DPT") or "?"
    proto = data.get("protocol") or data.get("proto") or _extract_proto(full_log) or "?"

    # Check if source IP is suppressed
    if src_ip in SUPPRESSED_IPS:
        return None

    # Rate limit check
    if _is_rate_limited(src_ip):
        return None

    # In-memory dedup
    if _is_network_dedup(src_ip, dst_ip, rule_id):
        return None

    # File-based dedup
    dedup_key = f"net:{agent_id}:{rule_id}:{src_ip}:{dst_ip}"
    if is_duplicate(dedup_key, "network"):
        return None

    # Get service info
    service = _get_service_name(dst_port)

    # Build the message in the requested format
    if service != "unknown":
        service_line = f"└─ Service: `{service}` ({dst_port})"
    else:
        service_line = f"└─ Port: `{dst_port}`"

    # Truncate description if too long
    short_desc = desc[:80] + "..." if len(desc) > 80 else desc

    msg = (
        f"{header('NETWORK ALERT', '🟠', alert)}\n"
        f"🔹 Port Scan — {esc(short_desc)}\n"
        f"├─ SRC: `{esc(src_ip)}:{esc(src_port)}`\n"
        f"├─ DST: `{esc(dst_ip)}:{esc(dst_port)}`\n"
        f"├─ Proto: `{esc(proto)}`\n"
        f"{service_line}\n"
        f"\n📌 **Action:** Block `{esc(src_ip)}` at firewall"
    )

    return msg