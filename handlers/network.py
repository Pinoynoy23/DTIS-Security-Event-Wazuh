# /var/ossec/integrations/security_events/handlers/network.py
from __future__ import annotations

import re
import socket
from security_events.utils.formatter import header, esc
from security_events.utils.dedup import is_duplicate

# Common port mappings with additional ports
PORT_SERVICES = {
    # Standard ports
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
    
    # Database ports
    5984: "CouchDB", 28015: "RethinkDB", 9300: "Elasticsearch",
    
    # Malware/C2 common ports
    4444: "C2/Backdoor", 5555: "C2/Backdoor", 6666: "C2/Backdoor",
    7777: "C2/Backdoor", 8888: "C2/Backdoor", 31337: "C2/Backdoor",
    4443: "C2/SSL", 8444: "C2/SSL",
}


def _get_service_name(port: str) -> str:
    """Get service name from port number."""
    try:
        port_num = int(port)
        if port_num in PORT_SERVICES:
            return PORT_SERVICES[port_num]
        try:
            return socket.getservbyport(port_num)
        except:
            return "unknown"
    except (ValueError, TypeError):
        return "unknown"


def _extract_ip(log: str, field: str) -> str | None:
    """Extract IP address from log lines."""
    if not log:
        return None
    patterns = [
        rf'{field}=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        rf'{field}\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        rf'{field}:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
    ]
    for pattern in patterns:
        m = re.search(pattern, log, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _extract_port(log: str, field: str) -> str | None:
    """Extract port from log lines."""
    if not log:
        return None
    patterns = [
        rf'{field}=([0-9]+)',
        rf'{field}\s+([0-9]+)',
        rf'{field}:([0-9]+)',
    ]
    for pattern in patterns:
        m = re.search(pattern, log, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _extract_proto(log: str) -> str | None:
    """Extract protocol from log."""
    if not log:
        return None
    # Quick string checks first
    if " TCP " in log or "TCP" in log:
        return "TCP"
    elif " UDP " in log or "UDP" in log:
        return "UDP"
    elif "ICMP" in log:
        return "ICMP"
    # Fallback to regex
    m = re.search(r'PROTO=([A-Z]+)', log, re.IGNORECASE)
    if m:
        return m.group(1).upper()
    return None


def _determine_attack_type(desc: str) -> tuple[str, str]:
    """Determine attack type and emoji."""
    desc_lower = desc.lower()
    
    if "scan" in desc_lower:
        return "🔍", "Port Scan"
    elif "brute" in desc_lower:
        return "🔐", "Brute Force"
    elif "flood" in desc_lower:
        return "🌊", "Traffic Flood"
    elif "dos" in desc_lower or "ddos" in desc_lower:
        return "💥", "DoS/DDoS"
    elif "suspicious" in desc_lower:
        return "⚠️", "Suspicious"
    else:
        return "🌐", "Network Anomaly"


def handle(alert: dict) -> str | None:
    """Main handler for network alerts."""
    data = alert.get("data", {})
    agent_info = alert.get("agent", {})
    agent_id = agent_info.get("id", "000")
    rule = alert.get("rule", {})
    rule_id = rule.get("id", "unknown")
    desc = rule.get("description", "Network anomaly")
    full_log = alert.get("full_log", "")
    
    # Extract network information
    src_ip = data.get("srcip") or data.get("src_ip") or _extract_ip(full_log, "SRC") or "Unknown"
    dst_ip = data.get("dstip") or data.get("dst_ip") or _extract_ip(full_log, "DST") or "Unknown"
    src_port = data.get("srcport") or data.get("src_port") or _extract_port(full_log, "SPT") or "?"
    dst_port = data.get("dstport") or data.get("dst_port") or _extract_port(full_log, "DPT") or "?"
    proto = data.get("protocol") or data.get("proto") or _extract_proto(full_log) or "?"
    
    # Dedup
    dedup_key = f"net:{agent_id}:{rule_id}:{src_ip}:{dst_ip}:{proto}"
    if is_duplicate(dedup_key, "network"):
        return None
    
    # Get service info
    service = _get_service_name(dst_port)
    
    # Determine attack type
    emoji, attack_type = _determine_attack_type(desc)
    
    # Build the message
    msg_parts = [
        f"{header('NETWORK ALERT', emoji, alert)}",
        f"🔹 {attack_type} — {esc(desc[:80])}",
        f"├─ SRC: `{esc(src_ip)}:{esc(src_port)}`",
        f"├─ DST: `{esc(dst_ip)}:{esc(dst_port)}`",
        f"├─ Proto: `{esc(proto)}`",
    ]
    
    # Add service info
    if service != "unknown":
        msg_parts.append(f"└─ Service: `{service}` ({dst_port})")
    else:
        msg_parts.append(f"└─ Port: `{dst_port}`")
    
    # Add recommendation
    if "scan" in desc.lower():
        msg_parts.append(f"\n📌 **Action:** Block `{esc(src_ip)}` at firewall")
    elif "brute" in desc.lower():
        msg_parts.append(f"\n📌 **Action:** Enable rate limiting for `{esc(src_ip)}`")
    elif "flood" in desc.lower() or "dos" in desc.lower():
        msg_parts.append(f"\n📌 **Action:** Enable DDoS protection for `{esc(src_ip)}`")
    else:
        msg_parts.append(f"\n📌 **Action:** Investigate `{esc(src_ip)}` - block if unauthorized")
    
    # Join and return
    return "\n".join(msg_parts)