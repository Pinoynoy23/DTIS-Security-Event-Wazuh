# /var/ossec/integrations/security_events/handlers/evasion.py
from __future__ import annotations

import re
import subprocess
from security_events.utils.formatter import header, divider, esc
from security_events.utils.dedup import is_duplicate


def handle(alert: dict) -> str | None:
    data     = alert.get("data",  {})
    agent    = alert.get("agent", {})
    full_log = alert.get("full_log", "")
    agent_id = agent.get("id", "000")

    action, service_desc = _extract_action_and_service(full_log)
    unit_name, unit_path  = _resolve_unit(service_desc)

    user = data.get("srcuser") or data.get("dstuser") or "system"

    key = f"evasion:{agent_id}:{action}:{service_desc}"
    if is_duplicate(key, "default"):
        return None

    if action == "stopped":
        icon, title = "🛑", "SERVICE STOPPED"
    elif action == "started":
        icon, title = "✅", "SERVICE STARTED"
    else:
        icon, title = "❓", "SERVICE EVENT (ACTION UNCLEAR)"

    msg = (
        f"{header(title, icon, alert)}\n"
        f"📝 INCIDENT ANALYSIS\n"
        f"⚠️ Service: <code>{esc(service_desc) if service_desc else 'Unknown'}</code>\n"
        f"🔧 Unit Name: <code>{esc(unit_name)}</code>\n"
        f"📂 Unit Path: <code>{esc(unit_path)}</code>\n"
        f"⚡ Action: <b>{esc(action.upper())}</b>\n"
        f"👤 Triggered by: <code>{esc(user)}</code>\n"
        f"{divider()}\n"
        f"🛡️ RECOMMENDED REMEDIATION\n"
        f"Verify this service change was intentional. Investigate if unauthorized."
    )
    return msg


def _extract_action_and_service(full_log: str) -> tuple[str, str]:
    m = re.search(r'Stopped\s+(.+?)\.?$', full_log)
    if m:
        return "stopped", m.group(1).strip()

    m = re.search(r'Started\s+(.+?)\.?$', full_log)
    if m:
        return "started", m.group(1).strip()

    m = re.search(r'Stopping\s+(.+?)\.{0,3}$', full_log)
    if m:
        return "stopped", m.group(1).strip()

    m = re.search(r'Starting\s+(.+?)\.{0,3}$', full_log)
    if m:
        return "started", m.group(1).strip()

    m = re.search(r'(\S+\.service):', full_log)
    if m:
        # We found a unit name but no clear Stopped/Started/Stopping/
        # Starting verb — don't guess an action, since main.py's rule
        # dispatch is based on Wazuh's own Stopping|Stopped vs Started
        # match, so this is a genuinely ambiguous log line, not a
        # confirmed stop.
        return "unknown", m.group(1)

    return "unknown", ""


def _resolve_unit(service_desc: str) -> tuple[str, str]:
    """Find the systemd unit file name + path matching a Description=."""
    if not service_desc:
        return "Unknown", "Unknown"

    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--all", "--type=service",
             "--no-legend", "--plain"],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 5:
                continue
            unit = parts[0]
            desc = parts[4]
            if desc.strip() == service_desc.strip():
                frag = subprocess.run(
                    ["systemctl", "show", unit, "-p", "FragmentPath", "--value"],
                    capture_output=True, text=True, timeout=2
                )
                path = frag.stdout.strip() or "Unknown"
                return unit, path
    except Exception:
        pass

    return "Unknown", "Unknown"