# /var/ossec/integrations/security_events/handlers/evasion.py
from __future__ import annotations

import re
import subprocess
from security_events.utils.formatter import header, divider, esc
from security_events.utils.dedup import is_duplicate

_SYSTEMCTL_TIMEOUT = 5
_unit_cache = {}

# Services to suppress completely (no alerts)
SUPPRESSED_SERVICES = [
    "clamav",
    "ClamAV",
    "clamav-daemon",
    "Clam AntiVirus",
    "freshclam",
    "snapd",
    "systemd-timesyncd",
    "ModemManager",
    "udisks",
    "accounts-daemon",
    "atd",
    "cron",
    "dbus",
    "irqbalance",
    "multipathd",
    "networkd",
    "polkit",
    "postfix",
    "upower",
    "getty",
]


def _is_suppressed_service(service_desc: str, unit_name: str) -> bool:
    """Check if this service should be suppressed."""
    if not service_desc and not unit_name:
        return False
    
    combined = f"{service_desc} {unit_name}".lower()
    
    for suppressed in SUPPRESSED_SERVICES:
        if suppressed.lower() in combined:
            return True
    return False


def handle(alert: dict) -> str | None:
    data = alert.get("data", {})
    agent = alert.get("agent", {})
    full_log = alert.get("full_log", "")
    agent_id = agent.get("id", "000")
    rule_id = alert.get("rule", {}).get("id", "")

    action, service_desc, unit_name = _extract_action_and_service(full_log)

    # Check if this service should be suppressed FIRST
    if _is_suppressed_service(service_desc, unit_name):
        return None

    # If we got a unit name directly from the log, use it
    if unit_name and unit_name != "Unknown":
        unit_path = _get_unit_path(unit_name)
    else:
        # Try to resolve by description
        unit_name, unit_path = _resolve_unit(service_desc)

    user = data.get("srcuser") or data.get("dstuser") or "system"

    key = f"evasion:{agent_id}:{action}:{service_desc}"
    if is_duplicate(key, "default"):
        return None

    # Determine icon and title based on action
    if action == "stopped":
        icon, title = "🛑", "SERVICE STOPPED"
    elif action == "started":
        icon, title = "✅", "SERVICE STARTED"
    elif action == "restarted":
        icon, title = "🔄", "SERVICE RESTARTED"
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
        f"📋 Rule ID: <code>{rule_id}</code>\n"
        f"{divider()}\n"
        f"🛡️ RECOMMENDED REMEDIATION\n"
        f"Verify this service change was intentional. Investigate if unauthorized."
    )
    return msg


def _extract_action_and_service(full_log: str) -> tuple[str, str, str]:
    """
    Extract action, service description, and unit name from systemd log.
    Returns: (action, service_description, unit_name)
    """
    # Extract action first
    action = "unknown"
    service_desc = ""
    unit_name = ""

    # Check for action keywords
    if "Stopped " in full_log:
        action = "stopped"
    elif "Started " in full_log:
        action = "started"
    elif "Stopping " in full_log:
        action = "stopped"
    elif "Starting " in full_log:
        action = "started"
    elif "Restarting " in full_log:
        action = "restarted"

    # Extract the service description
    patterns = [
        r'(?:Stopped|Started|Stopping|Starting|Restarting)\s+(.+?)(?:\.|$)',
        r'systemd\[\d+\]:\s+(?:Stopped|Started|Stopping|Starting|Restarting)\s+(.+?)(?:\.|$)',
    ]

    for pattern in patterns:
        m = re.search(pattern, full_log)
        if m:
            service_desc = m.group(1).strip()
            break

    # Try to extract unit name from the description or the log
    unit_match = re.search(r'(\S+\.service)', service_desc)
    if unit_match:
        unit_name = unit_match.group(1)
    else:
        unit_match = re.search(r'(\S+\.service)[:\s]', full_log)
        if unit_match:
            unit_name = unit_match.group(1)

    # If we still don't have a description, try to extract anything after the action
    if not service_desc:
        for prefix in ["Stopped ", "Started ", "Stopping ", "Starting ", "Restarting "]:
            if prefix in full_log:
                service_desc = full_log.split(prefix, 1)[1].strip()
                service_desc = re.sub(r'[.,;:]$', '', service_desc)
                break

    # If we have a unit name but no description, use the unit name as description
    if unit_name and not service_desc:
        service_desc = unit_name

    return action, service_desc, unit_name


def _get_unit_path(unit_name: str) -> str:
    """Get the unit file path for a given unit name."""
    if not unit_name or unit_name == "Unknown":
        return "Unknown"

    cached = _unit_cache.get(f"path:{unit_name}")
    if cached is not None:
        return cached

    unit_path = "Unknown"
    try:
        frag = subprocess.run(
            ["systemctl", "show", unit_name, "-p", "FragmentPath", "--value"],
            capture_output=True, text=True, timeout=_SYSTEMCTL_TIMEOUT
        )
        unit_path = frag.stdout.strip() or "Unknown"
        if unit_path != "Unknown":
            _unit_cache[f"path:{unit_name}"] = unit_path
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return unit_path


def _resolve_unit(service_desc: str) -> tuple[str, str]:
    """
    Resolve unit name and path from service description.
    Returns: (unit_name, unit_path)
    """
    if not service_desc:
        return "Unknown", "Unknown"

    # Check if we already have this cached
    cached = _unit_cache.get(f"desc:{service_desc}")
    if cached is not None:
        return cached

    unit_name = "Unknown"
    unit_path = "Unknown"

    try:
        # Get list of all services
        listing = subprocess.run(
            ["systemctl", "list-units", "--all", "--type=service",
             "--no-legend", "--plain"],
            capture_output=True, text=True, timeout=_SYSTEMCTL_TIMEOUT
        )

        # Try to match by description first (most accurate)
        for line in listing.stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 5:
                continue
            unit, desc = parts[0], parts[4]

            # Match if description contains our service description
            # or if our description contains the unit description
            if (service_desc.lower() in desc.lower() or
                desc.lower() in service_desc.lower()):
                unit_name = unit
                unit_path = _get_unit_path(unit)
                break

        # If no match found, try to find by unit name pattern
        if unit_name == "Unknown":
            # Try to extract a unit name from the description
            unit_match = re.search(r'(\S+\.service)', service_desc)
            if unit_match:
                candidate = unit_match.group(1)
                # Verify it exists
                verify = subprocess.run(
                    ["systemctl", "status", candidate],
                    capture_output=True, text=True, timeout=_SYSTEMCTL_TIMEOUT
                )
                if verify.returncode == 0:
                    unit_name = candidate
                    unit_path = _get_unit_path(unit_name)

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    result = (unit_name, unit_path)
    if unit_name != "Unknown":
        _unit_cache[f"desc:{service_desc}"] = result
    return result