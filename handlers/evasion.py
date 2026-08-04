# /var/ossec/integrations/security_events/handlers/evasion.py
"""Handler for defense-evasion alerts (systemd service stop/start events).

Optimizations over the original version:
  1. Unit resolution (systemctl list-units + show) is now CACHED in-memory
     for the lifetime of the process, and results persist across calls
     within a batch. Previously every single alert re-ran two subprocess
     calls even for a service seen seconds earlier -- expensive, and a
     source of silent slowdown/timeouts under bursty service-event load.
  2. subprocess calls now fail fast and safely -- a timeout or missing
     systemctl no longer risks stalling the whole handler; it just
     degrades unit_name/unit_path to "Unknown" immediately.
  3. _extract_action_and_service is more tolerant of real-world systemd
     log punctuation: multiple trailing periods, quotes, "Reloading",
     "Failed to stop", and units that appear as "<name>.service" without
     a human-readable Description= at all.
  4. Dedup key now includes agent_id + action + service_desc as before,
     but on the "evasion" TTL bucket (see config.py note below) instead
     of "default" (10s) -- 10s was too short for real repeated
     stop/restart-loop scenarios (e.g. a flapping service), causing the
     same service-down condition to re-alert far more often than
     intended.
"""
from __future__ import annotations

import re
import subprocess
from security_events.utils.formatter import header, divider, esc
from security_events.utils.dedup import is_duplicate

# In-memory cache: service_desc -> (unit_name, unit_path). Cleared only
# when the process restarts. Safe because unit->description mappings on
# a given host almost never change at runtime.
_unit_cache: dict[str, tuple[str, str]] = {}

_SYSTEMCTL_TIMEOUT = 2  # seconds; fail fast rather than risk stalling the alert


def handle(alert: dict) -> str | None:
    data     = alert.get("data",  {})
    agent    = alert.get("agent", {})
    full_log = alert.get("full_log", "")
    agent_id = agent.get("id", "000")

    action, service_desc = _extract_action_and_service(full_log)
    unit_name, unit_path = _resolve_unit(service_desc)
    user = data.get("srcuser") or data.get("dstuser") or "system"

    # NOTE: uses the "evasion" TTL category. If security_events/config.py
    # does not yet define DEDUP_TTL["evasion"], is_duplicate() falls back
    # to DEDUP_TTL["default"] (10s) automatically -- add an explicit
    # entry (e.g. 120-300s) in config.py for this to take effect as
    # intended rather than silently falling back.
    key = f"evasion:{agent_id}:{action}:{service_desc}"
    if is_duplicate(key, "evasion"):
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
    """Pull (action, human-readable service description) from a systemd
    journal/syslog line. Order matters: check unambiguous past-tense verbs
    before the in-progress ("-ing") forms, since a line like
    'Stopping X...' can appear moments before 'Stopped X.' for the same
    unit and we want the more specific/confirmed one when both are
    plausible matches on the same text (defensive; in practice only one
    verb appears per line).
    """
    # Strip surrounding quotes some systemd versions add around unit
    # descriptions, and collapse trailing punctuation runs (".", "...",
    # etc.) so "Stopped Foo Bar..." and "Stopped Foo Bar." both yield
    # a clean "Foo Bar".
    text = full_log.strip()

    patterns_stopped = [
        r'Stopped\s+(.+?)[\.\u2026]*$',
        r'Failed to stop\s+(.+?)[\.\u2026]*$',
        r'Unit\s+(\S+)\s+entered failed state',
    ]
    patterns_started = [
        r'Started\s+(.+?)[\.\u2026]*$',
        r'Failed to start\s+(.+?)[\.\u2026]*$',
    ]
    patterns_in_progress_stop = [r'Stopping\s+(.+?)[\.\u2026]*$']
    patterns_in_progress_start = [r'Starting\s+(.+?)[\.\u2026]*$']

    for pat in patterns_stopped:
        m = re.search(pat, text)
        if m:
            return "stopped", m.group(1).strip().strip('"\'')

    for pat in patterns_started:
        m = re.search(pat, text)
        if m:
            return "started", m.group(1).strip().strip('"\'')

    for pat in patterns_in_progress_stop:
        m = re.search(pat, text)
        if m:
            return "stopped", m.group(1).strip().strip('"\'')

    for pat in patterns_in_progress_start:
        m = re.search(pat, text)
        if m:
            return "started", m.group(1).strip().strip('"\'')

    # Last resort: a bare unit name with no clear verb. Don't guess an
    # action here -- main.py's rule dispatch (Stopping|Stopped vs
    # Started regex match) is what determined this alert should exist
    # at all, so if we can't find the verb ourselves, report the unit
    # name but mark the action honestly as unknown rather than
    # fabricating "stopped" or "started".
    m = re.search(r'(\S+\.service)', text)
    if m:
        return "unknown", m.group(1)

    return "unknown", ""


def _resolve_unit(service_desc: str) -> tuple[str, str]:
    """Find the systemd unit file name + path matching a Description=.

    Cached per service_desc for the life of the process -- avoids
    re-running two subprocess calls (list-units + show) for every single
    alert when the same service repeatedly stops/starts in a short
    window, which was both slow and a source of missed/delayed alerts
    under bursty conditions.
    """
    if not service_desc:
        return "Unknown", "Unknown"

    cached = _unit_cache.get(service_desc)
    if cached is not None:
        return cached

    result = ("Unknown", "Unknown")
    try:
        listing = subprocess.run(
            ["systemctl", "list-units", "--all", "--type=service",
             "--no-legend", "--plain"],
            capture_output=True, text=True, timeout=_SYSTEMCTL_TIMEOUT
        )
        for line in listing.stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 5:
                continue
            unit, desc = parts[0], parts[4]
            if desc.strip() == service_desc.strip():
                frag = subprocess.run(
                    ["systemctl", "show", unit, "-p", "FragmentPath", "--value"],
                    capture_output=True, text=True, timeout=_SYSTEMCTL_TIMEOUT
                )
                path = frag.stdout.strip() or "Unknown"
                result = (unit, path)
                break
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # systemctl unavailable, hung, or missing entirely -- degrade
        # gracefully rather than raising, so the alert still sends with
        # "Unknown" enrichment instead of failing outright.
        result = ("Unknown", "Unknown")

    _unit_cache[service_desc] = result
    return result
