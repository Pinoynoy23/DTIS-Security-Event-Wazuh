# /var/ossec/integrations/security_events/handlers/hardware.py
from __future__ import annotations

from security_events.utils.formatter import header, divider, esc
from security_events.utils.dedup import is_duplicate


CONNECT_RULES = {
    100060, 100061, 100063, 100064,
    100080, 100082,
    100084, 100086, 100087,
    100088,
    60227, 60229, 60230,
}

DISCONNECT_RULES = {
    100062, 100081, 100083, 100085, 60228,
}

FALSE_POSITIVE_KEYWORDS = [
    "logger-helper", "upsertElement", "wm_sca",
    "usbmux", "kvm", "usb-tablet",
]


def handle(alert: dict) -> str | None:
    rule    = alert.get("rule", {})
    agent   = alert.get("agent", {})
    syscheck = alert.get("syscheck", {})
    rule_id = int(rule.get("id", 0))
    agent_id   = agent.get("id", "000")
    agent_ip   = agent.get("ip", "Unknown")
    full_log   = alert.get("full_log", "")

    # Suppress macOS rules firing from manager (always false positive)
    if rule_id in (100088, 100089) and agent_id == "000":
        return None

    # Suppress Proxmox/SCA/QEMU false positives
    if rule_id in (100088, 100089):
        if any(kw in full_log for kw in FALSE_POSITIVE_KEYWORDS):
            return None

    # Device fingerprint for dedup: without this, the key had no
    # device-identifying component at all, meaning two DIFFERENT physical
    # devices plugged into the same agent within the same 10s TTL window
    # would be silently collapsed into a single alert — a real
    # false-negative risk (e.g. an attacker swapping USB drives quickly).
    # syscheck.path carries the actual registry device-instance path for
    # Windows rules; fall back to the raw log text for Linux/macOS rules
    # where no such path exists.
    device_fingerprint = syscheck.get("path") or full_log[:120]

    key = f"hw:{agent_id}:{rule_id}:{device_fingerprint}"
    if is_duplicate(key, "default"):
        return None

    if rule_id in CONNECT_RULES:
        title       = "HARDWARE PLUGGED IN"
        icon        = "🔌"
        analysis    = "A new external physical device (USB flash drive, peripheral, or mobile phone) was attached to this system port."
        remediation = "Verify with the workstation user if they plugged in a physical device. If completely unauthorized, remove the hardware immediately."
    elif rule_id in DISCONNECT_RULES:
        title       = "HARDWARE UNPLUGGED"
        icon        = "🔌"
        analysis    = "An external physical device was removed from this system port."
        remediation = "Verify with the workstation user if the device removal was expected."
    else:
        title       = "HARDWARE EVENT"
        icon        = "🔌"
        analysis    = "A hardware event was detected on this endpoint."
        remediation = "Verify this hardware event is authorized."

    msg = (
        f"{header(title, icon, alert)}\n"
        f"📝 INCIDENT ANALYSIS\n"
        f"{analysis}\n"
        f"🌐 Source IP: <code>{esc(agent_ip)}</code>\n"
        f"{divider()}\n"
        f"🛡️ RECOMMENDED REMEDIATION\n"
        f"{remediation}"
    )
    return msg