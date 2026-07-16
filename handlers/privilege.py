# /var/ossec/integrations/security_events/handlers/privilege.py
from __future__ import annotations

import re
from security_events.utils.formatter import header, divider, esc
from security_events.utils.dedup import is_duplicate


def handle(alert: dict) -> str | None:
    data     = alert.get("data", {})
    agent    = alert.get("agent", {})
    full_log = alert.get("full_log", "")
    agent_id = agent.get("id", "000")

    user    = _extract_user(data, full_log)
    command = _extract_command(data, full_log)
    tty     = _extract_tty(full_log)
    cwd     = data.get("pwd") or data.get("cwd") or "/"

    # Dedup key includes cwd: same user running the same command from a
    # DIFFERENT working directory is a meaningfully different event (e.g.
    # sudo bash from /home/user vs from /tmp/suspicious_dir), and should
    # not be silently collapsed into a single alert just because the user
    # and command strings match.
    key = f"priv:{agent_id}:{user}:{command}:{cwd}"
    if is_duplicate(key, "default"):
        return None

    msg = (
        f"{header('ELEVATED PRIVILEGES (SUDO/SU)', '👑', alert)}\n"
        f"📝 INCIDENT ANALYSIS\n"
        f"👤 <code>{esc(user)}</code>\n"
        f"💻 Command: <code>{esc(command)}</code>\n"
        f"📂 Directory: <code>{esc(cwd)}</code>\n"
        + (f"🖥️ TTY: <code>{esc(tty)}</code>\n" if tty else "")
        + f"{divider()}\n"
        f"🛡️ RECOMMENDED REMEDIATION\n"
        f"Review /etc/sudoers and verify if this user should have sudo access."
    )
    return msg


def _extract_user(data: dict, full_log: str) -> str:
    # sudo fields
    if data.get("srcuser"):
        return data["srcuser"]
    if data.get("dstuser"):
        return data["dstuser"]

    # su full_log: "(to root) chomnan on pts/7"
    m = re.search(r'\(to \S+\)\s+(\S+)', full_log)
    if m:
        return m.group(1)

    # fallback: "su: pam_unix(su:session): session opened for user root by chomnan"
    m = re.search(r'by\s+(\w+)', full_log)
    if m:
        return m.group(1)

    return "Unknown"


def _extract_command(data: dict, full_log: str) -> str:
    if data.get("command"):
        return data["command"]

    # sudo: COMMAND=/usr/bin/something
    m = re.search(r'COMMAND=(\S+)', full_log)
    if m:
        return m.group(1)

    # su has no command — show "su (switch user)"
    if "su[" in full_log or "su:" in full_log:
        return "su (switch user to root)"

    return "Unknown"


def _extract_tty(full_log: str) -> str:
    # su full_log: "... on pts/7"
    m = re.search(r'on\s+(pts/\d+|\w+)', full_log)
    return m.group(1) if m else ""