#!/usr/bin/env python3
# /var/ossec/integrations/security_events/agent_monitor.py
"""
Polls global.db every 15s, alerts on Telegram when an agent is
added or removed from the Wazuh manager.

Lives inside the security_events package (as a sibling to main.py, not
inside handlers/) because it's a second, independent entry point rather
than a rule-dispatched handler — it has no handle(alert) function and is
never imported by main.py's _get_handler(). It's invoked directly:

    python3 -m security_events.agent_monitor

or, from outside the package directory:

    python3 /var/ossec/integrations/security_events/agent_monitor.py

Reuses security_events.utils.telegram.send_message() for delivery instead
of a separate HTTP/SSL implementation, so this script gets the same TLS
verification, retry/backoff, and 429 handling as the main alert pipeline
for free — and any future fix to Telegram delivery only has to happen
in one place.
"""

import sqlite3
import json
import time
import os
import logging
import sys
from datetime import datetime, timezone, timedelta
from html import escape

if __package__ in (None, ""):
    # Allows `python3 agent_monitor.py` (direct path invocation) to still
    # resolve the security_events package for the absolute import below.
    # Not needed when run as `python3 -m security_events.agent_monitor`.
    sys.path.insert(0, "/var/ossec/integrations")

from security_events.utils.telegram import send_message  # noqa: E402

GLOBAL_DB = "/var/ossec/queue/db/global.db"
SNAPSHOT_FILE = "/var/ossec/integrations/.agent_monitor_snapshot.json"
SNAPSHOT_TMP = SNAPSHOT_FILE + ".tmp"
POLL_SECONDS = 15
ICT = timezone(timedelta(hours=7))
DIVIDER = "==========================="

logging.basicConfig(
    filename="/var/ossec/logs/integrations/agent_monitor.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("agent_monitor")


def now_ict_str() -> str:
    return datetime.now(ICT).strftime("%b %d, %Y(ICT) | %I:%M:%S %p")


def build_message(header_text: str, agent_id: str, agent_name: str, status_label: str) -> str:
    ts = now_ict_str()
    lines = [
        header_text,
        DIVIDER,
        f"#️⃣ : {escape(str(agent_id))}",
        "",
        f"🖥️ : {escape(str(agent_name))}",
        "",
        f"⚡️ : {escape(status_label)}",
        "",
        f"📅 : {ts}",
        DIVIDER,
    ]
    return "\n".join(lines)


def get_agents() -> dict:
    # Read-only connection: this script should never be able to write to
    # Wazuh's live agent database.
    con = sqlite3.connect(f"file:{GLOBAL_DB}?mode=ro", uri=True, timeout=5)
    try:
        cur = con.cursor()
        cur.execute("SELECT id, name FROM agent WHERE id != '000'")
        return {str(i): n for i, n in cur.fetchall()}
    finally:
        con.close()


def load_snapshot():
    if os.path.exists(SNAPSHOT_FILE):
        try:
            with open(SNAPSHOT_FILE) as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.error(f"Corrupt snapshot file {SNAPSHOT_FILE}, rebuilding baseline")
            return None
    return None


def save_snapshot(agents: dict) -> None:
    # Atomic write: write to temp file, then rename over the original,
    # so a crash mid-write can't leave a truncated/corrupt snapshot.
    with open(SNAPSHOT_TMP, "w") as f:
        json.dump(agents, f)
    os.replace(SNAPSHOT_TMP, SNAPSHOT_FILE)


def main() -> None:
    snapshot = load_snapshot()

    if snapshot is None:
        snapshot = get_agents()
        save_snapshot(snapshot)
        logger.info(f"Baseline saved: {len(snapshot)} agents")

    while True:
        try:
            current = get_agents()

            removed = set(snapshot) - set(current)
            added = set(current) - set(snapshot)
            # IDs present in both snapshots, but whose name changed —
            # this indicates the agent ID was reused by a different
            # machine (or renamed) between polls. Without this check,
            # an agent identity swap within a single 15s window would go
            # completely undetected: the ID exists in both `snapshot`
            # and `current`, so it appears in neither `removed` nor
            # `added`, even though the actual endpoint behind that ID
            # has changed.
            renamed = {
                aid for aid in (set(snapshot) & set(current))
                if snapshot[aid] != current[aid]
            }

            for aid in removed:
                msg = build_message("🔴 AGENT REMOVED", aid, snapshot[aid], "Removed ❌")
                if not send_message(msg):
                    logger.error(f"Failed to send removal alert for agent {aid}")

            for aid in added:
                msg = build_message("✅ AGENT REGISTERED", aid, current[aid], "Added ✅")
                if not send_message(msg):
                    logger.error(f"Failed to send registration alert for agent {aid}")

            for aid in renamed:
                msg = build_message(
                    "⚠️ AGENT IDENTITY CHANGED", aid,
                    f"{snapshot[aid]} -> {current[aid]}",
                    "Renamed/reassigned ⚠️",
                )
                if not send_message(msg):
                    logger.error(f"Failed to send rename alert for agent {aid}")

            if removed or added or renamed:
                snapshot = current
                save_snapshot(snapshot)

        except sqlite3.Error:
            logger.exception("Database error while polling agents")
        except Exception:
            logger.exception("Unexpected error in poll loop")

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()