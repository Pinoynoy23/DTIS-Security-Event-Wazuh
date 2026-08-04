#!/usr/bin/env python3
"""
Polls global.db every 15s, alerts on Telegram when an agent is
added or removed from the Wazuh manager.
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
    sys.path.insert(0, "/var/ossec/integrations")

from security_events.utils.telegram import send_message

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
    """Get agents from global.db with retry on lock."""
    max_retries = 5
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            # Use WAL mode and a longer timeout
            con = sqlite3.connect(
                f"file:{GLOBAL_DB}?mode=ro&cache=shared",
                uri=True,
                timeout=10.0,
                isolation_level=None
            )
            try:
                # Enable WAL mode for better concurrency
                con.execute("PRAGMA journal_mode=WAL")
                con.execute("PRAGMA busy_timeout=10000")
                
                cur = con.cursor()
                cur.execute("SELECT id, name FROM agent WHERE id != '000'")
                result = {str(i): n for i, n in cur.fetchall()}
                if attempt > 0:
                    logger.info(f"Database connection succeeded after {attempt} retries")
                return result
            finally:
                con.close()
        except sqlite3.OperationalError as e:
            if "locked" in str(e) and attempt < max_retries - 1:
                logger.warning(f"Database locked, retrying in {retry_delay}s (attempt {attempt+1}/{max_retries})")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
                continue
            raise
    return {}


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
    try:
        with open(SNAPSHOT_TMP, "w") as f:
            json.dump(agents, f, indent=2)
        os.replace(SNAPSHOT_TMP, SNAPSHOT_FILE)
        os.chmod(SNAPSHOT_FILE, 0o644)
    except Exception as e:
        logger.error(f"Failed to save snapshot: {e}")


def main() -> None:
    logger.info("Agent monitor started")
    
    snapshot = load_snapshot()

    if snapshot is None:
        snapshot = get_agents()
        if snapshot:
            save_snapshot(snapshot)
            logger.info(f"Baseline saved: {len(snapshot)} agents")
        else:
            logger.error("Failed to get initial agent list")
            return

    while True:
        try:
            current = get_agents()
            
            if not current:
                logger.warning("Could not get current agents, skipping poll")
                time.sleep(POLL_SECONDS)
                continue

            removed = set(snapshot) - set(current)
            added = set(current) - set(snapshot)
            renamed = {
                aid for aid in (set(snapshot) & set(current))
                if snapshot[aid] != current[aid]
            }

            for aid in removed:
                msg = build_message("🔴 AGENT REMOVED", aid, snapshot[aid], "Removed ❌")
                if send_message(msg):
                    logger.info(f"Sent removal alert for agent {aid}")
                else:
                    logger.error(f"Failed to send removal alert for agent {aid}")

            for aid in added:
                msg = build_message("✅ AGENT REGISTERED", aid, current[aid], "Added ✅")
                if send_message(msg):
                    logger.info(f"Sent registration alert for agent {aid}")
                else:
                    logger.error(f"Failed to send registration alert for agent {aid}")

            for aid in renamed:
                msg = build_message(
                    "⚠️ AGENT IDENTITY CHANGED", aid,
                    f"{snapshot[aid]} -> {current[aid]}",
                    "Renamed/reassigned ⚠️",
                )
                if send_message(msg):
                    logger.info(f"Sent rename alert for agent {aid}")
                else:
                    logger.error(f"Failed to send rename alert for agent {aid}")

            if removed or added or renamed:
                snapshot = current
                save_snapshot(snapshot)
                logger.info(f"Snapshot updated: {len(snapshot)} agents")

        except sqlite3.OperationalError as e:
            logger.error(f"Database error: {e}")
            time.sleep(5)
        except Exception as e:
            logger.exception(f"Unexpected error: {e}")
            time.sleep(5)

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()