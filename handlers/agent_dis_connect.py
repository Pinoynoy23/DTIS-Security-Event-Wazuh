# /var/ossec/integrations/security_events/handlers/agent_dis_connect.py
from __future__ import annotations

from security_events.utils.formatter import header, divider, esc
from security_events.utils.dedup import is_duplicate

# Rules intentionally NOT alerted here — handled separately:
#   100033 (agent reconnected)  — routine, covered by agent_monitor.py's
#                                  own connectivity tracking
#   100500 (agent connected)    — routine connect event, same reasoning;
#                                  also fires on every manager restart
#                                  for agent 000 itself, which is noise
# Both rules ARE still mapped to this handler in RULE_CATEGORY_MAP so
# they go through main.py's normal MIN_LEVEL gate, but this handler
# returns None for them unconditionally — see SUPPRESSED_RULE_IDS below.
SUPPRESSED_RULE_IDS = {"100033", "100500"}

# The manager's own agent ID — excluded from registration alerts since it
# re-registers on every wazuh-manager restart, which is not a real new
# agent joining the fleet.
MANAGER_AGENT_ID = "000"

REGISTER_RULE_IDS = {"100030", "100501"}
DISCONNECT_RULE_IDS = {"100031", "100032"}


def handle(alert: dict) -> str | None:
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    rule_id = str(rule.get("id", "?"))
    agent_id = agent.get("id", "000")
    agent_name = agent.get("name", "Unknown")
    agent_ip = agent.get("ip", "Unknown")

    if rule_id in SUPPRESSED_RULE_IDS:
        return None

    # The manager's own agent re-registers on every restart — not a real
    # new agent joining the monitored fleet, so suppress it here rather
    # than generating a false "new agent" alert every time the service
    # restarts.
    if rule_id in REGISTER_RULE_IDS and agent_id == MANAGER_AGENT_ID:
        return None

    key = f"agentstatus:{agent_id}:{rule_id}"
    if is_duplicate(key, "default"):
        return None

    if rule_id in REGISTER_RULE_IDS:
        icon, title = "🆕", "NEW AGENT REGISTERED"
        analysis = "A new Wazuh agent has registered with the manager for the first time."
        remediation = "Confirm this agent was intentionally deployed. If unexpected, investigate immediately — an unrecognized agent could indicate unauthorized access to the manager's enrollment port."
    elif rule_id in DISCONNECT_RULE_IDS:
        icon, title = "🔴", "AGENT DISCONNECTED"
        analysis = "This agent has stopped reporting to the manager and may be offline, or its Wazuh agent service may have been stopped."
        remediation = "Verify the endpoint is reachable and its Wazuh agent service is running. An unexpected disconnect can indicate the endpoint was taken offline to evade monitoring."
    else:
        # Any other rule id mapped to this handler that isn't explicitly
        # categorized above — should not normally happen given
        # RULE_CATEGORY_MAP, but fail safe rather than silently guessing.
        icon, title = "❓", "AGENT STATUS EVENT"
        analysis = rule.get("description", "An agent status change was detected.")
        remediation = "Review the Wazuh dashboard for full context."

    msg = (
        f"{header(title, icon, alert)}\n"
        f"📝 INCIDENT ANALYSIS\n"
        f"{esc(analysis)}\n"
        f"🖥️ Endpoint: <code>{esc(agent_name)}</code>\n"
        f"🌐 IP: <code>{esc(agent_ip)}</code>\n"
        f"{divider()}\n"
        f"🛡️ RECOMMENDED REMEDIATION\n"
        f"{esc(remediation)}"
    )
    return msg