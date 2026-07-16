# /var/ossec/integrations/security_events/main.py
"""Entry point called by the custom-telegram Wazuh integration script.

Wazuh invokes this with: alert_file, api_key (unused), hook_url (unused)
"""
import importlib
import logging
import sys

from security_events.config import (
    RULE_CATEGORY_MAP,
    VALID_HANDLER_CATEGORIES,
    MIN_LEVEL,
    load_alert,
)
from security_events.utils.telegram import send_message

logging.basicConfig(
    filename="/var/ossec/logs/integrations/telegram.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("main")


def _get_handler(rule_id: str):
    """Return the handler module for this rule_id, or the generic fallback.

    Category is validated against a whitelist before being used in
    import_module, so RULE_CATEGORY_MAP can never become an
    arbitrary-module-import primitive even if it's later extended from
    an external config source.
    """
    category = RULE_CATEGORY_MAP.get(rule_id, "generic")
    if category not in VALID_HANDLER_CATEGORIES:
        logger.error(f"Refusing to import unknown handler category '{category}'")
        category = "generic"

    try:
        return importlib.import_module(f"security_events.handlers.{category}")
    except ModuleNotFoundError:
        logger.warning(f"No handler module for category '{category}', using generic")
        return importlib.import_module("security_events.handlers.generic")


def run(argv: list) -> None:
    if len(argv) < 2:
        logger.error("No alert file path provided")
        sys.exit(1)

    alert_file = argv[1]

    try:
        alert = load_alert(alert_file)
    except (OSError, ValueError) as e:
        logger.error(f"Failed to load alert file {alert_file}: {e}")
        sys.exit(1)
    except Exception:
        logger.exception(f"Unexpected error loading alert file {alert_file}")
        sys.exit(1)

    rule = alert.get("rule", {}) or {}
    rule_id = str(rule.get("id", ""))
    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0

    if level < MIN_LEVEL:
        logger.debug(f"Skipping rule {rule_id} (level {level} < MIN_LEVEL {MIN_LEVEL})")
        return

    logger.info(f"Processing rule {rule_id} (level {level})")

    handler = _get_handler(rule_id)

    try:
        message = handler.handle(alert)
    except Exception:
        logger.exception(f"Handler error for rule {rule_id}")
        return

    if message is None:
        logger.info(f"Rule {rule_id} suppressed (duplicate or noise filter)")
        return

    success = send_message(message, level=level)
    if success:
        logger.info(f"Alert sent for rule {rule_id}")
    else:
        logger.error(f"Failed to deliver alert for rule {rule_id}")


if __name__ == "__main__":
    run(sys.argv)