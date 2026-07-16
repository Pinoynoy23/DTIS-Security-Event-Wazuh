# /var/ossec/integrations/security_events/utils/telegram.py
import json, logging, time, urllib.request, urllib.error

from security_events.config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_THREAD_ID

logger = logging.getLogger(__name__)

MAX_RETRIES = 4
BASE_DELAY = 2
MAX_RETRY_AFTER = 60  # cap how long a single HIGH-priority alert can block the pipeline

# Wazuh invokes custom-telegram as a separate process per alert; there is no
# in-process queue to reorder. A low-severity alert that hits a 429 and
# waits the full backoff can still delay whichever real alert Wazuh happens
# to invoke next, since invocations are effectively serialized by how fast
# wazuh-integratord spawns them. To limit that blast radius, low-severity
# alerts (level < LOW_PRIORITY_LEVEL_THRESHOLD) get a much shorter total
# retry budget and give up fast rather than sit on a 429 for up to 60s.
LOW_PRIORITY_LEVEL_THRESHOLD = 7
LOW_PRIORITY_MAX_RETRY_AFTER = 5
LOW_PRIORITY_MAX_RETRIES = 2


def send_message(text: str, parse_mode: str = "HTML", level: int = 10) -> bool:
    """Send a message to Telegram.

    `level` should be the originating Wazuh rule level (default 10, i.e.
    treated as high-priority, for any caller that doesn't pass one — this
    keeps existing call sites working without a required-arg break while
    still letting handlers opt into low-priority fast-fail behavior).
    """
    if not TELEGRAM_BOT_TOKEN:
        logger.error("[telegram] TELEGRAM_BOT_TOKEN not set")
        return False

    is_low_priority = level < LOW_PRIORITY_LEVEL_THRESHOLD
    max_retries = LOW_PRIORITY_MAX_RETRIES if is_low_priority else MAX_RETRIES
    max_retry_after = LOW_PRIORITY_MAX_RETRY_AFTER if is_low_priority else MAX_RETRY_AFTER

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text[:4096],
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }
    if TELEGRAM_THREAD_ID:
        payload["message_thread_id"] = int(TELEGRAM_THREAD_ID)

    data = json.dumps(payload).encode("utf-8")

    for attempt in range(1, max_retries + 1):
        try:
            req = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            # No custom SSL context: uses urllib's default, which verifies
            # certificates and hostnames against the system trust store.
            # Do not add ssl.CERT_NONE / check_hostname=False here — this
            # is the shared send path for every alert in the pipeline.
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    return True
        except urllib.error.HTTPError as e:
            if e.code == 429:
                retry_after = min(
                    int(e.headers.get("Retry-After", BASE_DELAY * attempt)),
                    max_retry_after,
                )
                logger.warning(
                    f"[telegram] 429 rate limit — waiting {retry_after}s "
                    f"(priority={'low' if is_low_priority else 'high'}, level={level})"
                )
                time.sleep(retry_after)
            else:
                logger.warning(f"[telegram] HTTPError {e.code} on attempt {attempt}")
                time.sleep(BASE_DELAY * attempt)
        except Exception as e:
            logger.warning(f"[telegram] Error on attempt {attempt}: {e}")
            time.sleep(BASE_DELAY * attempt)

    logger.error(
        f"[telegram] All retries exhausted — message not delivered "
        f"(priority={'low' if is_low_priority else 'high'}, level={level})"
    )
    return False