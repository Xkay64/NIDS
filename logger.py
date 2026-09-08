import json
from datetime import datetime, timedelta

from config import (
    ALERT_LOG,
    JSON_ALERT_LOG,
    ALERT_COOLDOWN_SECONDS,
)


ALERT_COOLDOWN = timedelta(seconds=ALERT_COOLDOWN_SECONDS)

# Tracks the last time each alert was generated
last_alert_time = {}


def log_alert(
    message,
    alert_key,
    severity="MEDIUM",
    event_type="GENERAL",
    details=None
):
    now = datetime.now()

    # Suppress duplicate alerts during the cooldown period
    if alert_key in last_alert_time:
        if now - last_alert_time[alert_key] < ALERT_COOLDOWN:
            return

    last_alert_time[alert_key] = now

    # Human-readable alert
    timestamp = now.strftime("[%Y-%m-%d %H:%M:%S]")
    log_entry = (
        f"{timestamp} [{severity}] [{event_type}] {message}"
    )

    print(log_entry)

    with open(ALERT_LOG, "a") as log_file:
        log_file.write(log_entry + "\n")

    # Machine-readable JSON alert
    json_entry = {
        "timestamp": now.isoformat(timespec="seconds"),
        "severity": severity,
        "event_type": event_type,
        "message": message,
        "alert_key": alert_key,
    }

    if details:
        json_entry.update(details)

    with open(JSON_ALERT_LOG, "a") as json_file:
        json.dump(json_entry, json_file)
        json_file.write("\n")
