from pathlib import Path
import tomllib


CONFIG_FILE = Path(__file__).with_name("nids.toml")


def load_config():
    if not CONFIG_FILE.exists():
        raise FileNotFoundError(
            f"NIDS configuration file not found: {CONFIG_FILE}"
        )

    with CONFIG_FILE.open("rb") as config_file:
        return tomllib.load(config_file)


CONFIG = load_config()


# Logging configuration
ALERT_LOG = CONFIG["logging"]["text_log"]
JSON_ALERT_LOG = CONFIG["logging"]["json_log"]
ALERT_COOLDOWN_SECONDS = CONFIG["logging"]["alert_cooldown_seconds"]


# Suspicious-port configuration
SUSPICIOUS_PORTS = set(
    CONFIG["detection"]["suspicious_ports"]["ports"]
)


# SYN scan configuration
SYN_ONLY_THRESHOLD = CONFIG["detection"]["syn_scan"]["threshold"]
SYN_TIME_WINDOW_SECONDS = CONFIG["detection"]["syn_scan"][
    "time_window_seconds"
]


# Unique-port scan configuration
PORT_SCAN_THRESHOLD = CONFIG["detection"]["port_scan"]["threshold"]
PORT_SCAN_TIME_WINDOW_SECONDS = CONFIG["detection"]["port_scan"][
    "time_window_seconds"
]
