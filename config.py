from pathlib import Path
import sys
import tomllib


CONFIG_FILE = Path(__file__).with_name("nids.toml")


class ConfigurationError(Exception):
    """Raised when the NIDS configuration is invalid."""


def require_positive_int(value, name):
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value <= 0
    ):
        raise ConfigurationError(
            f"{name} must be a positive integer"
        )

    return value


def require_non_negative_int(value, name):
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
    ):
        raise ConfigurationError(
            f"{name} must be a non-negative integer"
        )

    return value


def require_non_empty_string(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(
            f"{name} must be a non-empty string"
        )

    return value


def validate_config(config):
    try:
        logging_config = config["logging"]
        detection_config = config["detection"]

        suspicious_port_config = detection_config[
            "suspicious_ports"
        ]
        syn_config = detection_config["syn_scan"]
        port_scan_config = detection_config["port_scan"]

    except (KeyError, TypeError) as exc:
        raise ConfigurationError(
            f"missing or invalid configuration section/key: {exc}"
        ) from None

    require_non_empty_string(
        logging_config.get("text_log"),
        "logging.text_log"
    )

    require_non_empty_string(
        logging_config.get("json_log"),
        "logging.json_log"
    )

    require_non_negative_int(
        logging_config.get("alert_cooldown_seconds"),
        "logging.alert_cooldown_seconds"
    )

    ports = suspicious_port_config.get("ports")

    if not isinstance(ports, list):
        raise ConfigurationError(
            "detection.suspicious_ports.ports must be a list"
        )

    for port in ports:
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65535
        ):
            raise ConfigurationError(
                "suspicious ports must be integers "
                "between 1 and 65535"
            )

    require_positive_int(
        syn_config.get("threshold"),
        "detection.syn_scan.threshold"
    )

    require_positive_int(
        syn_config.get("time_window_seconds"),
        "detection.syn_scan.time_window_seconds"
    )

    require_positive_int(
        port_scan_config.get("threshold"),
        "detection.port_scan.threshold"
    )

    require_positive_int(
        port_scan_config.get("time_window_seconds"),
        "detection.port_scan.time_window_seconds"
    )

    return config


def load_config(path=CONFIG_FILE):
    path = Path(path)

    if not path.exists():
        raise ConfigurationError(
            f"configuration file not found: {path}"
        )

    try:
        with path.open("rb") as config_file:
            config = tomllib.load(config_file)

    except tomllib.TOMLDecodeError as exc:
        raise ConfigurationError(
            f"invalid TOML in {path}: {exc}"
        ) from None

    return validate_config(config)


try:
    CONFIG = load_config()
except ConfigurationError as exc:
    print(
        f"[!] Configuration error: {exc}",
        file=sys.stderr
    )
    raise SystemExit(2)


ALERT_LOG = CONFIG["logging"]["text_log"]
JSON_ALERT_LOG = CONFIG["logging"]["json_log"]
ALERT_COOLDOWN_SECONDS = CONFIG["logging"][
    "alert_cooldown_seconds"
]

SUSPICIOUS_PORTS = set(
    CONFIG["detection"]["suspicious_ports"]["ports"]
)

SYN_ONLY_THRESHOLD = CONFIG["detection"]["syn_scan"][
    "threshold"
]
SYN_TIME_WINDOW_SECONDS = CONFIG["detection"]["syn_scan"][
    "time_window_seconds"
]

PORT_SCAN_THRESHOLD = CONFIG["detection"]["port_scan"][
    "threshold"
]
PORT_SCAN_TIME_WINDOW_SECONDS = CONFIG["detection"]["port_scan"][
    "time_window_seconds"
]
