import config


def test_detection_configuration():
    assert config.SYN_ONLY_THRESHOLD == 100
    assert config.SYN_TIME_WINDOW_SECONDS == 10
    assert config.PORT_SCAN_THRESHOLD == 20
    assert config.PORT_SCAN_TIME_WINDOW_SECONDS == 10


def test_logging_configuration():
    assert config.ALERT_LOG == "alerts.log"
    assert config.JSON_ALERT_LOG == "alerts.jsonl"
    assert config.ALERT_COOLDOWN_SECONDS == 60


def test_suspicious_ports_configuration():
    assert 23 in config.SUSPICIOUS_PORTS
    assert 4444 in config.SUSPICIOUS_PORTS
    assert 31337 in config.SUSPICIOUS_PORTS

import pytest


def test_missing_config_file(tmp_path):
    missing_file = tmp_path / "missing.toml"

    with pytest.raises(
        config.ConfigurationError,
        match="configuration file not found"
    ):
        config.load_config(missing_file)


def test_invalid_syn_threshold(tmp_path):
    config_file = tmp_path / "invalid.toml"

    config_file.write_text(
        """
[logging]
text_log = "alerts.log"
json_log = "alerts.jsonl"
alert_cooldown_seconds = 60

[detection.suspicious_ports]
ports = [23]

[detection.syn_scan]
threshold = 0
time_window_seconds = 10

[detection.port_scan]
threshold = 20
time_window_seconds = 10
"""
    )

    with pytest.raises(
        config.ConfigurationError,
        match="syn_scan.threshold"
    ):
        config.load_config(config_file)


def test_invalid_suspicious_port(tmp_path):
    config_file = tmp_path / "invalid-port.toml"

    config_file.write_text(
        """
[logging]
text_log = "alerts.log"
json_log = "alerts.jsonl"
alert_cooldown_seconds = 60

[detection.suspicious_ports]
ports = [70000]

[detection.syn_scan]
threshold = 100
time_window_seconds = 10

[detection.port_scan]
threshold = 20
time_window_seconds = 10
"""
    )

    with pytest.raises(
        config.ConfigurationError,
        match="between 1 and 65535"
    ):
        config.load_config(config_file)
