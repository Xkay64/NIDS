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
