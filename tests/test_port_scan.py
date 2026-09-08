import detectors.port_scan as port_scan
from config import PORT_SCAN_THRESHOLD


def test_port_scan_below_threshold(monkeypatch):
    alerts = []
    port_scan.port_scan_activity.clear()

    def fake_log_alert(message, alert_key, **kwargs):
        alerts.append({
            "message": message,
            "alert_key": alert_key,
            **kwargs,
        })

    monkeypatch.setattr(
        port_scan,
        "log_alert",
        fake_log_alert
    )

    for port in range(
        1000,
        1000 + PORT_SCAN_THRESHOLD - 1
    ):
        port_scan.detect_port_scan(
            "192.168.1.10",
            "192.168.1.20",
            port
        )

    assert len(alerts) == 0


def test_port_scan_reaches_threshold(monkeypatch):
    alerts = []
    port_scan.port_scan_activity.clear()

    def fake_log_alert(message, alert_key, **kwargs):
        alerts.append({
            "message": message,
            "alert_key": alert_key,
            **kwargs,
        })

    monkeypatch.setattr(
        port_scan,
        "log_alert",
        fake_log_alert
    )

    for port in range(
        1000,
        1000 + PORT_SCAN_THRESHOLD
    ):
        port_scan.detect_port_scan(
            "192.168.1.10",
            "192.168.1.20",
            port
        )

    assert len(alerts) == 1
    assert alerts[0]["event_type"] == "PORT_SCAN"
    assert alerts[0]["severity"] == "HIGH"
    assert (
        alerts[0]["details"]["unique_ports"]
        == PORT_SCAN_THRESHOLD
    )


def test_repeated_same_port_is_not_port_scan(monkeypatch):
    alerts = []
    port_scan.port_scan_activity.clear()

    def fake_log_alert(message, alert_key, **kwargs):
        alerts.append(message)

    monkeypatch.setattr(
        port_scan,
        "log_alert",
        fake_log_alert
    )

    for _ in range(PORT_SCAN_THRESHOLD + 10):
        port_scan.detect_port_scan(
            "192.168.1.10",
            "192.168.1.20",
            80
        )

    assert len(alerts) == 0
