import detectors.suspicious_ports as suspicious_ports


def test_suspicious_port_generates_alert(monkeypatch):
    alerts = []

    def fake_log_alert(message, alert_key, **kwargs):
        alerts.append({
            "message": message,
            "alert_key": alert_key,
            **kwargs,
        })

    monkeypatch.setattr(
        suspicious_ports,
        "log_alert",
        fake_log_alert
    )

    suspicious_ports.detect_suspicious_port(
        "192.168.1.10",
        "192.168.1.20",
        23
    )

    assert len(alerts) == 1
    assert alerts[0]["event_type"] == "SUSPICIOUS_PORT"
    assert alerts[0]["severity"] == "MEDIUM"
    assert alerts[0]["details"]["destination_port"] == 23


def test_normal_port_does_not_generate_alert(monkeypatch):
    alerts = []

    def fake_log_alert(message, alert_key, **kwargs):
        alerts.append(message)

    monkeypatch.setattr(
        suspicious_ports,
        "log_alert",
        fake_log_alert
    )

    suspicious_ports.detect_suspicious_port(
        "192.168.1.10",
        "192.168.1.20",
        80
    )

    assert len(alerts) == 0
