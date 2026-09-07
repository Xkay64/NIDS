import detectors.syn_scan as syn_scan
from config import SYN_ONLY_THRESHOLD


def test_syn_scan_below_threshold(monkeypatch):
    alerts = []
    syn_scan.syn_timestamps.clear()

    def fake_log_alert(message, alert_key, **kwargs):
        alerts.append({
            "message": message,
            "alert_key": alert_key,
            **kwargs,
        })

    monkeypatch.setattr(
        syn_scan,
        "log_alert",
        fake_log_alert
    )

    for _ in range(SYN_ONLY_THRESHOLD):
        syn_scan.detect_syn_scan("192.168.1.10")

    assert len(alerts) == 0


def test_syn_scan_above_threshold(monkeypatch):
    alerts = []
    syn_scan.syn_timestamps.clear()

    def fake_log_alert(message, alert_key, **kwargs):
        alerts.append({
            "message": message,
            "alert_key": alert_key,
            **kwargs,
        })

    monkeypatch.setattr(
        syn_scan,
        "log_alert",
        fake_log_alert
    )

    for _ in range(SYN_ONLY_THRESHOLD + 1):
        syn_scan.detect_syn_scan("192.168.1.10")

    assert len(alerts) == 1
    assert alerts[0]["event_type"] == "SYN_SCAN"
    assert alerts[0]["severity"] == "HIGH"
    assert (
        alerts[0]["details"]["syn_count"]
        == SYN_ONLY_THRESHOLD + 1
    )
