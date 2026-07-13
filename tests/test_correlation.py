from datetime import datetime, timedelta, timezone

from src.correlation import detect_bruteforce


def make_alert(minutes, src_ip="203.0.113.10", event="SSH authentication failure"):
    timestamp = datetime(2026, 7, 13, 8, 0, tzinfo=timezone.utc) + timedelta(minutes=minutes)
    return {
        "timestamp": timestamp.isoformat(),
        "src_ip": src_ip,
        "agent": "ubuntu-server",
        "event": event,
    }


def test_detects_five_failed_logins_within_ten_minutes():
    alerts = [make_alert(minutes) for minutes in (0, 1, 2, 3, 4)]

    incidents = detect_bruteforce(alerts)

    assert len(incidents) == 1
    assert incidents[0]["risk"] == "HIGH"
    assert incidents[0]["alert_count"] == 5
    assert incidents[0]["src_ip"] == "203.0.113.10"


def test_does_not_correlate_different_source_ips():
    alerts = [make_alert(index, src_ip=f"203.0.113.{index}") for index in range(1, 7)]

    assert detect_bruteforce(alerts) == []


def test_does_not_detect_events_outside_time_window():
    alerts = [make_alert(minutes) for minutes in (0, 3, 6, 9, 12)]

    assert detect_bruteforce(alerts) == []


def test_ignores_non_login_events_and_invalid_timestamps():
    alerts = [make_alert(index, event="Wazuh server started") for index in range(5)]
    alerts.append({"timestamp": "invalid", "src_ip": "203.0.113.10", "event": "authentication failure"})

    assert detect_bruteforce(alerts) == []
