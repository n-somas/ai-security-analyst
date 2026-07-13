from collections import defaultdict
from datetime import datetime, timedelta, timezone

FAILED_LOGIN_PATTERNS = (
    "authentication failure",
    "user login failed",
    "failed password",
    "failed login",
)


def _parse_timestamp(value):
    """Parst ISO-8601-Zeitstempel; ungültige Werte werden ignoriert."""
    if not value or value == "unknown":
        return None
    normalized = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_failed_login(alert):
    event = str(alert.get("event", "")).lower()
    return any(pattern in event for pattern in FAILED_LOGIN_PATTERNS)


def detect_bruteforce(alerts, threshold=5, window_minutes=10):
    """Erkennt gehäufte fehlgeschlagene Logins derselben Quell-IP."""
    grouped = defaultdict(list)
    for alert in alerts:
        timestamp = _parse_timestamp(alert.get("timestamp"))
        src_ip = alert.get("src_ip", "unknown")
        if timestamp and src_ip != "unknown" and is_failed_login(alert):
            grouped[src_ip].append((timestamp, alert))

    incidents = []
    window = timedelta(minutes=window_minutes)

    for src_ip, entries in grouped.items():
        entries.sort(key=lambda item: item[0])
        left = 0
        for right, (current_time, _) in enumerate(entries):
            while current_time - entries[left][0] > window:
                left += 1

            matched = entries[left : right + 1]
            if len(matched) >= threshold:
                related_alerts = [item[1] for item in matched]
                incidents.append(
                    {
                        "incident_type": "Brute-Force-Verdacht",
                        "risk": "HIGH",
                        "src_ip": src_ip,
                        "agent": related_alerts[-1].get("agent", "unknown"),
                        "first_seen": matched[0][0].isoformat(),
                        "last_seen": matched[-1][0].isoformat(),
                        "alert_count": len(matched),
                        "description": (
                            f"{len(matched)} fehlgeschlagene Anmeldungen von {src_ip} "
                            f"innerhalb von {window_minutes} Minuten erkannt."
                        ),
                        "recommendation": (
                            "Quell-IP prüfen, betroffenes Benutzerkonto kontrollieren und "
                            "weitere Anmeldeereignisse auf einen erfolgreichen Zugriff untersuchen."
                        ),
                    }
                )
                break

    return incidents
