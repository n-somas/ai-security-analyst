import json
from pathlib import Path


def load_alerts(path="data/alerts_export.json"):
    """Lädt Wazuh-Alerts aus einer JSON-Lines-Datei."""
    alert_path = Path(path)
    if not alert_path.exists():
        return []

    alerts = []
    with alert_path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            rule = item.get("rule", {})
            data = item.get("data", {})
            mitre_ids = rule.get("mitre", {}).get("id", [])
            if isinstance(mitre_ids, str):
                mitre_ids = [mitre_ids]

            alerts.append(
                {
                    "rule_id": rule.get("id", "unknown"),
                    "timestamp": item.get("timestamp", "unknown"),
                    "level": rule.get("level", 0),
                    "agent": item.get("agent", {}).get("name", "unknown"),
                    "event": rule.get("description", "unknown"),
                    "src_ip": data.get("srcip", "unknown"),
                    "user": data.get("srcuser", data.get("dstuser", "unknown")),
                    "mitre": ", ".join(mitre_ids) if mitre_ids else "none",
                    "source_line": line_number,
                }
            )

    return alerts
