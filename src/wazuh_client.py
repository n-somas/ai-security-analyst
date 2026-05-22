import json


def load_alerts():
    """
    Lädt echte Wazuh-Alerts aus data/alerts_export.json.
    Die Datei enthält JSON Lines: eine JSON-Struktur pro Zeile.
    """

    alerts = []

    with open("data/alerts_export.json", "r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            item = json.loads(line)

            mitre_ids = item.get("rule", {}).get("mitre", {}).get("id", [])

            alert = {
                "rule_id": item.get("rule", {}).get("id", "unknown"),
                "level": item.get("rule", {}).get("level", 0),
                "agent": item.get("agent", {}).get("name", "unknown"),
                "event": item.get("rule", {}).get("description", "unknown"),
                "src_ip": item.get("data", {}).get("srcip", "unknown"),
                "mitre": ", ".join(mitre_ids) if mitre_ids else "none"
            }

            alerts.append(alert)

    return alerts