RISK_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def classify_risk(level):
    """Bewertet das Risiko eines Alerts anhand des Wazuh-Levels."""
    if level >= 12:
        return "HIGH"
    if level >= 7:
        return "MEDIUM"
    return "LOW"


def escalate_risk_by_pattern(alert):
    """Liefert eine Mindest-Risikostufe für bekannte Security-Muster."""
    event = alert.get("event", "").lower()

    medium_patterns = (
        "user login failed",
        "authentication failure",
        "pam misconfiguration",
        "sudo to root",
    )
    if any(pattern in event for pattern in medium_patterns):
        return "MEDIUM"
    return None


def get_recommendation(alert):
    """Erstellt eine Handlungsempfehlung anhand des Event-Typs."""
    event = alert.get("event", "").lower()

    if "authentication failure" in event or "user login failed" in event:
        return "Mehrere fehlgeschlagene Logins prüfen. Möglicher Brute-Force-Versuch oder fehlerhafte Zugangsdaten."
    if "sudo to root" in event:
        return "Sudo-Nutzung prüfen. Falls unerwartet, Benutzeraktivität und Root-Rechte kontrollieren."
    if "pam misconfiguration" in event:
        return "PAM-Konfiguration prüfen. Fehlerhafte Authentifizierungskonfiguration kann Sicherheitsrisiken verursachen."
    if "login session opened" in event:
        return "Login-Sitzung prüfen und mit Benutzeraktivität abgleichen."
    if "login session closed" in event:
        return "Normale Sitzungsbeendigung. Nur bei ungewöhnlicher Häufung weiter prüfen."
    if "wazuh server started" in event:
        return "Wazuh-Dienststart dokumentieren. Prüfen, ob der Neustart geplant war."
    if "agent status" in event:
        if "active" in event:
            return "Agent arbeitet korrekt und sendet Logs."
        return "Agent prüfen. Verbindung oder Dienststatus kontrollieren."
    if "ssh" in event and "failed" in event:
        return "SSH-Loginversuche prüfen, Quell-IP bewerten und Brute-Force-Schutz kontrollieren."
    if "sql injection" in event:
        return "Webserver-Logs prüfen, betroffene URL identifizieren und Eingabevalidierung kontrollieren."
    if "defender" in event:
        return "Kein akuter Handlungsbedarf. Defender-Status dokumentieren."
    return "Alert manuell prüfen und Kontextinformationen ergänzen."


def analyze_alert(alert):
    """Ergänzt einen Alert um Risiko und Handlungsempfehlung."""
    risk = classify_risk(alert.get("level", 0))
    custom_risk = escalate_risk_by_pattern(alert)

    if custom_risk and RISK_ORDER[custom_risk] > RISK_ORDER[risk]:
        risk = custom_risk

    return {
        "rule_id": alert.get("rule_id", "unknown"),
        "timestamp": alert.get("timestamp", "unknown"),
        "level": alert.get("level", 0),
        "risk": risk,
        "agent": alert.get("agent", "unknown"),
        "event": alert.get("event", "unknown"),
        "src_ip": alert.get("src_ip", "unknown"),
        "user": alert.get("user", "unknown"),
        "mitre": alert.get("mitre", "none"),
        "recommendation": get_recommendation(alert),
    }
