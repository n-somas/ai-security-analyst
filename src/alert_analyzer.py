def classify_risk(level):
    """
    Bewertet das Risiko eines Alerts anhand des Wazuh-Levels.
    Zusätzlich werden die originalen Wazuh-Level genutzt.
    """
    
    

    if level >= 12:
        return "HIGH"
    elif level >= 7:
        return "MEDIUM"
    else:
        return "LOW"
    
def escalate_risk_by_pattern(alert):
    """
    Hebt Risiken anhand bestimmter Security-Muster an.
    """

    event = alert["event"].lower()

    if "user login failed" in event:
        return "MEDIUM"

    if "authentication failure" in event:
        return "MEDIUM"

    if "pam misconfiguration" in event:
        return "MEDIUM"

    if "sudo to root" in event:
        return "MEDIUM"

    return None

def get_recommendation(alert):
    """
    Erstellt eine Handlungsempfehlung anhand des Event-Typs.
    """

    event = alert["event"].lower()

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
    """
    Ergänzt einen Alert um Risiko und Handlungsempfehlung.
    """

    risk = classify_risk(alert["level"])

    custom_risk = escalate_risk_by_pattern(alert)

    if custom_risk:
        risk = custom_risk

    recommendation = get_recommendation(alert)

    return {
        "rule_id": alert["rule_id"],
        "level": alert["level"],
        "risk": risk,
        "agent": alert["agent"],
        "event": alert["event"],
        "src_ip": alert["src_ip"],
        "mitre": alert.get("mitre", "none"),
        "recommendation": recommendation
    }