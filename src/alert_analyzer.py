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


def calculate_threat_score(alert, risk):
    """Berechnet einen nachvollziehbaren Threat Score zwischen 0 und 100."""
    level = max(0, int(alert.get("level", 0) or 0))
    event = alert.get("event", "").lower()
    src_ip = str(alert.get("src_ip", "unknown")).lower()
    mitre = str(alert.get("mitre", "none")).lower()

    score = min(level * 5, 60)
    reasons = [f"Wazuh-Level {level}: {min(level * 5, 60)} Punkte"]

    pattern_scores = (
        ("authentication failure", 15, "Authentifizierungsfehler"),
        ("user login failed", 15, "Fehlgeschlagene Anmeldung"),
        ("sudo to root", 20, "Mögliche Rechteausweitung"),
        ("pam misconfiguration", 10, "PAM-Konfigurationsfehler"),
        ("sql injection", 25, "SQL-Injection-Muster"),
        ("ssh", 5, "SSH-Bezug"),
    )

    for pattern, points, label in pattern_scores:
        if pattern in event:
            score += points
            reasons.append(f"{label}: +{points} Punkte")

    if src_ip not in ("", "unknown", "none"):
        score += 5
        reasons.append("Quell-IP vorhanden: +5 Punkte")

    if mitre not in ("", "none", "unknown"):
        score += 10
        reasons.append("MITRE-ATT&CK-Zuordnung: +10 Punkte")

    minimum_by_risk = {"LOW": 0, "MEDIUM": 40, "HIGH": 75}
    minimum_score = minimum_by_risk.get(risk, 0)

    if score < minimum_score:
        reasons.append(
            f"Mindestwert für {risk}: auf {minimum_score} Punkte angehoben"
        )
        score = minimum_score

    return min(score, 100), reasons


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
    """Ergänzt einen Alert um Risiko, Threat Score und Handlungsempfehlung."""
    risk = classify_risk(alert.get("level", 0))
    custom_risk = escalate_risk_by_pattern(alert)

    if custom_risk and RISK_ORDER[custom_risk] > RISK_ORDER[risk]:
        risk = custom_risk

    threat_score, score_reasons = calculate_threat_score(alert, risk)

    return {
        "rule_id": alert.get("rule_id", "unknown"),
        "timestamp": alert.get("timestamp", "unknown"),
        "level": alert.get("level", 0),
        "risk": risk,
        "threat_score": threat_score,
        "score_reasons": score_reasons,
        "agent": alert.get("agent", "unknown"),
        "event": alert.get("event", "unknown"),
        "src_ip": alert.get("src_ip", "unknown"),
        "user": alert.get("user", "unknown"),
        "mitre": alert.get("mitre", "none"),
        "recommendation": get_recommendation(alert),
    }
