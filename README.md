# AI Security Analyst

Ein lokales Cybersecurity-Analyse- und SOC-Showcase-Projekt mit:

- Wazuh SIEM
- Python Security Pipeline
- Streamlit Dashboard
- MITRE ATT&CK-Zuordnung
- lokaler KI-Analyse mit Ollama
- Threat Scoring
- Event Correlation
- Brute-Force-Erkennung
- KI-basierter Alert-Analyse

---

# Features

- Analyse echter Wazuh Security Alerts
- Risikoklassifizierung nach LOW, MEDIUM und HIGH
- Eigene Risiko-Eskalation anhand erkannter Event-Muster
- Erkennung mehrerer fehlgeschlagener Anmeldeversuche innerhalb eines definierten Zeitfensters
- Zusammenfassung korrelierter Alerts als Security Incident
- MITRE ATT&CK-Zuordnung
- KI-gestÃ¼tzte Alert-ErklÃ¤rung
- Streamlit Dashboard
- CSV-Report-Export
- Event Aggregation
- Duplicate Detection
- SOC-artige Ãœbersicht

---

# Dashboard-Ãœbersicht

![Dashboard Overview](dashboard.png)

---

# Alert-Tabelle

![Alerts Table](dashboard_alerts.png)

---

# Alert-Detailansicht

Die Detailansicht zeigt alle relevanten Informationen zu einem ausgewählten Security Alert. Dazu gehören Risikostufe, Wazuh-Level, Rule-ID, Zeitstempel, Agent, Benutzer, Quell-IP, MITRE-ATT&CK-Zuordnung und eine konkrete Handlungsempfehlung.

![Alert Detail View](dashboard_alert_detail_view.png)

---

# Brute-Force Detection und Event-Korrelation

Die Anwendung erkennt mehrere fehlgeschlagene Anmeldeversuche derselben Quell-IP innerhalb eines definierten Zeitfensters. Die zusammengehÃ¶rigen Alerts werden als korrelierter Security Incident mit Risikostufe, betroffenem Agent, Anzahl der Ereignisse, Zeitfenster und Handlungsempfehlung dargestellt.

![Brute-Force Detection](dashboard_bruteforce_detection.png)

---

# KI-Alert-Analyse

![AI Alert Analysis](dashboard_ai_alerts_analysis.png)

---

# Tech Stack

## Backend

- Python 3
- Requests
- Pandas
- Pytest

## Security Stack

- Wazuh SIEM
- MITRE ATT&CK
- Linux Auth Logs

## KI

- Ollama
- Llama 3.2 3B

## Frontend

- Streamlit

---

# Architektur

```text
Wazuh SIEM
    â†“
alerts_export.json
    â†“
Python Alert Pipeline
    â†“
Risikoklassifizierung
    â†“
Event-Korrelation und Brute-Force-Erkennung
    â†“
MITRE ATT&CK-Zuordnung
    â†“
LLM-Analyse mit Ollama
    â†“
Streamlit Dashboard
```

---

# Brute-Force-Erkennung

Ein Brute-Force-Verdacht wird ausgelÃ¶st, wenn mindestens fÃ¼nf fehlgeschlagene Anmeldeversuche derselben Quell-IP innerhalb von zehn Minuten erkannt werden.

Der erzeugte Incident enthÃ¤lt unter anderem:

- Risikostufe
- Incident-Typ
- Quell-IP
- betroffenen Agent
- Anzahl der korrelierten Alerts
- erstes und letztes erkanntes Ereignis
- Handlungsempfehlung

---

# Installation

## Repository klonen

```bash
git clone https://github.com/n-somas/ai-security-analyst.git
cd ai-security-analyst
```

## AbhÃ¤ngigkeiten installieren

```bash
pip install -r requirements.txt
```

## Tests ausfÃ¼hren

```bash
python -m pytest -q
```

## Ollama installieren

```text
https://ollama.com/download
```

## Modell herunterladen

```bash
ollama pull llama3.2:3b
```

## Dashboard starten

```bash
streamlit run src/dashboard.py
```

---

# Beispiel-Alerts

- PAM Authentication Failure
- sudo to ROOT
- PAM Misconfiguration
- Failed Logins
- Wazuh Agent Events

---

# MITRE ATT&CK-Beispiele

| Technik | Beschreibung |
|---|---|
| T1078 | GÃ¼ltige Benutzerkonten |
| T1110.001 | Password Guessing |
| T1548.003 | sudo / Rechteausweitung |

---

# Projektstatus

Aktiver Showcase fÃ¼r:

- SOC Analyst
- Cybersecurity Analyst
- SIEM / Blue Team
- Security Automation
- AI-assisted Security Operations

---

# Geplante Erweiterungen

- Live Alert Streaming
- Threat Intelligence Feeds
- VirusTotal Integration
- GeoIP Mapping
- PDF-Reports
- Docker Deployment
- Echtzeit-Monitoring
- Multi-Agent AI Workflow

