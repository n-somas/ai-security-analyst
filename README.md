# AI Security Analyst

Ein lokales Cybersecurity-Analyse- und SOC-Showcase-Projekt mit:

- Wazuh SIEM
- Python Security Pipeline
- Streamlit Dashboard
- MITRE ATT&CK Mapping
- lokaler KI-Analyse mit Ollama
- Threat Scoring
- Event Correlation
- AI-basierter Alert-Analyse

---

# Features

- Analyse echter Wazuh Security Alerts
- Risk Classification (LOW / MEDIUM / HIGH)
- Eigene Risiko-Eskalation
- MITRE ATT&CK Zuordnung
- KI-gestützte Alert-Erklärung
- Streamlit Dashboard
- CSV Report Export
- Event Aggregation
- Duplicate Detection
- SOC-artige Übersicht

---

# Dashboard Overview

![Dashboard Overview](dashboard.png)

---

# Alerts Table

![Alerts Table](dashboard_alerts.png)

---

# AI Alert Analysis

![AI Alert Analysis](dashboard_ai_alerts_analysis.png)

---

# Tech Stack

## Backend

- Python 3
- Requests
- Pandas

## Security Stack

- Wazuh SIEM
- MITRE ATT&CK
- Linux Auth Logs

## AI

- Ollama
- Llama 3.2 3B

## Frontend

- Streamlit

---

# Architecture

```text
Wazuh SIEM
    ↓
alerts.json
    ↓
Python Alert Pipeline
    ↓
Risk Classification
    ↓
MITRE Mapping
    ↓
LLM Analysis (Ollama)
    ↓
Streamlit Dashboard
```

# Installation

## Repository klonen

```bash
git clone https://github.com/USERNAME/ai-security-analyst.git
cd ai-security-analyst
```

## Abhängigkeiten installieren

```bash
pip install -r requirements.txt
```

## Ollama installieren

https://ollama.com/download

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

# MITRE ATT&CK Beispiele

| Technique | Beschreibung |
|---|---|
| T1078 | Valid Accounts |
| T1110.001 | Password Guessing |
| T1548.003 | sudo / Privilege Escalation |

---

# Projektstatus

Aktiver Showcase für:
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
- PDF Reports
- Docker Deployment
- Echtzeit Monitoring
- Multi-Agent AI Workflow