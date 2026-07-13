# Brute-Force Correlation

Die Erweiterung erkennt mindestens fünf fehlgeschlagene Anmeldungen derselben Quell-IP innerhalb von zehn Minuten und erzeugt daraus einen HIGH-Incident.

## Enthalten

- robuste Zeitstempelverarbeitung
- zusätzliche Felder aus Wazuh: Zeitstempel und Benutzer
- Brute-Force-Korrelation nach Quell-IP und Zeitfenster
- Schutz vor Risiko-Downgrades
- Incident-Tabelle im Streamlit-Dashboard
- Agent- und Freitextfilter
- sieben automatisierte Tests

## Tests

```bash
python -m pytest -q
```

## Start

```bash
streamlit run src/dashboard.py
```
