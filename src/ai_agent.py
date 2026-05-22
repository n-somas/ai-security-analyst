import requests


OLLAMA_URL = "http://localhost:11434/api/generate"


def generate_ai_summary(alert):
    """
    Nutzt ein lokales Ollama-LLM zur kurzen deutschen Analyse eines Security-Alerts.
    """

    prompt = f"""
Du bist ein Cybersecurity-Analyst.

Analysiere diesen Security-Alert kurz auf Deutsch.

Event: {alert['event']}
Risiko: {alert['risk']}
Agent: {alert['agent']}
Quell-IP: {alert['src_ip']}
MITRE ATT&CK: {alert.get('mitre', 'none')}

Antworte kurz und professionell mit:
1. Bedeutung
2. Warum relevant
3. Nächster Prüfschritt

Maximal 5 Sätze.
"""

    payload = {
        "model": "llama3.2:3b",
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=60)

        if response.status_code != 200:
            return "LLM-Analyse fehlgeschlagen."

        data = response.json()
        return data.get("response", "Keine Antwort vom Modell.")

    except Exception as error:
        return f"LLM-Fehler: {error}"