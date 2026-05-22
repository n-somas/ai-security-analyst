from collections import Counter

from wazuh_client import load_alerts
from alert_analyzer import analyze_alert
from report_writer import write_markdown_report
from ai_agent import generate_ai_summary


def main():
    print("AI Security Analyst gestartet.\n")

    alerts = load_alerts()

    analyzed_alerts = [analyze_alert(alert) for alert in alerts]

    print(f"{len(analyzed_alerts)} Alerts analysiert.\n")

    # =========================
    # EVENT ZÄHLUNG
    # =========================

    event_counter = Counter()

    for alert in analyzed_alerts:
        event_counter[alert["event"]] += 1

    print("Top Events:\n")

    top_events = event_counter.most_common(5)

    for event, count in top_events:
        print(f"{count}x -> {event}")

    print("\n" + "-" * 50 + "\n")

    # =========================
    # LLM ANALYSE NUR TOP EVENTS
    # =========================

    already_analyzed = set()

    for alert in analyzed_alerts:

        event_name = alert["event"]

        # Nur HIGH/MEDIUM
        if alert["risk"] not in ["HIGH", "MEDIUM"]:
            continue

        # Doppeltes LLM vermeiden
        if event_name in already_analyzed:
            continue

        already_analyzed.add(event_name)

        print(f"[{alert['risk']}] {event_name}")

        ai_summary = generate_ai_summary(alert)

        print("\nKI Analyse:")
        print(ai_summary)

        print("\n" + "-" * 50 + "\n")

    report_path = write_markdown_report(analyzed_alerts)

    print(f"Report erstellt: {report_path}")


if __name__ == "__main__":
    main()