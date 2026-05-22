from datetime import datetime


def write_markdown_report(alerts):
    """
    Erstellt einen Markdown-Report aus den analysierten Alerts.
    """

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = f"reports/security_report_{timestamp}.md"

    with open(report_path, "w", encoding="utf-8") as file:
        file.write("# AI Security Analyst Report\n\n")
        file.write(f"Erstellt am: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n\n")
        file.write(f"Anzahl analysierter Alerts: {len(alerts)}\n\n")

        high_count = sum(1 for alert in alerts if alert["risk"] == "HIGH")
        medium_count = sum(1 for alert in alerts if alert["risk"] == "MEDIUM")
        low_count = sum(1 for alert in alerts if alert["risk"] == "LOW")

        file.write("## Executive Summary\n\n")
        file.write(f"- High Risk Alerts: {high_count}\n")
        file.write(f"- Medium Risk Alerts: {medium_count}\n")
        file.write(f"- Low Risk Alerts: {low_count}\n\n")

        file.write("## Alerts\n\n")

        for alert in alerts:
            file.write(f"### {alert['risk']} - {alert['event']}\n\n")
            file.write(f"- Rule ID: {alert['rule_id']}\n")
            file.write(f"- Level: {alert['level']}\n")
            file.write(f"- Agent: {alert['agent']}\n")
            file.write(f"- Source IP: {alert['src_ip']}\n")
            file.write(f"- Empfehlung: {alert['recommendation']}\n\n")
            file.write(f"- AI Summary: {alert['ai_summary']}\n\n")
            file.write(f"- MITRE ATT&CK: {alert.get('mitre', 'none')}\n")

    return report_path