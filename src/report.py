import json
import uuid
from pathlib import Path
from datetime import datetime


def load_alerts(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def generate_incident_report(alert: dict) -> dict:
    """
    Convert a detection alert into a SOC-style incident report.
    """

    threat_intel = alert.get("threat_intel", {})

    severity = alert["severity"]

    # Upgrade severity if threat intel shows malicious activity
    if threat_intel.get("malicious", 0) > 0:
        severity = "high"

    report = {
        "incident_id": f"INC-{uuid.uuid4().hex[:8]}",
        "created_at": datetime.now().isoformat(),
        "source_ip": alert["source_ip"],
        "severity": severity,
        "summary": "Potential brute force attack detected",
        "details": {
            "failed_attempts": alert["failed_attempts"],
            "time_window": {
                "start": alert["first_seen"],
                "end": alert["last_seen"],
            },
            "reason": alert["reason"],
        },
        "threat_intel": threat_intel,
        "analysis": generate_analysis(alert),
        "recommended_actions": generate_recommendations(alert, threat_intel),
    }

    return report


def generate_analysis(alert: dict) -> str:
    return (
        f"The system detected {alert['failed_attempts']} failed login attempts "
        f"from IP {alert['source_ip']} within a short time window. "
        f"This behavior is consistent with a brute force attack attempt."
    )


def generate_recommendations(alert: dict, threat_intel: dict) -> list:
    actions = [
        f"Block IP address {alert['source_ip']} at firewall level",
        "Monitor for additional suspicious login attempts",
        "Check if any accounts were compromised",
    ]

    if threat_intel.get("malicious", 0) > 0:
        actions.append("Escalate incident due to confirmed malicious reputation")

    return actions


def save_reports(reports: list, output_path: str):
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2)


def main():
    alerts_file = "detections/brute_force_alerts.json"
    output_file = "reports/incidents.json"

    alerts = load_alerts(alerts_file)

    reports = []
    for alert in alerts:
        report = generate_incident_report(alert)
        reports.append(report)

    save_reports(reports, output_file)

    print(f"[+] Generated {len(reports)} incident report(s)")


if __name__ == "__main__":
    main()