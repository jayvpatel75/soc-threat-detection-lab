from enrich import get_ip_reputation
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


@dataclass
class BruteForceAlert:
    source_ip: str
    failed_attempts: int
    first_seen: str
    last_seen: str
    severity: str
    reason: str


def load_events(json_path: str) -> list[dict[str, Any]]:
    path = Path(json_path)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def detect_brute_force(
    events: list[dict[str, Any]],
    threshold: int = 3,
    window_minutes: int = 10,
) -> list[dict[str, Any]]:
    """
    Detect brute force attempts by counting failed logins
    from the same source IP within a time window.
    """
    failed_events_by_ip = defaultdict(list)

    for event in events:
        if (
            event.get("parsed") is True
            and event.get("status") == "failed"
            and event.get("source_ip")
            and event.get("timestamp")
        ):
            failed_events_by_ip[event["source_ip"]].append(event)

    alerts: list[dict[str, Any]] = []
    seen_ips = set()

    for source_ip, ip_events in failed_events_by_ip.items():
        ip_events.sort(key=lambda e: e["timestamp"])

        timestamps = [
            datetime.fromisoformat(event["timestamp"])
            for event in ip_events
        ]

        start = 0
        for end in range(len(timestamps)):
            while timestamps[end] - timestamps[start] > timedelta(minutes=window_minutes):
                start += 1

            attempt_count = end - start + 1

            max_attempts = 0
            best_start = 0
            best_end = 0

            start = 0
            for end in range(len(timestamps)):
                while timestamps[end] - timestamps[start] > timedelta(minutes=window_minutes):
                    start += 1

                attempt_count = end - start + 1

                if attempt_count > max_attempts:
                    max_attempts = attempt_count
                    best_start = start
                    best_end = end

            if max_attempts >= threshold:
                alert = BruteForceAlert(
                    source_ip=source_ip,
                    failed_attempts=max_attempts,
                    first_seen=timestamps[best_start].isoformat(),
                    last_seen=timestamps[best_end].isoformat(),
                    severity="high" if max_attempts >= threshold * 2 else "medium",
                    reason=(
                        f"{max_attempts} failed login attempts from {source_ip} "
                        f"within {window_minutes} minutes"
                    ),
                )
                if source_ip not in seen_ips:
                    alerts.append(alert.__dict__)
                    seen_ips.add(source_ip)

    return alerts


def save_alerts(alerts: list[dict[str, Any]], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)


def main() -> None:
    input_file = "data/processed/auth_parsed.json"
    output_file = "detections/brute_force_alerts.json"

    events = load_events(input_file)

    alerts = detect_brute_force(events, threshold=2, window_minutes=10)

    # Enrich alerts with threat intelligence
    for alert in alerts:
        reputation = get_ip_reputation(alert["source_ip"])
        alert["threat_intel"] = reputation
    
    save_alerts(alerts, output_file)

    if alerts:
        print(f"[!] Detected {len(alerts)} brute force alert(s)")
        for alert in alerts:
            print(
                f"IP: {alert['source_ip']} | "
                f"Attempts: {alert['failed_attempts']} | "
                f"Severity: {alert['severity']} | "
                f"Reason: {alert['reason']}"
            )
    else:
        print("[+] No brute force activity detected")


if __name__ == "__main__":
    main()