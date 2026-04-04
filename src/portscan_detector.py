import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


def load_events(path: str) -> list[dict[str, Any]]:
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def detect_port_scan(
    events: list[dict[str, Any]],
    threshold: int = 5,
    window_seconds: int = 60,
) -> list[dict[str, Any]]:
    """
    Detect port scan behavior by finding the maximum number of unique ports
    contacted by the same source IP within a sliding time window.

    One alert is generated per source IP.
    """
    events_by_ip = defaultdict(list)

    for event in events:
        if event.get("event_type") != "connection_attempt":
            continue

        source_ip = event.get("source_ip")
        timestamp = event.get("timestamp")
        destination_port = event.get("destination_port")

        if not source_ip or not timestamp or destination_port is None:
            continue

        events_by_ip[source_ip].append(event)

    alerts: list[dict[str, Any]] = []

    for source_ip, ip_events in events_by_ip.items():
        ip_events.sort(key=lambda e: e["timestamp"])

        timestamps = [datetime.fromisoformat(e["timestamp"]) for e in ip_events]
        ports = [e["destination_port"] for e in ip_events]

        start = 0
        max_unique_ports = 0
        best_start = 0
        best_end = 0

        for end in range(len(timestamps)):
            while timestamps[end] - timestamps[start] > timedelta(seconds=window_seconds):
                start += 1

            unique_ports = len(set(ports[start : end + 1]))

            if unique_ports > max_unique_ports:
                max_unique_ports = unique_ports
                best_start = start
                best_end = end

        if max_unique_ports >= threshold:
            alerts.append(
                {
                    "source_ip": source_ip,
                    "unique_ports": max_unique_ports,
                    "first_seen": timestamps[best_start].isoformat(),
                    "last_seen": timestamps[best_end].isoformat(),
                    "severity": "high" if max_unique_ports >= threshold + 2 else "medium",
                    "reason": (
                        f"Port scan detected: {max_unique_ports} ports scanned "
                        f"within {window_seconds} seconds"
                    ),
                }
            )

    return alerts


def main() -> None:
    input_file = "data/processed/network_parsed.json"
    events = load_events(input_file)
    alerts = detect_port_scan(events, threshold=5, window_seconds=60)

    if alerts:
        print(f"[!] Detected {len(alerts)} port scan alert(s)")
        for alert in alerts:
            print(alert)
    else:
        print("[+] No port scan detected")


if __name__ == "__main__":
    main()