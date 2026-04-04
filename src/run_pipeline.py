from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from parser import parse_log_file  
from detector import (  
    detect_brute_force,
    load_events as load_auth_events,
    save_alerts as save_bruteforce_alerts,
)
from enrich import get_ip_reputation 
from portscan_detector import (  
    detect_port_scan,
    load_events as load_network_events,
)
from report import (  
    generate_incident_report,
    save_reports,
)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def run_auth_pipeline() -> list[dict[str, Any]]:
    auth_raw = PROJECT_ROOT / "data" / "raw" / "auth.log"
    auth_processed = PROJECT_ROOT / "data" / "processed" / "auth_parsed.json"
    brute_force_alerts_file = PROJECT_ROOT / "detections" / "brute_force_alerts.json"
    incidents_file = PROJECT_ROOT / "reports" / "incidents.json"

    if not auth_raw.exists():
        raise FileNotFoundError(f"Missing auth log file: {auth_raw}")

    print("[*] Parsing auth logs...")
    parse_log_file(str(auth_raw), str(auth_processed))

    print("[*] Loading parsed auth events...")
    auth_events = load_auth_events(str(auth_processed))

    print("[*] Running brute force detection...")
    brute_force_alerts = detect_brute_force(auth_events, threshold=2, window_minutes=10)

    print("[*] Enriching brute force alerts with threat intelligence...")
    for alert in brute_force_alerts:
        alert["threat_intel"] = get_ip_reputation(alert["source_ip"])

    print("[*] Saving brute force alerts...")
    save_bruteforce_alerts(brute_force_alerts, str(brute_force_alerts_file))

    print("[*] Generating incident reports...")
    reports = [generate_incident_report(alert) for alert in brute_force_alerts]
    save_reports(reports, str(incidents_file))

    print(f"[+] Auth pipeline complete: {len(brute_force_alerts)} alert(s), {len(reports)} incident report(s)")
    return brute_force_alerts


def run_network_pipeline() -> list[dict[str, Any]]:
    network_raw = PROJECT_ROOT / "data" / "raw" / "network.log"
    network_processed = PROJECT_ROOT / "data" / "processed" / "network_parsed.json"
    portscan_alerts_file = PROJECT_ROOT / "detections" / "port_scan_alerts.json"

    if not network_raw.exists():
        raise FileNotFoundError(f"Missing network log file: {network_raw}")

    print("[*] Parsing network logs...")
    parse_log_file(str(network_raw), str(network_processed))

    print("[*] Loading parsed network events...")
    network_events = load_network_events(str(network_processed))

    print("[*] Running port scan detection...")
    portscan_alerts = detect_port_scan(network_events, threshold=5, window_seconds=60)

    print("[*] Saving port scan alerts...")
    write_json(portscan_alerts_file, portscan_alerts)

    print(f"[+] Network pipeline complete: {len(portscan_alerts)} alert(s)")
    return portscan_alerts


def main() -> int:
    
    print("SOC Threat Detection Lab - One-Click Pipeline")
    

    try:
        run_auth_pipeline()
        run_network_pipeline()
    except FileNotFoundError as exc:
        print(f"{exc}")
        return 1
    except Exception as exc:
        print(f"Pipeline failed: {exc}")
        return 1

    
    print("[+] Pipeline finished successfully")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())