import re
import json
from pathlib import Path
from datetime import datetime

LOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w\-/\[\]().]+):\s+"
    r"(?P<message>.+)$"
)

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (invalid user\s+)?(?P<username>\S+) from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})"
)

SUCCESS_LOGIN_PATTERN = re.compile(
    r"Accepted password for (?P<username>\S+) from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})"
)

NETWORK_PATTERN = re.compile(
    r"Connection attempt from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}) to port (?P<port>\d+)"
)

def parse_network_message(message: str) -> dict:
    result = {
        "source_ip": None,
        "destination_port": None,
        "event_type": None,
    }

    match = NETWORK_PATTERN.search(message)
    if match:
        result["source_ip"] = match.group("source_ip")
        result["destination_port"] = int(match.group("port"))
        result["event_type"] = "connection_attempt"

    return result

def parse_auth_message(message: str) -> dict:
    """
    Extract key SOC fields from authentication logs.
    """
    result = {
        "username": None,
        "source_ip": None,
        "status": "unknown",
        "auth_type": None,
        "is_suspicious": False,
    }

    failed_match = FAILED_LOGIN_PATTERN.search(message)
    if failed_match:
        result["username"] = failed_match.group("username")
        result["source_ip"] = failed_match.group("source_ip")
        result["status"] = "failed"
        result["auth_type"] = "password"
        result["is_suspicious"] = True
        return result

    success_match = SUCCESS_LOGIN_PATTERN.search(message)
    if success_match:
        result["username"] = success_match.group("username")
        result["source_ip"] = success_match.group("source_ip")
        result["status"] = "success"
        result["auth_type"] = "password"
        return result

    return result

def parse_log_line(line: str, year: int = None) -> dict | None:
    line = line.strip()
    if not line:
        return None

    match = LOG_PATTERN.match(line)
    if not match:
        return {
            "raw": line,
            "parsed": False,
            "reason": "line did not match expected format",
        }

    data = match.groupdict()

    if year is None:
        year = datetime.now().year

    timestamp_str = f"{data['month']} {data['day']} {year} {data['time']}"
    timestamp = datetime.strptime(timestamp_str, "%b %d %Y %H:%M:%S")

    auth_data = parse_auth_message(data["message"])
    network_data = parse_network_message(data["message"])

    source_ip = auth_data.get("source_ip") or network_data.get("source_ip")

    return {
        "timestamp": timestamp.isoformat(),
        "host": data["host"],
        "process": data["process"],
        "message": data["message"],
        "username": auth_data["username"],
        "source_ip": source_ip,
        "destination_port": network_data.get("destination_port"),
        "event_type": network_data.get("event_type"),
        "status": auth_data["status"],
        "auth_type": auth_data["auth_type"],
        "is_suspicious": auth_data["is_suspicious"],
        "parsed": True,
        "raw": line,
    }

def parse_log_file(input_path: str, output_path: str) -> list[dict]:
    input_file = Path(input_path)
    output_file = Path(output_path)
    events = []

    with input_file.open("r", encoding="utf-8") as f:
        for line in f:
            event = parse_log_line(line)
            if event:
                events.append(event)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    return events

if __name__ == "__main__":
    parsed = parse_log_file("data/raw/auth.log", "data/processed/auth_parsed.json")
    parsed = parse_log_file("data/raw/network.log", "data/processed/network_parsed.json")
    print(f"Parsed {len(parsed)} events")