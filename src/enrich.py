import os
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"


def get_ip_reputation(ip: str) -> dict:
    """
    Query VirusTotal for IP reputation.
    """
    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(VT_URL.format(ip), headers=headers, timeout=10)

        if response.status_code != 200:
            return {
                "ip": ip,
                "error": f"API error: {response.status_code}"
            }

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "reputation_score": stats.get("malicious", 0) + stats.get("suspicious", 0),
        }

    except Exception as e:
        return {
            "ip": ip,
            "error": str(e)
        }