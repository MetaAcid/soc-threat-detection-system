import json
from typing import List, Dict


def save_alerts_to_json(alerts: List[Dict], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4, ensure_ascii=False)


def print_alerts(alerts: List[Dict]) -> None:
    print("\n=== ALERTS DETECTED ===")
    print("=" * 30)

    if not alerts:
        print("No alerts detected.")
        return

    for index, alert in enumerate(alerts, start=1):
        print(f"\n[{index}] {alert['type']}")
        print(f"Severity   : {alert['severity']}")
        print(f"Source IP  : {alert['source_ip']}")
        print(f"Timestamp  : {alert.get('timestamp', 'N/A')}")
        print(f"Description: {alert['description']}")