from pathlib import Path
import argparse

from log_parser import parse_auth_log, parse_access_log
from detector import run_all_detections
from reporter import save_alerts_to_json, print_alerts


def main():
    base_dir = Path(__file__).resolve().parent.parent

    default_auth_log = base_dir / "logs" / "auth.log"
    default_access_log = base_dir / "logs" / "access.log"
    default_output = base_dir / "output" / "alerts.json"

    parser = argparse.ArgumentParser(description="SOC Threat Detection System")
    parser.add_argument("--auth", default=str(default_auth_log), help="Path to auth log file")
    parser.add_argument("--access", default=str(default_access_log), help="Path to access log file")
    parser.add_argument("--output", default=str(default_output), help="Path to output JSON file")

    args = parser.parse_args()

    auth_logs = parse_auth_log(args.auth)
    access_logs = parse_access_log(args.access)

    alerts = run_all_detections(auth_logs, access_logs)

    print_alerts(alerts)
    save_alerts_to_json(alerts, args.output)

    print(f"\nAlerts saved to: {args.output}")


if __name__ == "__main__":
    main()