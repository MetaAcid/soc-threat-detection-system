from pathlib import Path
import argparse
import os
import sys

from log_parser import parse_auth_log, parse_access_log
from detector import run_all_detections
from reporter import save_alerts_to_json, print_alerts


def main():
    base_dir = Path(__file__).resolve().parent.parent

    default_auth_log = base_dir / "logs" / "auth.log"
    default_access_log = base_dir / "logs" / "access.log"
    default_output = base_dir / "output" / "alerts.json"

    parser = argparse.ArgumentParser(
        description="SOC-style log analysis and threat detection tool"
    )
    parser.add_argument(
        "--auth",
        default=str(default_auth_log),
        help="Path to auth log file"
    )
    parser.add_argument(
        "--access",
        default=str(default_access_log),
        help="Path to access log file"
    )
    parser.add_argument(
        "--output",
        default=str(default_output),
        help="Path to output JSON file"
    )

    args = parser.parse_args()

    try:
        if not os.path.exists(args.auth):
            raise FileNotFoundError(f"Auth log not found: {args.auth}")

        if not os.path.exists(args.access):
            raise FileNotFoundError(f"Access log not found: {args.access}")

        auth_logs = parse_auth_log(args.auth)
        access_logs = parse_access_log(args.access)

        alerts = run_all_detections(auth_logs, access_logs)

        output_dir = Path(args.output).parent
        output_dir.mkdir(parents=True, exist_ok=True)

        print_alerts(alerts)
        save_alerts_to_json(alerts, args.output)

        print(f"\nAlerts saved to: {args.output}")
        return 0

    except FileNotFoundError as error:
        print(f"\n[ERROR] {error}")
        return 1

    except PermissionError as error:
        print(f"\n[ERROR] Permission denied: {error}")
        return 1

    except ValueError as error:
        print(f"\n[ERROR] Invalid data format: {error}")
        return 1

    except Exception as error:
        print(f"\n[ERROR] Unexpected error: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())