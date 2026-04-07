from collections import defaultdict
from typing import List, Dict
from rules import (
    BRUTE_FORCE_THRESHOLD,
    SUSPICIOUS_404_THRESHOLD,
    SERVER_ERROR_THRESHOLD,
    REPEATED_IP_THRESHOLD,
    SENSITIVE_PATHS
)


def create_alert(alert_type: str, severity: str, source_ip: str, description: str, timestamp: str = "N/A") -> Dict:
    return {
        "type": alert_type,
        "severity": severity,
        "source_ip": source_ip,
        "timestamp": timestamp,
        "description": description
    }


def detect_bruteforce(auth_logs: List[Dict]) -> List[Dict]:
    failed_attempts = defaultdict(int)
    alerts = []

    for log in auth_logs:
        if log["status"] == "Failed":
            failed_attempts[log["ip"]] += 1

    for ip, count in failed_attempts.items():
        if count > BRUTE_FORCE_THRESHOLD:
            alerts.append(create_alert(
                alert_type="Brute Force",
                severity="HIGH",
                source_ip=ip,
                description=f"Detected {count} failed login attempts from {ip}"
            ))

    return alerts


def detect_repeated_failed_logins(auth_logs: List[Dict]) -> List[Dict]:
    failed_attempts = defaultdict(int)
    alerts = []

    for log in auth_logs:
        if log["status"] == "Failed":
            failed_attempts[log["ip"]] += 1

    for ip, count in failed_attempts.items():
        if 3 <= count <= BRUTE_FORCE_THRESHOLD:
            alerts.append(create_alert(
                alert_type="Suspicious Authentication Activity",
                severity="MEDIUM",
                source_ip=ip,
                description=f"Detected repeated failed login attempts from {ip}: {count}"
            ))

    return alerts


def detect_sensitive_path_scanning(access_logs: List[Dict]) -> List[Dict]:
    suspicious_requests = defaultdict(int)
    alerts = []

    for log in access_logs:
        if log["path"] in SENSITIVE_PATHS or log["status_code"] == 404:
            suspicious_requests[log["ip"]] += 1

    for ip, count in suspicious_requests.items():
        if count >= SUSPICIOUS_404_THRESHOLD:
            alerts.append(create_alert(
                alert_type="Path Scanning / Reconnaissance",
                severity="HIGH",
                source_ip=ip,
                description=f"Detected suspicious probing activity from {ip}: {count} suspicious requests"
            ))

    return alerts


def detect_server_error_spike(access_logs: List[Dict]) -> List[Dict]:
    error_count = sum(1 for log in access_logs if log["status_code"] >= 500)
    alerts = []

    if error_count >= SERVER_ERROR_THRESHOLD:
        alerts.append(create_alert(
            alert_type="Server Error Spike",
            severity="MEDIUM",
            source_ip="multiple",
            description=f"Detected spike in server-side errors: {error_count} responses with 5xx status"
        ))

    return alerts


def detect_repeated_ip_activity(access_logs: List[Dict]) -> List[Dict]:
    request_count = defaultdict(int)
    alerts = []

    for log in access_logs:
        request_count[log["ip"]] += 1

    for ip, count in request_count.items():
        if count >= REPEATED_IP_THRESHOLD:
            alerts.append(create_alert(
                alert_type="Suspicious Repeated Activity",
                severity="MEDIUM",
                source_ip=ip,
                description=f"Detected unusually high number of requests from {ip}: {count}"
            ))

    return alerts


def run_all_detections(auth_logs: List[Dict], access_logs: List[Dict]) -> List[Dict]:
    alerts = []
    alerts.extend(detect_bruteforce(auth_logs))
    alerts.extend(detect_repeated_failed_logins(auth_logs))
    alerts.extend(detect_sensitive_path_scanning(access_logs))
    alerts.extend(detect_server_error_spike(access_logs))
    alerts.extend(detect_repeated_ip_activity(access_logs))
    return alerts