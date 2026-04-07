import re
from typing import List, Dict, Optional


AUTH_LOG_PATTERN = re.compile(
    r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"(Failed|Accepted)\s+password\s+for\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)"
)

ACCESS_LOG_PATTERN = re.compile(
    r'^(\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(.*?)\]\s+"(\w+)\s+(\S+)\s+HTTP/[\d.]+"\s+(\d{3})\s+(\d+)'
)


def parse_auth_log(file_path: str) -> List[Dict]:
    parsed_logs = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            match = AUTH_LOG_PATTERN.match(line)
            if match:
                timestamp, status, user, ip = match.groups()
                parsed_logs.append({
                    "timestamp": timestamp,
                    "status": status,
                    "user": user,
                    "ip": ip,
                    "raw": line
                })

    return parsed_logs


def parse_access_log(file_path: str) -> List[Dict]:
    parsed_logs = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            match = ACCESS_LOG_PATTERN.match(line)
            if match:
                ip, timestamp, method, path, status_code, size = match.groups()
                parsed_logs.append({
                    "ip": ip,
                    "timestamp": timestamp,
                    "method": method,
                    "path": path,
                    "status_code": int(status_code),
                    "size": int(size),
                    "raw": line
                })

    return parsed_logs