BRUTE_FORCE_THRESHOLD = 5
SUSPICIOUS_404_THRESHOLD = 4
SERVER_ERROR_THRESHOLD = 5
REPEATED_IP_THRESHOLD = 8

SENSITIVE_PATHS = [
    "/admin",
    "/phpmyadmin",
    "/wp-login.php",
    "/.env",
    "/config.php"
]