import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root (parent of backend directory)
project_root = Path(__file__).parent.parent.parent
env_path = project_root / ".env"
load_dotenv(dotenv_path=env_path)

# Fallback to current directory if project root .env doesn't exist
if not env_path.exists():
    load_dotenv()

# API Keys (loaded from environment variables)
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# Base URLs
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
IPAPI_BASE_URL = "http://ip-api.com"

# Persistence settings
REPORT_DB_PATH = os.getenv("REPORT_DB_PATH", str(project_root / "data" / "reports.db"))
REPORT_RETENTION_DAYS = int(os.getenv("REPORT_RETENTION_DAYS", "7"))
REPORT_RETENTION_LIMIT = int(os.getenv("REPORT_RETENTION_LIMIT", "1000"))

# Request configuration
REQUEST_TIMEOUT = 8  # seconds
MAX_RETRIES = 2

# Risk level mapping as inclusive ranges
RISK_LEVELS = {
    "LOW": (0, 25),
    "MEDIUM": (26, 50),
    "HIGH": (51, 75),
    "CRITICAL": (76, 100)
}

# Threat categories mapping
THREAT_CATEGORIES = {
    "malware": "Malware",
    "botnet": "Botnet",
    "c2": "C2 Server",
    "phishing": "Phishing",
    "spam": "Spam",
    "brute_force": "Brute Force",
    "web_attack": "Web Attack",
    "exploit": "Exploit",
    "scanner": "Scanner",
}

# High-risk countries (ISO codes)
HIGH_RISK_COUNTRIES = ["KP", "IR", "SY", "CU"]

# Known benign ASNs (contains match)
BENIGN_ASNS = [
    "Google",
    "Cloudflare",
    "Amazon",
    "Microsoft",
    "Facebook",
    "Akamai",
    "Fastly",
]


