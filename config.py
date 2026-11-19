import os
from dotenv import load_dotenv

load_dotenv()


def _bool(name, default):
    return os.environ.get(name, str(default)).lower() in ("1", "true", "yes")


class Config:
    QRADAR_HOST = os.environ.get("QRADAR_HOST", "https://qradar.example.local")
    QRADAR_TOKEN = os.environ["QRADAR_TOKEN"]
    API_VERSION = os.environ.get("QRADAR_API_VERSION", "16.0")
    VERIFY_SSL = os.environ.get("QRADAR_CA_BUNDLE") or _bool("QRADAR_VERIFY_SSL", True)
    REQUEST_TIMEOUT = int(os.environ.get("QRADAR_TIMEOUT", "60"))
    AQL_LOOKBACK = os.environ.get("AQL_LOOKBACK", "LAST 72 HOURS")
