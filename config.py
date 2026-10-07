import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "CHANGEME_SECRET")
MAX_CONTENT_LENGTH = 2 * 1024 * 1024

MASSCAN_PATH = "./masscan64.exe" if os.name == "nt" else "masscan"
SCAN_DIR = os.path.join(BASE_DIR, "scans")
CLEAN_DIR = os.path.join(BASE_DIR, "clean")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
HISTORY_DB_PATH = os.path.join(BASE_DIR, "scan_history.db")
