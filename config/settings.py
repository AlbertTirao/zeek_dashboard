from pathlib import Path

DATA_DIR = Path("data")
LOGS_DIR = Path("logs")
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

FOLDER_ID = "1k6tVW7ZmcpaTVu7xkVOS6Nx0xU1bQ8km"
CLIENT_SECRET_FILE = "client_secret_262013512528-s1lbcqmro9623l0j5akshcoq8o1dso09.apps.googleusercontent.com.json"
AUTO_REFRESH_INTERVAL = 3600  # seconds
