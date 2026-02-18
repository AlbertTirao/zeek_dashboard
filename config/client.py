from pathlib import Path

# =====================================================
# Local directories
# =====================================================
DATA_DIR = Path("data")
LOGS_DIR = Path("logs")
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

PARQUET_DIR = Path("data/parquet")
PICKLE_DIR = PARQUET_DIR / "pickle"

# =====================================================
# Google Drive settings
# =====================================================
FOLDER_ID = "1k6tVW7ZmcpaTVu7xkVOS6Nx0xU1bQ8km"

# OAuth client secret (your existing file)
CLIENT_SECRET_FILE = (
    "client_secret_262013512528-s1lbcqmro9623l0j5akshcoq8o1dso09.apps.googleusercontent.com.json"
)

# -----------------------------------------------------
# Drive auth mode:
#   - "service" : best for production, never prompts
#   - "oauth"   : prompts once then reuses token file
#   - "auto"    : try service first, fallback to oauth
# -----------------------------------------------------
DRIVE_AUTH_MODE = "oauth"
#DRIVE_AUTH_MODE = "auto"

# Store secrets OUTSIDE git (put secrets/ in .gitignore)
SERVICE_ACCOUNT_FILE = "secrets/service_account.json"
DRIVE_CREDENTIALS_FILE = "secrets/drive_credentials.json"

# =====================================================
# Streamlit refresh settings
# =====================================================
AUTO_REFRESH_INTERVAL = 3600  # seconds