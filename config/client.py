import json
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


def _looks_like_service_account_file(path: Path) -> bool:
    if not path.exists() or not path.is_file():
        return False
    try:
        if path.stat().st_size <= 0:
            return False
    except OSError:
        return False

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False

    return (
        str(payload.get("type", "")).strip() == "service_account"
        and bool(str(payload.get("client_email", "")).strip())
        and bool(str(payload.get("private_key", "")).strip())
    )


def _resolve_service_account_file() -> str:
    preferred = Path("secrets/service_account.json")
    if _looks_like_service_account_file(preferred):
        return str(preferred)

    secrets_dir = preferred.parent
    if secrets_dir.exists():
        for candidate in sorted(secrets_dir.glob("*.json")):
            if candidate.name == "drive_credentials.json":
                continue
            if _looks_like_service_account_file(candidate):
                return str(candidate)

    return str(preferred)

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
#   - "oauth"   : uses saved token file and refresh token silently
#   - "auto"    : try service first, fallback to oauth
# -----------------------------------------------------
DRIVE_AUTH_MODE = "service"
#DRIVE_AUTH_MODE = "auto"
DRIVE_ALLOW_INTERACTIVE_OAUTH = False

# Store secrets OUTSIDE git (put secrets/ in .gitignore)
SERVICE_ACCOUNT_FILE = _resolve_service_account_file()
DRIVE_CREDENTIALS_FILE = "secrets/drive_credentials.json"

# =====================================================
# Streamlit refresh settings
# =====================================================
AUTO_REFRESH_INTERVAL = 3600  # seconds
DRIVE_SYNC_INTERVAL = 3600  # seconds
# Number of recent days to sync from Drive on each cycle.
# Set to 0 or negative to sync all available historical dates.
DRIVE_SYNC_LOOKBACK_DAYS = 0
