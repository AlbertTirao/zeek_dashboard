import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services import auth_service


def main() -> int:
    # Force auth backend for this connectivity check.
    os.environ["AUTH_DB_BACKEND"] = "mysql"

    cfg = auth_service.get_mysql_config()
    if not cfg:
        print(
            "ERROR: MySQL auth config is incomplete. "
            "Set AUTH_MYSQL_HOST, AUTH_MYSQL_PORT, AUTH_MYSQL_USER, AUTH_MYSQL_PASSWORD, AUTH_MYSQL_DATABASE "
            "(or AUTH_MYSQL_URI)."
        )
        return 1

    try:
        auth_service.init_auth_schema()
    except Exception as exc:
        print(f"ERROR: MySQL auth check failed: {exc}")
        return 1

    host = str(cfg.get("host", ""))
    port = str(cfg.get("port", ""))
    database = str(cfg.get("database", ""))
    print(f"OK: Connected to MySQL auth backend at {host}:{port}/{database} and schema is ready.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
