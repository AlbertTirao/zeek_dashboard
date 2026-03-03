import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from pymongo import MongoClient
from pymongo.errors import PyMongoError


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services import auth_service


def _mongo_db_name() -> str:
    return str(
        os.getenv("AUTH_MONGODB_DB")
        or os.getenv("MONGODB_DB")
        or "zeek_auth"
    ).strip()


def _to_utc(value):
    if not isinstance(value, datetime):
        return value
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def main() -> int:
    mongo_uri = auth_service.get_mongodb_uri()
    if not mongo_uri:
        print("ERROR: MongoDB source is not configured. Set AUTH_MONGODB_URI or MONGODB_URI.")
        return 1

    if not auth_service.get_mysql_config():
        print(
            "ERROR: MySQL target is not configured. "
            "Set AUTH_MYSQL_HOST, AUTH_MYSQL_PORT, AUTH_MYSQL_USER, AUTH_MYSQL_PASSWORD, AUTH_MYSQL_DATABASE "
            "(or AUTH_MYSQL_URI)."
        )
        return 1

    old_backend = os.getenv("AUTH_DB_BACKEND")
    os.environ["AUTH_DB_BACKEND"] = "mysql"
    try:
        auth_service.init_auth_schema()
    except Exception as exc:
        print(f"ERROR: Cannot prepare MySQL auth schema: {exc}")
        if old_backend is not None:
            os.environ["AUTH_DB_BACKEND"] = old_backend
        else:
            os.environ.pop("AUTH_DB_BACKEND", None)
        return 1

    try:
        mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=6000)
        mongo_client.admin.command("ping")
    except PyMongoError as exc:
        print(f"ERROR: Cannot connect to MongoDB source: {exc}")
        if old_backend is not None:
            os.environ["AUTH_DB_BACKEND"] = old_backend
        else:
            os.environ.pop("AUTH_DB_BACKEND", None)
        return 1

    db = mongo_client[_mongo_db_name()]
    rows = list(db["app_users"].find({}, {"_id": 0}))

    inserted = 0
    updated = 0
    skipped = 0

    for row in rows:
        username = auth_service.normalize_username(str(row.get("username", "") or ""))
        if not username:
            skipped += 1
            continue

        payload = {
            "name": auth_service.normalize_display_name(str(row.get("name", "") or "")),
            "username": username,
            "password_hash": str(row.get("password_hash", "") or ""),
            "role": str(row.get("role", "staff") or "staff").strip().lower(),
            "is_active": bool(row.get("is_active", True)),
            "created_at": _to_utc(row.get("created_at")),
            "updated_at": _to_utc(row.get("updated_at")) or datetime.now(timezone.utc),
            "last_login_at": _to_utc(row.get("last_login_at")),
            "created_by": str(row.get("created_by", "") or ""),
        }

        if payload["role"] not in {"admin", "staff"}:
            payload["role"] = "staff"

        if not payload["name"]:
            payload["name"] = username

        try:
            auth_service._insert_user_row(payload)
            inserted += 1
        except auth_service.DuplicateUsernameError:
            auth_service._update_user_row(
                username,
                {
                    "name": payload["name"],
                    "password_hash": payload["password_hash"],
                    "role": payload["role"],
                    "is_active": payload["is_active"],
                    "updated_at": payload["updated_at"],
                    "last_login_at": payload["last_login_at"],
                    "created_by": payload["created_by"],
                },
            )
            updated += 1

    mongo_client.close()

    if old_backend is not None:
        os.environ["AUTH_DB_BACKEND"] = old_backend
    else:
        os.environ.pop("AUTH_DB_BACKEND", None)

    print(f"Done. Source users: {len(rows)} | inserted: {inserted} | updated: {updated} | skipped: {skipped}")
    print("Note: this script migrates app_users only (login accounts), not auth_login_audit history.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
