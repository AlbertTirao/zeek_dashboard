import binascii
import hashlib
import hmac
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import streamlit as st
from pymongo import ASCENDING, MongoClient
from pymongo.errors import DuplicateKeyError, PyMongoError


PBKDF2_ALG = "sha256"
PBKDF2_ITERATIONS = 260_000
PBKDF2_SALT_BYTES = 16
MONGO_TIMEOUT_MS = 6000


@dataclass(frozen=True)
class AuthUser:
    username: str
    role: str
    is_active: bool


def _get_secret(path: str, default=None):
    try:
        current = st.secrets
        for part in path.split("."):
            if part not in current:
                return default
            current = current[part]
        return current
    except Exception:
        return default


def _first_non_empty(values):
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
        if value:
            return value
    return None


def get_mongodb_uri() -> Optional[str]:
    return _first_non_empty(
        [
            os.getenv("AUTH_MONGODB_URI"),
            os.getenv("MONGODB_URI"),
            _get_secret("auth.mongodb_uri"),
            _get_secret("mongodb_uri"),
            _get_secret("AUTH_MONGODB_URI"),
            _get_secret("MONGODB_URI"),
        ]
    )


def _get_database_name() -> str:
    return (
        _first_non_empty(
            [
                os.getenv("AUTH_MONGODB_DB"),
                os.getenv("MONGODB_DB"),
                _get_secret("auth.mongodb_db"),
                _get_secret("mongodb_db"),
                _get_secret("AUTH_MONGODB_DB"),
                _get_secret("MONGODB_DB"),
            ]
        )
        or "zeek_auth"
    )


def _get_bootstrap_admin_username() -> Optional[str]:
    return _first_non_empty(
        [
            os.getenv("BOOTSTRAP_ADMIN_USERNAME"),
            _get_secret("auth.bootstrap_admin_username"),
            _get_secret("bootstrap_admin_username"),
            _get_secret("BOOTSTRAP_ADMIN_USERNAME"),
        ]
    )


def _get_bootstrap_admin_password() -> Optional[str]:
    return _first_non_empty(
        [
            os.getenv("BOOTSTRAP_ADMIN_PASSWORD"),
            _get_secret("auth.bootstrap_admin_password"),
            _get_secret("bootstrap_admin_password"),
            _get_secret("BOOTSTRAP_ADMIN_PASSWORD"),
        ]
    )


def _get_db():
    mongodb_uri = get_mongodb_uri()
    if not mongodb_uri:
        raise RuntimeError(
            "MongoDB is not configured. Set AUTH_MONGODB_URI (or MONGODB_URI) in environment variables or Streamlit secrets."
        )

    try:
        client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=MONGO_TIMEOUT_MS)
        client.admin.command("ping")
    except PyMongoError as exc:
        raise RuntimeError(
            "Could not connect to MongoDB. Check MONGODB_URI, database user/password, and Atlas IP access settings."
        ) from exc

    db_name = _get_database_name()
    return client[db_name]


def hash_password(password: str) -> str:
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    salt = os.urandom(PBKDF2_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(PBKDF2_ALG, password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_{PBKDF2_ALG}${PBKDF2_ITERATIONS}${binascii.hexlify(salt).decode()}${binascii.hexlify(digest).decode()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, iterations_s, salt_hex, digest_hex = stored_hash.split("$", 3)
        if not scheme.startswith("pbkdf2_"):
            return False
        alg = scheme.replace("pbkdf2_", "", 1)
        iterations = int(iterations_s)
        salt = binascii.unhexlify(salt_hex.encode())
        expected = binascii.unhexlify(digest_hex.encode())
        actual = hashlib.pbkdf2_hmac(alg, password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def init_auth_schema() -> None:
    db = _get_db()
    users = db["app_users"]
    audit = db["auth_login_audit"]
    users.create_index([("username", ASCENDING)], unique=True, name="ux_app_users_username")
    audit.create_index([("occurred_at", ASCENDING)], name="ix_auth_login_audit_occurred_at")


def seed_bootstrap_admin() -> None:
    username = _get_bootstrap_admin_username()
    password = _get_bootstrap_admin_password()
    if not username or not password:
        return

    db = _get_db()
    users = db["app_users"]
    if users.count_documents({}) > 0:
        return

    now = datetime.now(timezone.utc)
    users.insert_one(
        {
            "username": username.strip().lower(),
            "password_hash": hash_password(password),
            "role": "admin",
            "is_active": True,
            "created_at": now,
            "updated_at": now,
            "last_login_at": None,
            "created_by": "bootstrap",
        }
    )


def _audit_login(username: str, success: bool, reason: str = "") -> None:
    try:
        db = _get_db()
        db["auth_login_audit"].insert_one(
            {
                "username": (username or "unknown").strip().lower(),
                "success": bool(success),
                "reason": (reason or "")[:120],
                "occurred_at": datetime.now(timezone.utc),
            }
        )
    except Exception:
        return


def authenticate_user(username: str, password: str) -> Optional[AuthUser]:
    clean_user = (username or "").strip().lower()
    if not clean_user or not password:
        _audit_login(clean_user or "unknown", False, "missing_credentials")
        return None

    db = _get_db()
    row = db["app_users"].find_one({"username": clean_user})

    if not row:
        _audit_login(clean_user, False, "user_not_found")
        return None
    if not bool(row.get("is_active", False)):
        _audit_login(clean_user, False, "inactive_user")
        return None
    if not verify_password(password, row.get("password_hash", "")):
        _audit_login(clean_user, False, "invalid_password")
        return None

    now = datetime.now(timezone.utc)
    db["app_users"].update_one(
        {"username": clean_user},
        {"$set": {"last_login_at": now, "updated_at": now}},
    )

    _audit_login(clean_user, True, "ok")
    return AuthUser(
        username=str(row.get("username", clean_user)),
        role=str(row.get("role", "staff")),
        is_active=bool(row.get("is_active", True)),
    )


def get_active_user(username: str) -> Optional[AuthUser]:
    clean_user = (username or "").strip().lower()
    if not clean_user:
        return None

    row = _get_db()["app_users"].find_one({"username": clean_user})
    if not row:
        return None
    if not bool(row.get("is_active", False)):
        return None

    return AuthUser(
        username=str(row.get("username", clean_user)),
        role=str(row.get("role", "staff")),
        is_active=bool(row.get("is_active", True)),
    )


def create_user(username: str, password: str, role: str, created_by: str) -> None:
    clean_user = (username or "").strip().lower()
    clean_role = (role or "").strip().lower()
    if not clean_user:
        raise ValueError("Username is required.")
    if clean_role not in {"admin", "staff"}:
        raise ValueError("Role must be admin or staff.")

    now = datetime.now(timezone.utc)
    try:
        _get_db()["app_users"].insert_one(
            {
                "username": clean_user,
                "password_hash": hash_password(password),
                "role": clean_role,
                "is_active": True,
                "created_at": now,
                "updated_at": now,
                "last_login_at": None,
                "created_by": (created_by or "").strip().lower(),
            }
        )
    except DuplicateKeyError as exc:
        raise ValueError("Username already exists.") from exc


def set_user_status(username: str, is_active: bool) -> None:
    clean_user = (username or "").strip().lower()
    _get_db()["app_users"].update_one(
        {"username": clean_user},
        {"$set": {"is_active": bool(is_active), "updated_at": datetime.now(timezone.utc)}},
    )


def update_user(
    username: str,
    *,
    new_username: Optional[str] = None,
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    password: Optional[str] = None,
) -> None:
    clean_user = (username or "").strip().lower()
    if not clean_user:
        raise ValueError("Username is required.")

    updates = {}
    if new_username is not None:
        clean_new_username = (new_username or "").strip().lower()
        if not clean_new_username:
            raise ValueError("Username is required.")
        if clean_new_username != clean_user:
            updates["username"] = clean_new_username
    if role is not None:
        clean_role = (role or "").strip().lower()
        if clean_role not in {"admin", "staff"}:
            raise ValueError("Role must be admin or staff.")
        updates["role"] = clean_role
    if is_active is not None:
        updates["is_active"] = bool(is_active)
    if password is not None:
        if not password:
            raise ValueError("Password must be at least 8 characters.")
        updates["password_hash"] = hash_password(password)

    if not updates:
        raise ValueError("No updates were provided.")

    updates["updated_at"] = datetime.now(timezone.utc)
    try:
        result = _get_db()["app_users"].update_one({"username": clean_user}, {"$set": updates})
    except DuplicateKeyError as exc:
        raise ValueError("Username already exists.") from exc
    if result.matched_count == 0:
        raise ValueError("User not found.")


def delete_user(username: str) -> None:
    clean_user = (username or "").strip().lower()
    if not clean_user:
        raise ValueError("Username is required.")

    result = _get_db()["app_users"].delete_one({"username": clean_user})
    if result.deleted_count == 0:
        raise ValueError("User not found.")


def list_users():
    rows = _get_db()["app_users"].find({}, {"_id": 0, "password_hash": 0}).sort("username", ASCENDING)
    users = []
    for row in rows:
        users.append(
            {
                "username": row.get("username", ""),
                "role": row.get("role", ""),
                "is_active": bool(row.get("is_active")),
                "created_by": row.get("created_by", "") or "",
                "created_at": _fmt_dt(row.get("created_at")),
                "last_login_at": _fmt_dt(row.get("last_login_at")),
            }
        )
    return users


def _fmt_dt(value) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(value)
