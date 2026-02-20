import binascii
import hashlib
import hmac
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import psycopg2
import streamlit as st
from psycopg2.extras import RealDictCursor


PBKDF2_ALG = "sha256"
PBKDF2_ITERATIONS = 260_000
PBKDF2_SALT_BYTES = 16


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


def get_database_url() -> Optional[str]:
    return _first_non_empty(
        [
            os.getenv("AUTH_DATABASE_URL"),
            os.getenv("DATABASE_URL"),
            _get_secret("auth.database_url"),
            _get_secret("database_url"),
            _get_secret("AUTH_DATABASE_URL"),
            _get_secret("DATABASE_URL"),
            _get_secret("postgres.database_url"),
            _get_secret("postgres.url"),
            _get_secret("db.url"),
        ]
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


def _get_conn():
    database_url = get_database_url()
    if not database_url or not str(database_url).strip():
        raise RuntimeError(
            "PostgreSQL is not configured. Set AUTH_DATABASE_URL (or DATABASE_URL) in environment variables or Streamlit secrets."
        )
    parsed = urlparse(str(database_url).strip())
    placeholder_hosts = {"host", "hostname", "your_host", "<host>"}
    if (parsed.hostname or "").strip().lower() in placeholder_hosts:
        raise RuntimeError(
            "Invalid PostgreSQL host in database URL. Replace HOST with a real hostname "
            "(for local PostgreSQL usually 'localhost' or '127.0.0.1')."
        )
    return psycopg2.connect(database_url)


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
    sql = """
    CREATE TABLE IF NOT EXISTS app_users (
        id BIGSERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'staff')),
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_login_at TIMESTAMPTZ NULL,
        created_by VARCHAR(100) NULL
    );

    CREATE TABLE IF NOT EXISTS auth_login_audit (
        id BIGSERIAL PRIMARY KEY,
        username VARCHAR(100) NOT NULL,
        success BOOLEAN NOT NULL,
        reason VARCHAR(120) NULL,
        occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()


def seed_bootstrap_admin() -> None:
    username = _get_bootstrap_admin_username()
    password = _get_bootstrap_admin_password()
    if not username or not password:
        return

    with _get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT COUNT(*)::int AS total FROM app_users;")
            total = cur.fetchone()["total"]
            if total > 0:
                return
            cur.execute(
                """
                INSERT INTO app_users (username, password_hash, role, is_active, created_by)
                VALUES (%s, %s, 'admin', TRUE, 'bootstrap')
                """,
                (username.strip().lower(), hash_password(password)),
            )
        conn.commit()


def _audit_login(username: str, success: bool, reason: str = "") -> None:
    try:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO auth_login_audit (username, success, reason) VALUES (%s, %s, %s)",
                    (username.strip().lower(), success, reason[:120] if reason else None),
                )
            conn.commit()
    except Exception:
        return


def authenticate_user(username: str, password: str) -> Optional[AuthUser]:
    clean_user = (username or "").strip().lower()
    if not clean_user or not password:
        _audit_login(clean_user or "unknown", False, "missing_credentials")
        return None

    with _get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT username, password_hash, role, is_active
                FROM app_users
                WHERE username = %s
                LIMIT 1
                """,
                (clean_user,),
            )
            row = cur.fetchone()

    if not row:
        _audit_login(clean_user, False, "user_not_found")
        return None
    if not row["is_active"]:
        _audit_login(clean_user, False, "inactive_user")
        return None
    if not verify_password(password, row["password_hash"]):
        _audit_login(clean_user, False, "invalid_password")
        return None

    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE app_users SET last_login_at = NOW(), updated_at = NOW() WHERE username = %s",
                (clean_user,),
            )
        conn.commit()

    _audit_login(clean_user, True, "ok")
    return AuthUser(username=row["username"], role=row["role"], is_active=bool(row["is_active"]))


def create_user(username: str, password: str, role: str, created_by: str) -> None:
    clean_user = (username or "").strip().lower()
    clean_role = (role or "").strip().lower()
    if not clean_user:
        raise ValueError("Username is required.")
    if clean_role not in {"admin", "staff"}:
        raise ValueError("Role must be admin or staff.")

    with _get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT 1 FROM app_users WHERE username=%s LIMIT 1", (clean_user,))
            if cur.fetchone():
                raise ValueError("Username already exists.")
            cur.execute(
                """
                INSERT INTO app_users (username, password_hash, role, is_active, created_by)
                VALUES (%s, %s, %s, TRUE, %s)
                """,
                (clean_user, hash_password(password), clean_role, created_by),
            )
        conn.commit()


def set_user_status(username: str, is_active: bool) -> None:
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE app_users SET is_active=%s, updated_at=NOW() WHERE username=%s",
                (bool(is_active), username.strip().lower()),
            )
        conn.commit()


def list_users():
    with _get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT username, role, is_active, created_at, last_login_at, created_by
                FROM app_users
                ORDER BY username
                """
            )
            rows = cur.fetchall()

    users = []
    for row in rows:
        users.append(
            {
                "username": row["username"],
                "role": row["role"],
                "is_active": bool(row["is_active"]),
                "created_by": row["created_by"] or "",
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
