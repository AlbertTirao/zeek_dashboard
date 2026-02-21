import binascii
import hashlib
import hmac
import os
import re
import string
from urllib.parse import urlencode
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import requests
import streamlit as st
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token as google_id_token
from pymongo import ASCENDING, MongoClient
from pymongo.errors import DuplicateKeyError, PyMongoError


PBKDF2_ALG = "sha256"
PBKDF2_ITERATIONS = 260_000
PBKDF2_SALT_BYTES = 16
MONGO_TIMEOUT_MS = 6000
GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_OAUTH_SCOPES = "openid email profile"
DEFAULT_GOOGLE_OAUTH_CLOCK_SKEW_SECONDS = 90
GMAIL_EMAIL_PATTERN = re.compile(r"^[a-z0-9._%+-]+@gmail\.com$")
SPECIAL_CHARACTER_SET = set(string.punctuation)


@dataclass(frozen=True)
class AuthUser:
    username: str
    role: str
    is_active: bool


@dataclass(frozen=True)
class GoogleOAuthConfig:
    client_id: str
    client_secret: str
    redirect_uri: str


def normalize_username(username: str) -> str:
    return str(username or "").strip().lower()


def is_valid_gmail_email(username: str) -> bool:
    clean_user = normalize_username(username)
    return bool(clean_user and GMAIL_EMAIL_PATTERN.fullmatch(clean_user))


def password_has_special_character(password: str) -> bool:
    return isinstance(password, str) and any(ch in SPECIAL_CHARACTER_SET for ch in password)


def validate_username_policy(username: str) -> str:
    clean_user = normalize_username(username)
    if not clean_user:
        raise ValueError("E-mail is required.")
    if not is_valid_gmail_email(clean_user):
        raise ValueError("E-mail must be a valid @gmail.com address.")
    return clean_user


def validate_password_policy(password: str) -> None:
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    if not password_has_special_character(password):
        raise ValueError("Password must include at least one special character.")


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


def _coerce_bool(value, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "y"}:
        return True
    if text in {"0", "false", "no", "off", "n"}:
        return False
    return default


def _google_oauth_clock_skew_seconds() -> int:
    raw = _first_non_empty(
        [
            os.getenv("AUTH_GOOGLE_OAUTH_CLOCK_SKEW_SECONDS"),
            os.getenv("GOOGLE_OAUTH_CLOCK_SKEW_SECONDS"),
            _get_secret("auth.google_oauth_clock_skew_seconds"),
            _get_secret("google_oauth_clock_skew_seconds"),
        ]
    )
    if raw is None:
        return DEFAULT_GOOGLE_OAUTH_CLOCK_SKEW_SECONDS
    try:
        value = int(raw)
    except Exception:
        return DEFAULT_GOOGLE_OAUTH_CLOCK_SKEW_SECONDS
    # Keep this bounded to avoid weakening token time checks too much.
    return max(0, min(300, value))


def _get_google_oauth_config() -> Optional[GoogleOAuthConfig]:
    client_id = _first_non_empty(
        [
            os.getenv("AUTH_GOOGLE_CLIENT_ID"),
            os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
            _get_secret("auth.google_client_id"),
            _get_secret("google_client_id"),
        ]
    )
    client_secret = _first_non_empty(
        [
            os.getenv("AUTH_GOOGLE_CLIENT_SECRET"),
            os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
            _get_secret("auth.google_client_secret"),
            _get_secret("google_client_secret"),
        ]
    )
    redirect_uri = _first_non_empty(
        [
            os.getenv("AUTH_GOOGLE_REDIRECT_URI"),
            os.getenv("GOOGLE_OAUTH_REDIRECT_URI"),
            _get_secret("auth.google_redirect_uri"),
            _get_secret("google_redirect_uri"),
        ]
    )

    if not (client_id and client_secret and redirect_uri):
        return None

    enabled_raw = os.getenv("AUTH_GOOGLE_OAUTH_ENABLED")
    if enabled_raw is None:
        enabled_raw = os.getenv("GOOGLE_OAUTH_ENABLED")
    if enabled_raw is None:
        enabled_raw = _get_secret("auth.google_oauth_enabled", default=None)
    if enabled_raw is None:
        enabled_raw = _get_secret("google_oauth_enabled", default=None)

    if not _coerce_bool(enabled_raw, default=True):
        return None

    return GoogleOAuthConfig(
        client_id=str(client_id).strip(),
        client_secret=str(client_secret).strip(),
        redirect_uri=str(redirect_uri).strip(),
    )


def is_google_oauth_configured() -> bool:
    return _get_google_oauth_config() is not None


def build_google_oauth_authorization_url(state: str) -> Optional[str]:
    cfg = _get_google_oauth_config()
    clean_state = str(state or "").strip()
    if not cfg or not clean_state:
        return None

    params = {
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "response_type": "code",
        "scope": GOOGLE_OAUTH_SCOPES,
        "state": clean_state,
        "access_type": "online",
        "include_granted_scopes": "true",
        "prompt": "select_account",
    }
    return f"{GOOGLE_AUTH_ENDPOINT}?{urlencode(params)}"


def _exchange_google_code_for_id_token(code: str, cfg: GoogleOAuthConfig) -> str:
    response = requests.post(
        GOOGLE_TOKEN_ENDPOINT,
        data={
            "code": str(code or "").strip(),
            "client_id": cfg.client_id,
            "client_secret": cfg.client_secret,
            "redirect_uri": cfg.redirect_uri,
            "grant_type": "authorization_code",
        },
        timeout=12,
    )

    try:
        payload = response.json()
    except Exception:
        payload = {}

    if response.status_code >= 400:
        detail = str(payload.get("error_description") or payload.get("error") or "token exchange failed")
        raise RuntimeError(f"Google OAuth token exchange failed: {detail}")

    id_token_jwt = str(payload.get("id_token") or "").strip()
    if not id_token_jwt:
        raise RuntimeError("Google OAuth token response did not include an ID token.")
    return id_token_jwt


def _verified_google_email_from_id_token(id_token_jwt: str, cfg: GoogleOAuthConfig) -> Optional[str]:
    claims = google_id_token.verify_oauth2_token(
        id_token_jwt,
        GoogleAuthRequest(),
        cfg.client_id,
        clock_skew_in_seconds=_google_oauth_clock_skew_seconds(),
    )
    issuer = str(claims.get("iss") or "").strip()
    if issuer not in {"accounts.google.com", "https://accounts.google.com"}:
        raise RuntimeError("Google OAuth token issuer is invalid.")

    email = normalize_username(str(claims.get("email") or ""))
    if not bool(claims.get("email_verified")):
        return None
    return email


def _normalize_email_collection(raw_value) -> set[str]:
    if raw_value is None:
        return set()

    if isinstance(raw_value, str):
        candidates = [part.strip() for part in raw_value.split(",")]
    elif isinstance(raw_value, (list, tuple, set)):
        candidates = [str(part).strip() for part in raw_value]
    else:
        return set()

    normalized = set()
    for candidate in candidates:
        clean_candidate = normalize_username(candidate)
        if is_valid_gmail_email(clean_candidate):
            normalized.add(clean_candidate)
    return normalized


def get_allowed_google_emails() -> set[str]:
    # Optional allowlist primarily for Google OAuth mode.
    allowlist = set()
    allowlist.update(_normalize_email_collection(os.getenv("AUTH_ALLOWED_GOOGLE_EMAILS")))
    allowlist.update(_normalize_email_collection(_get_secret("auth.allowed_google_emails")))
    allowlist.update(_normalize_email_collection(_get_secret("allowed_google_emails")))
    return allowlist


def is_email_allowed_for_login(username: str) -> bool:
    clean_user = normalize_username(username)
    if not is_valid_gmail_email(clean_user):
        return False

    allowlist = get_allowed_google_emails()
    if not allowlist:
        return True
    if not is_google_oauth_configured():
        # In form-only login mode, rely on app_users + password checks.
        return True
    return clean_user in allowlist


def authenticate_google_oauth_code(code: str, expected_email: Optional[str] = None) -> Optional[AuthUser]:
    cfg = _get_google_oauth_config()
    clean_code = str(code or "").strip()
    if not cfg or not clean_code:
        return None

    id_token_jwt = _exchange_google_code_for_id_token(clean_code, cfg)
    email = _verified_google_email_from_id_token(id_token_jwt, cfg)
    if not email:
        _audit_login("unknown", False, "google_email_unverified")
        return None

    clean_expected_email = normalize_username(expected_email or "")
    if clean_expected_email and email != clean_expected_email:
        _audit_login(email, False, "google_email_mismatch")
        return None

    if not is_email_allowed_for_login(email):
        _audit_login(email, False, "email_not_allowlisted")
        return None

    db = _get_db()
    row = db["app_users"].find_one({"username": email})
    if not row:
        _audit_login(email, False, "user_not_found")
        return None
    if not bool(row.get("is_active", False)):
        _audit_login(email, False, "inactive_user")
        return None

    now = datetime.now(timezone.utc)
    db["app_users"].update_one(
        {"username": email},
        {"$set": {"last_login_at": now, "updated_at": now}},
    )

    _audit_login(email, True, "ok_google_oauth")
    return AuthUser(
        username=str(row.get("username", email)),
        role=str(row.get("role", "staff")),
        is_active=bool(row.get("is_active", True)),
    )


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
    validate_password_policy(password)
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

    clean_username = validate_username_policy(username)
    now = datetime.now(timezone.utc)
    users.insert_one(
        {
            "username": clean_username,
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


def authenticate_user_password_only(username: str, password: str) -> Optional[AuthUser]:
    clean_user = normalize_username(username)
    if not clean_user or not isinstance(password, str) or not password:
        _audit_login(clean_user or "unknown", False, "missing_credentials")
        return None

    if not is_valid_gmail_email(clean_user):
        _audit_login(clean_user, False, "invalid_email_domain")
        return None
    if not is_email_allowed_for_login(clean_user):
        _audit_login(clean_user, False, "email_not_allowlisted")
        return None
    if not password_has_special_character(password):
        _audit_login(clean_user, False, "password_policy_violation")
        return None

    db = _get_db()
    row = db["app_users"].find_one({"username": clean_user})

    # Backward compatibility: allow legacy local usernames (e.g. "admin")
    # to authenticate via "<name>@gmail.com", then migrate them in place.
    if not row and clean_user.endswith("@gmail.com"):
        legacy_username = clean_user.split("@", 1)[0].strip().lower()
        if legacy_username:
            legacy_row = db["app_users"].find_one({"username": legacy_username})
            if legacy_row:
                if not bool(legacy_row.get("is_active", False)):
                    _audit_login(clean_user, False, "inactive_user")
                    return None
                if not verify_password(password, legacy_row.get("password_hash", "")):
                    _audit_login(clean_user, False, "invalid_password")
                    return None

                now = datetime.now(timezone.utc)
                try:
                    db["app_users"].update_one(
                        {"username": legacy_username},
                        {"$set": {"username": clean_user, "last_login_at": now, "updated_at": now}},
                    )
                except DuplicateKeyError:
                    _audit_login(clean_user, False, "username_conflict_during_migration")
                    return None

                _audit_login(clean_user, True, "ok_migrated_legacy_username")
                return AuthUser(
                    username=clean_user,
                    role=str(legacy_row.get("role", "staff")),
                    is_active=bool(legacy_row.get("is_active", True)),
                )

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


def authenticate_user(username: str, password: str) -> Optional[AuthUser]:
    clean_user = normalize_username(username)
    if is_google_oauth_configured():
        _audit_login(clean_user or "unknown", False, "password_login_disabled")
        return None
    return authenticate_user_password_only(username, password)


def get_active_user(username: str) -> Optional[AuthUser]:
    clean_user = normalize_username(username)
    if not clean_user or not is_email_allowed_for_login(clean_user):
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
    clean_user = validate_username_policy(username)
    clean_role = (role or "").strip().lower()
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
    clean_user = normalize_username(username)
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
    clean_user = normalize_username(username)
    if not clean_user:
        raise ValueError("E-mail is required.")

    updates = {}
    if new_username is not None:
        clean_new_username = validate_username_policy(new_username)
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
        validate_password_policy(password)
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
    clean_user = normalize_username(username)
    if not clean_user:
        raise ValueError("E-mail is required.")

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
