import binascii
import hashlib
import hmac
import os
import smtplib
import re
import secrets
import string
import time
from urllib.parse import parse_qs, unquote, urlencode, urlparse
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr
from typing import Optional

import requests
import streamlit as st
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token as google_id_token
from pymongo import ASCENDING, MongoClient
from pymongo.errors import (
    AutoReconnect,
    ConnectionFailure,
    DuplicateKeyError,
    NetworkTimeout,
    PyMongoError,
    ServerSelectionTimeoutError,
)

try:
    import mysql.connector as mysql_connector
    from mysql.connector import Error as MySQLError
    from mysql.connector import errorcode as MYSQL_ERRORCODE
except Exception:
    mysql_connector = None
    MySQLError = Exception
    MYSQL_ERRORCODE = None


PBKDF2_ALG = "sha256"
PBKDF2_ITERATIONS = 260_000
PBKDF2_SALT_BYTES = 16
MONGO_TIMEOUT_MS = 6000
MYSQL_DEFAULT_PORT = 3306
MYSQL_DEFAULT_CONNECT_TIMEOUT_SECONDS = 6
AUTH_DB_BACKEND_DEFAULT = "mongodb"
GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_OAUTH_SCOPES = "openid email profile"
DEFAULT_GOOGLE_OAUTH_CLOCK_SKEW_SECONDS = 90
DEFAULT_SMTP_TIMEOUT_SECONDS = 12
DEFAULT_OTP_EXPIRES_SECONDS = 60
GMAIL_EMAIL_PATTERN = re.compile(r"^[a-z0-9._%+-]+@gmail\.com$")
SPECIAL_CHARACTER_SET = set(string.punctuation)
MONGO_WRITE_RETRY_ATTEMPTS = 2
MONGO_WRITE_RETRY_SLEEP_SECONDS = 0.2
MONGO_TRANSIENT_WRITE_ERRORS = (
    AutoReconnect,
    ConnectionFailure,
    NetworkTimeout,
    ServerSelectionTimeoutError,
)


class DuplicateUsernameError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuthUser:
    name: str
    username: str
    role: str
    is_active: bool
    password_reset_required: bool = False


@dataclass(frozen=True)
class GoogleOAuthConfig:
    client_id: str
    client_secret: str
    redirect_uri: str


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int
    username: str
    password: str
    from_email: str
    from_name: str
    use_tls: bool
    use_ssl: bool


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


def normalize_display_name(name: str) -> str:
    return " ".join(str(name or "").strip().split())


def validate_display_name_policy(name: str) -> str:
    clean_name = normalize_display_name(name)
    if not clean_name:
        raise ValueError("Name is required.")
    if len(clean_name) > 100:
        raise ValueError("Name must be 100 characters or fewer.")
    return clean_name


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


def get_auth_backend() -> str:
    raw = _first_non_empty(
        [
            os.getenv("AUTH_DB_BACKEND"),
            os.getenv("AUTH_DATABASE_BACKEND"),
            _get_secret("auth.db_backend"),
            _get_secret("db_backend"),
        ]
    )
    backend = str(raw or AUTH_DB_BACKEND_DEFAULT).strip().lower()
    if backend == "mongo":
        backend = "mongodb"
    if backend not in {"mongodb", "mysql"}:
        backend = AUTH_DB_BACKEND_DEFAULT
    return backend


def _get_smtp_config() -> Optional[SmtpConfig]:
    host = _first_non_empty(
        [
            os.getenv("AUTH_SMTP_HOST"),
            os.getenv("SMTP_HOST"),
            _get_secret("auth.smtp_host"),
            _get_secret("smtp_host"),
        ]
    )
    username = _first_non_empty(
        [
            os.getenv("AUTH_SMTP_USERNAME"),
            os.getenv("SMTP_USERNAME"),
            _get_secret("auth.smtp_username"),
            _get_secret("smtp_username"),
        ]
    )
    password = _first_non_empty(
        [
            os.getenv("AUTH_SMTP_PASSWORD"),
            os.getenv("SMTP_PASSWORD"),
            _get_secret("auth.smtp_password"),
            _get_secret("smtp_password"),
        ]
    )
    from_email = _first_non_empty(
        [
            os.getenv("AUTH_SMTP_FROM_EMAIL"),
            os.getenv("SMTP_FROM_EMAIL"),
            _get_secret("auth.smtp_from_email"),
            _get_secret("smtp_from_email"),
            username,
        ]
    )
    from_name = _first_non_empty(
        [
            os.getenv("AUTH_SMTP_FROM_NAME"),
            os.getenv("SMTP_FROM_NAME"),
            _get_secret("auth.smtp_from_name"),
            _get_secret("smtp_from_name"),
            "Zeek Dashboard",
        ]
    )
    if not host or not from_email:
        return None

    use_ssl_raw = _first_non_empty(
        [
            os.getenv("AUTH_SMTP_USE_SSL"),
            os.getenv("SMTP_USE_SSL"),
            _get_secret("auth.smtp_use_ssl"),
            _get_secret("smtp_use_ssl"),
        ]
    )
    use_ssl = _coerce_bool(use_ssl_raw, default=False)
    use_tls_raw = _first_non_empty(
        [
            os.getenv("AUTH_SMTP_USE_TLS"),
            os.getenv("SMTP_USE_TLS"),
            _get_secret("auth.smtp_use_tls"),
            _get_secret("smtp_use_tls"),
        ]
    )
    use_tls = _coerce_bool(use_tls_raw, default=not use_ssl)
    if use_ssl:
        use_tls = False

    port_raw = _first_non_empty(
        [
            os.getenv("AUTH_SMTP_PORT"),
            os.getenv("SMTP_PORT"),
            _get_secret("auth.smtp_port"),
            _get_secret("smtp_port"),
        ]
    )
    default_port = 465 if use_ssl else 587
    try:
        port = int(port_raw) if port_raw is not None else default_port
    except Exception:
        port = default_port
    if port <= 0:
        port = default_port

    return SmtpConfig(
        host=str(host).strip(),
        port=int(port),
        username=str(username or "").strip(),
        password="" if password is None else str(password),
        from_email=str(from_email).strip(),
        from_name=str(from_name or "Zeek Dashboard").strip(),
        use_tls=bool(use_tls),
        use_ssl=bool(use_ssl),
    )


def _send_email(
    to_email: str,
    *,
    subject: str,
    text_body: str,
    html_body: Optional[str] = None,
) -> None:
    cfg = _get_smtp_config()
    if cfg is None:
        raise RuntimeError(
            "SMTP is not configured. Set AUTH_SMTP_HOST, AUTH_SMTP_PORT, AUTH_SMTP_FROM_EMAIL, AUTH_SMTP_USERNAME, and AUTH_SMTP_PASSWORD."
        )

    recipient = validate_username_policy(to_email)
    message = EmailMessage()
    message["Subject"] = str(subject or "").strip() or "Zeek Dashboard Notification"
    message["From"] = formataddr((cfg.from_name, cfg.from_email))
    message["To"] = recipient
    message.set_content(str(text_body or "").strip() or "Notification")
    if html_body:
        message.add_alternative(str(html_body), subtype="html")

    smtp_connection = None
    try:
        if cfg.use_ssl:
            smtp_connection = smtplib.SMTP_SSL(
                host=cfg.host,
                port=cfg.port,
                timeout=DEFAULT_SMTP_TIMEOUT_SECONDS,
            )
        else:
            smtp_connection = smtplib.SMTP(
                host=cfg.host,
                port=cfg.port,
                timeout=DEFAULT_SMTP_TIMEOUT_SECONDS,
            )
            smtp_connection.ehlo()
            if cfg.use_tls:
                smtp_connection.starttls()
                smtp_connection.ehlo()

        if cfg.username:
            smtp_connection.login(cfg.username, cfg.password)
        smtp_connection.send_message(message)
    except Exception as exc:
        if isinstance(exc, smtplib.SMTPAuthenticationError):
            raise RuntimeError(
                "SMTP authentication failed. For Gmail, set AUTH_SMTP_PASSWORD to a 16-character Google App Password."
            ) from exc
        raise RuntimeError(
            "Could not send e-mail notification. Check AUTH_SMTP_* settings and sender credentials."
        ) from exc
    finally:
        try:
            if smtp_connection is not None:
                smtp_connection.quit()
        except Exception:
            pass


def send_new_user_credentials_email(username: str, default_password: str, created_by: str) -> None:
    clean_username = validate_username_policy(username)
    clean_created_by = normalize_username(created_by) or "admin"
    clean_default_password = str(default_password or "").strip()
    if not clean_default_password:
        raise ValueError("Default password is required.")

    subject = "Your Zeek Dashboard account credentials"
    text_body = (
        "Your account has been created for Zeek Dashboard.\n\n"
        f"E-mail: {clean_username}\n"
        f"Default Password: {clean_default_password}\n\n"
        "For your security, OTP verification is required and this password must be changed after OTP verification.\n"
        f"Provisioned by: {clean_created_by}\n"
    )
    html_body = (
        "<p>Your account has been created for <strong>Zeek Dashboard</strong>.</p>"
        "<p>"
        f"E-mail: <strong>{clean_username}</strong><br>"
        f"Default Password: <strong>{clean_default_password}</strong>"
        "</p>"
        "<p>For your security, OTP verification is required and this password must be changed after OTP verification.</p>"
        f"<p>Provisioned by: <strong>{clean_created_by}</strong></p>"
    )
    _send_email(
        clean_username,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
    )


def generate_email_otp_code(length: int = 6) -> str:
    digits = "0123456789"
    safe_length = max(4, min(8, int(length or 6)))
    return "".join(secrets.choice(digits) for _ in range(safe_length))


def send_login_otp_email(username: str, otp_code: str, expires_seconds: int = DEFAULT_OTP_EXPIRES_SECONDS) -> None:
    clean_username = validate_username_policy(username)
    code = str(otp_code or "").strip()
    if not code.isdigit():
        raise ValueError("OTP code must be numeric.")
    ttl = max(30, min(600, int(expires_seconds or DEFAULT_OTP_EXPIRES_SECONDS)))
    ttl_minutes = max(1, ttl // 60)

    subject = "Your Zeek Dashboard OTP Code"
    text_body = (
        "Use this One-Time Password (OTP) to complete your Zeek Dashboard login.\n\n"
        f"OTP Code: {code}\n"
        f"Expires in: {ttl_minutes} minute(s)\n\n"
        "If you did not request this, ignore this e-mail."
    )
    html_body = (
        "<p>Use this One-Time Password (OTP) to complete your <strong>Zeek Dashboard</strong> login.</p>"
        f"<p>OTP Code: <strong style='font-size:20px;'>{code}</strong><br>"
        f"Expires in: <strong>{ttl_minutes} minute(s)</strong></p>"
        "<p>If you did not request this, ignore this e-mail.</p>"
    )
    _send_email(
        clean_username,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
    )


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


def _mysql_connect_timeout_seconds() -> int:
    raw = _first_non_empty(
        [
            os.getenv("AUTH_MYSQL_CONNECT_TIMEOUT"),
            os.getenv("MYSQL_CONNECT_TIMEOUT"),
            _get_secret("auth.mysql_connect_timeout"),
            _get_secret("mysql_connect_timeout"),
        ]
    )
    if raw is None:
        return MYSQL_DEFAULT_CONNECT_TIMEOUT_SECONDS
    try:
        value = int(raw)
    except Exception:
        return MYSQL_DEFAULT_CONNECT_TIMEOUT_SECONDS
    return max(1, min(60, value))


def _parse_mysql_uri(uri: str) -> Optional[dict]:
    text = str(uri or "").strip()
    if not text:
        return None
    parsed = urlparse(text)
    if not parsed.scheme.lower().startswith("mysql"):
        return None
    host = (parsed.hostname or "").strip()
    database = (parsed.path or "").lstrip("/").strip()
    if not host or not database:
        return None
    cfg = {
        "host": host,
        "port": int(parsed.port or MYSQL_DEFAULT_PORT),
        "user": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
        "database": database,
    }
    query = parse_qs(parsed.query or "", keep_blank_values=True)
    if "ssl_disabled" in query:
        cfg["ssl_disabled"] = _coerce_bool((query.get("ssl_disabled") or [None])[0], default=False)
    for key in ("ssl_ca", "ssl_cert", "ssl_key"):
        if key in query:
            cfg[key] = str((query.get(key) or [""])[0] or "").strip()
    return cfg


def get_mysql_config() -> Optional[dict]:
    uri_cfg = {}
    mysql_uri = _first_non_empty(
        [
            os.getenv("AUTH_MYSQL_URI"),
            os.getenv("MYSQL_URI"),
            _get_secret("auth.mysql_uri"),
            _get_secret("mysql_uri"),
        ]
    )
    if mysql_uri:
        uri_cfg = _parse_mysql_uri(mysql_uri) or {}

    host = _first_non_empty(
        [
            os.getenv("AUTH_MYSQL_HOST"),
            os.getenv("MYSQL_HOST"),
            _get_secret("auth.mysql_host"),
            _get_secret("mysql_host"),
            uri_cfg.get("host"),
        ]
    )
    port_raw = _first_non_empty(
        [
            os.getenv("AUTH_MYSQL_PORT"),
            os.getenv("MYSQL_PORT"),
            _get_secret("auth.mysql_port"),
            _get_secret("mysql_port"),
            uri_cfg.get("port"),
        ]
    )
    user = _first_non_empty(
        [
            os.getenv("AUTH_MYSQL_USER"),
            os.getenv("MYSQL_USER"),
            _get_secret("auth.mysql_user"),
            _get_secret("mysql_user"),
            uri_cfg.get("user"),
        ]
    )
    password = _first_non_empty(
        [
            os.getenv("AUTH_MYSQL_PASSWORD"),
            os.getenv("MYSQL_PASSWORD"),
            _get_secret("auth.mysql_password"),
            _get_secret("mysql_password"),
            uri_cfg.get("password"),
        ]
    )
    database = _first_non_empty(
        [
            os.getenv("AUTH_MYSQL_DATABASE"),
            os.getenv("AUTH_MYSQL_DB"),
            os.getenv("MYSQL_DATABASE"),
            os.getenv("MYSQL_DB"),
            _get_secret("auth.mysql_database"),
            _get_secret("auth.mysql_db"),
            _get_secret("mysql_database"),
            _get_secret("mysql_db"),
            uri_cfg.get("database"),
        ]
    )
    if not (host and user and database):
        return None

    try:
        port = int(port_raw) if port_raw is not None else MYSQL_DEFAULT_PORT
    except Exception:
        port = MYSQL_DEFAULT_PORT

    ssl_disabled_raw = _first_non_empty(
        [
            os.getenv("AUTH_MYSQL_SSL_DISABLED"),
            os.getenv("MYSQL_SSL_DISABLED"),
            _get_secret("auth.mysql_ssl_disabled"),
            _get_secret("mysql_ssl_disabled"),
            uri_cfg.get("ssl_disabled"),
        ]
    )
    ssl_ca = _first_non_empty(
        [
            os.getenv("AUTH_MYSQL_SSL_CA"),
            os.getenv("MYSQL_SSL_CA"),
            _get_secret("auth.mysql_ssl_ca"),
            _get_secret("mysql_ssl_ca"),
            uri_cfg.get("ssl_ca"),
        ]
    )
    ssl_cert = _first_non_empty(
        [
            os.getenv("AUTH_MYSQL_SSL_CERT"),
            os.getenv("MYSQL_SSL_CERT"),
            _get_secret("auth.mysql_ssl_cert"),
            _get_secret("mysql_ssl_cert"),
            uri_cfg.get("ssl_cert"),
        ]
    )
    ssl_key = _first_non_empty(
        [
            os.getenv("AUTH_MYSQL_SSL_KEY"),
            os.getenv("MYSQL_SSL_KEY"),
            _get_secret("auth.mysql_ssl_key"),
            _get_secret("mysql_ssl_key"),
            uri_cfg.get("ssl_key"),
        ]
    )

    cfg = {
        "host": str(host).strip(),
        "port": int(port),
        "user": str(user).strip(),
        "password": "" if password is None else str(password),
        "database": str(database).strip(),
        "connection_timeout": _mysql_connect_timeout_seconds(),
        "autocommit": False,
    }
    if _coerce_bool(ssl_disabled_raw, default=False):
        cfg["ssl_disabled"] = True
    else:
        if ssl_ca:
            cfg["ssl_ca"] = str(ssl_ca).strip()
        if ssl_cert:
            cfg["ssl_cert"] = str(ssl_cert).strip()
        if ssl_key:
            cfg["ssl_key"] = str(ssl_key).strip()
    return cfg


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

    row = _fetch_user_row(email)
    if not row:
        _audit_login(email, False, "user_not_found")
        return None
    if not bool(row.get("is_active", False)):
        _audit_login(email, False, "inactive_user")
        return None

    now = datetime.now(timezone.utc)
    _update_user_row(email, {"last_login_at": now, "updated_at": now})

    _audit_login(email, True, "ok_google_oauth")
    row_copy = dict(row)
    row_copy["last_login_at"] = now
    return _auth_user_from_row(row_copy, fallback_username=email)


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


def get_auth_connection_fingerprint() -> Optional[str]:
    if get_auth_backend() == "mysql":
        cfg = get_mysql_config()
        if not cfg:
            return None
        user = str(cfg.get("user", "")).strip()
        host = str(cfg.get("host", "")).strip()
        port = str(cfg.get("port", "")).strip()
        database = str(cfg.get("database", "")).strip()
        return f"mysql://{user}@{host}:{port}/{database}"
    return get_mongodb_uri()


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


def _mysql_connect():
    if mysql_connector is None:
        raise RuntimeError("MySQL backend requested but mysql-connector-python is not installed.")

    cfg = get_mysql_config()
    if not cfg:
        raise RuntimeError(
            "MySQL is not configured. Set AUTH_MYSQL_HOST, AUTH_MYSQL_PORT, AUTH_MYSQL_USER, AUTH_MYSQL_PASSWORD, "
            "AUTH_MYSQL_DATABASE (or AUTH_MYSQL_URI), and set AUTH_DB_BACKEND=mysql."
        )

    try:
        return mysql_connector.connect(**cfg)
    except MySQLError as exc:
        raise RuntimeError(
            "Could not connect to MySQL. Check AUTH_MYSQL_* credentials, database name, network/IP allowlist, and server reachability."
        ) from exc


def _mysql_errno(exc: Exception) -> Optional[int]:
    try:
        raw = getattr(exc, "errno", None)
        if raw is None:
            return None
        return int(raw)
    except Exception:
        return None


def _is_mysql_duplicate_entry(exc: Exception) -> bool:
    code = _mysql_errno(exc)
    if code is None:
        return False
    if MYSQL_ERRORCODE is not None:
        try:
            return code == int(MYSQL_ERRORCODE.ER_DUP_ENTRY)
        except Exception:
            return code == 1062
    return code == 1062


def _to_mysql_datetime(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime) and value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _auth_user_from_row(row: dict, fallback_username: str) -> AuthUser:
    return AuthUser(
        name=normalize_display_name(str(row.get("name", "") or "")),
        username=str(row.get("username", fallback_username)),
        role=str(row.get("role", "staff")),
        is_active=bool(row.get("is_active", True)),
        password_reset_required=bool(row.get("password_reset_required", False)),
    )


def _fetch_user_row(username: str) -> Optional[dict]:
    backend = get_auth_backend()
    if backend == "mysql":
        conn = _mysql_connect()
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(
                """
                SELECT
                    name,
                    username,
                    password_hash,
                    password_reset_required,
                    role,
                    is_active,
                    created_at,
                    updated_at,
                    last_login_at,
                    created_by
                FROM app_users
                WHERE username = %s
                LIMIT 1
                """,
                (username,),
            )
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            cur.close()
            conn.close()

    row = _get_db()["app_users"].find_one({"username": username})
    return dict(row) if row else None


def _count_users() -> int:
    backend = get_auth_backend()
    if backend == "mysql":
        conn = _mysql_connect()
        cur = conn.cursor()
        try:
            cur.execute("SELECT COUNT(*) FROM app_users")
            row = cur.fetchone()
            return int((row or [0])[0] or 0)
        finally:
            cur.close()
            conn.close()
    return int(_get_db()["app_users"].count_documents({}))


def _insert_user_row(payload: dict) -> None:
    backend = get_auth_backend()
    if backend == "mysql":
        conn = _mysql_connect()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO app_users (
                    name, username, password_hash, password_reset_required, role, is_active, created_at, updated_at, last_login_at, created_by
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(payload.get("name", "") or ""),
                    str(payload.get("username", "") or ""),
                    str(payload.get("password_hash", "") or ""),
                    1 if bool(payload.get("password_reset_required", False)) else 0,
                    str(payload.get("role", "staff") or "staff"),
                    1 if bool(payload.get("is_active", True)) else 0,
                    _to_mysql_datetime(payload.get("created_at")),
                    _to_mysql_datetime(payload.get("updated_at")),
                    _to_mysql_datetime(payload.get("last_login_at")),
                    str(payload.get("created_by", "") or ""),
                ),
            )
            conn.commit()
            return
        except MySQLError as exc:
            conn.rollback()
            if _is_mysql_duplicate_entry(exc):
                raise DuplicateUsernameError("Username already exists.") from exc
            raise
        finally:
            cur.close()
            conn.close()

    try:
        for attempt in range(MONGO_WRITE_RETRY_ATTEMPTS):
            try:
                _get_db()["app_users"].insert_one(payload)
                break
            except MONGO_TRANSIENT_WRITE_ERRORS:
                if attempt >= (MONGO_WRITE_RETRY_ATTEMPTS - 1):
                    raise
                time.sleep(MONGO_WRITE_RETRY_SLEEP_SECONDS)
    except DuplicateKeyError as exc:
        raise DuplicateUsernameError("Username already exists.") from exc


def _update_user_row(username: str, updates: dict) -> int:
    if not updates:
        return 0

    backend = get_auth_backend()
    if backend == "mysql":
        allowed_cols = {
            "name",
            "username",
            "password_hash",
            "password_reset_required",
            "role",
            "is_active",
            "created_at",
            "updated_at",
            "last_login_at",
            "created_by",
        }
        set_parts = []
        params = []
        for key, value in updates.items():
            if key not in allowed_cols:
                continue
            if key in {"created_at", "updated_at", "last_login_at"}:
                value = _to_mysql_datetime(value)
            if key in {"is_active", "password_reset_required"}:
                value = 1 if bool(value) else 0
            set_parts.append(f"{key} = %s")
            params.append(value)
        if not set_parts:
            return 0

        conn = _mysql_connect()
        cur = conn.cursor()
        try:
            cur.execute(
                f"UPDATE app_users SET {', '.join(set_parts)} WHERE username = %s",
                tuple(params + [username]),
            )
            conn.commit()
            return int(cur.rowcount or 0)
        except MySQLError as exc:
            conn.rollback()
            if _is_mysql_duplicate_entry(exc):
                raise DuplicateUsernameError("Username already exists.") from exc
            raise
        finally:
            cur.close()
            conn.close()

    try:
        result = _get_db()["app_users"].update_one({"username": username}, {"$set": updates})
    except DuplicateKeyError as exc:
        raise DuplicateUsernameError("Username already exists.") from exc
    return int(result.matched_count or 0)


def _delete_user_row(username: str) -> int:
    backend = get_auth_backend()
    if backend == "mysql":
        conn = _mysql_connect()
        cur = conn.cursor()
        try:
            cur.execute("DELETE FROM app_users WHERE username = %s", (username,))
            conn.commit()
            return int(cur.rowcount or 0)
        finally:
            cur.close()
            conn.close()

    result = _get_db()["app_users"].delete_one({"username": username})
    return int(result.deleted_count or 0)


def _list_user_rows() -> list[dict]:
    backend = get_auth_backend()
    if backend == "mysql":
        conn = _mysql_connect()
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(
                """
                SELECT name, username, role, is_active, password_reset_required, created_by, created_at, last_login_at
                FROM app_users
                ORDER BY username ASC
                """
            )
            return [dict(row) for row in (cur.fetchall() or [])]
        finally:
            cur.close()
            conn.close()

    rows = _get_db()["app_users"].find({}, {"_id": 0, "password_hash": 0}).sort("username", ASCENDING)
    return [dict(row) for row in rows]


def _insert_audit_row(username: str, success: bool, reason: str, occurred_at: datetime) -> None:
    backend = get_auth_backend()
    if backend == "mysql":
        conn = _mysql_connect()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO auth_login_audit (username, success, reason, occurred_at)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    str(username or "unknown").strip().lower(),
                    1 if bool(success) else 0,
                    str(reason or "")[:120],
                    _to_mysql_datetime(occurred_at),
                ),
            )
            conn.commit()
        finally:
            cur.close()
            conn.close()
        return

    _get_db()["auth_login_audit"].insert_one(
        {
            "username": (username or "unknown").strip().lower(),
            "success": bool(success),
            "reason": (reason or "")[:120],
            "occurred_at": occurred_at,
        }
    )


def _mysql_index_exists(cur, table_name: str, index_name: str) -> bool:
    cur.execute(
        """
        SELECT 1
        FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s
          AND INDEX_NAME = %s
        LIMIT 1
        """,
        (table_name, index_name),
    )
    return cur.fetchone() is not None


def _mysql_column_exists(cur, table_name: str, column_name: str) -> bool:
    cur.execute(
        """
        SELECT 1
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s
          AND COLUMN_NAME = %s
        LIMIT 1
        """,
        (table_name, column_name),
    )
    return cur.fetchone() is not None


def _init_mysql_auth_schema() -> None:
    conn = _mysql_connect()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS app_users (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                name VARCHAR(100) NOT NULL,
                username VARCHAR(255) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                password_reset_required TINYINT(1) NOT NULL DEFAULT 0,
                role VARCHAR(20) NOT NULL DEFAULT 'staff',
                is_active TINYINT(1) NOT NULL DEFAULT 1,
                created_at DATETIME(6) NOT NULL,
                updated_at DATETIME(6) NOT NULL,
                last_login_at DATETIME(6) NULL,
                created_by VARCHAR(255) NOT NULL DEFAULT '',
                PRIMARY KEY (id),
                UNIQUE KEY ux_app_users_username (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_login_audit (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                username VARCHAR(255) NOT NULL,
                success TINYINT(1) NOT NULL,
                reason VARCHAR(120) NOT NULL DEFAULT '',
                occurred_at DATETIME(6) NOT NULL,
                PRIMARY KEY (id),
                KEY ix_auth_login_audit_occurred_at (occurred_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """
        )

        if not _mysql_column_exists(cur, "app_users", "password_reset_required"):
            cur.execute(
                """
                ALTER TABLE app_users
                ADD COLUMN password_reset_required TINYINT(1) NOT NULL DEFAULT 0
                AFTER password_hash
                """
            )
        if not _mysql_index_exists(cur, "app_users", "ux_app_users_username"):
            cur.execute("CREATE UNIQUE INDEX ux_app_users_username ON app_users (username)")
        if not _mysql_index_exists(cur, "auth_login_audit", "ix_auth_login_audit_occurred_at"):
            cur.execute("CREATE INDEX ix_auth_login_audit_occurred_at ON auth_login_audit (occurred_at)")
        conn.commit()
    finally:
        cur.close()
        conn.close()


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
    if get_auth_backend() == "mysql":
        _init_mysql_auth_schema()
        return

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

    if _count_users() > 0:
        return

    clean_username = validate_username_policy(username)
    now = datetime.now(timezone.utc)
    try:
        _insert_user_row(
            {
                "name": "Administrator",
                "username": clean_username,
                "password_hash": hash_password(password),
                "password_reset_required": False,
                "role": "admin",
                "is_active": True,
                "created_at": now,
                "updated_at": now,
                "last_login_at": None,
                "created_by": "bootstrap",
            }
        )
    except DuplicateUsernameError:
        return


def _audit_login(username: str, success: bool, reason: str = "") -> None:
    try:
        _insert_audit_row(
            username=(username or "unknown").strip().lower(),
            success=bool(success),
            reason=(reason or "")[:120],
            occurred_at=datetime.now(timezone.utc),
        )
    except Exception:
        return


def _authenticate_password_credentials(
    username: str,
    password: str,
    *,
    update_last_login: bool,
    success_reason: Optional[str],
) -> Optional[AuthUser]:
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

    row = _fetch_user_row(clean_user)

    # Backward compatibility: allow legacy local usernames (e.g. "admin")
    # to authenticate via "<name>@gmail.com", then migrate them in place.
    if not row and clean_user.endswith("@gmail.com"):
        legacy_username = clean_user.split("@", 1)[0].strip().lower()
        if legacy_username:
            legacy_row = _fetch_user_row(legacy_username)
            if legacy_row:
                if not bool(legacy_row.get("is_active", False)):
                    _audit_login(clean_user, False, "inactive_user")
                    return None
                if not verify_password(password, legacy_row.get("password_hash", "")):
                    _audit_login(clean_user, False, "invalid_password")
                    return None

                now = datetime.now(timezone.utc)
                migration_updates = {"username": clean_user, "updated_at": now}
                if update_last_login:
                    migration_updates["last_login_at"] = now
                try:
                    _update_user_row(
                        legacy_username,
                        migration_updates,
                    )
                except DuplicateUsernameError:
                    _audit_login(clean_user, False, "username_conflict_during_migration")
                    return None

                result_row = dict(legacy_row)
                result_row["username"] = clean_user
                if update_last_login:
                    result_row["last_login_at"] = now
                if success_reason:
                    _audit_login(clean_user, True, success_reason)
                return _auth_user_from_row(result_row, fallback_username=clean_user)

    if not row:
        _audit_login(clean_user, False, "user_not_found")
        return None
    if not bool(row.get("is_active", False)):
        _audit_login(clean_user, False, "inactive_user")
        return None
    if not verify_password(password, row.get("password_hash", "")):
        _audit_login(clean_user, False, "invalid_password")
        return None

    result_row = dict(row)
    if update_last_login:
        now = datetime.now(timezone.utc)
        _update_user_row(clean_user, {"last_login_at": now, "updated_at": now})
        result_row["last_login_at"] = now

    if success_reason:
        _audit_login(clean_user, True, success_reason)
    return _auth_user_from_row(
        result_row,
        fallback_username=clean_user,
    )


def verify_user_credentials_for_otp(username: str, password: str) -> Optional[AuthUser]:
    return _authenticate_password_credentials(
        username=username,
        password=password,
        update_last_login=False,
        success_reason="ok_credentials_verified_pending_otp",
    )


def authenticate_user_password_only(username: str, password: str) -> Optional[AuthUser]:
    return _authenticate_password_credentials(
        username=username,
        password=password,
        update_last_login=True,
        success_reason="ok",
    )


def complete_login_after_otp(username: str) -> Optional[AuthUser]:
    clean_user = normalize_username(username)
    if not clean_user:
        _audit_login("unknown", False, "missing_credentials")
        return None
    if not is_valid_gmail_email(clean_user):
        _audit_login(clean_user, False, "invalid_email_domain")
        return None
    if not is_email_allowed_for_login(clean_user):
        _audit_login(clean_user, False, "email_not_allowlisted")
        return None

    row = _fetch_user_row(clean_user)
    if not row:
        _audit_login(clean_user, False, "user_not_found")
        return None
    if not bool(row.get("is_active", False)):
        _audit_login(clean_user, False, "inactive_user")
        return None

    now = datetime.now(timezone.utc)
    _update_user_row(clean_user, {"last_login_at": now, "updated_at": now})
    _audit_login(clean_user, True, "ok_otp")

    result_row = dict(row)
    result_row["last_login_at"] = now
    return _auth_user_from_row(result_row, fallback_username=clean_user)


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

    row = _fetch_user_row(clean_user)
    if not row:
        return None
    if not bool(row.get("is_active", False)):
        return None

    return _auth_user_from_row(row, fallback_username=clean_user)


def create_user(name: str, username: str, password: str, role: str, created_by: str) -> None:
    clean_name = validate_display_name_policy(name)
    clean_user = validate_username_policy(username)
    clean_role = (role or "").strip().lower()
    if clean_role not in {"admin", "staff"}:
        raise ValueError("Role must be admin or staff.")
    clean_created_by = normalize_username(created_by) or "system"

    now = datetime.now(timezone.utc)
    try:
        _insert_user_row(
            {
                "name": clean_name,
                "username": clean_user,
                "password_hash": hash_password(password),
                "password_reset_required": True,
                "role": clean_role,
                "is_active": True,
                "created_at": now,
                "updated_at": now,
                "last_login_at": None,
                "created_by": clean_created_by,
            }
        )
    except DuplicateUsernameError as exc:
        raise ValueError("Username already exists.") from exc
    except PyMongoError as exc:
        raise RuntimeError("Database error while creating user.") from exc


def set_user_status(username: str, is_active: bool) -> None:
    clean_user = normalize_username(username)
    _update_user_row(
        clean_user,
        {"is_active": bool(is_active), "updated_at": datetime.now(timezone.utc)},
    )


def complete_default_password_reset(username: str, new_password: str) -> None:
    clean_user = normalize_username(username)
    if not clean_user:
        raise ValueError("E-mail is required.")
    validate_password_policy(new_password)

    row = _fetch_user_row(clean_user)
    if not row:
        raise ValueError("User not found.")
    if not bool(row.get("is_active", False)):
        raise ValueError("User is inactive.")
    if verify_password(new_password, str(row.get("password_hash", "") or "")):
        raise ValueError("New password must be different from the current password.")

    _update_user_row(
        clean_user,
        {
            "password_hash": hash_password(new_password),
            "password_reset_required": False,
            "updated_at": datetime.now(timezone.utc),
        },
    )


def update_user(
    username: str,
    *,
    name: Optional[str] = None,
    new_username: Optional[str] = None,
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    password: Optional[str] = None,
    password_reset_required: Optional[bool] = None,
) -> None:
    clean_user = normalize_username(username)
    if not clean_user:
        raise ValueError("E-mail is required.")

    updates = {}
    if name is not None:
        updates["name"] = validate_display_name_policy(name)
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
        if password_reset_required is None:
            updates["password_reset_required"] = True
    if password_reset_required is not None:
        updates["password_reset_required"] = bool(password_reset_required)

    if not updates:
        raise ValueError("No updates were provided.")

    updates["updated_at"] = datetime.now(timezone.utc)
    try:
        matched_count = _update_user_row(clean_user, updates)
    except DuplicateUsernameError as exc:
        raise ValueError("Username already exists.") from exc
    if matched_count == 0:
        raise ValueError("User not found.")


def delete_user(username: str) -> None:
    clean_user = normalize_username(username)
    if not clean_user:
        raise ValueError("E-mail is required.")

    deleted_count = _delete_user_row(clean_user)
    if deleted_count == 0:
        raise ValueError("User not found.")


def list_users():
    rows = _list_user_rows()
    users = []
    for row in rows:
        users.append(
            {
                "name": normalize_display_name(str(row.get("name", "") or "")),
                "username": row.get("username", ""),
                "role": row.get("role", ""),
                "is_active": bool(row.get("is_active")),
                "password_reset_required": bool(row.get("password_reset_required")),
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
