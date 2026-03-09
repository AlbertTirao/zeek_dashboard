import base64
import hashlib
import hmac
import json
import os
import secrets as py_secrets
import time
from pathlib import Path
from typing import Optional

import streamlit as st

from services import auth_service
from services.auth_service import (
    authenticate_google_oauth_code,
    build_google_oauth_authorization_url,
    complete_default_password_reset,
    complete_login_after_otp,
    generate_email_otp_code,
    is_email_allowed_for_login,
    is_google_oauth_configured,
    is_valid_gmail_email,
    password_has_special_character,
    send_login_otp_email,
    verify_user_credentials_for_otp,
)


PERSISTENT_AUTH_QUERY_KEY = "auth"
PERSISTENT_AUTH_STORE_FILE = Path(".streamlit") / "auth_session_store.json"
PERSISTENT_AUTH_STORE_MAX_ROWS = 256
DEFAULT_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
GOOGLE_OAUTH_STATE_SESSION_KEY = "google_oauth_state"
GOOGLE_OAUTH_EXPECTED_EMAIL_SESSION_KEY = "google_oauth_expected_email"
GOOGLE_OAUTH_STATE_TTL_SECONDS = 10 * 60
LOGIN_CAPTCHA_A_SESSION_KEY = "login_captcha_a"
LOGIN_CAPTCHA_B_SESSION_KEY = "login_captcha_b"
LOGIN_CAPTCHA_ANSWER_SESSION_KEY = "login_captcha_answer"
LOGIN_CAPTCHA_INPUT_SESSION_KEY = "login_captcha_input"
LOGIN_CAPTCHA_CLEAR_INPUT_FLAG_SESSION_KEY = "login_captcha_clear_input_flag"
LOGIN_STAGE_SESSION_KEY = "login_stage"
LOGIN_PENDING_USER_SESSION_KEY = "login_pending_user"
LOGIN_OTP_HASH_SESSION_KEY = "login_otp_hash"
LOGIN_OTP_EXPIRES_AT_SESSION_KEY = "login_otp_expires_at"
LOGIN_OTP_SENT_AT_SESSION_KEY = "login_otp_sent_at"
LOGIN_FEEDBACK_MESSAGE_SESSION_KEY = "login_feedback_message"
LOGIN_FEEDBACK_LEVEL_SESSION_KEY = "login_feedback_level"
LOGIN_STAGE_CREDENTIALS = "credentials"
LOGIN_STAGE_OTP = "otp"
LOGIN_STAGE_PASSWORD_RESET = "password_reset"
LOGIN_OTP_EXPIRES_SECONDS = 60
GOOGLE_OAUTH_QUERY_KEYS = (
    "code",
    "state",
    "scope",
    "authuser",
    "prompt",
    "error",
    "error_description",
)


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


def _session_secret() -> Optional[bytes]:
    secret = _first_non_empty(
        [
            os.getenv("AUTH_SESSION_SECRET"),
            os.getenv("SESSION_SECRET"),
            _get_secret("auth.session_secret"),
            _get_secret("auth_session_secret"),
            os.getenv("STREAMLIT_SERVER_COOKIE_SECRET"),
        ]
    )
    if not secret:
        # Fallback keeps persistence working without extra setup in local environments.
        secret = auth_service.get_auth_connection_fingerprint()
    if not secret:
        return None
    return str(secret).encode("utf-8")


def _session_ttl_seconds() -> int:
    raw = _first_non_empty(
        [
            os.getenv("AUTH_SESSION_TTL_SECONDS"),
            _get_secret("auth.session_ttl_seconds"),
            _get_secret("auth_session_ttl_seconds"),
        ]
    )
    if raw is None:
        return DEFAULT_SESSION_TTL_SECONDS
    try:
        ttl = int(raw)
        if ttl >= 300:
            return ttl
    except Exception:
        pass
    return DEFAULT_SESSION_TTL_SECONDS


def _reset_login_captcha() -> None:
    # Keep numbers compact so humans solve quickly while still blocking scripted noise.
    a = 10 + py_secrets.randbelow(41)  # 10..50
    b = 10 + py_secrets.randbelow(41)  # 10..50
    st.session_state[LOGIN_CAPTCHA_A_SESSION_KEY] = int(a)
    st.session_state[LOGIN_CAPTCHA_B_SESSION_KEY] = int(b)
    st.session_state[LOGIN_CAPTCHA_ANSWER_SESSION_KEY] = int(a + b)
    # Do not mutate widget-bound session keys in the same run after render.
    # Mark input for clearing on next run before widget instantiation.
    st.session_state[LOGIN_CAPTCHA_CLEAR_INPUT_FLAG_SESSION_KEY] = True


def _ensure_login_captcha() -> None:
    a = st.session_state.get(LOGIN_CAPTCHA_A_SESSION_KEY)
    b = st.session_state.get(LOGIN_CAPTCHA_B_SESSION_KEY)
    expected = st.session_state.get(LOGIN_CAPTCHA_ANSWER_SESSION_KEY)
    if not isinstance(a, int) or not isinstance(b, int) or expected != (a + b):
        _reset_login_captcha()


def _parse_captcha_answer(raw_value: str) -> Optional[int]:
    cleaned = str(raw_value or "").strip()
    if not cleaned:
        return None
    if not cleaned.isdigit():
        return None
    try:
        return int(cleaned)
    except Exception:
        return None


def _set_login_feedback(message: str, level: str = "info") -> None:
    text = str(message or "").strip()
    if not text:
        return
    lvl = str(level or "info").strip().lower()
    if lvl not in {"info", "success", "warning", "error"}:
        lvl = "info"
    st.session_state[LOGIN_FEEDBACK_MESSAGE_SESSION_KEY] = text
    st.session_state[LOGIN_FEEDBACK_LEVEL_SESSION_KEY] = lvl


def _show_login_feedback() -> None:
    message = str(st.session_state.pop(LOGIN_FEEDBACK_MESSAGE_SESSION_KEY, "") or "").strip()
    if not message:
        return
    level = str(st.session_state.pop(LOGIN_FEEDBACK_LEVEL_SESSION_KEY, "info") or "info").strip().lower()
    if level == "success":
        st.success(message)
    elif level == "warning":
        st.warning(message)
    elif level == "error":
        st.error(message)
    else:
        st.info(message)


def _login_stage() -> str:
    raw_stage = str(st.session_state.get(LOGIN_STAGE_SESSION_KEY, LOGIN_STAGE_CREDENTIALS) or "").strip().lower()
    if raw_stage not in {LOGIN_STAGE_CREDENTIALS, LOGIN_STAGE_OTP, LOGIN_STAGE_PASSWORD_RESET}:
        raw_stage = LOGIN_STAGE_CREDENTIALS
    st.session_state[LOGIN_STAGE_SESSION_KEY] = raw_stage
    return raw_stage


def _set_login_stage(stage: str) -> None:
    clean_stage = str(stage or "").strip().lower()
    if clean_stage not in {LOGIN_STAGE_CREDENTIALS, LOGIN_STAGE_OTP, LOGIN_STAGE_PASSWORD_RESET}:
        clean_stage = LOGIN_STAGE_CREDENTIALS
    st.session_state[LOGIN_STAGE_SESSION_KEY] = clean_stage


def _pending_login_user() -> Optional[dict]:
    row = st.session_state.get(LOGIN_PENDING_USER_SESSION_KEY)
    if not isinstance(row, dict):
        return None
    username = str(row.get("username", "") or "").strip().lower()
    if not username:
        return None
    return row


def _clear_pending_login_flow(*, reset_stage: bool = True) -> None:
    for key in (
        LOGIN_PENDING_USER_SESSION_KEY,
        LOGIN_OTP_HASH_SESSION_KEY,
        LOGIN_OTP_EXPIRES_AT_SESSION_KEY,
        LOGIN_OTP_SENT_AT_SESSION_KEY,
    ):
        st.session_state.pop(key, None)
    if reset_stage:
        _set_login_stage(LOGIN_STAGE_CREDENTIALS)


def _otp_signature(username: str, otp_code: str) -> str:
    secret = _session_secret() or b"otp-session-secret"
    payload = f"{str(username or '').strip().lower()}|{str(otp_code or '').strip()}".encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def _issue_and_send_login_otp(username: str) -> None:
    clean_username = str(username or "").strip().lower()
    code = generate_email_otp_code(length=6)
    send_login_otp_email(clean_username, code, expires_seconds=LOGIN_OTP_EXPIRES_SECONDS)
    now = int(time.time())
    st.session_state[LOGIN_OTP_HASH_SESSION_KEY] = _otp_signature(clean_username, code)
    st.session_state[LOGIN_OTP_SENT_AT_SESSION_KEY] = now
    st.session_state[LOGIN_OTP_EXPIRES_AT_SESSION_KEY] = now + LOGIN_OTP_EXPIRES_SECONDS


def _otp_seconds_remaining() -> int:
    expires_at = int(st.session_state.get(LOGIN_OTP_EXPIRES_AT_SESSION_KEY, 0) or 0)
    return max(0, expires_at - int(time.time()))


def _complete_authenticated_session(user) -> None:
    st.session_state.auth_user = {
        "name": user.name,
        "username": user.username,
        "role": user.role,
        "is_active": user.is_active,
    }
    _clear_pending_login_flow(reset_stage=True)
    _reset_login_captcha()
    persist_auth_session(user.username)
    st.rerun()


def _begin_google_oauth_after_otp(clean_username: str) -> None:
    state = _issue_google_oauth_state(clean_username)
    if not state:
        st.error("Google sign-in is not configured correctly.")
        st.stop()

    st.session_state[GOOGLE_OAUTH_STATE_SESSION_KEY] = state
    st.session_state[GOOGLE_OAUTH_EXPECTED_EMAIL_SESSION_KEY] = clean_username
    _clear_pending_login_flow(reset_stage=True)

    oauth_url = build_google_oauth_authorization_url(state)
    if not oauth_url:
        st.error("Google sign-in is not configured correctly.")
        st.stop()

    st.info("OTP verified. Redirecting to Google sign-in...")
    st.markdown(
        f"<meta http-equiv='refresh' content='0;url={oauth_url}'>",
        unsafe_allow_html=True,
    )
    st.link_button(
        "Continue to Google Sign-In",
        oauth_url,
        width="stretch",
    )
    st.stop()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _issue_persistent_auth_token(username: str) -> Optional[str]:
    clean_username = (username or "").strip().lower()
    secret = _session_secret()
    if not clean_username or not secret:
        return None
    now = int(time.time())
    payload = {"u": clean_username, "iat": now, "exp": now + _session_ttl_seconds()}
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(secret, payload_bytes, hashlib.sha256).digest()
    return f"{_b64url_encode(payload_bytes)}.{_b64url_encode(signature)}"


def _issue_google_oauth_state(expected_email: str) -> Optional[str]:
    clean_email = (expected_email or "").strip().lower()
    secret = _session_secret()
    if not clean_email or not secret:
        return None
    now = int(time.time())
    payload = {
        "e": clean_email,
        "iat": now,
        "exp": now + GOOGLE_OAUTH_STATE_TTL_SECONDS,
        "n": py_secrets.token_urlsafe(16),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(secret, payload_bytes, hashlib.sha256).digest()
    return f"{_b64url_encode(payload_bytes)}.{_b64url_encode(signature)}"


def _verify_google_oauth_state(state: str) -> Optional[str]:
    secret = _session_secret()
    if not secret or not state:
        return None
    try:
        payload_part, signature_part = state.split(".", 1)
        payload_bytes = _b64url_decode(payload_part)
        provided_signature = _b64url_decode(signature_part)
        expected_signature = hmac.new(secret, payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(provided_signature, expected_signature):
            return None
        payload = json.loads(payload_bytes.decode("utf-8"))
        expected_email = str(payload.get("e", "")).strip().lower()
        exp = int(payload.get("exp", 0))
        if not expected_email or exp < int(time.time()):
            return None
        return expected_email
    except Exception:
        return None


def _verify_persistent_auth_token(token: str) -> Optional[str]:
    secret = _session_secret()
    if not secret or not token:
        return None
    try:
        payload_part, signature_part = token.split(".", 1)
        payload_bytes = _b64url_decode(payload_part)
        provided_signature = _b64url_decode(signature_part)
        expected_signature = hmac.new(secret, payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(provided_signature, expected_signature):
            return None
        payload = json.loads(payload_bytes.decode("utf-8"))
        username = str(payload.get("u", "")).strip().lower()
        exp = int(payload.get("exp", 0))
        if not username or exp < int(time.time()):
            return None
        return username
    except Exception:
        return None


def _query_param_value(key: str) -> Optional[str]:
    token = st.query_params.get(key)
    if isinstance(token, list):
        token = token[0] if token else ""
    token = str(token or "").strip()
    return token or None


def _query_param_auth_token() -> Optional[str]:
    return _query_param_value(PERSISTENT_AUTH_QUERY_KEY)


def _current_client_fingerprint() -> Optional[str]:
    try:
        ip_address = str(getattr(st.context, "ip_address", "") or "").strip().lower()
        headers = getattr(st.context, "headers", {}) or {}
        user_agent = str(
            headers.get("User-Agent")
            or headers.get("user-agent")
            or ""
        ).strip().lower()
    except Exception:
        return None

    if not ip_address and not user_agent:
        return None

    source = f"{ip_address}|{user_agent}"
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _load_persistent_auth_store() -> dict:
    path = PERSISTENT_AUTH_STORE_FILE
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _save_persistent_auth_store(store: dict) -> None:
    path = PERSISTENT_AUTH_STORE_FILE
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(store, separators=(",", ":"), sort_keys=True)
        temp_path = path.with_suffix(".tmp")
        temp_path.write_text(serialized, encoding="utf-8")
        temp_path.replace(path)
    except Exception:
        return


def _save_local_persistent_auth_token(token: str) -> None:
    client_key = _current_client_fingerprint()
    clean_token = str(token or "").strip()
    if not client_key or not clean_token:
        return

    store = _load_persistent_auth_store()
    sessions = store.get("sessions")
    if not isinstance(sessions, dict):
        sessions = {}

    sessions[client_key] = {
        "token": clean_token,
        "updated_at": int(time.time()),
    }

    if len(sessions) > PERSISTENT_AUTH_STORE_MAX_ROWS:
        oldest_rows = sorted(
            sessions.items(),
            key=lambda row: int((row[1] or {}).get("updated_at", 0)) if isinstance(row[1], dict) else 0,
        )
        overflow = len(sessions) - PERSISTENT_AUTH_STORE_MAX_ROWS
        for key, _ in oldest_rows[:overflow]:
            sessions.pop(key, None)

    store["sessions"] = sessions
    _save_persistent_auth_store(store)


def _remove_local_persistent_auth_token() -> None:
    client_key = _current_client_fingerprint()
    if not client_key:
        return

    store = _load_persistent_auth_store()
    sessions = store.get("sessions")
    if not isinstance(sessions, dict):
        return

    if client_key in sessions:
        sessions.pop(client_key, None)
        store["sessions"] = sessions
        _save_persistent_auth_store(store)


def _local_persistent_auth_token() -> Optional[str]:
    client_key = _current_client_fingerprint()
    if not client_key:
        return None

    store = _load_persistent_auth_store()
    sessions = store.get("sessions")
    if not isinstance(sessions, dict):
        return None

    row = sessions.get(client_key)
    if not isinstance(row, dict):
        return None

    token = str(row.get("token") or "").strip()
    if not token:
        sessions.pop(client_key, None)
        store["sessions"] = sessions
        _save_persistent_auth_store(store)
        return None
    return token


def persist_auth_session(username: str) -> None:
    token = _issue_persistent_auth_token(username)
    if token:
        st.query_params[PERSISTENT_AUTH_QUERY_KEY] = token
        _save_local_persistent_auth_token(token)


def clear_persistent_auth_session() -> None:
    if PERSISTENT_AUTH_QUERY_KEY in st.query_params:
        del st.query_params[PERSISTENT_AUTH_QUERY_KEY]
    _remove_local_persistent_auth_token()


def _clear_google_oauth_query_params() -> None:
    for key in GOOGLE_OAUTH_QUERY_KEYS:
        if key in st.query_params:
            del st.query_params[key]


def _handle_google_oauth_callback() -> None:
    if not is_google_oauth_configured():
        return

    oauth_error = _query_param_value("error")
    if oauth_error:
        detail = _query_param_value("error_description")
        st.error("Google sign-in was cancelled or failed.")
        if detail:
            st.caption(detail)
        _clear_google_oauth_query_params()
        return

    code = _query_param_value("code")
    if not code:
        return

    returned_state = _query_param_value("state")
    expected_email = _verify_google_oauth_state(str(returned_state or "").strip())
    if not expected_email:
        st.error("Google sign-in verification failed. Please try again.")
        _clear_google_oauth_query_params()
        st.session_state.pop(GOOGLE_OAUTH_STATE_SESSION_KEY, None)
        st.session_state.pop(GOOGLE_OAUTH_EXPECTED_EMAIL_SESSION_KEY, None)
        return

    try:
        user = authenticate_google_oauth_code(code, expected_email=expected_email)
    except Exception as e:
        st.error("Google sign-in is unavailable.")
        detail = str(e)
        if "Token used too early" in detail or "Token expired" in detail:
            st.caption("System clock mismatch detected. Turn on automatic date/time and retry login.")
        else:
            st.caption(detail)
        _clear_google_oauth_query_params()
        st.session_state.pop(GOOGLE_OAUTH_STATE_SESSION_KEY, None)
        st.session_state.pop(GOOGLE_OAUTH_EXPECTED_EMAIL_SESSION_KEY, None)
        return

    _clear_google_oauth_query_params()
    st.session_state.pop(GOOGLE_OAUTH_STATE_SESSION_KEY, None)
    st.session_state.pop(GOOGLE_OAUTH_EXPECTED_EMAIL_SESSION_KEY, None)

    if user is None:
        st.error("Google account verification failed for the entered e-mail.")
        return

    st.session_state.auth_user = {
        "name": user.name,
        "username": user.username,
        "role": user.role,
        "is_active": user.is_active,
    }
    persist_auth_session(user.username)
    st.rerun()


def _restore_user_from_persistent_auth() -> None:
    if is_authenticated():
        return

    token = _query_param_auth_token()
    if not token:
        token = _local_persistent_auth_token()
    if not token:
        return

    username = _verify_persistent_auth_token(token)
    if not username:
        clear_persistent_auth_session()
        return

    try:
        user = auth_service.get_active_user(username)
    except Exception:
        # Keep the token if backend is temporarily unavailable.
        return

    if user is None:
        clear_persistent_auth_session()
        return

    st.session_state.auth_user = {
        "name": user.name,
        "username": user.username,
        "role": user.role,
        "is_active": user.is_active,
    }
    _save_local_persistent_auth_token(token)


def current_user():
    user = st.session_state.get("auth_user")
    return user if isinstance(user, dict) else None


def is_authenticated() -> bool:
    return current_user() is not None


def require_authentication() -> None:
    _restore_user_from_persistent_auth()
    if is_authenticated():
        return
    google_oauth_ready = is_google_oauth_configured()
    if google_oauth_ready:
        _handle_google_oauth_callback()
        if is_authenticated():
            return

    bg_image_path = Path(__file__).resolve().parent / "pages" / "Pic" / "bg.png"
    bg_image_data = ""
    if bg_image_path.exists():
        bg_image_data = base64.b64encode(bg_image_path.read_bytes()).decode("utf-8")

    right_panel_style = ""
    if bg_image_data:
        right_panel_style = (
            f"background-image: linear-gradient(0deg, rgba(3, 10, 28, 0.34), "
            f"rgba(3, 10, 28, 0.20)), url('data:image/png;base64,{bg_image_data}');"
        )
    _ensure_login_captcha()
    if st.session_state.pop(LOGIN_CAPTCHA_CLEAR_INPUT_FLAG_SESSION_KEY, False):
        st.session_state.pop(LOGIN_CAPTCHA_INPUT_SESSION_KEY, None)
    captcha_a = int(st.session_state.get(LOGIN_CAPTCHA_A_SESSION_KEY, 15))
    captcha_b = int(st.session_state.get(LOGIN_CAPTCHA_B_SESSION_KEY, 15))

    st.markdown(
        f"""
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Manrope:wght@500;600;700;800&family=Space+Grotesk:wght@600;700&display=swap');

            :root {{
                --auth-text-strong: #eef5ff;
                --auth-text-muted: #b7c7e6;
                --auth-border-soft: rgba(133, 164, 215, 0.34);
                --auth-border-strong: rgba(149, 188, 247, 0.62);
                --auth-fill-soft: rgba(10, 22, 47, 0.66);
                --auth-focus: rgba(98, 168, 255, 0.8);
                --auth-focus-ring: rgba(98, 168, 255, 0.35);
            }}

            .stApp {{
                background:
                    radial-gradient(circle at 10% 12%, rgba(41, 127, 255, 0.23) 0%, rgba(0, 23, 56, 0) 38%),
                    radial-gradient(circle at 84% 86%, rgba(0, 177, 255, 0.20) 0%, rgba(0, 28, 70, 0) 36%),
                    linear-gradient(130deg, #010913 0%, #05132a 52%, #020d1d 100%);
                color: var(--auth-text-strong);
                font-family: "Manrope", "Segoe UI", sans-serif;
            }}
            [data-testid="stSidebar"],
            [data-testid="collapsedControl"] {{
                display: none !important;
            }}
            header[data-testid="stHeader"],
            [data-testid="stToolbar"],
            #MainMenu,
            footer {{
                display: none !important;
            }}
            section.main > div {{
                max-width: 1120px;
                padding-top: 0.8rem;
                padding-bottom: 0.8rem;
                margin-left: auto;
                margin-right: auto;
            }}
            [data-testid="stMainBlockContainer"] {{
                max-width: 1120px !important;
                padding-top: 0.8rem !important;
                padding-bottom: 0.8rem !important;
                width: 100% !important;
                margin-left: auto !important;
                margin-right: auto !important;
                min-height: calc(100vh - 1.6rem) !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
            }}
            .st-key-login_shell {{
                position: relative;
                isolation: isolate;
                border: 1px solid rgba(128, 165, 220, 0.30);
                border-radius: 20px;
                overflow: hidden;
                background: linear-gradient(152deg, rgba(4, 16, 39, 0.95), rgba(3, 11, 28, 0.97));
                box-shadow:
                    0 24px 56px rgba(0, 0, 0, 0.36),
                    inset 0 1px 0 rgba(221, 237, 255, 0.04);
                padding: 0.28rem;
                width: 100%;
                max-width: 1020px;
                margin: 0 auto;
                animation: auth-fade-up 420ms ease-out;
            }}
            .st-key-login_shell > div[data-testid="stHorizontalBlock"] {{
                align-items: stretch !important;
            }}
            .st-key-login_shell > div[data-testid="stHorizontalBlock"] > div[data-testid="column"] {{
                display: flex;
            }}
            .st-key-login_shell > div[data-testid="stHorizontalBlock"] > div[data-testid="column"] > div {{
                width: 100%;
                display: flex;
                height: 100%;
            }}
            .st-key-login_shell::before {{
                content: "";
                position: absolute;
                inset: 0;
                border-radius: inherit;
                pointer-events: none;
                background:
                    radial-gradient(circle at 20% 0%, rgba(117, 199, 255, 0.12) 0%, rgba(117, 199, 255, 0) 48%),
                    radial-gradient(circle at 98% 96%, rgba(54, 130, 230, 0.16) 0%, rgba(54, 130, 230, 0) 44%);
                z-index: -1;
            }}
            .st-key-login_form_panel {{
                min-height: auto;
                max-width: 400px;
                margin: 0 auto;
                border: 1px solid rgba(126, 160, 214, 0.30);
                border-radius: 14px;
                padding: 0.95rem 1rem 1.02rem 1rem;
                background:
                    radial-gradient(circle at 14% 12%, rgba(112, 174, 255, 0.10) 0%, rgba(112, 174, 255, 0) 40%),
                    linear-gradient(180deg, rgba(10, 22, 44, 0.82), rgba(6, 14, 31, 0.82));
                backdrop-filter: blur(4px);
                animation: auth-fade-up 520ms ease-out;
            }}
            .st-key-login_image_panel {{
                min-height: 560px;
                height: 100%;
                flex: 1 1 auto;
                background-color: #041022;
                background-repeat: no-repeat;
                background-size: cover;
                background-position: 50% 46%;
                border-radius: 14px;
                border: 1px solid rgba(124, 156, 209, 0.24);
                {right_panel_style}
                position: relative;
                overflow: hidden;
                animation: auth-fade-up 620ms ease-out;
                filter: saturate(1.05) contrast(1.03);
            }}
            .st-key-login_image_panel::after {{
                content: "";
                position: absolute;
                inset: 0;
                background: linear-gradient(162deg, rgba(5, 16, 35, 0.08) 0%, rgba(5, 16, 35, 0.28) 100%);
                backdrop-filter: blur(1.5px);
                -webkit-backdrop-filter: blur(1.5px);
                pointer-events: none;
                z-index: 1;
            }}
            .st-key-login_image_panel > * {{
                position: relative;
                z-index: 2;
            }}
            .st-key-login_form_panel h1 {{
                margin: 0 0 0.28rem 0;
                font-family: "Space Grotesk", "Segoe UI", sans-serif;
                font-size: clamp(1.42rem, 1.18rem + 0.72vw, 1.76rem);
                font-weight: 700;
                letter-spacing: 0.02em;
                color: var(--auth-text-strong);
            }}
            .st-key-login_form_panel p {{
                margin: 0 0 0.72rem 0;
                color: var(--auth-text-muted);
                font-size: 0.88rem;
                line-height: 1.45;
            }}
            .st-key-login_form_panel form {{
                display: grid;
                gap: 0.15rem;
            }}
            .st-key-login_form_panel label {{
                color: #d8e7ff;
                font-weight: 600;
                letter-spacing: 0.015em;
                font-size: 0.8rem;
            }}
            .st-key-login_form_panel div[data-baseweb="input"] > div {{
                border: 1px solid rgba(145, 173, 216, 0.38);
                border-radius: 10px;
                background: var(--auth-fill-soft);
                min-height: 42px;
                transition: border-color 0.18s ease, box-shadow 0.18s ease, transform 0.18s ease;
            }}
            .st-key-login_form_panel div[data-baseweb="input"] > div:focus-within {{
                border-color: var(--auth-focus);
                box-shadow:
                    0 0 0 1px var(--auth-focus),
                    0 0 0 5px var(--auth-focus-ring);
                transform: translateY(-1px);
            }}
            .st-key-login_form_panel div[data-testid="stTextInputRootElement"] {{
                padding-right: 0px !important;
                padding-inline-end: 0px !important;
            }}
            .st-key-login_form_panel div[data-testid="stTextInputRootElement"]:has(input[type="password"]) {{
                padding-right: 0 !important;
                padding-inline-end: 0 !important;
            }}
            .st-key-login_form_panel div[data-testid="stTextInputRootElement"][style*="padding-right"] {{
                padding-right: 0px !important;
                padding-inline-end: 0px !important;
            }}
            .st-key-login_form_panel div[data-testid="stTextInputRootElement"]:has(input[type="password"]) > div[data-baseweb="base-input"] {{
                padding-right: 0 !important;
                padding-inline-end: 0 !important;
            }}
            .st-key-login_form_panel input {{
                color: #f3f8ff !important;
                font-size: 0.92rem !important;
                font-weight: 600 !important;
            }}
            .st-key-login_form_panel input::placeholder {{
                color: rgba(200, 220, 249, 0.72) !important;
            }}
            .st-key-login_form_panel button[kind="formSubmit"] {{
                margin-top: 0.28rem;
                min-height: 42px;
                border-radius: 10px;
                border: 1px solid var(--auth-border-strong);
                background: linear-gradient(180deg, rgba(26, 74, 145, 0.98) 0%, rgba(13, 44, 96, 0.98) 100%);
                color: #eef5ff;
                font-family: "Space Grotesk", "Segoe UI", sans-serif;
                font-size: 0.84rem;
                font-weight: 700;
                letter-spacing: 0.05em;
                text-transform: uppercase;
                box-shadow:
                    0 12px 30px rgba(10, 37, 86, 0.44),
                    inset 0 1px 0 rgba(231, 242, 255, 0.18);
                transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease, filter 0.18s ease;
            }}
            .st-key-login_form_panel button[kind="formSubmit"]:hover {{
                border-color: rgba(196, 223, 255, 0.86);
                transform: translateY(-1px);
                box-shadow:
                    0 15px 34px rgba(7, 30, 72, 0.52),
                    inset 0 1px 0 rgba(231, 242, 255, 0.22);
                filter: brightness(1.04);
            }}
            .st-key-login_form_panel button[kind="formSubmit"]:focus-visible {{
                outline: none;
                box-shadow:
                    0 0 0 2px rgba(102, 176, 255, 0.92),
                    0 0 0 5px rgba(102, 176, 255, 0.28),
                    0 14px 32px rgba(7, 30, 72, 0.52);
            }}
            .st-key-login_form_panel button[kind="formSubmit"]:active {{
                transform: translateY(0);
            }}
            .st-key-login_form_panel .stCaption {{
                color: rgba(194, 214, 244, 0.92) !important;
                margin-top: 0.14rem !important;
                font-size: 0.76rem !important;
                line-height: 1.38 !important;
            }}
            .auth-captcha-shell {{
                margin-top: 0.25rem;
                margin-bottom: 0.1rem;
                border: 1px solid rgba(134, 173, 226, 0.48);
                border-radius: 10px;
                padding: 0.42rem 0.58rem;
                background:
                    radial-gradient(circle at 0% 0%, rgba(102, 168, 255, 0.18) 0%, rgba(102, 168, 255, 0) 52%),
                    rgba(9, 20, 42, 0.76);
            }}
            .auth-captcha-label {{
                font-size: 0.72rem;
                letter-spacing: 0.08em;
                text-transform: uppercase;
                color: rgba(201, 223, 255, 0.88);
                margin-bottom: 0.16rem;
                font-weight: 700;
            }}
            .auth-captcha-question {{
                font-family: "Space Grotesk", "Segoe UI", sans-serif;
                font-size: 0.94rem;
                font-weight: 700;
                color: #f1f7ff;
                letter-spacing: 0.02em;
            }}
            .auth-captcha-hint {{
                margin-top: 0.1rem;
                font-size: 0.68rem;
                color: rgba(188, 212, 244, 0.86);
            }}
            .st-key-login_form_panel div[data-baseweb="input"] button[aria-label*="password"],
            .st-key-login_form_panel div[data-baseweb="input"] button[title*="password"] {{
                width: 32px;
                height: 32px;
                border-radius: 10px;
                margin-right: 4px;
                transition: background-color 0.16s ease;
            }}
            .st-key-login_form_panel div[data-baseweb="input"] button[aria-label*="password"]:hover,
            .st-key-login_form_panel div[data-baseweb="input"] button[title*="password"]:hover {{
                background: rgba(155, 196, 252, 0.16);
            }}

            @keyframes auth-fade-up {{
                from {{
                    opacity: 0;
                    transform: translateY(12px);
                }}
                to {{
                    opacity: 1;
                    transform: translateY(0);
                }}
            }}

            @media (max-width: 980px) {{
                [data-testid="stMainBlockContainer"] {{
                    min-height: auto !important;
                    display: block !important;
                    padding-top: 0.95rem !important;
                    padding-bottom: 0.95rem !important;
                }}
                .st-key-login_shell > div[data-testid="stHorizontalBlock"] > div[data-testid="column"] > div {{
                    display: block;
                }}
                .st-key-login_shell {{
                    border-radius: 18px;
                    padding: 0.38rem;
                }}
                .st-key-login_form_panel {{
                    min-height: auto;
                    max-width: 100%;
                    border-radius: 14px;
                    padding: 0.9rem 0.9rem 0.95rem 0.9rem;
                }}
                .st-key-login_image_panel {{
                    min-height: 270px;
                    border-radius: 14px;
                    background-size: cover;
                    background-position: 50% 42%;
                }}
            }}
            @media (max-width: 640px) {{
                .st-key-login_shell {{
                    padding: 0.28rem;
                }}
                .st-key-login_form_panel h1 {{
                    margin-bottom: 0.22rem;
                }}
                .st-key-login_form_panel p {{
                    margin-bottom: 0.9rem;
                }}
            }}

            /* ---- Password toggle icon fix (f-string safe) ---- */
            div[data-baseweb="input"] button[aria-label*="Hide password"],
            div[data-baseweb="input"] button[aria-label*="Show password"],
            div[data-baseweb="input"] button[title*="Hide password"],
            div[data-baseweb="input"] button[title*="Show password"] {{
                position: relative;
            }}

            div[data-baseweb="input"] button[aria-label*="Hide password"] svg,
            div[data-baseweb="input"] button[aria-label*="Show password"] svg,
            div[data-baseweb="input"] button[title*="Hide password"] svg,
            div[data-baseweb="input"] button[title*="Show password"] svg {{
                display: none !important;
            }}

            div[data-baseweb="input"] button[aria-label*="Hide password"]::before,
            div[data-baseweb="input"] button[title*="Hide password"]::before {{
                content: "";
                width: 18px;
                height: 18px;
                display: block;
                background: url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI0U3RjJGRiI+PHBhdGggZD0iTTEyIDQuNUM3IDQuNSAyLjczIDcuNjEgMSAxMmMxLjczIDQuMzkgNiA3LjUgMTEgNy41czkuMjctMy4xMSAxMS03LjVjLTEuNzMtNC4zOS02LTcuNS0xMS03LjV6bTAgMTIuNWMtMi43NiAwLTUtMi4yNC01LTVzMi4yNC01IDUtNSA1IDIuMjQgNSA1LTIuMjQgNS01IDV6bTAtOGMtMS42NiAwLTMgMS4zNC0zIDNzMS4zNCAzIDMgMyAzLTEuMzQtMy0zLTEuMzQtMy0zLTN6Ii8+PC9zdmc+") center/18px 18px no-repeat;
            }}

            div[data-baseweb="input"] button[aria-label*="Show password"]::before,
            div[data-baseweb="input"] button[title*="Show password"]::before {{
                content: "";
                width: 18px;
                height: 18px;
                display: block;
                background: url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI0U3RjJGRiI+PHBhdGggZD0iTTEyIDYuNWMzLjMgMCA2LjEgMS43IDcuOCA0LjUtLjcgMS4yLTEuNyAyLjItMi45IDNsMS40IDEuNGMxLjUtMS4xIDIuNy0yLjUgMy41LTQuNC0xLjczLTQuMzktNi03LjUtMTEtNy41LTEuNCAwLTIuNy4yLTQgLjZsMS43IDEuN2MuNy0uMiAxLjUtLjMgMi41LS4zem0tMTAtNC4xIDIuMyAyLjMuNS41QzMuNCA2LjYgMi4zIDkuMSAxIDEyYzEuNzMgNC4zOSA2IDcuNSAxMSA3LjUgMS43IDAgMy4zLS4zIDQuOC0uOGwuNC40IDIuOSAyLjkgMS4zLTEuM0wzLjMgMS4xIDIgMi40em01LjEgNS4xIDEuNSAxLjVjLS40LjctLjYgMS41LS42IDIuNSAwIDIuNzYgMi4yNCA1IDUgNSAxIDAgMS44LS4yIDIuNS0uNmwxLjUgMS41Yy0xLjEuNS0yLjMuOC00IC44LTMuMyAwLTYuMS0xLjctNy44LTQuNS45LTEuNiAyLjMtMi45IDMuOS0zLjd6bTQuOSA0LjkgMS43IDEuN2MtLjUuMi0xIC4zLTEuNy4zLTEuNjYgMC0zLTEuMzQtMy0zIDAtLjYuMS0xLjIuMy0xLjdsMS43IDEuN2MwIC4zLS4xIC40LS4xIC42IDAgLjYuNCAxIDEgMSAuMiAwIC4zIDAgLjYtLjF6Ii8+PC9zdmc+") center/18px 18px no-repeat;
            }}
        </style>
        """,
        unsafe_allow_html=True,
    )

    stage = _login_stage()
    pending_user = _pending_login_user()
    if stage in {LOGIN_STAGE_OTP, LOGIN_STAGE_PASSWORD_RESET} and pending_user is None:
        _clear_pending_login_flow(reset_stage=True)
        stage = _login_stage()

    credentials_submitted = False
    otp_verify_submitted = False
    otp_resend_clicked = False
    otp_cancel_clicked = False
    password_reset_submitted = False
    password_reset_cancel_clicked = False
    username = ""
    password = ""
    captcha_response = ""
    otp_code = ""
    new_password = ""
    confirm_new_password = ""

    with st.container(key="login_shell"):
        col_form, col_image = st.columns([0.88, 1.12], gap="small")
        with col_form:
            with st.container(key="login_form_panel"):
                _show_login_feedback()

                if stage == LOGIN_STAGE_CREDENTIALS:
                    if google_oauth_ready:
                        st.markdown("<h1>Log In</h1><p>Use your Gmail and password to continue.</p>", unsafe_allow_html=True)
                    else:
                        st.markdown("<h1>Log In</h1><p>Sign in with your assigned @gmail.com account.</p>", unsafe_allow_html=True)
                    with st.form("login_form", clear_on_submit=False):
                        username = st.text_input("E-mail", placeholder="name@gmail.com")
                        password = st.text_input("Password", type="password", placeholder="Password")
                        st.markdown(
                            (
                                "<div class='auth-captcha-shell'>"
                                "<div class='auth-captcha-label'>Security Check</div>"
                                f"<div class='auth-captcha-question'>{captcha_a} + {captcha_b} = ?</div>"
                                "<div class='auth-captcha-hint'>Enter the exact sum to continue.</div>"
                                "</div>"
                            ),
                            unsafe_allow_html=True,
                        )
                        captcha_response = st.text_input(
                            "Captcha answer",
                            placeholder="Type the answer here",
                            key=LOGIN_CAPTCHA_INPUT_SESSION_KEY,
                            label_visibility="collapsed",
                        )
                        st.caption(
                            "If your account is still on a default password, an OTP is sent to your e-mail and expires in 1 minute."
                        )
                        credentials_submitted = st.form_submit_button("LOG IN", width="stretch")
                elif stage == LOGIN_STAGE_OTP:
                    pending_username = str((pending_user or {}).get("username", "") or "").strip().lower()
                    seconds_left = _otp_seconds_remaining()
                    st.markdown("<h1>Verify OTP</h1><p>An OTP was sent to your e-mail.</p>", unsafe_allow_html=True)
                    st.caption(f"OTP for {pending_username} expires in {seconds_left} second(s).")
                    with st.form("login_otp_form", clear_on_submit=False):
                        otp_code = st.text_input(
                            "OTP Code",
                            placeholder="Enter the 6-digit code",
                        )
                        otp_verify_submitted = st.form_submit_button("VERIFY OTP", width="stretch", type="primary")
                    c1, c2 = st.columns(2, gap="small")
                    with c1:
                        otp_resend_clicked = st.button("Resend OTP", width="stretch", key="login_otp_resend")
                    with c2:
                        otp_cancel_clicked = st.button("Use Different Account", width="stretch", key="login_otp_cancel")
                else:
                    pending_username = str((pending_user or {}).get("username", "") or "").strip().lower()
                    st.markdown(
                        "<h1>Change Password</h1><p>Your account is using a default password. Set a new password to continue.</p>",
                        unsafe_allow_html=True,
                    )
                    st.caption(f"Account: {pending_username}")
                    with st.form("login_password_reset_form", clear_on_submit=False):
                        new_password = st.text_input(
                            "New Password",
                            type="password",
                            placeholder="At least 8 characters and 1 special character",
                        )
                        confirm_new_password = st.text_input(
                            "Confirm New Password",
                            type="password",
                            placeholder="Re-enter new password",
                        )
                        st.caption("After changing the default password, you will be signed in and redirected to Zeek Dashboard.")
                        password_reset_submitted = st.form_submit_button(
                            "CHANGE PASSWORD",
                            width="stretch",
                            type="primary",
                        )
                    password_reset_cancel_clicked = st.button(
                        "Back to Login",
                        width="stretch",
                        key="login_password_reset_cancel",
                    )
        with col_image:
            with st.container(key="login_image_panel"):
                st.markdown("&nbsp;", unsafe_allow_html=True)

    if credentials_submitted:
        captcha_answer = _parse_captcha_answer(captcha_response)
        expected_captcha = st.session_state.get(LOGIN_CAPTCHA_ANSWER_SESSION_KEY)
        if not isinstance(expected_captcha, int) or captcha_answer is None or captcha_answer != expected_captcha:
            st.error("Captcha incorrect. Please solve the new challenge and try again.")
            _reset_login_captcha()
            st.rerun()

        clean_username = (username or "").strip().lower()
        if not is_valid_gmail_email(clean_username):
            st.error("Use a valid @gmail.com e-mail address.")
            st.stop()
        if not is_email_allowed_for_login(clean_username):
            st.error("This e-mail is not approved for login.")
            st.stop()
        if not password_has_special_character(password):
            st.error("Password must include at least one special character.")
            st.stop()

        try:
            user = verify_user_credentials_for_otp(username=clean_username, password=password)
        except Exception as e:
            st.error("Login service is unavailable.")
            st.caption("Check AUTH_MONGODB_URI / MONGODB_URI and database connectivity.")
            st.code(str(e))
            st.stop()

        if user is None:
            st.error("Invalid e-mail or password.")
            st.stop()

        requires_password_reset = bool(getattr(user, "password_reset_required", False))
        if not requires_password_reset:
            try:
                final_user = complete_login_after_otp(user.username)
            except Exception as e:
                st.error("Login service is unavailable.")
                st.caption("Check AUTH_MONGODB_URI / MONGODB_URI and database connectivity.")
                st.code(str(e))
                st.stop()
            if final_user is None:
                st.error("User account is not available for login.")
                st.stop()
            _complete_authenticated_session(final_user)

        st.session_state[LOGIN_PENDING_USER_SESSION_KEY] = {
            "name": user.name,
            "username": user.username,
            "role": user.role,
            "is_active": user.is_active,
            "password_reset_required": requires_password_reset,
        }
        try:
            _issue_and_send_login_otp(user.username)
        except Exception as e:
            _clear_pending_login_flow(reset_stage=True)
            st.error("Could not send OTP to your e-mail.")
            st.caption(str(e))
            st.stop()

        _set_login_stage(LOGIN_STAGE_OTP)
        _set_login_feedback("OTP sent to your e-mail. The code expires in 1 minute.", "success")
        st.rerun()

    if otp_cancel_clicked:
        _clear_pending_login_flow(reset_stage=True)
        _set_login_feedback("OTP verification canceled. Enter your credentials again.", "info")
        st.rerun()

    if otp_resend_clicked:
        pending = _pending_login_user()
        pending_username = str((pending or {}).get("username", "") or "").strip().lower()
        if not pending_username:
            _clear_pending_login_flow(reset_stage=True)
            _set_login_feedback("Your login session expired. Enter your credentials again.", "warning")
            st.rerun()
        try:
            _issue_and_send_login_otp(pending_username)
        except Exception as e:
            st.error("Could not resend OTP to your e-mail.")
            st.caption(str(e))
            st.stop()
        _set_login_feedback("A new OTP was sent. It expires in 1 minute.", "success")
        st.rerun()

    if otp_verify_submitted:
        pending = _pending_login_user()
        pending_username = str((pending or {}).get("username", "") or "").strip().lower()
        if not pending_username:
            _clear_pending_login_flow(reset_stage=True)
            _set_login_feedback("Your login session expired. Enter your credentials again.", "warning")
            st.rerun()

        clean_otp = str(otp_code or "").strip()
        if not clean_otp.isdigit():
            st.error("OTP code must be numeric.")
            st.stop()
        if _otp_seconds_remaining() <= 0:
            st.error("OTP expired. Click Resend OTP to get a new code.")
            st.stop()

        expected_hash = str(st.session_state.get(LOGIN_OTP_HASH_SESSION_KEY, "") or "").strip()
        if not expected_hash or not hmac.compare_digest(_otp_signature(pending_username, clean_otp), expected_hash):
            st.error("Invalid OTP code.")
            st.stop()

        st.session_state.pop(LOGIN_OTP_HASH_SESSION_KEY, None)
        st.session_state.pop(LOGIN_OTP_EXPIRES_AT_SESSION_KEY, None)
        st.session_state.pop(LOGIN_OTP_SENT_AT_SESSION_KEY, None)

        if bool((pending or {}).get("password_reset_required", False)):
            _set_login_stage(LOGIN_STAGE_PASSWORD_RESET)
            _set_login_feedback("OTP verified. Set a new password to replace your default password.", "success")
            st.rerun()

        if google_oauth_ready:
            _begin_google_oauth_after_otp(pending_username)

        try:
            final_user = complete_login_after_otp(pending_username)
        except Exception as e:
            st.error("Login service is unavailable.")
            st.caption("Check AUTH_MONGODB_URI / MONGODB_URI and database connectivity.")
            st.code(str(e))
            st.stop()
        if final_user is None:
            st.error("User account is not available for login.")
            st.stop()
        _complete_authenticated_session(final_user)

    if password_reset_cancel_clicked:
        _clear_pending_login_flow(reset_stage=True)
        _set_login_feedback("Password update canceled. Log in again to continue.", "info")
        st.rerun()

    if password_reset_submitted:
        pending = _pending_login_user()
        pending_username = str((pending or {}).get("username", "") or "").strip().lower()
        if not pending_username:
            _clear_pending_login_flow(reset_stage=True)
            _set_login_feedback("Your login session expired. Enter your credentials again.", "warning")
            st.rerun()

        clean_new_password = str(new_password or "")
        clean_confirm_password = str(confirm_new_password or "")
        if clean_new_password != clean_confirm_password:
            st.error("New password and confirmation do not match.")
            st.stop()
        try:
            complete_default_password_reset(
                username=pending_username,
                new_password=clean_new_password,
            )
        except Exception as e:
            st.error(str(e))
            st.stop()

        if google_oauth_ready:
            _set_login_feedback(
                "Password changed successfully. Continue with Google sign-in to open Zeek Dashboard.",
                "success",
            )
            _begin_google_oauth_after_otp(pending_username)

        try:
            final_user = complete_login_after_otp(pending_username)
        except Exception as e:
            _clear_pending_login_flow(reset_stage=True)
            _reset_login_captcha()
            st.error("Password changed, but automatic sign-in is unavailable.")
            st.caption("Log in again with your new password.")
            st.code(str(e))
            st.stop()
        if final_user is None:
            _clear_pending_login_flow(reset_stage=True)
            _reset_login_captcha()
            _set_login_feedback("Password changed successfully. Log in again with your new password.", "warning")
            st.rerun()

        _complete_authenticated_session(final_user)

    st.stop()


def require_role(*allowed_roles: str) -> None:
    user = current_user()
    if not user:
        st.error("Login is required.")
        st.stop()
    if user.get("role") not in set(allowed_roles):
        st.error("You do not have permission to access this page.")
        st.stop()
