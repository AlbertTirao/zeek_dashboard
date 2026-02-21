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
    authenticate_user_password_only,
    authenticate_user,
    build_google_oauth_authorization_url,
    is_email_allowed_for_login,
    is_google_oauth_configured,
    is_valid_gmail_email,
    password_has_special_character,
)


PERSISTENT_AUTH_QUERY_KEY = "auth"
DEFAULT_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
GOOGLE_OAUTH_STATE_SESSION_KEY = "google_oauth_state"
GOOGLE_OAUTH_EXPECTED_EMAIL_SESSION_KEY = "google_oauth_expected_email"
GOOGLE_OAUTH_STATE_TTL_SECONDS = 10 * 60
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
        secret = auth_service.get_mongodb_uri()
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


def persist_auth_session(username: str) -> None:
    token = _issue_persistent_auth_token(username)
    if token:
        st.query_params[PERSISTENT_AUTH_QUERY_KEY] = token


def clear_persistent_auth_session() -> None:
    if PERSISTENT_AUTH_QUERY_KEY in st.query_params:
        del st.query_params[PERSISTENT_AUTH_QUERY_KEY]


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
        "username": user.username,
        "role": user.role,
        "is_active": user.is_active,
    }


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
            f"background-image: linear-gradient(0deg, rgba(3, 10, 28, 0.72), "
            f"rgba(3, 10, 28, 0.72)), url('data:image/png;base64,{bg_image_data}');"
        )

    st.markdown(
        f"""
        <style>
            .stApp {{
                background:
                    radial-gradient(circle at 14% 18%, rgba(0, 44, 104, 0.24) 0%, rgba(0, 18, 48, 0) 34%),
                    radial-gradient(circle at 86% 84%, rgba(0, 58, 138, 0.20) 0%, rgba(0, 18, 48, 0) 36%),
                    #020913;
            }}
            [data-testid="stSidebar"],
            [data-testid="collapsedControl"] {{
                display: none !important;
            }}
            section.main > div {{
                max-width: 1240px;
                padding-top: 2.0rem;
                padding-bottom: 2.0rem;
                margin-left: auto;
                margin-right: auto;
            }}
            [data-testid="stMainBlockContainer"] {{
                max-width: 1240px !important;
                padding-top: 2.0rem !important;
                padding-bottom: 2.0rem !important;
                width: 100% !important;
                margin-left: auto !important;
                margin-right: auto !important;
                min-height: calc(100vh - 7.2rem) !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
            }}
            .st-key-login_shell {{
                border: 1px solid rgba(112, 146, 205, 0.30);
                border-radius: 20px;
                overflow: hidden;
                background: linear-gradient(180deg, rgba(2, 11, 32, 0.95), rgba(1, 9, 24, 0.96));
                box-shadow: 0 18px 60px rgba(0, 0, 0, 0.38);
                padding: 0.35rem;
                width: 100%;
                max-width: 1120px;
                margin: 0 auto;
            }}
            .st-key-login_form_panel {{
                min-height: 560px;
                max-width: 460px;
                margin: 0 auto;
                padding: 1.2rem 1rem;
                border: 1px solid rgba(112, 146, 205, 0.36);
                border-radius: 16px;
                padding: 1.25rem 1.25rem 1.35rem 1.25rem;
                background: linear-gradient(180deg, rgba(14, 24, 44, 0.72), rgba(7, 14, 29, 0.72));
                backdrop-filter: blur(3px);
            }}
            .st-key-login_image_panel {{
                min-height: 560px;
                background-color: #091223;
                background-repeat: no-repeat;
                background-size: cover;
                background-position: right center;
                border-radius: 14px;
                border: 1px solid rgba(112, 146, 205, 0.25);
                {right_panel_style}
            }}
            .st-key-login_form_panel h1 {{
                margin: 0 0 0.2rem 0;
                font-size: 1.9rem;
                font-weight: 700;
                letter-spacing: 0.02em;
                color: #eef4ff;
            }}
            .st-key-login_form_panel p {{
                margin: 0 0 1rem 0;
                color: #b3c4e2;
                font-size: 0.95rem;
            }}
            .st-key-login_form_panel label {{
                color: #d5e1f7;
                font-weight: 600;
                letter-spacing: 0.01em;
            }}
            .st-key-login_form_panel div[data-baseweb="input"] > div {{
                border: 1px solid rgba(148, 176, 219, 0.35);
                border-radius: 14px;
                background: rgba(239, 244, 255, 0.14);
                min-height: 48px;
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }}
            .st-key-login_form_panel div[data-baseweb="input"] > div:focus-within {{
                border-color: rgba(140, 182, 255, 0.85);
                box-shadow: 0 0 0 1px rgba(140, 182, 255, 0.45);
            }}
            .st-key-login_form_panel input {{
                color: #f0f5ff !important;
            }}
            .st-key-login_form_panel input::placeholder {{
                color: rgba(225, 236, 255, 0.64) !important;
            }}
            .st-key-login_form_panel button[kind="formSubmit"] {{
                margin-top: 0.35rem;
                min-height: 48px;
                border-radius: 12px;
                border: 1px solid rgba(160, 188, 228, 0.4);
                background: linear-gradient(180deg, rgba(8, 20, 43, 0.95), rgba(4, 13, 31, 0.95));
                color: #eef5ff;
                font-weight: 700;
                letter-spacing: 0.03em;
            }}
            .st-key-login_form_panel button[kind="formSubmit"]:hover {{
                border-color: rgba(175, 204, 242, 0.62);
            }}
            @media (max-width: 980px) {{
                [data-testid="stMainBlockContainer"] {{
                    min-height: auto !important;
                    display: block !important;
                }}
                .st-key-login_form_panel {{
                    min-height: auto;
                    max-width: 100%;
                    padding: 0.9rem 0.8rem;
                }}
                .st-key-login_image_panel {{
                    min-height: 300px;
                }}
            }}
        </style>
        """,
        unsafe_allow_html=True,
    )

    with st.container(key="login_shell"):
        submitted = False
        username = ""
        password = ""
        col_form, col_image = st.columns([1, 1.18], gap="small")
        with col_form:
            with st.container(key="login_form_panel"):
                if google_oauth_ready:
                    st.markdown("<h1>Log In</h1><p>Use your Gmail and password to continue.</p>", unsafe_allow_html=True)
                else:
                    st.markdown("<h1>Log In</h1><p>Sign in with your assigned @gmail.com account.</p>", unsafe_allow_html=True)
                with st.form("login_form", clear_on_submit=False):
                    username = st.text_input("E-mail", placeholder="name@gmail.com")
                    password = st.text_input("Password", type="password", placeholder="Password")
                    if google_oauth_ready:
                        st.caption(
                            "After login, the system verifies that this is a real Google account."
                        )
                    else:
                        st.caption("Use an approved @gmail.com address. Password must include at least one special character.")
                    submitted = st.form_submit_button("LOG IN", use_container_width=True)
        with col_image:
            with st.container(key="login_image_panel"):
                st.markdown("&nbsp;", unsafe_allow_html=True)

    if submitted:
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

        if google_oauth_ready:
            try:
                user = authenticate_user_password_only(username=clean_username, password=password)
            except Exception as e:
                st.error("Login service is unavailable.")
                st.caption(
                    "Check AUTH_MONGODB_URI / MONGODB_URI and MongoDB connectivity."
                )
                st.code(str(e))
                st.stop()

            if user is None:
                st.error("Invalid e-mail or password.")
                st.stop()

            state = _issue_google_oauth_state(clean_username)
            if not state:
                st.error("Google sign-in is not configured correctly.")
                st.stop()
            st.session_state[GOOGLE_OAUTH_STATE_SESSION_KEY] = state
            st.session_state[GOOGLE_OAUTH_EXPECTED_EMAIL_SESSION_KEY] = clean_username
            oauth_url = build_google_oauth_authorization_url(state)
            if not oauth_url:
                st.error("Google sign-in is not configured correctly.")
                st.stop()

            st.info("Redirecting to Google sign-in...")
            st.markdown(
                f"<meta http-equiv='refresh' content='0;url={oauth_url}'>",
                unsafe_allow_html=True,
            )
            st.link_button(
                "Continue to Google Sign-In",
                oauth_url,
                use_container_width=True,
            )
            st.stop()

        try:
            user = authenticate_user(username=clean_username, password=password)
        except Exception as e:
            st.error("Login service is unavailable.")
            st.caption(
                "Check AUTH_MONGODB_URI / MONGODB_URI and MongoDB connectivity."
            )
            st.code(str(e))
            st.stop()

        if user is None:
            st.error("Invalid e-mail or password.")
            st.stop()
        st.session_state.auth_user = {
            "username": user.username,
            "role": user.role,
            "is_active": user.is_active,
        }
        persist_auth_session(user.username)
        st.rerun()
    st.stop()


def require_role(*allowed_roles: str) -> None:
    user = current_user()
    if not user:
        st.error("Login is required.")
        st.stop()
    if user.get("role") not in set(allowed_roles):
        st.error("You do not have permission to access this page.")
        st.stop()

