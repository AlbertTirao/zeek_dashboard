from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from pathlib import Path

import streamlit as st
import toml

try:
    import mysql.connector
except Exception:  # pragma: no cover - runtime dependency
    mysql = None

ADMIN_ROLE = "admin"
STAFF_ROLE = "staff"
AUTHORIZATION_PAGE = "Authorization"


def _pbkdf2_hash(password: str, salt: bytes, iterations: int) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return base64.b64encode(dk).decode("utf-8")


def make_password_hash(password: str, iterations: int = 200_000) -> str:
    salt = os.urandom(16)
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    digest_b64 = _pbkdf2_hash(password, salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt_b64}${digest_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    if not password or not stored_hash:
        return False

    if stored_hash.startswith("pbkdf2_sha256$"):
        parts = stored_hash.split("$")
        if len(parts) != 4:
            return False
        _, iter_str, salt_b64, digest_b64 = parts
        try:
            iterations = int(iter_str)
            salt = base64.b64decode(salt_b64.encode("utf-8"))
        except Exception:
            return False
        actual = _pbkdf2_hash(password, salt, iterations)
        return hmac.compare_digest(actual, digest_b64)

    # Fallback for existing plain-text credentials during migration.
    return hmac.compare_digest(password, stored_hash)


def _mysql_settings() -> dict:
    settings = {
        "host": os.getenv("MYSQL_AUTH_HOST", "127.0.0.1"),
        "port": int(os.getenv("MYSQL_AUTH_PORT", "3306")),
        "database": os.getenv("MYSQL_AUTH_DB", "zeek_dashboard"),
        "user": os.getenv("MYSQL_AUTH_USER", ""),
        "password": os.getenv("MYSQL_AUTH_PASSWORD", ""),
        "table": os.getenv("MYSQL_AUTH_TABLE", "auth_users"),
    }
    try:
        block = st.secrets.get("mysql_auth")
        if isinstance(block, dict):
            settings["host"] = str(block.get("host", settings["host"]))
            settings["port"] = int(block.get("port", settings["port"]))
            settings["database"] = str(block.get("database", settings["database"]))
            settings["user"] = str(block.get("user", settings["user"]))
            settings["password"] = str(block.get("password", settings["password"]))
            settings["table"] = str(block.get("table", settings["table"]))
    except Exception:
        pass

    # Fallback: read secrets.toml directly when Streamlit secrets are unavailable.
    candidates = [
        Path.cwd() / ".streamlit" / "secrets.toml",
        Path(__file__).resolve().parents[1] / ".streamlit" / "secrets.toml",
        Path.home() / ".streamlit" / "secrets.toml",
    ]
    for p in candidates:
        try:
            if not p.exists():
                continue
            payload = toml.loads(p.read_text(encoding="utf-8-sig"))
            block = payload.get("mysql_auth", {})
            if not isinstance(block, dict):
                continue
            settings["host"] = str(block.get("host", settings["host"]))
            settings["port"] = int(block.get("port", settings["port"]))
            settings["database"] = str(block.get("database", settings["database"]))
            settings["user"] = str(block.get("user", settings["user"]))
            settings["password"] = str(block.get("password", settings["password"]))
            settings["table"] = str(block.get("table", settings["table"]))
            break
        except Exception:
            continue
    return settings


def mysql_auth_ready() -> tuple[bool, str]:
    if mysql is None:
        return False, "mysql-connector-python is not installed."

    s = _mysql_settings()
    if not s["user"] or not s["password"]:
        return False, "MySQL auth credentials are missing."
    if not s["database"]:
        return False, "MySQL database name is missing."
    if not s["table"]:
        return False, "MySQL auth table name is missing."
    return True, ""


def _get_mysql_connection():
    s = _mysql_settings()
    return mysql.connector.connect(
        host=s["host"],
        port=s["port"],
        user=s["user"],
        password=s["password"],
        database=s["database"],
        connection_timeout=5,
        autocommit=True,
    )


def authenticate_mysql_user(username: str, password: str) -> tuple[bool, str]:
    ok, reason = mysql_auth_ready()
    if not ok:
        return False, reason

    s = _mysql_settings()
    table = str(s["table"]).strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table):
        return False, "Invalid MySQL auth table name."
    sql = (
        f"SELECT password_hash, role, is_active "
        f"FROM {table} "
        f"WHERE username = %s "
        f"LIMIT 1"
    )

    try:
        conn = _get_mysql_connection()
        cur = conn.cursor()
        cur.execute(sql, (username,))
        row = cur.fetchone()
        cur.close()
        conn.close()
    except Exception:
        return False, "Unable to connect/query MySQL auth database."

    if not row:
        return False, "Invalid username or password."

    stored_hash = str(row[0] or "").strip()
    role = str(row[1] or STAFF_ROLE).strip().lower()
    is_active = int(row[2] or 0)

    if is_active != 1:
        return False, "Account is disabled."
    if role not in {ADMIN_ROLE, STAFF_ROLE}:
        return False, "Invalid role configured for account."
    if not verify_password(password, stored_hash):
        return False, "Invalid username or password."

    return True, role


def init_auth_state() -> None:
    st.session_state.setdefault("auth_logged_in", False)
    st.session_state.setdefault("auth_username", "")
    st.session_state.setdefault("auth_role", "")
    st.session_state.setdefault("auth_error", "")


def is_authenticated() -> bool:
    return bool(st.session_state.get("auth_logged_in", False))


def get_current_user() -> str:
    return str(st.session_state.get("auth_username", "")).strip()


def get_current_role() -> str:
    role = str(st.session_state.get("auth_role", "")).strip().lower()
    return role if role in {ADMIN_ROLE, STAFF_ROLE} else ""


def can_access_authorization() -> bool:
    return get_current_role() == ADMIN_ROLE


def can_access_page(page_name: str) -> bool:
    if page_name == AUTHORIZATION_PAGE:
        return can_access_authorization()
    return is_authenticated()


def get_allowed_pages(all_pages: list[str]) -> list[str]:
    if get_current_role() == ADMIN_ROLE:
        return list(all_pages)
    return [p for p in all_pages if p != AUTHORIZATION_PAGE]


def logout() -> None:
    for key in [
        "auth_logged_in",
        "auth_username",
        "auth_role",
        "auth_error",
        "sidebar_page",
        "sidebar_option_menu",
        "current_page",
    ]:
        st.session_state.pop(key, None)
    st.rerun()


def _resolve_login_background_url() -> str:
    img = Path.cwd() / "ui" / "picture" / "bg.png"
    if img.exists():
        try:
            encoded = base64.b64encode(img.read_bytes()).decode("utf-8")
            return f"data:image/png;base64,{encoded}"
        except Exception:
            pass
    return ""


def _inject_login_css(background_url: str) -> None:
    css = """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&display=swap');

    :root {
        --ink: #ecf3f8;
        --muted: #9fb0be;
        --panel-border: rgba(147, 179, 204, 0.28);
    }

    html, body, [class*="css"] {
        font-family: "Manrope", sans-serif;
    }

    /* Login view: hide sidebar and avoid leftover sidebar spacing after logout */
    [data-testid="stSidebar"],
    [data-testid="stSidebarCollapsedControl"] {
        display: none !important;
    }

    [data-testid="stAppViewContainer"] {
        margin-left: 0 !important;
    }

    [data-testid="stAppViewContainer"] > .main {
        width: 100% !important;
        max-width: 100% !important;
    }

    .stApp {
        background:
            linear-gradient(120deg, rgba(8, 14, 22, 0.82), rgba(8, 15, 24, 0.86)),
            radial-gradient(1200px 520px at 12% 12%, rgba(140, 69, 111, 0.32), transparent 55%),
            radial-gradient(980px 460px at 88% 90%, rgba(62, 129, 178, 0.32), transparent 52%);
        background-attachment: fixed;
    }

    [data-testid="stAppViewContainer"] > .main,
    [data-testid="stAppViewContainer"] > .main > div,
    [data-testid="stAppViewContainer"] > .main .block-container {
        min-height: 100vh;
    }

    [data-testid="stAppViewContainer"] > .main .block-container {
        max-width: 100% !important;
        width: 100% !important;
        padding: 1.4rem;
    }

    .st-key-login_center_root,
    div[data-testid="stVerticalBlock"].st-key-login_center_root {
        width: 100%;
        display: flex;
        justify-content: center;
        align-items: center;
    }

    .st-key-login_shell,
    div[data-testid="stVerticalBlock"].st-key-login_shell {
        width: min(1360px, 99vw);
        margin-left: auto !important;
        margin-right: auto !important;
        border-radius: 24px;
        border: 1px solid var(--panel-border);
        overflow: hidden;
        background: linear-gradient(145deg, rgba(10, 18, 29, 0.86), rgba(8, 14, 24, 0.9));
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        box-shadow: 0 34px 90px rgba(4, 9, 16, 0.68);
        animation: fadeUp 380ms ease-out both;
    }

    .st-key-login_shell [data-testid="stHorizontalBlock"] {
        gap: 0 !important;
    }

    .st-key-login_form_panel,
    div[data-testid="stVerticalBlock"].st-key-login_form_panel {
        background: linear-gradient(160deg, rgba(10, 18, 30, 0.92), rgba(8, 14, 24, 0.95));
        min-height: 700px;
        padding: 2rem 1.8rem 1.5rem 1.8rem;
        border-right: 1px solid rgba(146, 174, 198, 0.18);
        color: var(--ink);
    }

    .st-key-login_visual_panel,
    div[data-testid="stVerticalBlock"].st-key-login_visual_panel {
        min-height: 700px;
        padding: 0;
        color: #ecf3f8;
        position: relative;
        overflow: hidden;
        background: linear-gradient(165deg, rgba(8, 20, 36, 0.84), rgba(7, 17, 30, 0.94));
    }

    .st-key-login_visual_panel::before,
    div[data-testid="stVerticalBlock"].st-key-login_visual_panel::before {
        content: "";
        position: absolute;
        inset: 0;
        background: url('__BG__') 66% center/cover no-repeat;
        filter: saturate(1.02) contrast(1.03) brightness(0.72);
        z-index: 0;
    }

    .st-key-login_visual_panel::after,
    div[data-testid="stVerticalBlock"].st-key-login_visual_panel::after {
        content: "";
        position: absolute;
        inset: -16px;
        background:
            linear-gradient(165deg, rgba(7, 13, 23, 0.54), rgba(6, 11, 20, 0.62)),
            radial-gradient(520px 260px at 18% 22%, rgba(62, 98, 129, 0.38), transparent 62%),
            radial-gradient(440px 240px at 86% 84%, rgba(24, 40, 59, 0.5), transparent 62%);
        filter: blur(9px);
        z-index: 1;
    }

    .st-key-login_visual_panel > div[data-testid="stVerticalBlockBorderWrapper"]::before,
    div[data-testid="stVerticalBlock"].st-key-login_visual_panel > div[data-testid="stVerticalBlockBorderWrapper"]::before {
        content: "";
        position: absolute;
        inset: 18px;
        border: 1px solid rgba(197, 220, 237, 0.24);
        border-radius: 18px;
        z-index: 2;
        pointer-events: none;
        box-shadow: inset 0 0 40px rgba(129, 177, 211, 0.12);
    }

    .st-key-login_visual_panel > div[data-testid="stVerticalBlockBorderWrapper"]::after,
    div[data-testid="stVerticalBlock"].st-key-login_visual_panel > div[data-testid="stVerticalBlockBorderWrapper"]::after {
        content: "";
        position: absolute;
        left: 10%;
        right: 10%;
        bottom: 14%;
        height: 2px;
        border-radius: 999px;
        background: linear-gradient(90deg, transparent, rgba(142, 198, 232, 0.68), transparent);
        z-index: 2;
        pointer-events: none;
    }

    .login-visual-fill {
        position: relative;
        z-index: 3;
        min-height: 700px;
    }

    .st-key-login_form_wrap,
    div[data-testid="stVerticalBlock"].st-key-login_form_wrap {
        max-width: 540px;
        margin: 4rem auto 0 auto;
        padding: 1.25rem;
        border-radius: 18px;
        background: linear-gradient(160deg, rgba(255, 255, 255, 0.035), rgba(255, 255, 255, 0.01));
        border: 1px solid rgba(170, 194, 213, 0.2);
        box-shadow: 0 18px 44px rgba(0, 0, 0, 0.28);
    }

    .st-key-login_form_panel .stTextInput label p {
        color: #dce9f1 !important;
        font-size: 0.88rem !important;
        font-weight: 700 !important;
        margin-top: 0.25rem;
    }

    .st-key-login_form_panel [data-testid="stForm"] {
        border: 0 !important;
        background: transparent !important;
        padding: 0 !important;
    }

    .st-key-login_form_panel [data-baseweb="input"] > div,
    .st-key-login_form_panel [data-baseweb="base-input"] > div {
        border: 1px solid rgba(138, 167, 191, 0.3) !important;
        border-radius: 999px !important;
        background: rgba(255, 255, 255, 0.03) !important;
        min-height: 2.8rem !important;
    }

    .st-key-login_form_panel .stTextInput input {
        color: #f2f8fc !important;
        background: transparent !important;
        border: 0 !important;
        padding: 0.72rem 0.95rem !important;
        font-size: 0.98rem !important;
    }

    .st-key-login_form_panel [data-baseweb="input"] > div:focus-within,
    .st-key-login_form_panel [data-baseweb="base-input"] > div:focus-within {
        border: 1px solid rgba(212, 230, 243, 0.78) !important;
        box-shadow: 0 0 0 2px rgba(145, 191, 222, 0.17) !important;
    }

    .st-key-login_form_panel .stButton > button {
        border: 0 !important;
        border-radius: 999px !important;
        min-height: 3rem;
        margin-top: 0.8rem;
        font-size: 1rem !important;
        font-weight: 800 !important;
        color: #f9fbff !important;
        background: linear-gradient(90deg, #d26c91 0%, #5faecb 100%) !important;
        transition: filter 160ms ease, transform 160ms ease;
    }

    .st-key-login_form_panel .stButton > button:hover {
        filter: brightness(1.07);
        transform: translateY(-1px);
    }

    .st-key-login_form_panel .stButton > button:active {
        transform: translateY(0);
    }

    .st-key-login_form_panel [data-testid="stAlert"] {
        border-radius: 10px;
        margin-top: 0.75rem;
        background: rgba(120, 30, 30, 0.46) !important;
        border: 1px solid rgba(255, 157, 157, 0.42);
        color: #ffe8e8;
    }

    @keyframes fadeUp {
        from { opacity: 0; transform: translateY(8px); }
        to { opacity: 1; transform: translateY(0); }
    }

    @media (max-width: 920px) {
        [data-testid="stAppViewContainer"] > .main .block-container {
            padding: 0.7rem;
        }

        .st-key-login_shell,
        div[data-testid="stVerticalBlock"].st-key-login_shell {
            width: min(1360px, 99vw);
            border-radius: 16px;
        }

        .st-key-login_form_panel,
        .st-key-login_visual_panel,
        div[data-testid="stVerticalBlock"].st-key-login_form_panel,
        div[data-testid="stVerticalBlock"].st-key-login_visual_panel {
            min-height: auto;
            border-right: 0;
            padding: 1.4rem 1rem 1.2rem 1rem;
        }

        .st-key-login_form_wrap,
        div[data-testid="stVerticalBlock"].st-key-login_form_wrap {
            margin-top: 0.2rem;
            padding: 0.9rem;
            border-radius: 12px;
        }

        .login-visual-fill {
            min-height: 320px;
        }
    }
    </style>
    """
    st.markdown(css.replace("__BG__", background_url.replace("'", "%27")), unsafe_allow_html=True)


def render_login_form() -> None:
    _inject_login_css(_resolve_login_background_url())
    ok, reason = mysql_auth_ready()

    center_root = st.container(key="login_center_root")
    with center_root:
        shell = st.container(key="login_shell")
        with shell:
            left, right = st.columns([1.02, 1.0], gap="small")

            with left:
                form_panel = st.container(key="login_form_panel")
                with form_panel:
                    form_wrap = st.container(key="login_form_wrap")
                    with form_wrap:
                        with st.form("login_form", clear_on_submit=False):
                            username = st.text_input("E-mail", placeholder="Enter your e-mail").strip()
                            password = st.text_input("Password", type="password", placeholder="Password")
                            submitted = st.form_submit_button("LOG IN", use_container_width=True)

                    if not ok:
                        st.error(
                            f"MySQL auth is not ready: {reason} "
                            "Configure `.streamlit/secrets.toml` (or MYSQL_AUTH_* env vars)."
                        )
                        st.stop()

                    if submitted:
                        is_ok, role_or_msg = authenticate_mysql_user(username=username, password=password)
                        if is_ok:
                            st.session_state["auth_logged_in"] = True
                            st.session_state["auth_username"] = username
                            st.session_state["auth_role"] = str(role_or_msg).lower()
                            st.session_state["auth_error"] = ""
                            st.rerun()

                        st.session_state["auth_error"] = str(role_or_msg)

                    if st.session_state.get("auth_error"):
                        st.error(st.session_state["auth_error"])

            with right:
                visual_panel = st.container(key="login_visual_panel")
                with visual_panel:
                    st.markdown(
                        """
                        <div class="login-visual-fill"></div>
                        """,
                        unsafe_allow_html=True,
                    )
