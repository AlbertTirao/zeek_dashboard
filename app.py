# app.py
import importlib
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import streamlit as st
from streamlit_autorefresh import st_autorefresh

# Use one global page layout so auth/logout cycles render consistently.
st.set_page_config(page_title="Zeek Dashboard", layout="wide")

from config import client as client_config

AUTO_REFRESH_INTERVAL = int(getattr(client_config, "AUTO_REFRESH_INTERVAL", 3600))
CLIENT_SECRET_FILE = str(getattr(client_config, "CLIENT_SECRET_FILE", ""))
DRIVE_AUTH_MODE = str(getattr(client_config, "DRIVE_AUTH_MODE", "oauth")).strip().lower()
DRIVE_CREDENTIALS_FILE = str(getattr(client_config, "DRIVE_CREDENTIALS_FILE", "secrets/drive_credentials.json"))
DRIVE_SYNC_INTERVAL = int(getattr(client_config, "DRIVE_SYNC_INTERVAL", AUTO_REFRESH_INTERVAL))
DRIVE_SYNC_LOOKBACK_DAYS = int(getattr(client_config, "DRIVE_SYNC_LOOKBACK_DAYS", 2))
FOLDER_ID = str(getattr(client_config, "FOLDER_ID", ""))
PARQUET_DIR = Path(getattr(client_config, "PARQUET_DIR", Path("data/parquet")))

from services import auth_service
from services.drive_services import (
    DriveOAuthReauthRequired,
    reauthenticate_drive_oauth_interactive,
    sync_drive_to_parquet,
)

from ui.auth import require_authentication, current_user, clear_persistent_auth_session
from ui.sidebar import render_sidebar

BACKGROUND_SYNC_POLL_INTERVAL_SECONDS = 15


@dataclass
class DriveSyncManager:
    executor: ThreadPoolExecutor = field(default_factory=lambda: ThreadPoolExecutor(max_workers=1))
    lock: threading.Lock = field(default_factory=threading.Lock)
    future: object = None
    messages: deque[str] = field(default_factory=lambda: deque(maxlen=50))
    requested_at: float = 0.0
    completed_at: float = 0.0
    last_error: str = ""
    last_processed: int = 0
    last_run_at: str = ""
    target_dates: tuple[str, ...] = field(default_factory=tuple)
    reauth_required: bool = False
    completion_token: int = 0
    parquet_token: int = 0

    def log(self, message: str) -> None:
        with self.lock:
            self.messages.append(str(message))

    def snapshot(self) -> dict:
        with self.lock:
            future = self.future
            return {
                "running": bool(future is not None and not future.done()),
                "messages": list(self.messages),
                "requested_at": float(self.requested_at or 0.0),
                "completed_at": float(self.completed_at or 0.0),
                "last_error": str(self.last_error or ""),
                "last_processed": int(self.last_processed or 0),
                "last_run_at": str(self.last_run_at or ""),
                "target_dates": tuple(self.target_dates),
                "reauth_required": bool(self.reauth_required),
                "completion_token": int(self.completion_token or 0),
                "parquet_token": int(self.parquet_token or 0),
            }

    def maybe_start(self, *, min_interval_seconds: int, target_dates: tuple[str, ...]) -> bool:
        with self.lock:
            future = self.future
            last_tick = max(float(self.requested_at or 0.0), float(self.completed_at or 0.0))
            if future is not None and not future.done():
                return False
            if self.reauth_required:
                return False
            if last_tick and (time.time() - last_tick) < max(int(min_interval_seconds), 30):
                return False
            self.requested_at = time.time()
            self.target_dates = tuple(target_dates)
            self.future = self.executor.submit(
                sync_drive_to_parquet,
                CLIENT_SECRET_FILE,
                FOLDER_ID,
                PARQUET_DIR,
                self.target_dates,
                self.log,
            )
            return True

    def poll(self) -> bool:
        with self.lock:
            future = self.future
        if future is None or not future.done():
            return False

        processed = 0
        error = ""
        reauth_required = False
        try:
            processed = int(future.result() or 0)
        except Exception as exc:
            error = str(exc)
            reauth_required = isinstance(exc, DriveOAuthReauthRequired)

        with self.lock:
            if self.future is future:
                self.future = None
            self.last_error = error
            self.reauth_required = bool(reauth_required)
            if not error:
                self.last_processed = processed
                if processed > 0:
                    self.parquet_token = int(self.parquet_token or 0) + 1
                self.reauth_required = False
            self.last_run_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.completed_at = time.time()
            self.completion_token = int(self.completion_token or 0) + 1
        return True

    def notify_credentials_refreshed(self) -> None:
        with self.lock:
            self.future = None
            self.requested_at = 0.0
            self.completed_at = 0.0
            self.last_error = ""
            self.reauth_required = False
            self.messages.append("Google Drive reconnected. Background sync will retry automatically.")


# =====================================================
# Helpers
# =====================================================

def _clear_query_params():
    """
    Important: if your login uses ?auth=... in the URL, this MUST be cleared
    on logout or require_authentication() may instantly log you back in.
    """
    try:
        # Newer Streamlit
        st.query_params.clear()
    except Exception:
        try:
            # Older Streamlit
            st.experimental_set_query_params()
        except Exception:
            pass


def perform_logout():
    """
    Hard logout:
      - clears persistent auth (cookie/file/etc.)
      - clears URL query params (auth token)
      - clears session_state
      - reruns -> login page is shown by require_authentication()
    """
    clear_persistent_auth_session()
    _clear_query_params()

    preserve_keys = {"auth_schema_initialized"}
    for key in list(st.session_state.keys()):
        if key not in preserve_keys:
            st.session_state.pop(key, None)

    st.rerun()


def _auto_sync_target_dates() -> tuple[str, ...]:
    lookback_days = int(DRIVE_SYNC_LOOKBACK_DAYS or 0)
    # lookback_days <= 0 means "sync every available Drive date".
    if lookback_days <= 0:
        return tuple()

    today = datetime.now().date()
    return tuple((today - timedelta(days=offset)).strftime("%Y-%m-%d") for offset in range(lookback_days))


@st.cache_resource
def _drive_sync_manager() -> DriveSyncManager:
    return DriveSyncManager()


def _sync_session_drive_state(snapshot: dict) -> None:
    st.session_state["_drive_sync_messages"] = list(snapshot.get("messages") or [])
    st.session_state["_drive_sync_last_error"] = str(snapshot.get("last_error") or "")
    st.session_state["_drive_sync_last_processed"] = int(snapshot.get("last_processed") or 0)
    st.session_state["_drive_sync_last_run_at"] = str(snapshot.get("last_run_at") or "")
    st.session_state["_drive_sync_requested_at"] = float(snapshot.get("requested_at") or 0.0)
    st.session_state["_drive_sync_completed_at"] = float(snapshot.get("completed_at") or 0.0)
    st.session_state["_drive_sync_target_dates"] = tuple(snapshot.get("target_dates") or ())
    st.session_state["_drive_sync_reauth_required"] = bool(snapshot.get("reauth_required"))

    previous_completion_token = st.session_state.get("_drive_sync_seen_completion_token")
    completion_token = int(snapshot.get("completion_token") or 0)
    parquet_token = int(snapshot.get("parquet_token") or 0)
    current_parquet_token = int(st.session_state.get("_parquet_sync_token", 0) or 0)

    st.session_state["_drive_sync_seen_completion_token"] = completion_token
    if parquet_token != current_parquet_token:
        st.session_state["_parquet_sync_token"] = parquet_token
        if previous_completion_token is not None:
            st.cache_data.clear()
            st.rerun()


def _poll_background_drive_sync() -> dict:
    manager = _drive_sync_manager()
    manager.poll()
    snapshot = manager.snapshot()
    _sync_session_drive_state(snapshot)
    return snapshot


def _maybe_schedule_background_drive_sync() -> dict:
    manager = _drive_sync_manager()
    manager.maybe_start(
        min_interval_seconds=max(int(DRIVE_SYNC_INTERVAL), 30),
        target_dates=_auto_sync_target_dates(),
    )
    snapshot = manager.snapshot()
    _sync_session_drive_state(snapshot)
    return snapshot


def _background_refresh_interval_seconds(*, sync_running: bool) -> int:
    if sync_running:
        return max(min(int(AUTO_REFRESH_INTERVAL), BACKGROUND_SYNC_POLL_INTERVAL_SECONDS), 5)
    return max(int(AUTO_REFRESH_INTERVAL), 30)


def _ensure_background_refresh(*, sync_running: bool) -> None:
    st_autorefresh(
        interval=int(_background_refresh_interval_seconds(sync_running=sync_running)) * 1000,
        key="background_sync_refresh_timer",
    )


def _render_drive_reauth_notice() -> None:
    if DRIVE_AUTH_MODE not in {"oauth", "auto"}:
        return
    if not bool(st.session_state.get("_drive_sync_reauth_required")):
        return

    error_text = str(st.session_state.get("_drive_sync_last_error") or "").strip()
    with st.sidebar:
        st.warning("Google Drive login expired. Reconnect to resume parquet backfill.")
        st.caption("Click reconnect to open the Google login flow and save a new Drive token.")
        if error_text:
            st.caption(error_text)
        if st.button("Reconnect Google Drive", key="drive_oauth_reconnect_btn", use_container_width=True):
            try:
                with st.spinner("Waiting for Google Drive login..."):
                    reauthenticate_drive_oauth_interactive(
                        CLIENT_SECRET_FILE,
                        DRIVE_CREDENTIALS_FILE,
                    )
            except Exception as exc:
                st.session_state["_drive_sync_last_error"] = f"Drive re-login failed: {exc}"
                st.error(st.session_state["_drive_sync_last_error"])
            else:
                manager = _drive_sync_manager()
                manager.notify_credentials_refreshed()
                _sync_session_drive_state(manager.snapshot())
                st.rerun()


PARQUET_DIR.mkdir(parents=True, exist_ok=True)
drive_sync_snapshot = _poll_background_drive_sync()
drive_sync_snapshot = _maybe_schedule_background_drive_sync()
_ensure_background_refresh(sync_running=bool(drive_sync_snapshot.get("running")))


# =====================================================
# Authentication (MongoDB/MySQL via Python)
# =====================================================

if "auth_schema_initialized" not in st.session_state:
    try:
        auth_service.init_auth_schema()
        auth_service.seed_bootstrap_admin()
        st.session_state.auth_schema_initialized = True
    except Exception as e:
        st.error("Authentication service is not available.")
        st.caption(
            "Set AUTH_DB_BACKEND plus DB settings. For MongoDB: AUTH_MONGODB_URI. "
            "For MySQL: AUTH_MYSQL_HOST, AUTH_MYSQL_PORT, AUTH_MYSQL_USER, AUTH_MYSQL_PASSWORD, AUTH_MYSQL_DATABASE. "
            "Optional first-run admin: BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD."
        )
        st.code(str(e))
        st.stop()

require_authentication()
auth_user = current_user()
if not auth_user:
    st.stop()


# =====================================================
# CONFIGURATION
# =====================================================

AUTHORIZED_MACS_FILE = Path("authorized_macs.txt")

if "initialized" not in st.session_state:
    st.session_state.current_page = "Device Inspection"
    st.session_state.initialized = True

if auth_user["role"] == "admin":
    menu_options = [
        "Device Inspection",
        "Traffic Monitoring",
        "Zeek Logs",
        "Alerts",
        "Authorization",
        "User Management",
    ]
    menu_icons = [
        "pc-display",
        "activity",
        "file-earmark-text",
        "bell",
        "shield-lock",
        "people",
    ]
else:
    menu_options = [
        "Device Inspection",
        "Traffic Monitoring",
        "Zeek Logs",
        "Alerts",
    ]
    menu_icons = [
        "pc-display",
        "activity",
        "file-earmark-text",
        "bell",
    ]

# ✅ Logout in option_menu (last)
if "Logout" not in menu_options:
    menu_options.append("Logout")
    menu_icons.append("box-arrow-right")

# Prevent "Logout" from sticking as a page
if st.session_state.get("current_page") == "Logout":
    st.session_state.current_page = menu_options[0]

if st.session_state.current_page not in menu_options:
    st.session_state.current_page = menu_options[0]

# Keep the sidebar on the current page when any dialog is open.
def _is_any_dialog_open() -> bool:
    if st.session_state.get("active_dialog"):
        return True
    for key, value in st.session_state.items():
        if "dialog_open" in str(key) and bool(value):
            return True
    return False

dialog_open = _is_any_dialog_open()
if dialog_open and st.session_state.get("current_page"):
    st.session_state.sidebar_page = st.session_state.current_page

# Render sidebar ONCE
selected_page = render_sidebar(
    auto_refresh_interval=0,
    menu_options=menu_options,
    menu_icons=menu_icons,
)
_render_drive_reauth_notice()

# ✅ Logout action: go back to login page immediately
if selected_page == "Logout":
    perform_logout()

if dialog_open and st.session_state.get("current_page"):
    st.session_state.sidebar_page = st.session_state.current_page
else:
    st.session_state.current_page = selected_page


PAGE_LOADING_CONFIG = {
    "Device Inspection": {
        "title": "Loading Device Inspection",
        "subtitle": "Preparing device inventory, trust posture, and activity context for the latest telemetry.",
        "steps": ["Read inventory", "Merge trust state", "Render overview"],
    },
    "Zeek Logs": {
        "title": "Loading Zeek Logs",
        "subtitle": "Scanning parquet logs, discovering datasets, and preparing the raw log explorer.",
        "steps": ["Discover dates", "Read parquet", "Render explorer"],
    },
    "Alerts": {
        "title": "Loading Alerts",
        "subtitle": "Calculating trust posture, alert summaries, and anomaly context from the latest device activity.",
        "steps": ["Read signals", "Score alerts", "Render overview"],
    },
    "Authorization": {
        "title": "Loading Authorization",
        "subtitle": "Preparing device, domain, AI policy, and ban-list controls for administration.",
        "steps": ["Read policies", "Prepare tables", "Render controls"],
    },
    "User Management": {
        "title": "Loading User Management",
        "subtitle": "Loading account records, access roles, and the admin management workspace.",
        "steps": ["Read users", "Prepare table", "Render controls"],
    },
}


def inject_page_loading_css() -> None:
    st.markdown(
        """
        <style>
        .dashboard-loading-shell {
            position: relative;
            overflow: hidden;
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 18px;
            padding: 18px 20px 16px 20px;
            margin: 8px 0 16px 0;
            background:
                radial-gradient(circle at top right, rgba(0,247,255,0.08), transparent 40%),
                linear-gradient(135deg, rgba(255,255,255,0.045), rgba(255,255,255,0.015));
            box-shadow: 0 14px 38px rgba(0,0,0,0.25);
        }

        .dashboard-loading-shell::before {
            content: "";
            position: absolute;
            inset: 0;
            background: linear-gradient(110deg, transparent 20%, rgba(255,255,255,0.08) 48%, transparent 72%);
            transform: translateX(-120%);
            animation: dashboard-loading-sweep 1.9s linear infinite;
            pointer-events: none;
        }

        .dashboard-loading-kicker {
            font-size: 0.72rem;
            letter-spacing: 0.16em;
            text-transform: uppercase;
            font-weight: 800;
            color: #7EE7FF;
            margin-bottom: 0.32rem;
        }

        .dashboard-loading-title {
            font-size: 1.05rem;
            font-weight: 900;
            line-height: 1.2;
            color: #F5FAFF;
        }

        .dashboard-loading-copy {
            margin-top: 0.22rem;
            color: rgba(255,255,255,0.76);
            font-size: 0.88rem;
        }

        .dashboard-loading-steps {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-top: 0.85rem;
        }

        .dashboard-loading-step {
            display: inline-flex;
            align-items: center;
            border: 1px solid rgba(255,255,255,0.14);
            background: rgba(255,255,255,0.04);
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 0.74rem;
            font-weight: 700;
            color: #DCEAFB;
        }

        .dashboard-loading-bars {
            display: grid;
            gap: 7px;
            margin-top: 0.85rem;
        }

        .dashboard-loading-bar {
            position: relative;
            overflow: hidden;
            height: 8px;
            border-radius: 999px;
            background: rgba(255,255,255,0.09);
        }

        .dashboard-loading-bar::after {
            content: "";
            position: absolute;
            inset: 0;
            border-radius: inherit;
            background: linear-gradient(90deg, rgba(0,247,255,0.12), rgba(0,247,255,0.95), rgba(246,48,73,0.28));
            transform: translateX(-55%);
            animation: dashboard-loading-pulse 1.25s ease-in-out infinite;
            animation-delay: var(--delay, 0s);
        }

        @keyframes dashboard-loading-sweep {
            to { transform: translateX(120%); }
        }

        @keyframes dashboard-loading-pulse {
            0%, 100% { transform: translateX(-55%); opacity: 0.78; }
            50% { transform: translateX(20%); opacity: 1; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _render_page_loading_state(slot, *, title: str, subtitle: str, steps: list[str]) -> None:
    chips = "".join(
        [f"<span class='dashboard-loading-step'>{step}</span>" for step in steps if str(step).strip()]
    )
    bars = "".join(
        [f"<div class='dashboard-loading-bar' style='--delay:{idx * 0.15}s'></div>" for idx in range(3)]
    )
    slot.markdown(
        f"""
        <div class="dashboard-loading-shell">
            <div class="dashboard-loading-kicker">Dashboard</div>
            <div class="dashboard-loading-title">{title}</div>
            <div class="dashboard-loading-copy">{subtitle}</div>
            <div class="dashboard-loading-steps">{chips}</div>
            <div class="dashboard-loading-bars">{bars}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


@contextmanager
def _page_loading_ui(page: str):
    config = PAGE_LOADING_CONFIG.get(str(page))
    if not config:
        yield
        return

    inject_page_loading_css()
    slot = st.empty()
    _render_page_loading_state(
        slot,
        title=str(config["title"]),
        subtitle=str(config["subtitle"]),
        steps=[str(x) for x in config.get("steps", [])],
    )
    try:
        with st.spinner(f"Loading {page}..."):
            yield
    finally:
        slot.empty()


def render_current_page():
    page = st.session_state.current_page

    if page == "Device Inspection":
        devices = importlib.import_module("ui.pages.devices")
        devices.render(PARQUET_DIR, AUTHORIZED_MACS_FILE)

    elif page == "Traffic Monitoring":
        analytics = importlib.import_module("ui.pages.analytics")
        analytics.render(PARQUET_DIR)

    elif page == "Zeek Logs":
        zeek_logs = importlib.import_module("ui.pages.zeek_logs")
        zeek_logs.render(PARQUET_DIR)

    elif page == "Alerts":
        alerts = importlib.import_module("ui.pages.alerts")
        alerts.render(PARQUET_DIR, AUTHORIZED_MACS_FILE)

    elif page == "Authorization":
        if auth_user["role"] != "admin":
            st.error("Admin role is required for this page.")
            return
        authorization = importlib.import_module("ui.pages.authorization")
        authorization.render(AUTHORIZED_MACS_FILE)

    elif page == "User Management":
        if auth_user["role"] != "admin":
            st.error("Admin role is required for this page.")
            return
        user_management = importlib.import_module("ui.pages.user_management")
        user_management.render(current_username=auth_user["username"])


def inject_global_header_alignment_css():
    st.markdown(
        """
        <style>
        html body header[data-testid="stHeader"],
        html body [data-testid="stToolbar"],
        html body #MainMenu,
        html body footer,
        html body [data-testid="stDecoration"] {
            display: none !important;
            visibility: hidden !important;
            height: 0 !important;
            min-height: 0 !important;
        }

        html body [data-testid="stAppViewContainer"] .block-container,
        html body [data-testid="stAppViewContainer"] .main .block-container,
        html body [data-testid="stAppViewContainer"] [data-testid="stMainBlockContainer"] {
            padding-top: 0.35rem !important;
            margin-top: -3.05rem !important;
        }

        html body [data-testid="stAppViewContainer"],
        html body [data-testid="stAppViewContainer"] > .main,
        html body [data-testid="stAppViewContainer"] .main,
        html body [data-testid="stMain"] {
            padding-top: 0 !important;
            margin-top: 0 !important;
            top: 0 !important;
        }

        html body [data-testid="stSidebar"] .block-container {
            padding-top: 0.35rem !important;
            margin-top: -3.05rem !important;
        }

        html body .tm-page-header,
        html body .alerts-page-header,
        html body .page-header,
        html body .um-page-header {
            margin-top: 0 !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


# =====================================================
# MAIN EXECUTION
# =====================================================

render_current_page()
inject_global_header_alignment_css()
