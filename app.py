# app.py
import time
import queue
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import streamlit as st

# Use one global page layout so auth/logout cycles render consistently.
st.set_page_config(page_title="Zeek Dashboard", layout="wide")

# CHANGED: import PARQUET_DIR from config (single source of truth)
from config.client import (
    CLIENT_SECRET_FILE,
    FOLDER_ID,
    AUTO_REFRESH_INTERVAL,
    PARQUET_DIR,   # CHANGED (was local Path("data/parquet"))
)

# CHANGED: import once
from services.drive_services import sync_drive_to_parquet
from services import auth_service

from ui.auth import require_authentication, current_user, clear_persistent_auth_session
from ui.sidebar import render_sidebar
from ui.pages import analytics, devices, zeek_logs, alerts, authorization, user_management


# =====================================================
# Terminal logger
# =====================================================

APP_LOGGER = logging.getLogger("zeek_dashboard.app")
if not APP_LOGGER.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    APP_LOGGER.addHandler(_handler)
APP_LOGGER.setLevel(logging.INFO)
APP_LOGGER.propagate = False


# =====================================================
# Authentication (MongoDB via Python)
# =====================================================

if "auth_schema_initialized" not in st.session_state:
    try:
        auth_service.init_auth_schema()
        auth_service.seed_bootstrap_admin()
        st.session_state.auth_schema_initialized = True
    except Exception as e:
        st.error("Authentication service is not available.")
        st.caption(
            "Set AUTH_MONGODB_URI (or MONGODB_URI). "
            "Optional first-run admin: BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD."
        )
        st.code(str(e))
        st.stop()

require_authentication()
auth_user = current_user()
if not auth_user:
    st.stop()


# =====================================================
# One-time Zeek log → Parquet warm-up (DISK GUARDED)
# =====================================================

# CHANGED: ensure parquet root exists before warmup flag operations
PARQUET_DIR.mkdir(parents=True, exist_ok=True)

# CHANGED: warmup flag lives under the parquet root
WARMUP_FLAG = PARQUET_DIR / ".WARMED"

# NOTE: LOGS_DIR imported previously but unused in your code; removed to keep clean.


# =====================================================
# Background sync + toast log queue
# =====================================================

@st.cache_resource
def _bg_executor():
    return ThreadPoolExecutor(max_workers=1)

# CHANGED: per-session toast queue (avoids cross-session log mixing)
def _sync_log_queue():
    if "sync_log_queue" not in st.session_state:
        st.session_state.sync_log_queue = queue.Queue()
    return st.session_state.sync_log_queue

def _drain_sync_toasts(max_items: int = 4):
    """Write queued Drive/Parquet messages to terminal logs."""
    q = _sync_log_queue()
    shown = 0
    while shown < max_items:
        try:
            msg = q.get_nowait()
        except queue.Empty:
            break
        APP_LOGGER.info(msg)
        shown += 1

def _start_background_sync(reason: str):
    """Schedule sync without blocking the dashboard render."""
    fut = st.session_state.get("sync_future")
    if fut is not None and not fut.done():
        return  # already running

    st.session_state.sync_reason = reason
    st.session_state.sync_started_ts = time.time()

    # CHANGED: call sync_drive_to_parquet exactly once; auth mode handled inside drive_services.py
    st.session_state.sync_future = _bg_executor().submit(
        sync_drive_to_parquet,
        client_secret_path=CLIENT_SECRET_FILE,
        folder_id=FOLDER_ID,
        parquet_root=PARQUET_DIR,
        log_callback=_sync_log_queue().put,  # log → queue → terminal logs
    )
    APP_LOGGER.info(f"🔄 Sync started: {reason}")

def _poll_background_sync():
    """When sync finishes, clear caches + mark warmup flag."""
    fut = st.session_state.get("sync_future")
    if fut is None or not fut.done():
        return

    try:
        updated = fut.result()

        # Mark warmup complete ONLY after a successful sync
        if not WARMUP_FLAG.exists():
            WARMUP_FLAG.touch()

        # Important: pages use both st.cache_data and st.cache_resource.
        # Clear both so freshly-synced parquet is reflected immediately.
        st.cache_data.clear()
        st.cache_resource.clear()
        st.session_state["_parquet_sync_token"] = int(st.session_state.get("_parquet_sync_token", 0)) + 1
        APP_LOGGER.info(f"✅ Sync finished ({updated} logs updated)")

        # refresh UI immediately to reflect new parquet
        st.rerun()

    except Exception as e:
        APP_LOGGER.error(f"❌ Sync failed: {e}")
    finally:
        st.session_state.pop("sync_future", None)


# =====================================================
# Non-blocking warmup + polling
# =====================================================

# REMOVED: status_placeholder = st.empty() (unused)

_drain_sync_toasts()
_poll_background_sync()

if not WARMUP_FLAG.exists():
    if "warmup_started" not in st.session_state:
        st.session_state.warmup_started = True
        _start_background_sync("initial warmup")
        APP_LOGGER.info("🔥 Initializing Parquet cache in background...")
else:
    if "warmup_notice_shown" not in st.session_state:
        APP_LOGGER.info("⚡ Parquet cache already initialized — skipping Drive parse")
        st.session_state.warmup_notice_shown = True


# =====================================================
# CONFIGURATION
# =====================================================

AUTHORIZED_MACS_FILE = Path("authorized_macs.txt")

# schedule auto-sync in background; do NOT block page render
if "data_synced" not in st.session_state:
    _start_background_sync("auto session sync")
    st.session_state.data_synced = True

# make default match render_current_page() routing
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

if st.session_state.current_page not in menu_options:
    st.session_state.current_page = menu_options[0]

# render sidebar ONCE and persist selection (fixes DuplicateElementId)
selected_page = render_sidebar(
    auto_refresh_interval=AUTO_REFRESH_INTERVAL,
    menu_options=menu_options,
    menu_icons=menu_icons,
)
st.session_state.current_page = selected_page

with st.sidebar:
    st.markdown(
        """
        <style>
        [data-testid="stSidebar"] .block-container {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        [data-testid="stSidebar"] .block-container > div {
            min-height: 100%;
            display: flex;
            flex-direction: column;
        }

        [data-testid="stSidebar"] [data-testid="stVerticalBlock"]:has(.sidebar-account-marker) {
            margin-top: auto;
            padding-top: 1rem;
            border-top: 1px solid #334255;
        }

        .sidebar-user-card {
            margin-top: 0.8rem;
            margin-bottom: 0.55rem;
            padding: 0.65rem 0.75rem;
            border: 1px solid #2f3f57;
            border-radius: 12px;
            background: linear-gradient(160deg, #1f2d3f 0%, #182233 100%);
        }

        .sidebar-user-label {
            color: #90a2ba;
            font-size: 0.69rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            margin-bottom: 0.25rem;
        }

        .sidebar-user-name {
            color: #eef5ff;
            font-size: 0.95rem;
            font-weight: 700;
            line-height: 1.2;
        }

        .sidebar-user-role {
            color: #9ec8ff;
            font-size: 0.78rem;
            font-weight: 600;
            margin-top: 0.15rem;
        }

        [data-testid="stSidebar"] .stButton {
            margin-top: 0.35rem;
        }

        [data-testid="stSidebar"] .stButton > button {
            border-radius: 14px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    account_actions = st.container()
    with account_actions:
        st.markdown("<div class='sidebar-account-marker'></div>", unsafe_allow_html=True)
        st.markdown(
            f"""
            <div class="sidebar-user-card">
                <div class="sidebar-user-label">Signed in</div>
                <div class="sidebar-user-name">{auth_user["username"]}</div>
                <div class="sidebar-user-role">{auth_user["role"].title()}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Logout", use_container_width=True):
            clear_persistent_auth_session()
            # Reset all transient UI/session state so the login page always
            # renders with a clean layout after logout.
            preserve_keys = {"auth_schema_initialized"}
            for key in list(st.session_state.keys()):
                if key not in preserve_keys:
                    st.session_state.pop(key, None)
            st.rerun()
        # force refresh schedules background sync + keeps dashboard visible
        if st.button("🔄 Force Refresh Data", use_container_width=True):
            st.session_state.pop("data_synced", None)
            _start_background_sync("manual refresh")
            st.rerun()


def render_current_page():
    page = st.session_state.current_page

    # NOTE: Ensure your page modules (devices, tables, etc.)
    # are updated to accept PARQUET_DIR (Path object)
    # and use load_single_log() internally.

    if page == "Device Inspection":
        devices.render(PARQUET_DIR, AUTHORIZED_MACS_FILE)

    elif page == "Traffic Monitoring":
        analytics.render(PARQUET_DIR)

    elif page == "Zeek Logs":
        zeek_logs.render(PARQUET_DIR)

    elif page == "Alerts":
        alerts.render(PARQUET_DIR, AUTHORIZED_MACS_FILE)

    elif page == "Authorization":
        if auth_user["role"] != "admin":
            st.error("Admin role is required for this page.")
            return
        authorization.render(AUTHORIZED_MACS_FILE)

    elif page == "User Management":
        if auth_user["role"] != "admin":
            st.error("Admin role is required for this page.")
            return
        user_management.render(current_username=auth_user["username"])


# Keep header vertical position consistent across pages.
def inject_global_header_alignment_css():
    st.markdown(
        """
        <style>
        html body [data-testid="stAppViewContainer"] .block-container,
        html body [data-testid="stAppViewContainer"] .main .block-container,
        html body [data-testid="stAppViewContainer"] [data-testid="stMainBlockContainer"] {
            padding-top: 0.05rem !important;
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

