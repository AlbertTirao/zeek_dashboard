# app.py
import time
import queue
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import streamlit as st

# Use one global page layout so auth/logout cycles render consistently.
st.set_page_config(page_title="Zeek Dashboard", layout="wide")

from config.client import (
    CLIENT_SECRET_FILE,
    FOLDER_ID,
    AUTO_REFRESH_INTERVAL,
    PARQUET_DIR,
)

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
# One-time Zeek log → Parquet warm-up (DISK GUARDED)
# =====================================================

PARQUET_DIR.mkdir(parents=True, exist_ok=True)
WARMUP_FLAG = PARQUET_DIR / ".WARMED"


# =====================================================
# Background sync + toast log queue
# =====================================================

@st.cache_resource
def _bg_executor():
    return ThreadPoolExecutor(max_workers=1)

def _sync_log_queue():
    if "sync_log_queue" not in st.session_state:
        st.session_state.sync_log_queue = queue.Queue()
    return st.session_state.sync_log_queue

def _drain_sync_toasts(max_items: int = 4):
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
    fut = st.session_state.get("sync_future")
    if fut is not None and not fut.done():
        return  # already running

    st.session_state.sync_reason = reason
    st.session_state.sync_started_ts = time.time()

    st.session_state.sync_future = _bg_executor().submit(
        sync_drive_to_parquet,
        client_secret_path=CLIENT_SECRET_FILE,
        folder_id=FOLDER_ID,
        parquet_root=PARQUET_DIR,
        log_callback=_sync_log_queue().put,
    )
    APP_LOGGER.info(f"🔄 Sync started: {reason}")

def _poll_background_sync():
    fut = st.session_state.get("sync_future")
    if fut is None or not fut.done():
        return

    try:
        updated = fut.result()

        if not WARMUP_FLAG.exists():
            WARMUP_FLAG.touch()

        # Important: pages use both st.cache_data and st.cache_resource.
        # Clear both so freshly-synced parquet is reflected immediately.
        st.cache_data.clear()
        st.cache_resource.clear()
        st.session_state["_parquet_sync_token"] = int(st.session_state.get("_parquet_sync_token", 0)) + 1
        APP_LOGGER.info(f"✅ Sync finished ({updated} logs updated)")
        st.rerun()

    except Exception as e:
        APP_LOGGER.error(f"❌ Sync failed: {e}")
    finally:
        st.session_state.pop("sync_future", None)


# =====================================================
# Non-blocking warmup + polling
# =====================================================

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

if "data_synced" not in st.session_state:
    _start_background_sync("auto session sync")
    st.session_state.data_synced = True

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

# Render sidebar ONCE
selected_page = render_sidebar(
    auto_refresh_interval=AUTO_REFRESH_INTERVAL,
    menu_options=menu_options,
    menu_icons=menu_icons,
)

# ✅ Logout action: go back to login page immediately
if selected_page == "Logout":
    perform_logout()

st.session_state.current_page = selected_page


def render_current_page():
    page = st.session_state.current_page

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
