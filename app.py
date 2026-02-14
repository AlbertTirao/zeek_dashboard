# app.py
import streamlit as st
from config.client import LOGS_DIR, CLIENT_SECRET_FILE, FOLDER_ID, AUTO_REFRESH_INTERVAL
# UPDATED: Import the new sync function
from services.drive_services import sync_drive_to_parquet 
from ui.sidebar import render_sidebar
from ui.pages import analytics, devices, zeek_logs, alerts, authorization
from pathlib import Path
import os
# CHANGED: background sync + toast log queue
from concurrent.futures import ThreadPoolExecutor
import queue
import time


# -------------------------
# One-time Zeek log → Parquet warm-up (DISK GUARDED)
# -------------------------
from pathlib import Path
# UPDATED: Import the new sync function
from services.drive_services import sync_drive_to_parquet

PARQUET_DIR = Path("data/parquet")
# CHANGED: ensure parquet root exists before warmup flag operations
PARQUET_DIR.mkdir(parents=True, exist_ok=True)
WARMUP_FLAG = PARQUET_DIR / ".WARMED"
# CHANGED: background sync infra (non-blocking dashboard render)

@st.cache_resource
def _bg_executor():
    return ThreadPoolExecutor(max_workers=1)

# CHANGED: per-session toast queue (avoids cross-session log mixing)
def _sync_log_queue():
    if "sync_log_queue" not in st.session_state:
        st.session_state.sync_log_queue = queue.Queue()
    return st.session_state.sync_log_queue

def _drain_sync_toasts(max_items: int = 4):
    """CHANGED: show Drive/Parquet logs as upper-right toasts."""
    q = _sync_log_queue()
    shown = 0
    while shown < max_items:
        try:
            msg = q.get_nowait()
        except queue.Empty:
            break
        st.toast(msg)
        shown += 1

def _start_background_sync(reason: str):
    """CHANGED: schedule sync without blocking the dashboard render."""
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
        log_callback=_sync_log_queue().put,  # CHANGED: log → queue → toasts
    )
    st.toast(f"🔄 Sync started: {reason}")

def _poll_background_sync():
    """CHANGED: when sync finishes, clear caches + mark warmup flag."""
    fut = st.session_state.get("sync_future")
    if fut is None or not fut.done():
        return

    try:
        updated = fut.result()

        # Mark warmup complete ONLY after a successful sync
        if not WARMUP_FLAG.exists():
            WARMUP_FLAG.touch()

        # Important: pages use st.cache_data; clear so new parquet is reflected
        st.cache_data.clear()
        st.toast(f"✅ Sync finished ({updated} logs updated)")

        # CHANGED: refresh UI immediately to reflect new parquet
        st.rerun()

    except Exception as e:
        st.toast(f"❌ Sync failed: {e}")
    finally:
        st.session_state.pop("sync_future", None)

status_placeholder = st.empty()

# CHANGED: non-blocking warmup (dashboard can render immediately)
_drain_sync_toasts()
_poll_background_sync()

if not WARMUP_FLAG.exists():
    if "warmup_started" not in st.session_state:
        st.session_state.warmup_started = True
        _start_background_sync("initial warmup")
        st.toast("🔥 Initializing Parquet cache in background...")
else:
    if "warmup_notice_shown" not in st.session_state:
        st.toast("⚡ Parquet cache already initialized — skipping Drive parse")
        st.session_state.warmup_notice_shown = True

# =====================================================
# CONFIGURATION
# =====================================================
# PARQUET_ROOT = Path("data/parquet")
AUTHORIZED_MACS_FILE = Path("authorized_macs.txt")

# CHANGED: schedule auto-sync in background; do NOT block page render
if "data_synced" not in st.session_state:
    _start_background_sync("auto session sync")
    st.session_state.data_synced = True

# CHANGED: make default match render_current_page() routing
if "initialized" not in st.session_state:
    st.session_state.current_page = "Device Inspections"
    st.session_state.initialized = True

# CHANGED: render sidebar ONCE and persist selection (fixes DuplicateElementId)
selected_page = render_sidebar(auto_refresh_interval=AUTO_REFRESH_INTERVAL)  # CHANGED
st.session_state.current_page = selected_page  # CHANGED

# CHANGED: force refresh schedules background sync + keeps dashboard visible
if st.sidebar.button("🔄 Force Refresh Data"):
    st.session_state.pop("data_synced", None)
    _start_background_sync("manual refresh")
    st.rerun()

def render_current_page():
    page = st.session_state.current_page
    
    # NOTE: Ensure your page modules (devices, tables, etc.) 
    # are updated to accept PARQUET_DIR (Path object) 
    # and use load_single_log() internally.
    
    if page == "Device Inspections":
        devices.render(PARQUET_DIR, AUTHORIZED_MACS_FILE)
        
    elif page == "Traffic Monitoring":
        analytics.render(PARQUET_DIR)
        
    elif page == "Zeek Logs":
        zeek_logs.render(PARQUET_DIR)
        
    elif page == "Alerts":  
        alerts.render(PARQUET_DIR, AUTHORIZED_MACS_FILE)
        
    elif page == "Authorization":
        authorization.render(AUTHORIZED_MACS_FILE)

# =====================================================
# MAIN EXECUTION
# =====================================================
render_current_page()