# app.py
import streamlit as st
from config.client import LOGS_DIR, CLIENT_SECRET_FILE, FOLDER_ID, AUTO_REFRESH_INTERVAL
from services.drive_services import parse_drive_logs_to_parquet
from ui.sidebar import render_sidebar
from ui.pages import analytics, devices, tables, zeek_logs, alerts, authorization
from pathlib import Path
import os

# -------------------------
# One-time Zeek log → Parquet warm-up (DISK GUARDED)
# -------------------------
from pathlib import Path
from services.drive_services import parse_drive_logs_to_parquet

PARQUET_DIR = Path("data/parquet")
WARMUP_FLAG = PARQUET_DIR / ".WARMED"
status_placeholder = st.empty()

if not WARMUP_FLAG.exists():
    st.write("🔥 Initializing Parquet cache from ALL Zeek logs...")

    parse_drive_logs_to_parquet(
        client_secret_path=CLIENT_SECRET_FILE,
        folder_id=FOLDER_ID,
        parquet_root=PARQUET_DIR,
    )

    WARMUP_FLAG.touch()
    st.write("✅ Parquet cache ready (raw logs untouched)")
else:
    if "warmup_notice_shown" not in st.session_state:
        status_placeholder.write(
            "Parquet cache already initialized — skipping Drive parse"
        )
        st.session_state.warmup_notice_shown = True
    else:
        status_placeholder.empty()

# # -------------------------
# # Load & verify Parquet cache (PRINT ON EVERY RERUN)
# # -------------------------
# from services.drive_services import load_all_parquets
# from pathlib import Path

# PARQUET_DIR = Path("data/parquet")

# # Always load from Streamlit cache (fast, no re-read if unchanged)
# parquet_cache = load_all_parquets(PARQUET_DIR)

# # 🔁 ALWAYS print on every script execution (refresh, rerun, auto-refresh)
# st.write("🔎 Verifying Parquet cache on this run:")
# debug_print_parquet_cache(parquet_cache)

# # -------------------------
# # One-time Parquet → Pickle warm-up (DISK GUARDED)
# # -------------------------
# PICKLE_DIR = PARQUET_DIR / "pickle"
# PICKLE_WARMUP_FLAG = PICKLE_DIR / ".WARMED"

# if not PICKLE_WARMUP_FLAG.exists():
#     save_parquet_as_pickle(PARQUET_DIR, PICKLE_DIR)
#     PICKLE_WARMUP_FLAG.touch()
#     st.write("💾 Pickle cache ready")
# else:
#     st.write("⚡ Pickle cache already initialized — skipping conversion")

# # =====================================================
# # CONFIGURATION
# # =====================================================
# PARQUET_ROOT = Path("data/parquet")
AUTHORIZED_MACS_FILE = Path("authorized_macs.txt")

# # Ensure Parquet Root Exists
# os.makedirs(PARQUET_ROOT, exist_ok=True)

# WARMUP_FLAG = PARQUET_ROOT / ".WARMED"

# if not WARMUP_FLAG.exists():
#     st.write("🔥 Initializing Parquet cache...")

# =====================================================
# AUTOMATIC DATA LOADING (The "Magic" Part)
# =====================================================
# This block runs AUTOMATICALLY once per session (when you first open the tab)
if "data_synced" not in st.session_state:
    # Run the download/conversion process
    # It will now print "👍 Local cache is up to date" if nothing new exists
    parse_drive_logs_to_parquet(
        client_secret_path=CLIENT_SECRET_FILE,
        folder_id=FOLDER_ID,
        parquet_root=PARQUET_DIR,
    )

    st.session_state.data_synced = True
    st.rerun()

# =====================================================
# STATE MANAGEMENT
# =====================================================
if "initialized" not in st.session_state:
    st.session_state.current_page = "Visual"
    st.session_state.initialized = True

# =====================================================
# NAVIGATION & ROUTING
# =====================================================
selected_page = render_sidebar(auto_refresh_interval=AUTO_REFRESH_INTERVAL)
if st.sidebar.button("🔄 Force Refresh Data"):  
    del st.session_state.data_synced
    st.rerun()

st.session_state.current_page = selected_page

def render_current_page():
    page = st.session_state.current_page
    
    if page == "Devices":
        devices.render(PARQUET_DIR, AUTHORIZED_MACS_FILE)
    
    elif page == "Tables":
        tables.render(PARQUET_DIR, AUTHORIZED_MACS_FILE)
        
    elif page == "Analytics":
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