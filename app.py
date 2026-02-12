# app.py
import streamlit as st
from config.client import LOGS_DIR, CLIENT_SECRET_FILE, FOLDER_ID, AUTO_REFRESH_INTERVAL
# UPDATED: Import the new sync function
from services.drive_services import sync_drive_to_parquet 
from ui.sidebar import render_sidebar
from ui.pages import analytics, devices, zeek_logs, alerts, authorization
from pathlib import Path
import os

# -------------------------
# One-time Zeek log → Parquet warm-up (DISK GUARDED)
# -------------------------
from pathlib import Path
# UPDATED: Import the new sync function
from services.drive_services import sync_drive_to_parquet

PARQUET_DIR = Path("data/parquet")
WARMUP_FLAG = PARQUET_DIR / ".WARMED"
status_placeholder = st.empty()

if not WARMUP_FLAG.exists():
    st.write("🔥 Initializing Parquet cache from ALL Zeek logs...")

    # UPDATED: Use the new incremental sync function
    sync_drive_to_parquet(
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

# =====================================================
# CONFIGURATION
# =====================================================
# PARQUET_ROOT = Path("data/parquet")
AUTHORIZED_MACS_FILE = Path("authorized_macs.txt")

# =====================================================
# AUTOMATIC DATA LOADING (The "Magic" Part)
# =====================================================
# This block runs AUTOMATICALLY once per session (when you first open the tab)
if "data_synced" not in st.session_state:
    # Run the download/conversion process
    # It will now print "👍 Local cache is up to date" if nothing new exists
    
    # UPDATED: Use the new incremental sync function
    sync_drive_to_parquet(
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
    # Optional: Delete the warmup flag if you want a hard reset
    # if WARMUP_FLAG.exists():
    #     WARMUP_FLAG.unlink()
    st.rerun()

st.session_state.current_page = selected_page

def render_current_page():
    page = st.session_state.current_page
    
    # NOTE: Ensure your page modules (devices, tables, etc.) 
    # are updated to accept PARQUET_DIR (Path object) 
    # and use load_single_log() internally.
    
    if page == "Devices":
        devices.render(PARQUET_DIR, AUTHORIZED_MACS_FILE)
        
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