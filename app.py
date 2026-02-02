import streamlit as st
import time
import pandas as pd
from pathlib import Path

# -------------------------
# Import Custom Modules
# -------------------------
# Ensure these files exist in your project structure
from config.settings import LOGS_DIR, CLIENT_SECRET_FILE, FOLDER_ID, AUTO_REFRESH_INTERVAL
from services.drive_services import load_logs, load_zeek_logs
from ui.sidebar import render_sidebar
from ui.pages import analytics, tables, visual, zeek_logs, alerts, authorization

# -------------------------
# 1. Page Configuration
# -------------------------
st.set_page_config(
    page_title="Network Security Dashboard",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------------
# 2. Session State Initialization
# -------------------------
if "initialized" not in st.session_state:
    st.session_state.current_page = "Visual"
    st.session_state.last_refresh = 0
    st.session_state.initialized = True
    # Initialize empty defaults to prevent errors on first load
    st.session_state.data = pd.DataFrame()
    st.session_state.zeek_logs = {
        "http": pd.DataFrame(),
        "ssl": pd.DataFrame(),
        "dns": pd.DataFrame(),
        "files": pd.DataFrame(),
        "conn": pd.DataFrame()
    }

# -------------------------
# 3. Data Loading Logic (Real-Time Engine)
# -------------------------
def refresh_all_data():
    """Fetches fresh data from Drive/Local logs and updates Session State."""
    with st.spinner("Fetching latest network logs..."):
        try:
            # 1. Load DHCP / Device Logs (Inventory)
            st.session_state.data = load_logs(LOGS_DIR, CLIENT_SECRET_FILE, FOLDER_ID)
            
            # 2. Load Zeek Logs (Traffic)
            # load_zeek_logs should return a tuple of DataFrames
            http, ssl, dns, files, conn = load_zeek_logs(LOGS_DIR, CLIENT_SECRET_FILE, FOLDER_ID)
            
            # 3. Store in Session State (Handle potential None returns safely)
            st.session_state.zeek_logs = {
                "http": http if http is not None else pd.DataFrame(),
                "ssl": ssl if ssl is not None else pd.DataFrame(),
                "dns": dns if dns is not None else pd.DataFrame(),
                "files": files if files is not None else pd.DataFrame(),
                "conn": conn if conn is not None else pd.DataFrame()
            }
            
            # 4. Update timestamp
            st.session_state.last_refresh = time.time()
            
        except Exception as e:
            st.error(f"Failed to refresh data: {e}")
            # Optional: Print traceback to console for debugging
            print(f"Error refreshing data: {e}")

# Initial Load (Runs only once when the server starts)
if st.session_state.data.empty and st.session_state.zeek_logs["http"].empty:
    refresh_all_data()

# -------------------------
# 4. Data Processing & Authorization
# -------------------------
df = st.session_state.data
zeek_logs_data = st.session_state.zeek_logs

# Load Authorized MACs
AUTHORIZED_MACS_FILE = Path("authorized_macs.txt")
authorized = set()
if AUTHORIZED_MACS_FILE.exists():
    with open(AUTHORIZED_MACS_FILE, "r") as f:
        authorized = {line.strip().lower() for line in f if line.strip()}

# Apply Authorization Status to Devices
if df is not None and not df.empty:
    if "mac" in df.columns:
        df["status"] = df["mac"].apply(lambda m: "Authorized" if str(m).lower() in authorized else "Unauthorized")
    else:
        df["status"] = "Unknown"
    filtered = df.copy()
else:
    filtered = pd.DataFrame() # Safe fallback

# -------------------------
# 5. UI & Navigation
# -------------------------
# Render Sidebar (Returns selected page)
selected_page = render_sidebar(auto_refresh_interval=AUTO_REFRESH_INTERVAL)
st.session_state.current_page = selected_page

# Page Routing
def render_current_page():
    page = st.session_state.current_page
    
    if page == "Visual":
        # Ensure visual.py accepts these arguments
        visual.render(LOGS_DIR, AUTHORIZED_MACS_FILE)
        
    elif page == "Tables":
        # Ensure tables.py accepts these arguments
        tables.render(authorized)
        
    elif page == "Analytics":
        # [CRITICAL LINK] Passing the live Zeek logs to the new Analytics module
        analytics.render(
            filtered_devices=filtered,
            http_logs=zeek_logs_data.get("http"),
            ssl_logs=zeek_logs_data.get("ssl"),
            dns_logs=zeek_logs_data.get("dns")
        )
        
    elif page == "Zeek Logs":
        # Ensure zeek_logs.py accepts these arguments
        zeek_logs.render(filtered, LOGS_DIR, authorized)
        
    elif page == "Alerts":
        # Ensure alerts.py accepts these arguments
        alerts.render(filtered)
        
    elif page == "Authorization":
        # Ensure authorization.py accepts these arguments
        authorization.render(AUTHORIZED_MACS_FILE)

# Execute Render
render_current_page()

# -------------------------
# 6. Auto-Refresh Mechanism
# -------------------------
if AUTO_REFRESH_INTERVAL > 0:
    # This creates the "Heartbeat" of the application
    time.sleep(AUTO_REFRESH_INTERVAL)
    refresh_all_data()
    st.rerun()