import streamlit as st
import pandas as pd
from datetime import datetime
from pathlib import Path

# Internal imports
from config.settings import LOGS_DIR, CLIENT_SECRET_FILE, FOLDER_ID, AUTO_REFRESH_INTERVAL
from services.drive_services import load_logs, load_zeek_logs
from ui.sidebar import render_sidebar
from ui.pages import analytics, tables, visual, zeek_logs, alerts, authorization

# ---------------------------------------------------------
# 1. REAL-TIME DATA LOADER
# ---------------------------------------------------------
# We use ttl (Time To Live) to auto-refresh data every 30 seconds.
@st.cache_data(ttl=30, show_spinner="Scanning live logs...")
def get_fresh_main_logs():
    return load_logs(LOGS_DIR, CLIENT_SECRET_FILE, FOLDER_ID)

@st.cache_data(ttl=30, show_spinner=False)
def get_fresh_zeek_logs():
    return load_zeek_logs(LOGS_DIR, CLIENT_SECRET_FILE, FOLDER_ID)

# Load the data
try:
    df_raw = get_fresh_main_logs()
    df = df_raw.copy()
except Exception as e:
    st.error(f"⚠️ Critical Error: Could not connect to log source. \n\n{e}")
    st.stop()

# ---------------------------------------------------------
# 2. STANDARDIZE COLUMNS
# ---------------------------------------------------------
rename_map = {
    "mac": "MAC Address",
    "hostname": "Host Name",
    "ip": "IP Address",
    "addr": "IP Address"
}
df.rename(columns=rename_map, inplace=True)

# ---------------------------------------------------------
# 3. DATA CLEANING & SAFETY
# ---------------------------------------------------------
# Ensure Timestamp is a proper datetime object
if "timestamp" in df.columns:
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')
else:
    df["timestamp"] = datetime.now()

# Fill missing critical columns
for col in ["IP Address", "Host Name", "Domain"]:
    if col not in df.columns:
        df[col] = "Unknown"

# ---------------------------------------------------------
# 4. AUTHORIZATION LOGIC (UPDATED)
# ---------------------------------------------------------
# Define paths for both MAC and Domain whitelist files
AUTHORIZED_MACS_FILE = Path("authorized_macs.txt")
AUTHORIZED_DOMAINS_FILE = Path("authorized_domains.txt")

# Load MACs to determine status in the main dataframe
if AUTHORIZED_MACS_FILE.exists():
    with open(AUTHORIZED_MACS_FILE, "r") as f:
        authorized = {line.strip().lower() for line in f if line.strip()}
else:
    authorized = set()

# Assign Status (Authorized vs Unauthorized based on MAC)
if "MAC Address" in df.columns:
    df["status"] = df["MAC Address"].apply(
        lambda m: "Authorized" if str(m).strip().lower() in authorized else "Unauthorized"
    )
else:
    df["status"] = "Unauthorized"

# ---------------------------------------------------------
# 5. LOAD ZEEK LOGS (REAL-TIME)
# ---------------------------------------------------------
http_logs, ssl_logs, dns_logs, files_logs, conn_logs = get_fresh_zeek_logs()

# Pack them for the pages
zeek_data_pack = { 
    "http": http_logs, 
    "ssl": ssl_logs, 
    "dns": dns_logs, 
    "files": files_logs, 
    "conn": conn_logs 
}

# ---------------------------------------------------------
# 6. RENDER SIDEBAR
# ---------------------------------------------------------
selected_page = render_sidebar(auto_refresh_interval=AUTO_REFRESH_INTERVAL)

# ---------------------------------------------------------
# 7. PAGE ROUTING (UPDATED)
# ---------------------------------------------------------
def render_current_page(page_name, data_df):
    
    if page_name == "Visual": 
        visual.render(LOGS_DIR, AUTHORIZED_MACS_FILE)
        
    elif page_name == "Tables": 
        tables.render(authorized)
        
    elif page_name == "Analytics": 
        analytics.render(
            data_df, 
            http_logs=zeek_data_pack.get("http"), 
            ssl_logs=zeek_data_pack.get("ssl"), 
            dns_logs=zeek_data_pack.get("dns")
        )
        
    elif page_name == "Zeek Logs": 
        zeek_logs.render(data_df, LOGS_DIR, authorized)
        
    elif page_name == "Alerts": 
        alerts.render(data_df)
        
    elif page_name == "Authorization": 
        # FIX: Now passing both the MAC and Domain file paths
        authorization.render(AUTHORIZED_MACS_FILE, AUTHORIZED_DOMAINS_FILE)

# Execute the page render
render_current_page(selected_page, df)