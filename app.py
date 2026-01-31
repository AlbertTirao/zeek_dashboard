import streamlit as st
from config.settings import DATA_DIR, LOGS_DIR, FOLDER_ID, CLIENT_SECRET_FILE, AUTO_REFRESH_INTERVAL
from services.drive_services import load_logs, load_known_hosts
from utils.helpers import get_mac_vendor
from ui.sidebar import render_sidebar
from ui.pages import overview, devices, analytics, zeek_logs, alerts, authorization

# Sidebar
page, start_date, end_date = render_sidebar(auto_refresh_interval=AUTO_REFRESH_INTERVAL)

# Load logs
if "data" not in st.session_state:
    st.session_state.data = load_logs(LOGS_DIR, CLIENT_SECRET_FILE, FOLDER_ID)
df = st.session_state.data

# Authorized MACs
authorized = load_known_hosts(LOGS_DIR)
df["status"] = df["mac"].apply(lambda m: "Authorized" if m.lower() in authorized else "Unauthorized")
filtered = df[(df["timestamp"].dt.date >= start_date) & (df["timestamp"].dt.date <= end_date)]

# Render pages
if page == "Overview":
    overview.render(filtered)
elif page == "Devices":
    devices.render(authorized)
elif page == "Analytics":
    analytics.render(filtered, get_mac_vendor, authorized) 
elif page == "Zeek Logs":
    zeek_logs.render(filtered, LOGS_DIR, authorized)
elif page == "Alerts":
    alerts.render(filtered)
elif page == "Authorization":
    authorization.render(LOGS_DIR, authorized)
