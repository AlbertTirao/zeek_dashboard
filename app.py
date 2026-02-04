import streamlit as st
from config.settings import LOGS_DIR, CLIENT_SECRET_FILE, FOLDER_ID, AUTO_REFRESH_INTERVAL, PICKLE_DIR
from services.drive_services import debug_print_parquet_cache, load_logs, load_zeek_logs, save_parquet_as_pickle
from utils.helpers import get_mac_vendor
from ui.sidebar import render_sidebar
from ui.pages import analytics, tables, visual, zeek_logs, alerts, authorization
from pathlib import Path

# -------------------------
# One-time Zeek log → Parquet warm-up (DISK GUARDED)
# -------------------------
from pathlib import Path
from services.drive_services import parse_drive_logs_to_parquet

PARQUET_DIR = Path("data/parquet")
WARMUP_FLAG = PARQUET_DIR / ".WARMED"

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
    st.write("⚡ Parquet cache already initialized — skipping Drive parse")

# -------------------------
# Load & verify Parquet cache (PRINT ON EVERY RERUN)
# -------------------------
from services.drive_services import load_all_parquets
from pathlib import Path

PARQUET_DIR = Path("data/parquet")

# Always load from Streamlit cache (fast, no re-read if unchanged)
parquet_cache = load_all_parquets(PARQUET_DIR)

# 🔁 ALWAYS print on every script execution (refresh, rerun, auto-refresh)
st.write("🔎 Verifying Parquet cache on this run:")
debug_print_parquet_cache(parquet_cache)

# -------------------------
# One-time Parquet → Pickle warm-up (DISK GUARDED)
# -------------------------
PICKLE_DIR = PARQUET_DIR / "pickle"
PICKLE_WARMUP_FLAG = PICKLE_DIR / ".WARMED"

if not PICKLE_WARMUP_FLAG.exists():
    save_parquet_as_pickle(PARQUET_DIR, PICKLE_DIR)
    PICKLE_WARMUP_FLAG.touch()
    st.write("💾 Pickle cache ready")
else:
    st.write("⚡ Pickle cache already initialized — skipping conversion")

# -------------------------
# Load DHCP / device logs (cached)
# -------------------------
if "data" not in st.session_state:
    st.session_state.data = load_logs(LOGS_DIR, CLIENT_SECRET_FILE, FOLDER_ID)
df = st.session_state.data

# -------------------------
# Load authorized MACs from authorized_macs.txt
# -------------------------
AUTHORIZED_MACS_FILE = Path("authorized_macs.txt")
if AUTHORIZED_MACS_FILE.exists():
    with open(AUTHORIZED_MACS_FILE, "r") as f:
        authorized = {line.strip().lower() for line in f if line.strip()}
else:
    authorized = set()

# -------------------------
# Assign status to device logs
# -------------------------
df["status"] = df["mac"].apply(lambda m: "Authorized" if m.lower() in authorized else "Unauthorized")
filtered = df.copy()

# -------------------------
# Load Zeek logs (HTTP, SSL, DNS, FILES, CONN)
# -------------------------
if "zeek_logs" not in st.session_state:
    http_logs, ssl_logs, dns_logs, files_logs, conn_logs = load_zeek_logs(LOGS_DIR, CLIENT_SECRET_FILE, FOLDER_ID)
    st.session_state.zeek_logs = {
        "http": http_logs,
        "ssl": ssl_logs,
        "dns": dns_logs,
        "files": files_logs,
        "conn": conn_logs
    }
zeek_logs_data = st.session_state.zeek_logs

# -------------------------
# Force only Visual on first startup
# -------------------------
if "initialized" not in st.session_state:
    st.session_state.current_page = "Visual"
    st.session_state.initialized = True

# -------------------------
# Sidebar
# -------------------------
selected_page = render_sidebar(auto_refresh_interval=AUTO_REFRESH_INTERVAL)
st.session_state.current_page = selected_page

# -------------------------
# Render only the page stored in sessiont
# -------------------------
def render_current_page():
    page = st.session_state.current_page
    if page == "Visual":
        visual.render(LOGS_DIR, AUTHORIZED_MACS_FILE)
    elif page == "Tables":
        tables.render(authorized)
    elif page == "Analytics":
        analytics.render(
            filtered,
            http_logs=zeek_logs_data["http"],
            ssl_logs=zeek_logs_data["ssl"],
            dns_logs=zeek_logs_data["dns"]
        )
    elif page == "Zeek Logs":
        zeek_logs.render(filtered, LOGS_DIR, authorized)
    elif page == "Alerts":
        alerts.render(filtered)
    elif page == "Authorization":
        authorization.render(AUTHORIZED_MACS_FILE)

# -------------------------
# Call render
# -------------------------
render_current_page()
