import streamlit as st
import pandas as pd
from pathlib import Path
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from datetime import datetime
import json
import time
import os

# -------------------------
# CONFIG
# -------------------------
st.set_page_config(
    page_title="Zeek Device Dashboard",
    layout="wide"
)

# -------------------------
# DIRECTORIES
# -------------------------
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

LOGS_DIR = Path("logs")
LOGS_DIR.mkdir(exist_ok=True)

AUTHORIZED_FILE = "authorized_macs.txt"

# -------------------------
# GOOGLE DRIVE CONFIG
# -------------------------
FOLDER_ID = "1k6tVW7ZmcpaTVu7xkVOS6Nx0xU1bQ8km"

# -------------------------
# GOOGLE DRIVE AUTH
# -------------------------
@st.cache_resource
def authenticate_drive():
    gauth = GoogleAuth()
    gauth.LoadClientConfigFile(
        "client_secret_262013512528-s1lbcqmro9623l0j5akshcoq8o1dso09.apps.googleusercontent.com.json"
    )
    gauth.LocalWebserverAuth()
    return GoogleDrive(gauth)

# -------------------------
# FORCE REDOWNLOAD (MANUAL)
# -------------------------
if st.sidebar.button("Force Re-download Logs"):
    for f in LOGS_DIR.rglob("*"):
        if f.is_file():
            f.unlink()
    st.cache_data.clear()
    st.experimental_rerun()

# -------------------------
# DOWNLOAD ONLY NEW / UPDATED FILES
# -------------------------
def download_logs(drive):
    def download_folder(folder_id, local_path):
        local_path.mkdir(exist_ok=True)

        files = drive.ListFile({
            "q": f"'{folder_id}' in parents and trashed=false"
        }).GetList()

        for file in files:
            if file["mimeType"] == "application/vnd.google-apps.folder":
                download_folder(file["id"], local_path / file["title"])
            else:
                dest = local_path / file["title"]

                remote_mtime = file.get("modifiedDate")
                if remote_mtime:
                    remote_ts = datetime.fromisoformat(
                        remote_mtime.replace("Z", "+00:00")
                    ).timestamp()
                else:
                    remote_ts = 0

                if dest.exists():
                    local_ts = dest.stat().st_mtime
                    if remote_ts <= local_ts:
                        continue

                try:
                    if file["mimeType"].startswith("application/vnd.google-apps"):
                        file.GetContentFile(str(dest), mimetype="text/csv")
                    else:
                        file.GetContentFile(str(dest))

                    os.utime(dest, (time.time(), remote_ts))
                except Exception:
                    pass

    download_folder(FOLDER_ID, LOGS_DIR)

# -------------------------
# LOAD AUTHORIZED MACS
# -------------------------
def load_authorized_macs(path):
    if not Path(path).exists():
        return set()
    with open(path) as f:
        return {line.strip().lower() for line in f if line.strip()}

# -------------------------
# PARSE ZEEK DHCP LOGS ONLY
# -------------------------
def parse_zeek_log(file_path, log_type):
    if log_type != "dhcp":
        return pd.DataFrame()

    rows = []
    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            try:
                if line.startswith("{"):
                    data = json.loads(line)
                    ts = float(data.get("ts", 0))
                    mac = data.get("mac", "unknown").lower()
                    hostname = data.get("host_name", "unknown")
                else:
                    parts = line.split("\t")
                    ts = float(parts[0])
                    mac = parts[6].lower()
                    hostname = parts[7] if len(parts) > 7 else "unknown"

                rows.append({
                    "timestamp": datetime.fromtimestamp(ts),
                    "mac": mac,
                    "hostname": hostname
                })
            except Exception:
                continue

    return pd.DataFrame(rows)

# -------------------------
# LOAD ALL LOGS
# -------------------------
@st.cache_data
def load_all_logs():
    drive = authenticate_drive()
    download_logs(drive)

    df_all = pd.DataFrame()
    for file in LOGS_DIR.rglob("*.*"):
        log_type = file.stem.split(".")[0].lower()
        df = parse_zeek_log(file, log_type)
        df_all = pd.concat([df_all, df], ignore_index=True)

    return df_all

# -------------------------
# APP START
# -------------------------
st.title("Zeek Device Dashboard")

# -------------------------
# SIDEBAR NAVIGATION & LOG SELECTION
# -------------------------
st.sidebar.title("Dashboard")

page = st.sidebar.radio(
    "Go to",
    ["Dashboard", "Graphs", "Logs", "Authorize / Unauthorize"]
)

# Detect available log types automatically
log_files = list(LOGS_DIR.rglob("*.*"))
available_logs = sorted({f.stem.split(".")[0].lower() for f in log_files})

selected_logs = st.sidebar.multiselect(
    "Select log types to display in table",
    options=available_logs,
    default=available_logs
)

# Button to refresh table after changing log selection
if st.sidebar.button("Update Table"):
    st.experimental_rerun()

# -------------------------
# LOAD DATA
# -------------------------
all_logs = load_all_logs()
if all_logs.empty:
    st.warning("No logs found.")
    st.stop()

authorized_macs = load_authorized_macs(AUTHORIZED_FILE)

all_logs["status"] = all_logs["mac"].apply(
    lambda m: "Authorized" if m in authorized_macs else "Unauthorized"
)

authorized_df = all_logs[all_logs["status"] == "Authorized"]
unauthorized_df = all_logs[all_logs["status"] == "Unauthorized"]

# -------------------------
# DASHBOARD PAGE
# -------------------------
if page == "Dashboard":
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Devices", len(all_logs))
    c2.metric("Authorized", len(authorized_df))
    c3.metric("Unauthorized", len(unauthorized_df))

    status_counts = all_logs["status"].value_counts()
    st.plotly_chart(
        {
            "data": [{"labels": status_counts.index,
                      "values": status_counts.values,
                      "type": "pie",
                      "hole": 0.4}],
            "layout": {"title": "Authorization Overview"}
        },
        use_container_width=True
    )

# -------------------------
# GRAPHS PAGE
# -------------------------
elif page == "Graphs":
    timeline = (
        all_logs
        .set_index("timestamp")
        .resample("1H")
        .size()
        .reset_index(name="count")
    )

    st.line_chart(timeline, x="timestamp", y="count")

    top_unauth = unauthorized_df["mac"].value_counts().head(10).reset_index()
    top_unauth.columns = ["mac", "count"]
    st.bar_chart(top_unauth, x="mac", y="count")

# -------------------------
# LOGS PAGE WITH DYNAMIC TABLE
# -------------------------
elif page == "Logs":
    def load_selected_logs(selected_logs):
        df_combined = pd.DataFrame()
        for file in LOGS_DIR.rglob("*.*"):
            log_type = file.stem.split(".")[0].lower()
            if log_type not in selected_logs:
                continue
            df = parse_zeek_log(file, log_type)
            if not df.empty:
                df_combined = pd.concat([df_combined, df], ignore_index=True)

        if not df_combined.empty:
            cols = ["timestamp", "mac", "hostname", "status"]
            for c in cols:
                if c not in df_combined.columns:
                    df_combined[c] = None
            df_combined = df_combined[cols]

        return df_combined

    filtered_logs = load_selected_logs(selected_logs)
    filtered_logs["status"] = filtered_logs["mac"].apply(
        lambda m: "Authorized" if m in authorized_macs else "Unauthorized"
    )

    st.subheader("Logs Table")
    if filtered_logs.empty:
        st.warning("No logs found for the selected types.")
    else:
        st.dataframe(filtered_logs, use_container_width=True)

# -------------------------
# AUTHORIZE / UNAUTHORIZE PAGE
# -------------------------
elif page == "Authorize / Unauthorize":
    mac_text = st.text_area(
        "Authorized MAC addresses (one per line)",
        value="\n".join(sorted(authorized_macs)),
        height=250
    )

    if st.button("Save"):
        macs = {m.strip().lower() for m in mac_text.splitlines() if m.strip()}
        with open(AUTHORIZED_FILE, "w") as f:
            f.write("\n".join(sorted(macs)))

        st.success("Authorized MAC list updated.")
        st.cache_data.clear()
        st.experimental_rerun()
