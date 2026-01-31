import os
import time
from datetime import datetime
from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive

# =====================================================
# Google Drive Authentication
# =====================================================
@st.cache_resource
def authenticate_drive(client_secret_path: str):
    gauth = GoogleAuth()
    gauth.LoadClientConfigFile(client_secret_path)
    gauth.LocalWebserverAuth()
    return GoogleDrive(gauth)


# =====================================================
# Download entire folder recursively from Google Drive
# =====================================================
# def download_folder(drive: GoogleDrive, folder_id: str, local_path: Path):
#     """
#     Download all files and subfolders from a Google Drive folder to local_path,
#     skipping files that are already up to date.  
#     """
#     local_path.mkdir(exist_ok=True, parents=True)

#     query = f"'{folder_id}' in parents and trashed=false"
#     files = drive.ListFile({"q": query}).GetList()

#     for f in files:
#         file_name = f["title"]
#         file_id = f["id"]
#         dest_path = local_path / file_name

#         # Recurse into subfolders
#         if f["mimeType"].endswith("folder") or f["mimeType"].endswith("apps-folder"):
#             download_folder(drive, file_id, dest_path)
#             continue

#         # Only download CSV or LOG files
#         if not file_name.lower().endswith((".csv", ".log")):
#             continue

#         # Remote timestamp
#         remote_ts = datetime.fromisoformat(f["modifiedDate"].replace("Z", "+00:00")).timestamp()

#         # Skip if local file is newer
#         if dest_path.exists() and dest_path.stat().st_mtime >= remote_ts:
#             continue

#         # Download file
#         try:
#             f.GetContentFile(str(dest_path))
#         except Exception as e:
#             st.warning(f"Failed to download {file_name}: {e}")
#             continue

#         # Sync timestamp
#         os.utime(dest_path, (time.time(), remote_ts))

def download_folder(drive: GoogleDrive, folder_id: str, local_path: Path):
    """
    Download all CSV files recursively from a Google Drive folder to local_path,
    preserving folder structure and skipping up-to-date files.
    """
    local_path.mkdir(exist_ok=True, parents=True)

    query = f"'{folder_id}' in parents and trashed=false"
    files = drive.ListFile({"q": query}).GetList()

    for f in files:
        file_name = f["title"]
        file_id = f["id"]
        mime_type = f["mimeType"]
        dest_path = local_path / file_name

        # -----------------------------------------
        # Recurse into subfolders
        # -----------------------------------------
        if mime_type == "application/vnd.google-apps.folder":
            download_folder(drive, file_id, dest_path)
            continue

        # -----------------------------------------
        # CSV FILES ONLY
        # -----------------------------------------
        if not file_name.lower().endswith(".csv"):
            continue

        # Remote modified timestamp
        remote_ts = datetime.fromisoformat(
            f["modifiedDate"].replace("Z", "+00:00")
        ).timestamp()

        # Skip if local file is newer or same
        if dest_path.exists() and dest_path.stat().st_mtime >= remote_ts:
            continue

        try:
            f.GetContentFile(str(dest_path))
        except Exception as e:
            st.warning(f"Failed to download {file_name}: {e}")
            continue

        # Sync timestamps
        os.utime(dest_path, (time.time(), remote_ts))

# =====================================================
# Parse DHCP log
# =====================================================
def parse_dhcp(file_path: Path, log_dir: Path):
    rows = []
    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                continue
            try:
                parts = line.strip().split("\t")
                ts = float(parts[0])
                mac = parts[6].lower()
                host = parts[7] if len(parts) > 7 else "unknown"
                rows.append({
                    "timestamp": datetime.fromtimestamp(ts),
                    "mac": mac,
                    "hostname": host,
                    "log_file": str(file_path.relative_to(log_dir))
                })
            except Exception:
                continue
    return pd.DataFrame(rows)


# =====================================================
# Load DHCP logs
# =====================================================
@st.cache_data
def load_logs(log_dir: Path, client_secret_path: str, folder_id: str):
    drive = authenticate_drive(client_secret_path)
    download_folder(drive, folder_id, log_dir)

    df = pd.DataFrame()
    for f in log_dir.rglob("dhcp.log"):
        df = pd.concat([df, parse_dhcp(f, log_dir)], ignore_index=True)
    return df


# =====================================================
# Load known_hosts
# =====================================================
def load_known_hosts(log_dir: Path):
    files = list(log_dir.rglob("known_hosts.log"))
    if not files:
        return set()
    latest_file = max(files, key=lambda f: f.stat().st_mtime)

    macs = set()
    with open(latest_file, "r", errors="ignore") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split("\t")
            if len(parts) > 1:
                macs.add(parts[1].lower())
    return macs


# =====================================================
# Helper: get latest folder by today
# =====================================================
def get_latest_today_folder(root: Path, suffix="-CSV"):
    today_str = datetime.now().strftime("%Y-%m-%d")
    for f in root.iterdir():
        if f.is_dir() and f.name.startswith(today_str) and f.name.endswith(suffix):
            return f
    return None


# =====================================================
# Render Streamlit Overview Dashboard
# =====================================================
def render_overview(log_dir: Path, authorized_macs_file: Path):
    st.title("Network Overview")

    # Load known_hosts
    known_hosts_file = get_latest_today_folder(log_dir)
    known_hosts_set = load_known_hosts(known_hosts_file) if known_hosts_file else set()

    if not known_hosts_set:
        st.info("No known_hosts.log data available for today")
        return

    # Load authorized MACs
    authorized_macs = set()
    if authorized_macs_file.exists():
        with open(authorized_macs_file, "r") as f:
            authorized_macs = set(line.strip().lower() for line in f if line.strip())

    # Load DHCP logs
    dhcp_df = pd.DataFrame()
    for f in log_dir.rglob("dhcp.log"):
        dhcp_df = pd.concat([dhcp_df, parse_dhcp(f, log_dir)], ignore_index=True)

    # Merge known_hosts and DHCP (optional)
    merged = pd.DataFrame({"mac": list(known_hosts_set)})
    merged["mac"] = merged["mac"].str.lower()
    merged["status"] = merged["mac"].apply(
        lambda m: "Authorized" if m in authorized_macs else "Unauthorized"
    )

    # Metrics
    total = merged["mac"].nunique()
    auth = merged[merged["status"] == "Authorized"]["mac"].nunique()
    unauth = merged[merged["status"] == "Unauthorized"]["mac"].nunique()
    percent_unauth = round((unauth / total * 100), 2) if total else 0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Active Devices", total)
    col2.metric("Authorized", auth)
    col3.metric("Unauthorized", unauth, delta_color="inverse")
    col4.metric("Risk Ratio", f"{percent_unauth}%", delta_color="inverse")

    # Timeline chart (optional if DHCP logs available)
    if not dhcp_df.empty:
        dhcp_df["ts"] = pd.to_datetime(dhcp_df["timestamp"], errors="coerce")
        dhcp_df["status"] = dhcp_df["mac"].apply(
            lambda m: "Authorized" if m in authorized_macs else "Unauthorized"
        )
        hourly = (
            dhcp_df.set_index("ts")
            .groupby("status")
            .resample("1H")
            .size()
            .reset_index(name="events")
        )
        if not hourly.empty:
            fig = px.line(
                hourly,
                x="ts",
                y="events",
                color="status",
                color_discrete_map={"Authorized": "#10B981", "Unauthorized": "#f43f5e"},
                template="plotly_dark",
            )
            fig.update_layout(xaxis_title=None, yaxis_title="Events")
            st.plotly_chart(fig, use_container_width=True)


# =====================================================
# Streamlit main
# =====================================================
if __name__ == "__main__":
    LOG_DIR = Path("logs")
    CLIENT_SECRET = "client_secrets.json"
    DRIVE_FOLDER_ID = "YOUR_DRIVE_FOLDER_ID"  # Replace with your folder ID
    AUTHORIZED_MACS = Path("authorized_macs.txt")

    # Render overview
    render_overview(LOG_DIR, AUTHORIZED_MACS)
