import os
import time
from datetime import datetime
from pathlib import Path
import pandas as pd
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
import streamlit as st

# -------------------------------
# Google Drive Authentication
# -------------------------------
@st.cache_resource
def authenticate_drive(client_secret_path: str):
    gauth = GoogleAuth()
    gauth.LoadClientConfigFile(client_secret_path)
    gauth.LocalWebserverAuth()
    return GoogleDrive(gauth)

# -------------------------------
# Download logs from Drive
# -------------------------------
# def download_csv_logs(drive, folder_id: str, log_dir: Path):
#     def walk(fid, local_path):
#         local_path.mkdir(exist_ok=True)
#         files = drive.ListFile({
#             "q": f"'{fid}' in parents and trashed=false"
#         }).GetList()
#         for f in files:
#             # Only process folders if they might contain CSVs
#             if f["mimeType"].endswith("folder"):
#                 # Only recurse into folders that contain "CSV" in their title
#                 if "CSV" in f["title"]:
#                     walk(f["id"], local_path / f["title"])
#                 continue

#             # Only download files ending with .csv
#             if f["title"].lower().endswith(".csv"):
#                 dest = local_path / f["title"]
#                 remote_ts = datetime.fromisoformat(f["modifiedDate"].replace("Z", "+00:00")).timestamp()
#                 if dest.exists() and dest.stat().st_mtime >= remote_ts:
#                     continue
#                 f.GetContentFile(str(dest))
#                 os.utime(dest, (time.time(), remote_ts))

#     walk(folder_id, log_dir)

def download_logs(drive, folder_id: str, log_dir: Path):
    """
    Recursively downloads logs from Google Drive to a local directory,
    skipping files that are already up to date.
    """
    def walk(fid: str, local_path: Path):
        local_path.mkdir(exist_ok=True, parents=True)
        
        # Query files in the current Drive folder
        query = {"q": f"'{fid}' in parents and trashed=false"}
        files = drive.ListFile(query).GetList()
        
        for f in files:
            file_title = f["title"]
            file_id = f["id"]
            dest = local_path / file_title
            
            # Handle recursive folder traversal
            if f["mimeType"].endswith("apps-file.folder"):
                walk(file_id, dest)
                continue
            
            # Parse remote timestamp (handling ISO format)
            remote_ts = datetime.fromisoformat(
                f["modifiedDate"].replace("Z", "+00:00")
            ).timestamp()
            
            # Skip download if local file is newer or same age
            if dest.exists() and dest.stat().st_mtime >= remote_ts:
                continue
            
            # Download and sync the timestamp
            f.GetContentFile(str(dest))
            os.utime(dest, (time.time(), remote_ts))

    walk(folder_id, log_dir)

# -------------------------------
# Parse DHCP logs
# -------------------------------
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
            except:
                continue
    return pd.DataFrame(rows)

# -------------------------------
# Load logs
# -------------------------------
@st.cache_data
def load_logs(log_dir: Path, client_secret_path: str, folder_id: str):
    drive = authenticate_drive(client_secret_path)
    download_logs(drive, folder_id, log_dir)
    df = pd.DataFrame()
    for f in log_dir.rglob("dhcp.log"):
        df = pd.concat([df, parse_dhcp(f, log_dir)], ignore_index=True)
    return df

# -------------------------------
# Load known hosts
# -------------------------------
def load_known_hosts(log_dir: Path):
    known_hosts_file = log_dir / "known_hosts.log"
    if not known_hosts_file.exists():
        return set()
    macs = set()
    with open(known_hosts_file, "r", errors="ignore") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split("\t")
            if len(parts) > 1:
                macs.add(parts[1].lower())
    return macs
