import os
import time
from datetime import datetime
from pathlib import Path
import pandas as pd
import numpy as np  # Required for optimization
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
import streamlit as st

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
def download_folder(drive: GoogleDrive, folder_id: str, local_path: Path):
    """
    Download all files and subfolders from a Google Drive folder to local_path,
    skipping files that are already up to date.
    """
    local_path.mkdir(exist_ok=True, parents=True)

    query = f"'{folder_id}' in parents and trashed=false"
    files = drive.ListFile({"q": query}).GetList()

    for f in files:
        file_name = f["title"]
        file_id = f["id"]
        dest_path = local_path / file_name

        # Recurse into subfolders
        if f["mimeType"].endswith("folder") or f["mimeType"].endswith("apps-folder"):
            download_folder(drive, file_id, dest_path)
            continue

        # Only download LOG files
        if not file_name.lower().endswith(".log"):
            continue

        # Remote timestamp
        remote_ts = datetime.fromisoformat(f["modifiedDate"].replace("Z", "+00:00")).timestamp()

        # Skip if local file is newer
        if dest_path.exists() and dest_path.stat().st_mtime >= remote_ts:
            continue

        # Download file
        try:
            f.GetContentFile(str(dest_path))
        except Exception as e:
            continue

        os.utime(dest_path, (time.time(), remote_ts))


# =====================================================
# Helper: Optimize Data Types to Save RAM
# =====================================================
def optimize_dtypes(df):
    """
    Helper to downcast objects to categories to save RAM.
    """
    # List of common Zeek fields that are low-cardinality (repeated often)
    cat_cols = ['proto', 'service', 'conn_state', 'history', 'method', 'status', 'dns_type', 'qtype_name']
    
    for col in df.columns:
        # If the column name is in our list OR if it's an object type
        if col in cat_cols or df[col].dtype == 'object':
            # Only convert if unique values are less than 50% of total rows
            # This prevents overhead on high-cardinality columns like IDs or timestamps
            if df[col].nunique() < len(df) * 0.5:
                df[col] = df[col].astype('category')
    return df


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
# Generic Zeek log parser (OPTIMIZED)
# =====================================================
def parse_zeek_log(file_path: Path, log_dir: Path):
    """
    Parses a generic Zeek log into a Pandas DataFrame using chunking
    to avoid MemoryError on large files.
    """
    chunk_size = 50000  # Process 50k rows at a time
    chunks = []
    current_chunk = []
    headers = []
    
    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            
            # Skip empty lines or close markers
            if not line or line.startswith("#close"):
                continue
            
            # Handle Headers
            if line.startswith("#fields"):
                headers = line.split("\t")[1:]
                continue
            
            # Ignore other metadata lines
            if line.startswith("#"):
                continue
                
            # If no headers found yet, skip data
            if not headers:
                continue
                
            # Parse Data
            parts = line.split("\t")
            
            # Fill missing columns with None if line is short
            while len(parts) < len(headers):
                parts.append(None)
                
            # Create dictionary for the row
            # Note: We slice parts to len(headers) to avoid issues if line is too long
            row = dict(zip(headers, parts[:len(headers)]))
            current_chunk.append(row)
            
            # --- CHUNK PROCESSING ---
            if len(current_chunk) >= chunk_size:
                df_chunk = pd.DataFrame(current_chunk)
                df_chunk = optimize_dtypes(df_chunk) # Compress to save RAM
                chunks.append(df_chunk)
                current_chunk = [] # Clear memory
    
    # Process remaining rows
    if current_chunk:
        df_chunk = pd.DataFrame(current_chunk)
        df_chunk = optimize_dtypes(df_chunk)
        chunks.append(df_chunk)
        
    # If file was empty or only headers
    if not chunks:
        return pd.DataFrame()

    return pd.concat(chunks, ignore_index=True)


# =====================================================
# Load Zeek logs by type
# =====================================================
@st.cache_data
def load_zeek_logs(log_dir: Path, client_secret_path: str, folder_id: str):
    """
    Downloads the logs from Google Drive and loads:
    HTTP, SSL, DNS, FILES, CONN logs into DataFrames
    """
    drive = authenticate_drive(client_secret_path)
    download_folder(drive, folder_id, log_dir)

    logs = {
        "http": pd.DataFrame(),
        "ssl": pd.DataFrame(),
        "dns": pd.DataFrame(),
        "files": pd.DataFrame(),
        "conn": pd.DataFrame()
    }

    for log_type in logs.keys():
        for f in log_dir.rglob(f"{log_type}.log"):
            df = parse_zeek_log(f, log_dir)
            
            # Optimization: Try to concat efficiently
            if not df.empty:
                logs[log_type] = pd.concat([logs[log_type], df], ignore_index=True)

    return logs["http"], logs["ssl"], logs["dns"], logs["files"], logs["conn"]


# =====================================================
# Helper: get latest folder by today
# =====================================================
def get_latest_today_folder(root: Path, suffix="-CSV"):
    today_str = datetime.now().strftime("%Y-%m-%d")
    for f in root.iterdir():
        if f.is_dir() and f.name.startswith(today_str) and f.name.endswith(suffix):
            return f
    return None