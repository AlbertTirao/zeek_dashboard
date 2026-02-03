import os
import time
from datetime import datetime, date
from pathlib import Path
import pandas as pd
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
import streamlit as st
from config.settings import PARQUET_DIR
PARQUET_DIR = Path("data") 


def get_log_date_folder(file_path: Path, log_root: Path) -> str:
    """
    Extracts date folder name (YYYY-MM-DD) from log path.
    logs/2026-02-03/conn.log → 2026-02-03
    """
    try:
        return file_path.relative_to(log_root).parts[0]
    except Exception:
        return "unknown"
    
def get_parquet_path(log_file: Path) -> Path:
    """
    Returns the path to save the parquet.
    Creates a daily folder based on log's last modified date.
    Example: data/2026-01-31/dhcp.parquet
    """
    log_date = datetime.fromtimestamp(log_file.stat().st_mtime).date()
    daily_folder = PARQUET_DIR / log_date.strftime("%Y-%m-%d")
    daily_folder.mkdir(parents=True, exist_ok=True)
    return daily_folder / f"{log_file.stem}.parquet"


def parse_any_log(file_path: Path, log_dir: Path) -> pd.DataFrame:
    if file_path.name == "dhcp.log":
        return parse_dhcp(file_path, log_dir)
    else:
        return parse_zeek_log(file_path, log_dir)
    
@st.cache_data(show_spinner=False)
def build_parquet_cache(log_dir: Path, client_secret_path: str, folder_id: str):
    """
    Download logs from Google Drive and save one parquet per log per day.
    All parquets for the same day go into data/YYYY-MM-DD/
    """
    drive = authenticate_drive(client_secret_path)
    download_folder(drive, folder_id, log_dir)

    for log_file in log_dir.rglob("*.log"):
        parquet_path = get_parquet_path(log_file)

        # Skip if parquet already exists
        if parquet_path.exists():
            continue

        df = parse_any_log(log_file, log_dir)
        if df.empty:
            continue

        df["_source_file"] = str(log_file.relative_to(log_dir))
        df.to_parquet(parquet_path, index=False)

# =====================================================
# Load all parquets by date
# =====================================================
def load_all_daily_parquet() -> dict[str, dict[str, pd.DataFrame]]:
    """
    Returns nested dict:
    {
        "2026-01-31": {
            "dhcp.parquet": DataFrame,
            "conn.parquet": DataFrame,
            ...
        },
        ...
    }
    """
    data = {}
    if not PARQUET_DIR.exists():
        return data

    for daily_folder in sorted(PARQUET_DIR.iterdir()):
        if not daily_folder.is_dir():
            continue
        day_str = daily_folder.name
        data[day_str] = {}
        for parquet_file in daily_folder.glob("*.parquet"):
            data[day_str][parquet_file.name] = pd.read_parquet(parquet_file)
    return data


def is_today(file_path: Path) -> bool:
    return datetime.fromtimestamp(file_path.stat().st_mtime).date() == date.today()

def load_all_parquet() -> dict[str, pd.DataFrame]:
    data = {}
    for parquet_file in PARQUET_DIR.rglob("*.parquet"):
        key = parquet_file.relative_to(PARQUET_DIR).as_posix()
        data[key] = pd.read_parquet(parquet_file)
    return data

def load_today_parquet() -> dict[str, pd.DataFrame]:
    today = date.today().strftime("%Y-%m-%d")
    data = {}
    base = PARQUET_DIR / today
    if not base.exists():
        return data

    for p in base.glob("*.parquet"):
        data[p.stem] = pd.read_parquet(p)
    return data

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
@st.cache_data(show_spinner=False)
def load_logs(log_dir: Path, client_secret_path: str, folder_id: str):
    drive = authenticate_drive(client_secret_path)
    download_folder(drive, folder_id, log_dir)

    parquet_file = PARQUET_DIR / "dhcp.parquet"
    dfs = []

    if parquet_file.exists():
        dfs.append(pd.read_parquet(parquet_file))

    today_dfs = []
    for f in log_dir.rglob("dhcp.log"):
        if is_today(f):
            df = parse_dhcp(f, log_dir)
            if not df.empty:
                df["_source_file"] = str(f)
                today_dfs.append(df)

    if today_dfs:
        today_df = pd.concat(today_dfs, ignore_index=True)

        if dfs:
            historical = dfs[0]
            historical = historical[
                ~historical["_source_file"].isin(today_df["_source_file"])
            ]
            final_df = pd.concat([historical, today_df], ignore_index=True)
        else:
            final_df = today_df

        final_df.to_parquet(parquet_file, index=False)
    elif dfs:
        final_df = dfs[0]
    else:
        final_df = pd.DataFrame()

    return final_df

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
# Generic Zeek log parser
# =====================================================
def parse_zeek_log(file_path: Path, log_dir: Path):
    """
    Parses a generic Zeek log into a Pandas DataFrame.
    Skips lines starting with # and handles missing columns.
    """
    rows = []
    with open(file_path, "r", errors="ignore") as f:
        headers = None
        for line in f:
            line = line.strip()
            if not line or line.startswith("#close"):
                continue
            if line.startswith("#fields"):
                headers = line.split("\t")[1:]
                continue
            if not headers:
                continue
            parts = line.split("\t")
            while len(parts) < len(headers):
                parts.append(None)
            rows.append(dict(zip(headers, parts)))
    return pd.DataFrame(rows)

# =====================================================
# Load Zeek logs by type
# =====================================================
@st.cache_data
def load_zeek_logs(log_dir: Path, client_secret_path: str, folder_id: str):
    drive = authenticate_drive(client_secret_path)
    download_folder(drive, folder_id, log_dir)

    results = {}

    for log_type in ["http", "ssl", "dns", "files", "conn"]:
        parquet_file = PARQUET_DIR / f"{log_type}.parquet"
        dfs = []

        # 1️⃣ Load existing parquet (historical)
        if parquet_file.exists():
            dfs.append(pd.read_parquet(parquet_file))

        # 2️⃣ Parse ONLY today's raw logs
        today_dfs = []
        for f in log_dir.rglob(f"{log_type}.log"):
            if is_today(f):
                df = parse_zeek_log(f, log_dir)
                if not df.empty:
                    df["_source_file"] = str(f)
                    today_dfs.append(df)

        # 3️⃣ Merge & deduplicate
        if today_dfs:
            combined_today = pd.concat(today_dfs, ignore_index=True)

            if dfs:
                historical = dfs[0]
                historical = historical[
                    ~historical["_source_file"].isin(combined_today["_source_file"])
                ]
                final_df = pd.concat([historical, combined_today], ignore_index=True)
            else:
                final_df = combined_today

            final_df.to_parquet(parquet_file, index=False)
        elif dfs:
            final_df = dfs[0]
        else:
            final_df = pd.DataFrame()

        results[log_type] = final_df

    return (
        results["http"],
        results["ssl"],
        results["dns"],
        results["files"],
        results["conn"],
    )

# =====================================================
# Helper: get latest folder by today
# =====================================================
def get_latest_today_folder(root: Path, suffix="-CSV"):
    today_str = datetime.now().strftime("%Y-%m-%d")
    for f in root.iterdir():
        if f.is_dir() and f.name.startswith(today_str) and f.name.endswith(suffix):
            return f
    return None