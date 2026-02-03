import os
import time
from datetime import datetime, date
from pathlib import Path
import pandas as pd
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
import streamlit as st
from config.settings import PARQUET_DIR


# =====================================================
# Helpers
# =====================================================

def get_log_date_folder(file_path: Path, log_root: Path) -> str:
    try:
        return file_path.relative_to(log_root).parts[0]
    except Exception:
        return "unknown"


def get_parquet_path(log_file: Path, log_root: Path) -> Path:
    date_folder = get_log_date_folder(log_file, log_root)
    parquet_dir = PARQUET_DIR / date_folder
    parquet_dir.mkdir(parents=True, exist_ok=True)
    return parquet_dir / f"{log_file.stem}.parquet"


def is_today(file_path: Path) -> bool:
    return datetime.fromtimestamp(file_path.stat().st_mtime).date() == date.today()


# =====================================================
# Main parquet builder (FIXED)
# =====================================================

@st.cache_data(show_spinner=False)
def build_parquet_cache(log_dir: Path, client_secret_path: str, folder_id: str):
    drive = authenticate_drive(client_secret_path)
    download_folder(drive, folder_id, log_dir)

    for log_file in log_dir.rglob("*.log"):
        parquet_path = get_parquet_path(log_file, log_dir)

        # ✅ Skip historical logs already parsed
        if parquet_path.exists() and not is_today(log_file):
            continue

        df = parse_any_log(log_file, log_dir)
        if df.empty:
            continue

        df["_source_file"] = str(log_file.relative_to(log_dir))
        parquet_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_parquet(parquet_path, index=False)


# =====================================================
# Load parquet
# =====================================================

def load_all_parquet() -> dict[str, pd.DataFrame]:
    data = {}
    for parquet_file in PARQUET_DIR.rglob("*.parquet"):
        key = parquet_file.relative_to(PARQUET_DIR).as_posix()
        data[key] = pd.read_parquet(parquet_file)
    return data


def load_today_parquet() -> dict[str, pd.DataFrame]:
    today = date.today().strftime("%Y-%m-%d")
    base = PARQUET_DIR / today
    if not base.exists():
        return {}

    return {p.stem: pd.read_parquet(p) for p in base.glob("*.parquet")}


# =====================================================
# Google Drive
# =====================================================

@st.cache_resource
def authenticate_drive(client_secret_path: str):
    gauth = GoogleAuth()
    gauth.LoadClientConfigFile(client_secret_path)
    gauth.LocalWebserverAuth()
    return GoogleDrive(gauth)


def download_folder(drive: GoogleDrive, folder_id: str, local_path: Path):
    local_path.mkdir(exist_ok=True, parents=True)

    query = f"'{folder_id}' in parents and trashed=false"
    files = drive.ListFile({"q": query}).GetList()

    for f in files:
        dest_path = local_path / f["title"]

        if f["mimeType"].endswith("folder"):
            download_folder(drive, f["id"], dest_path)
            continue

        if not f["title"].lower().endswith(".log"):
            continue

        remote_ts = datetime.fromisoformat(
            f["modifiedDate"].replace("Z", "+00:00")
        ).timestamp()

        if dest_path.exists() and dest_path.stat().st_mtime >= remote_ts:
            continue

        f.GetContentFile(str(dest_path))
        os.utime(dest_path, (time.time(), remote_ts))


# =====================================================
# DHCP
# =====================================================

def parse_dhcp(file_path: Path, log_dir: Path):
    rows = []
    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                continue
            try:
                parts = line.strip().split("\t")
                rows.append({
                    "timestamp": datetime.fromtimestamp(float(parts[0])),
                    "mac": parts[6].lower(),
                    "hostname": parts[7] if len(parts) > 7 else "unknown",
                    "log_file": str(file_path.relative_to(log_dir))
                })
            except Exception:
                continue
    return pd.DataFrame(rows)


# =====================================================
# Zeek generic parser
# =====================================================

def parse_zeek_log(file_path: Path, log_dir: Path):
    rows = []
    headers = None

    with open(file_path, "r", errors="ignore") as f:
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
            parts += [None] * (len(headers) - len(parts))
            rows.append(dict(zip(headers, parts)))

    return pd.DataFrame(rows)


def parse_any_log(file_path: Path, log_dir: Path) -> pd.DataFrame:
    return parse_dhcp(file_path, log_dir) if file_path.name == "dhcp.log" else parse_zeek_log(file_path, log_dir)


# =====================================================
# Known hosts
# =====================================================

def load_known_hosts(log_dir: Path):
    files = list(log_dir.rglob("known_hosts.log"))
    if not files:
        return set()

    latest = max(files, key=lambda f: f.stat().st_mtime)
    macs = set()

    with open(latest, "r", errors="ignore") as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) > 1:
                macs.add(parts[1].lower())

    return macs
