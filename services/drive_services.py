import os
import time
from datetime import datetime
from pathlib import Path
import pandas as pd
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
import streamlit as st
import pyarrow as pa
import pyarrow.parquet as pq
import tempfile
import tempfile
import os
import pandas as pd
from pathlib import Path

# def save_parquet_as_pickle(parquet_root: Path, pickle_root: Path):
#     """
#     Convert all parquet files under parquet_root to pickle files under pickle_root.
#     Directory structure is preserved.
#     """
#     pickle_root.mkdir(parents=True, exist_ok=True)

#     for date_dir in sorted(parquet_root.iterdir()):
#         if not date_dir.is_dir():
#             continue

#         pickle_date_dir = pickle_root / date_dir.name
#         pickle_date_dir.mkdir(parents=True, exist_ok=True)

#         for pq_file in date_dir.glob("*.parquet"):
#             df = pd.read_parquet(pq_file)
#             pickle_file = pickle_date_dir / f"{pq_file.stem}.pkl"
#             df.to_pickle(pickle_file)
#             print(f"💾 Saved {pq_file} → {pickle_file}")


# def load_pickles(pickle_root: Path, dates: list[str] = None, log_types: list[str] = None):
#     """
#     Load pickle files from disk into memory.
#     - dates: list of date strings (YYYY-MM-DD) to load. None = all dates
#     - log_types: list of log types (http, conn, dns, etc) to load. None = all logs
#     Returns dict[date][log_type] = DataFrame
#     """
#     result = {}

#     for date_dir in sorted(pickle_root.iterdir()):
#         if not date_dir.is_dir():
#             continue

#         date_key = date_dir.name
#         if dates and date_key not in dates:
#             continue

#         result[date_key] = {}

#         for pkl_file in date_dir.glob("*.pkl"):
#             log_type = pkl_file.stem
#             if log_types and log_type not in log_types:
#                 continue

#             df = pd.read_pickle(pkl_file)
#             result[date_key][log_type] = df

#     return result

@st.cache_data(show_spinner=False)
def load_all_parquets(parquet_root: Path):
    """
    Load all parquet files from disk into memory (cached).
    Returns dict[date][log_type] = DataFrame
    """
    result = {}

    for date_dir in sorted(parquet_root.iterdir()):
        if not date_dir.is_dir():
            continue

        date_key = date_dir.name
        result[date_key] = {}

        for pq_file in date_dir.glob("*.parquet"):
            log_type = pq_file.stem
            df = pd.read_parquet(pq_file)
            result[date_key][log_type] = df

    return result

def debug_print_parquet_cache(parquet_cache: dict):
    for date, logs in parquet_cache.items():
        st.write(f"📁 **{date}/**")

        for log_type, df in logs.items():
            st.write(f"  📄 `{log_type}.parquet`")

            if df.empty:
                st.write("    ⚠ empty dataframe")
                continue

            st.write(f"    🔑 fields: {list(df.columns)}")

            # show exactly ONE row
            sample = df.iloc[0].to_dict()
            st.write("    🧪 sample row:")
            st.json(sample)

def walk_drive_folder(drive, folder_id):
    """
    Recursively yield all files under a Drive folder.
    """
    query = f"'{folder_id}' in parents and trashed=false"
    items = drive.ListFile({"q": query}).GetList()

    for item in items:
        if item["mimeType"].endswith("folder"):
            yield from walk_drive_folder(drive, item["id"])
        else:
            yield item

def stream_zeek_log_to_parquet(
    drive,
    file_obj,
    parquet_path: Path,
    chunk_size: int = 50_000,
):
    parquet_path.parent.mkdir(parents=True, exist_ok=True)

    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp_path = tmp.name
    tmp.close()  # 🔥 IMPORTANT: release Windows file lock

    try:
        # Download Drive file to temp path
        file_obj.GetContentFile(tmp_path)

        rows = []
        headers = None
        writer = None

        with open(tmp_path, "r", errors="ignore") as f:
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

                if len(rows) >= chunk_size:
                    df = pd.DataFrame(rows)
                    table = pa.Table.from_pandas(df)

                    if writer is None:
                        writer = pq.ParquetWriter(parquet_path, table.schema)

                    writer.write_table(table)
                    rows.clear()

        if rows:
            df = pd.DataFrame(rows)
            table = pa.Table.from_pandas(df)
            if writer is None:
                writer = pq.ParquetWriter(parquet_path, table.schema)
            writer.write_table(table)

        if writer:
            writer.close()

    finally:
        os.remove(tmp_path)  # ✅ cleanup temp file

def parse_drive_logs_to_parquet(
    client_secret_path: str,
    folder_id: str,
    parquet_root: Path,
):
    drive = authenticate_drive(client_secret_path)

    for f in walk_drive_folder(drive, folder_id):
        name = f["title"]

        if not name.endswith(".log"):
            continue

        log_type = name.replace(".log", "")

        log_date = datetime.fromisoformat(
            f["modifiedDate"].replace("Z", "+00:00")
        ).strftime("%Y-%m-%d")

        parquet_path = parquet_root / log_date / f"{log_type}.parquet"

        st.write(f"🚀 Streaming {name} → {parquet_path}")

        try:
            stream_zeek_log_to_parquet(
                drive=drive,
                file_obj=f,
                parquet_path=parquet_path,
            )
            st.write("✅ done")

        except Exception as e:
            st.write(f"❌ failed {name}: {e}")

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
