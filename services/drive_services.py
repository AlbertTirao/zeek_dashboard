# drive_services.py
import os
import time
import tempfile
from datetime import datetime
from pathlib import Path
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import streamlit as st
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from pydrive2.files import ApiRequestError  # Required for error handling

# =====================================================
# Debug helper: print parquet cache structure and sample data
# =====================================================
def debug_print_parquet_cache(parquet_cache: dict):
    """Prints a clean summary of folders, files, row counts, and field names."""
    if not parquet_cache:
        st.warning("The Parquet cache is currently empty.")
        return

    # Sort dates descending (newest first)
    sorted_dates = sorted(parquet_cache.keys(), reverse=True)

    for date in sorted_dates:
        logs = parquet_cache[date]
        st.markdown(f"### 📁 Folder: {date}")
        
        file_details = []
        for log_type, df in logs.items():
            row_count = len(df)
            
            # Get field names or show "no fields"
            if not df.empty and len(df.columns) > 0:
                fields_str = ", ".join(df.columns.tolist())
                fields_display = f"[{fields_str}]"
            else:
                fields_display = "[no fields]"
                
            file_details.append(f"📄 `{log_type}.parquet` — **{row_count}** rows {fields_display}")
        
        if file_details:
            # Join with double newlines for proper Markdown list spacing
            st.markdown("\n".join([f"* {item}" for item in file_details]))
        else:
            st.write("  *(No parquet files found)*")
        
        st.divider()

# =====================================================
# Helper: Retry Logic for Google Drive API 500 Errors
# =====================================================
def list_files_with_retry(drive, query, max_retries=8):
    """
    Attempts to list files with exponential backoff for 500/503 errors.
    """
    for n in range(max_retries):
        try:
            return drive.ListFile({"q": query}).GetList()
        except ApiRequestError as e:
            error_str = str(e)
            # Retry on Internal Error (500) or Service Unavailable (503)
            if '500' in error_str or '503' in error_str:
                wait_time = (2 ** n)  # 1s, 2s, 4s, 8s...
                print(f"⚠️ Google Drive API Error ({error_str}). Retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise e  # Raise other errors immediately
    
    raise Exception("Max retries exceeded: Google Drive API continues to fail.")

# =====================================================
# Zeek log → Parquet streaming parser   
# =====================================================
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

# =====================================================
# Debug helper: print parquet cache structure and sample data
# =====================================================
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

# =====================================================
# Zeek log → Parquet streaming parser
# =====================================================
def walk_drive_folder(drive, folder_id):
    """
    Recursively yield all files under a Drive folder.
    """
    query = f"'{folder_id}' in parents and trashed=false"
    
    # UPDATED: Use retry logic here
    items = list_files_with_retry(drive, query)

    for item in items:
        if item["mimeType"].endswith("folder"):
            yield from walk_drive_folder(drive, item["id"])
        else:
            yield item

# =====================================================
# Stream a single Zeek log file from Drive to Parquet in chunks
# ===================================================== 
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
        raw_lines = [] # Fallback for non-Zeek logs (stdout/stderr)

        with open(tmp_path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#close"):
                    continue

                if line.startswith("#fields"):
                    headers = line.split("\t")[1:]
                    continue

                if not headers:
                    # Keep track of raw lines in case this isn't a standard Zeek log
                    raw_lines.append(line)
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

        # 🛑 FALLBACK: If no Zeek headers were found, but there is text (stdout/stderr)
        if writer is None and raw_lines:
            df = pd.DataFrame({"raw_message": raw_lines})
            df.to_parquet(parquet_path)
        
        # 🛑 PLACEHOLDER: If the file was completely empty (0 bytes)
        elif writer is None and not parquet_path.exists():
            df = pd.DataFrame({"status": ["empty_log"]})
            df.to_parquet(parquet_path)

        if writer:
            writer.close()  

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)  # ✅ cleanup temp file

# =====================================================
# Main: Parse all Zeek logs from Drive to Parquet
# =====================================================
def parse_drive_logs_to_parquet(
    client_secret_path: str,
    folder_id: str,
    parquet_root: Path,
):
    drive = authenticate_drive(client_secret_path)
    # Track if we actually downloaded anything to show/hide messages
    files_processed = 0

    # Generator to walk Drive
    def walk_drive_folder(drive, folder_id):
        query = f"'{folder_id}' in parents and trashed=false"
        items = list_files_with_retry(drive, query)
        for item in items:
            if item["mimeType"].endswith("folder"):
                yield from walk_drive_folder(drive, item["id"])
            else:
                yield item

    for f in walk_drive_folder(drive, folder_id):
        name = f["title"]

        # 1. Totally ignore conn-summary and non-log files
        if not name.endswith(".log") or "conn-summary" in name:
            continue

        log_type = name.replace(".log", "")

        # Safe date parsing
        try:
            log_date = datetime.fromisoformat(
                f["modifiedDate"].replace("Z", "+00:00")
            ).strftime("%Y-%m-%d")
        except:
            log_date = datetime.now().strftime("%Y-%m-%d")

        parquet_path = parquet_root / log_date / f"{log_type}.parquet"

        # 2. Skip if already exists locally
        if parquet_path.exists():
            continue

        st.write(f"Processing {name}...")

        try:
            stream_zeek_log_to_parquet(
                drive=drive,
                file_obj=f,
                parquet_path=parquet_path,
            )
            files_processed += 1
        except Exception as e:
            st.write(f"❌ Error processing {name}: {e}")
            
    if files_processed == 0:
        st.info("👍 Local cache is up to date.")

# =====================================================
# Google Drive Authentication
# =====================================================
@st.cache_resource
def authenticate_drive(client_secret_path: str):
    gauth = GoogleAuth()
    gauth.LoadClientConfigFile(client_secret_path)
    gauth.LocalWebserverAuth()
    return GoogleDrive(gauth)
