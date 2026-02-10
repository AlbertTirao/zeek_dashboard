# # drive_services.py
# import os
# import time
# import tempfile
# from datetime import datetime
# from pathlib import Path
# import pandas as pd
# import pyarrow as pa
# import pyarrow.parquet as pq
# import streamlit as st
# from pydrive2.auth import GoogleAuth
# from pydrive2.drive import GoogleDrive
# from pydrive2.files import ApiRequestError  # Required for error handling

# # =====================================================
# # Debug helper: print parquet cache structure and sample data
# # =====================================================
# def debug_print_parquet_cache(parquet_cache: dict):
#     """Prints a clean summary of folders, files, row counts, and field names."""
#     if not parquet_cache:
#         st.warning("The Parquet cache is currently empty.")
#         return

#     # Sort dates descending (newest first)
#     sorted_dates = sorted(parquet_cache.keys(), reverse=True)

#     for date in sorted_dates:
#         logs = parquet_cache[date]
#         st.markdown(f"### 📁 Folder: {date}")
        
#         file_details = []
#         for log_type, df in logs.items():
#             row_count = len(df)
            
#             # Get field names or show "no fields"
#             if not df.empty and len(df.columns) > 0:
#                 fields_str = ", ".join(df.columns.tolist())
#                 fields_display = f"[{fields_str}]"
#             else:
#                 fields_display = "[no fields]"
                
#             file_details.append(f"📄 `{log_type}.parquet` — **{row_count}** rows {fields_display}")
        
#         if file_details:
#             # Join with double newlines for proper Markdown list spacing
#             st.markdown("\n".join([f"* {item}" for item in file_details]))
#         else:
#             st.write("  *(No parquet files found)*")
        
#         st.divider()

# # =====================================================
# # Helper: Retry Logic for Google Drive API 500 Errors
# # =====================================================
# def list_files_with_retry(drive, query, max_retries=8):
#     """
#     Attempts to list files with exponential backoff for 500/503 errors.
#     """
#     for n in range(max_retries):
#         try:
#             return drive.ListFile({"q": query}).GetList()
#         except ApiRequestError as e:
#             error_str = str(e)
#             # Retry on Internal Error (500) or Service Unavailable (503)
#             if '500' in error_str or '503' in error_str:
#                 wait_time = (2 ** n)  # 1s, 2s, 4s, 8s...
#                 print(f"⚠️ Google Drive API Error ({error_str}). Retrying in {wait_time}s...")
#                 time.sleep(wait_time)
#             else:
#                 raise e  # Raise other errors immediately
    
#     raise Exception("Max retries exceeded: Google Drive API continues to fail.")

# # =====================================================
# # Zeek log → Parquet streaming parser   
# # =====================================================
# @st.cache_data(show_spinner=False, ttl=600)
# def load_all_parquets(parquet_root: Path):
#     """
#     Load all parquet files from disk into memory (cached).
#     Returns dict[date][log_type] = DataFrame
#     """
#     result = {}

#     for date_dir in sorted(parquet_root.iterdir()):
#         if not date_dir.is_dir():
#             continue

#         date_key = date_dir.name
#         result[date_key] = {}

#         for pq_file in date_dir.glob("*.parquet"):
#             log_type = pq_file.stem
#             df = pd.read_parquet(pq_file)
#             result[date_key][log_type] = df

#     return result

# # =====================================================
# # Debug helper: print parquet cache structure and sample data
# # =====================================================
# def debug_print_parquet_cache(parquet_cache: dict):
#     for date, logs in parquet_cache.items():
#         st.write(f"📁 **{date}/**")

#         for log_type, df in logs.items():
#             st.write(f"  📄 `{log_type}.parquet`")

#             if df.empty:
#                 st.write("    ⚠ empty dataframe")
#                 continue

#             st.write(f"    🔑 fields: {list(df.columns)}")

#             # show exactly ONE row
#             sample = df.iloc[0].to_dict()
#             st.write("    🧪 sample row:")
#             st.json(sample)

# # =====================================================
# # Zeek log → Parquet streaming parser
# # =====================================================
# def walk_drive_folder(drive, folder_id):
#     """
#     Recursively yield all files under a Drive folder.
#     """
#     query = f"'{folder_id}' in parents and trashed=false"
    
#     # UPDATED: Use retry logic here
#     items = list_files_with_retry(drive, query)

#     for item in items:
#         if item["mimeType"].endswith("folder"):
#             yield from walk_drive_folder(drive, item["id"])
#         else:
#             yield item

# # =====================================================
# # Stream a single Zeek log file from Drive to Parquet in chunks
# # ===================================================== 
# def stream_zeek_log_to_parquet(
#     drive,
#     file_obj,
#     parquet_path: Path,
#     chunk_size: int = 50_000,
# ):
#     parquet_path.parent.mkdir(parents=True, exist_ok=True)

#     tmp = tempfile.NamedTemporaryFile(delete=False)
#     tmp_path = tmp.name
#     tmp.close()  # 🔥 IMPORTANT: release Windows file lock

#     try:
#         # Download Drive file to temp path
#         file_obj.GetContentFile(tmp_path)

#         rows = []
#         headers = None
#         writer = None
#         raw_lines = [] # Fallback for non-Zeek logs (stdout/stderr)

#         with open(tmp_path, "r", errors="ignore") as f:
#             for line in f:
#                 line = line.strip()
#                 if not line or line.startswith("#close"):
#                     continue

#                 if line.startswith("#fields"):
#                     headers = line.split("\t")[1:]
#                     continue

#                 if not headers:
#                     # Keep track of raw lines in case this isn't a standard Zeek log
#                     raw_lines.append(line)
#                     continue

#                 parts = line.split("\t")
#                 while len(parts) < len(headers):
#                     parts.append(None)

#                 rows.append(dict(zip(headers, parts)))

#                 if len(rows) >= chunk_size:
#                     df = pd.DataFrame(rows)
#                     table = pa.Table.from_pandas(df)

#                     if writer is None:
#                         writer = pq.ParquetWriter(parquet_path, table.schema)

#                     writer.write_table(table)
#                     rows.clear()

#         if rows:
#             df = pd.DataFrame(rows)
#             table = pa.Table.from_pandas(df)
#             if writer is None:
#                 writer = pq.ParquetWriter(parquet_path, table.schema)
#             writer.write_table(table)

#         # 🛑 FALLBACK: If no Zeek headers were found, but there is text (stdout/stderr)
#         if writer is None and raw_lines:
#             df = pd.DataFrame({"raw_message": raw_lines})
#             df.to_parquet(parquet_path)
        
#         # 🛑 PLACEHOLDER: If the file was completely empty (0 bytes)
#         elif writer is None and not parquet_path.exists():
#             df = pd.DataFrame({"status": ["empty_log"]})
#             df.to_parquet(parquet_path)

#         if writer:
#             writer.close()  

#     finally:
#         if os.path.exists(tmp_path):
#             os.remove(tmp_path)  # ✅ cleanup temp file

# # =====================================================
# # Main: Parse all Zeek logs from Drive to Parquet
# # =====================================================
# def parse_drive_logs_to_parquet(
#     client_secret_path: str,
#     folder_id: str,
#     parquet_root: Path,
# ):
#     drive = authenticate_drive(client_secret_path)
#     # Track if we actually downloaded anything to show/hide messages
#     files_processed = 0

#     # Generator to walk Drive
#     def walk_drive_folder(drive, folder_id):
#         query = f"'{folder_id}' in parents and trashed=false"
#         items = list_files_with_retry(drive, query)
#         for item in items:
#             if item["mimeType"].endswith("folder"):
#                 yield from walk_drive_folder(drive, item["id"])
#             else:
#                 yield item

#     for f in walk_drive_folder(drive, folder_id):
#         name = f["title"]

#         # 1. Totally ignore conn-summary and non-log files
#         if not name.endswith(".log") or "conn-summary" in name:
#             continue

#         log_type = name.replace(".log", "")

#         # Safe date parsing
#         try:
#             log_date = datetime.fromisoformat(
#                 f["modifiedDate"].replace("Z", "+00:00")
#             ).strftime("%Y-%m-%d")
#         except:
#             log_date = datetime.now().strftime("%Y-%m-%d")

#         parquet_path = parquet_root / log_date / f"{log_type}.parquet"

#         # --- FIX: ALLOW RE-DOWNLOAD FOR CURRENT DAY ---
#         today_str = datetime.now().strftime("%Y-%m-%d")

#         if parquet_path.exists():
#             # If it's a historical file (yesterday or older), skip it.
#             if log_date != today_str:
#                 continue
            
#             # If it IS today's file, we must overwrite it to get new data.
#             # We delete the old partial file so the new one can replace it.
#             try:
#                 os.remove(parquet_path)
#                 st.toast(f"♻️ Updating current day log: {name}")
#             except OSError:
#                 pass # File might be open/locked, skip for now
#         # ----------------------------------------------

#         st.write(f"Processing {name}...")

#         try:
#             stream_zeek_log_to_parquet(
#                 drive=drive,
#                 file_obj=f,
#                 parquet_path=parquet_path,
#             )
#             files_processed += 1
#         except Exception as e:
#             st.write(f"❌ Error processing {name}: {e}")
            
#     if files_processed == 0:
#         st.info("👍 Local cache is up to date.")

# # =====================================================
# # Google Drive Authentication
# # =====================================================
# @st.cache_resource
# def authenticate_drive(client_secret_path: str):
#     gauth = GoogleAuth()
#     gauth.LoadClientConfigFile(client_secret_path)
#     gauth.LocalWebserverAuth()
#     return GoogleDrive(gauth)


# import os
# import time
# import shutil
# import tempfile
# from datetime import datetime
# from pathlib import Path
# import pandas as pd
# import pyarrow as pa
# import pyarrow.parquet as pq
# import streamlit as st
# from pydrive2.auth import GoogleAuth
# from pydrive2.drive import GoogleDrive
# from pydrive2.files import ApiRequestError

# # =====================================================
# # 1. AUTHENTICATION & API HELPERS
# # =====================================================

# @st.cache_resource
# def authenticate_drive(client_secret_path: str):
#     """
#     Authenticates with Google Drive and caches the client object.
#     """
#     gauth = GoogleAuth()
#     gauth.LoadClientConfigFile(client_secret_path)
    
#     # Try to load saved credentials if available, otherwise auth via web
#     gauth.LoadCredentialsFile("mycreds.txt")
#     if gauth.credentials is None:
#         gauth.LocalWebserverAuth()
#     elif gauth.access_token_expired:
#         gauth.Refresh()
#     else:
#         gauth.Authorize()
        
#     gauth.SaveCredentialsFile("mycreds.txt")
#     return GoogleDrive(gauth)

# def list_files_with_retry(drive, query, max_retries=5):
#     """
#     Exponential backoff for Google Drive API 500/503 errors.
#     """
#     for n in range(max_retries):
#         try:
#             return drive.ListFile({"q": query}).GetList()
#         except ApiRequestError as e:
#             error_str = str(e)
#             if '500' in error_str or '503' in error_str:
#                 wait_time = (2 ** n)
#                 time.sleep(wait_time)
#             else:
#                 raise e
#     return []

# # =====================================================
# # 2. STREAMING INGEST (The Pipeline Engine)
# # =====================================================

# def stream_zeek_log_to_parquet(drive, file_obj, parquet_path: Path, chunk_size=100_000):
#     """
#     Downloads a Zeek log, parses it line-by-line, and streams it 
#     into a Parquet file with Snappy compression.
#     """
#     # Ensure parent directory exists (Partitioning)
#     parquet_path.parent.mkdir(parents=True, exist_ok=True)
    
#     # create temp file for download (Windows safe: delete=False)
#     fd, tmp_path = tempfile.mkstemp()
#     os.close(fd) 

#     try:
#         # 1. Download Content
#         file_obj.GetContentFile(tmp_path)
        
#         rows = []
#         headers = []
#         writer = None
        
#         # 2. Stream Parse
#         with open(tmp_path, "r", errors="ignore", encoding="utf-8") as f:
#             for line in f:
#                 line = line.strip()
#                 if not line or line.startswith("#close"): 
#                     continue
                
#                 # Extract Headers
#                 if line.startswith("#fields"):
#                     headers = line.split("\t")[1:]
#                     continue
                
#                 # Skip comments or unset headers
#                 if line.startswith("#") or not headers: 
#                     continue

#                 # Parse Data
#                 parts = line.split("\t")
#                 # Pad missing columns with None
#                 if len(parts) < len(headers):
#                     parts += [None] * (len(headers) - len(parts))
                
#                 rows.append(dict(zip(headers, parts)))

#                 # 3. Flush Chunk to Parquet
#                 if len(rows) >= chunk_size:
#                     writer = _flush_chunk(rows, parquet_path, writer)
#                     rows.clear() # Free memory

#         # 4. Flush Remaining Rows
#         if rows:
#             writer = _flush_chunk(rows, parquet_path, writer)
        
#         # 5. Handle Empty Files (Metadata only)
#         if writer is None and not parquet_path.exists():
#             # Create a placeholder empty parquet so we don't re-download it
#             pd.DataFrame({"status": ["empty"]}).to_parquet(parquet_path)

#         if writer:
#             writer.close()

#     finally:
#         # Cleanup temp file
#         if os.path.exists(tmp_path):
#             os.remove(tmp_path)

# def _flush_chunk(rows, path, writer):
#     """
#     Helper: Writes a list of dicts to the Parquet writer. 
#     Initializes the writer if it doesn't exist.
#     """
#     if not rows:
#         return writer

#     df = pd.DataFrame(rows)
#     # Convert object columns to compatible types where possible, 
#     # but for logs, string (object) is usually safest to start.
#     table = pa.Table.from_pandas(df)

#     if writer is None:
#         # Snappy is fast and provides decent compression
#         writer = pq.ParquetWriter(path, table.schema, compression='snappy')
    
#     writer.write_table(table)
#     return writer

# # =====================================================
# # 3. ORCHESTRATION (Incremental Sync)
# # =====================================================

# def sync_drive_to_parquet(client_secret_path: str, folder_id: str, parquet_root: Path):
#     """
#     Main function to sync Google Drive logs to local Parquet cache.
#     - Skips historical logs that already exist.
#     - Overwrites today's logs to capture new events.
#     """
#     drive = authenticate_drive(client_secret_path)
#     today_str = datetime.now().strftime("%Y-%m-%d")
    
#     # Progress tracking
#     status_text = st.empty()
#     progress_bar = st.progress(0)
#     files_processed = 0

#     # Recursive generator
#     def walk_folder(fid):
#         items = list_files_with_retry(drive, f"'{fid}' in parents and trashed=false")
#         for item in items:
#             if item["mimeType"] == "application/vnd.google-apps.folder":
#                 yield from walk_folder(item["id"])
#             else:
#                 yield item

#     # Collect all candidates first (optional, but helps with progress bar)
#     # For massive drives, just iterate directly. Here we iterate directly.
    
#     for f in walk_folder(folder_id):
#         name = f["title"]
        
#         # Filter: Only .log files, ignore summaries
#         if not name.endswith(".log") or "conn-summary" in name:
#             continue

#         log_type = name.replace(".log", "")
        
#         # Determine Partition Date
#         try:
#             # Prefer Drive 'modifiedDate' as the partition key
#             mod_time = f["modifiedDate"] # e.g., 2023-10-27T10:00:00.000Z
#             dt_obj = datetime.strptime(mod_time.split(".")[0], "%Y-%m-%dT%H:%M:%S")
#             log_date = dt_obj.strftime("%Y-%m-%d")
#         except:
#             log_date = today_str

#         target_path = parquet_root / log_date / f"{log_type}.parquet"

#         # === INCREMENTAL LOGIC ===
#         if target_path.exists():
#             # If it's an old file, skip it (Immutable History)
#             if log_date != today_str:
#                 continue
#             # If it is TODAY'S file, delete it so we can re-ingest (Append Simulation)
#             try:
#                 os.remove(target_path)
#             except OSError:
#                 pass 

#         status_text.text(f"📥 Ingesting: {log_date} / {name} ...")
        
#         try:
#             stream_zeek_log_to_parquet(drive, f, target_path)
#             files_processed += 1
#         except Exception as e:
#             st.error(f"❌ Error on {name}: {e}")

#     status_text.empty()
#     progress_bar.empty()
    
#     if files_processed > 0:
#         st.toast(f"✅ Sync Complete: {files_processed} new logs.")
#     else:
#         st.toast("⚡ Cache is up to date.")

# # =====================================================
# # 4. LAZY LOADING (Read API)
# # =====================================================

# def get_parquet_catalog(parquet_root: Path):
#     """
#     Fast metadata scan. Returns a nested dict of what exists.
#     Does NOT read the actual data files.
#     Structure: { '2023-10-27': ['conn', 'dns', 'http'] }
#     """
#     catalog = {}
#     if not parquet_root.exists():
#         return catalog

#     # Sort dates descending
#     for date_dir in sorted(parquet_root.iterdir(), reverse=True):
#         if date_dir.is_dir():
#             logs = []
#             for pq_file in date_dir.glob("*.parquet"):
#                 # Get file size for UI hints
#                 size_mb = pq_file.stat().st_size / (1024 * 1024)
#                 logs.append({
#                     "type": pq_file.stem,
#                     "size_mb": round(size_mb, 2)
#                 })
            
#             if logs:
#                 # Sort logs by name
#                 logs.sort(key=lambda x: x["type"])
#                 catalog[date_dir.name] = logs
    
#     return catalog

# @st.cache_data(ttl=600, show_spinner=False)
# def load_single_log(parquet_root: Path, selected_date: str, log_type: str):
#     """
#     Lazy Loader: Reads a SINGLE Parquet file into memory when requested.
#     """
#     path = parquet_root / selected_date / f"{log_type}.parquet"
#     if path.exists():
#         return pd.read_parquet(path)
#     return pd.DataFrame()

# # =====================================================
# # 5. DEBUGGING
# # =====================================================

# def debug_print_catalog(parquet_root: Path):
#     """
#     Prints the catalog structure to Streamlit without crashing memory.
#     """
#     catalog = get_parquet_catalog(parquet_root)
    
#     if not catalog:
#         st.warning("Cache is empty. Run Sync.")
#         return

#     st.markdown("### 🗂️ Data Catalog (Lazy Index)")
    
#     # Iterate dates
#     for date, files in catalog.items():
#         with st.expander(f"📅 {date} ({len(files)} files)"):
#             # Create a small table for the files in this date
#             df_files = pd.DataFrame(files)
#             st.dataframe(
#                 df_files, 
#                 column_config={
#                     "type": "Log Type",
#                     "size_mb": st.column_config.NumberColumn("Size (MB)", format="%.2f MB")
#                 },
#                 hide_index=True,
#                 use_container_width=True
#             )


import os
import time
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import streamlit as st
import duckdb  # <--- NEW: The Speed Engine
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from pydrive2.files import ApiRequestError

# =====================================================
# 1. AUTHENTICATION & API HELPERS
# =====================================================

@st.cache_resource
def authenticate_drive(client_secret_path):
    gauth = GoogleAuth()

    # Explicit client config
    gauth.settings["client_config_file"] = client_secret_path
    gauth.settings["oauth_scope"] = [
        "https://www.googleapis.com/auth/drive.readonly"
    ]

    # 🔴 CRITICAL SETTINGS (THIS FIXES YOUR ERROR)
    gauth.settings["get_refresh_token"] = True
    gauth.settings["access_type"] = "offline"
    gauth.settings["approval_prompt"] = "force"

    # Do NOT refresh if no credentials yet
    if gauth.credentials is None:
        gauth.LocalWebserverAuth()
    else:
        if gauth.credentials.refresh_token:
            gauth.Refresh()
        else:
            # Force re-auth if refresh token is missing
            gauth.LocalWebserverAuth()

    return GoogleDrive(gauth)

def list_files_with_retry(drive, query, max_retries=5):
    """
    Exponential backoff for Google Drive API 500/503 errors.
    """
    for n in range(max_retries):
        try:
            return drive.ListFile({"q": query}).GetList()
        except ApiRequestError as e:
            error_str = str(e)
            if '500' in error_str or '503' in error_str:
                wait_time = (2 ** n)
                time.sleep(wait_time)
            else:
                raise e
    return []

# =====================================================
# 2. STREAMING INGEST (The Pipeline Engine)
# =====================================================

def stream_zeek_log_to_parquet(drive, file_obj, parquet_path: Path, chunk_size=100_000):
    """
    Downloads a Zeek log, parses it line-by-line, and streams it 
    into a Parquet file with Snappy compression.
    """
    # Ensure parent directory exists (Partitioning)
    parquet_path.parent.mkdir(parents=True, exist_ok=True)
    
    # create temp file for download (Windows safe: delete=False)
    fd, tmp_path = tempfile.mkstemp()
    os.close(fd) 

    try:
        # 1. Download Content
        file_obj.GetContentFile(tmp_path)
        
        rows = []
        headers = []
        writer = None
        
        # 2. Stream Parse (Python is best here to handle Zeek's #fields header)
        with open(tmp_path, "r", errors="ignore", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#close"): 
                    continue
                
                # Extract Headers
                if line.startswith("#fields"):
                    headers = line.split("\t")[1:]
                    continue
                
                # Skip comments or unset headers
                if line.startswith("#") or not headers: 
                    continue

                # Parse Data
                parts = line.split("\t")
                # Pad missing columns with None
                if len(parts) < len(headers):
                    parts += [None] * (len(headers) - len(parts))
                
                rows.append(dict(zip(headers, parts)))

                # 3. Flush Chunk to Parquet
                if len(rows) >= chunk_size:
                    writer = _flush_chunk(rows, parquet_path, writer)
                    rows.clear() # Free memory

        # 4. Flush Remaining Rows
        if rows:
            writer = _flush_chunk(rows, parquet_path, writer)
        
        # 5. Handle Empty Files (Metadata only)
        if writer is None and not parquet_path.exists():
            # Create a placeholder empty parquet so we don't re-download it
            pd.DataFrame({"status": ["empty"]}).to_parquet(parquet_path)

        if writer:
            writer.close()

    finally:
        # Cleanup temp file
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

def _flush_chunk(rows, path, writer):
    """
    Helper: Writes a list of dicts to the Parquet writer. 
    Initializes the writer if it doesn't exist.
    """
    if not rows:
        return writer

    df = pd.DataFrame(rows)
    # Convert object columns to compatible types where possible, 
    # but for logs, string (object) is usually safest to start.
    table = pa.Table.from_pandas(df)

    if writer is None:
        # Snappy is fast and provides decent compression
        writer = pq.ParquetWriter(path, table.schema, compression='snappy')
    
    writer.write_table(table)
    return writer

# =====================================================
# 3. ORCHESTRATION (Incremental Sync)
# =====================================================

def sync_drive_to_parquet(client_secret_path: str, folder_id: str, parquet_root: Path):
    """
    Main function to sync Google Drive logs to local Parquet cache.
    - Skips historical logs that already exist.
    - Overwrites today's logs to capture new events.
    """
    drive = authenticate_drive(client_secret_path)
    today_str = datetime.now().strftime("%Y-%m-%d")
    
    # Progress tracking
    status_text = st.empty()
    progress_bar = st.progress(0)
    files_processed = 0

    # Recursive generator
    def walk_folder(fid):
        items = list_files_with_retry(drive, f"'{fid}' in parents and trashed=false")
        for item in items:
            if item["mimeType"] == "application/vnd.google-apps.folder":
                yield from walk_folder(item["id"])
            else:
                yield item

    # Collect all candidates first (optional, but helps with progress bar)
    # For massive drives, just iterate directly. Here we iterate directly.
    
    for f in walk_folder(folder_id):
        name = f["title"]
        
        # Filter: Only .log files, ignore summaries
        if not name.endswith(".log") or "conn-summary" in name:
            continue

        log_type = name.replace(".log", "")
        
        # Determine Partition Date
        try:
            # Prefer Drive 'modifiedDate' as the partition key
            mod_time = f["modifiedDate"] # e.g., 2023-10-27T10:00:00.000Z
            dt_obj = datetime.strptime(mod_time.split(".")[0], "%Y-%m-%dT%H:%M:%S")
            log_date = dt_obj.strftime("%Y-%m-%d")
        except:
            log_date = today_str

        target_path = parquet_root / log_date / f"{log_type}.parquet"

        # === INCREMENTAL LOGIC ===
        if target_path.exists():
            # If it's an old file, skip it (Immutable History)
            if log_date != today_str:
                continue
            # If it is TODAY'S file, delete it so we can re-ingest (Append Simulation)
            try:
                os.remove(target_path)
            except OSError:
                pass 

        status_text.text(f"📥 Ingesting: {log_date} / {name} ...")
        
        try:
            stream_zeek_log_to_parquet(drive, f, target_path)
            files_processed += 1
        except Exception as e:
            st.error(f"❌ Error on {name}: {e}")

    status_text.empty()
    progress_bar.empty()
    
    if files_processed > 0:
        st.toast(f"✅ Sync Complete: {files_processed} new logs.")
    else:
        st.toast("⚡ Cache is up to date.")

# =====================================================
# 4. LAZY LOADING & DUCKDB INTEGRATION (Read API)
# =====================================================

def get_parquet_catalog(parquet_root: Path):
    """
    Fast metadata scan. Returns a nested dict of what exists.
    Structure: { '2023-10-27': ['conn', 'dns', 'http'] }
    """
    catalog = {}
    if not parquet_root.exists():
        return catalog

    # Sort dates descending
    for date_dir in sorted(parquet_root.iterdir(), reverse=True):
        if date_dir.is_dir():
            logs = []
            for pq_file in date_dir.glob("*.parquet"):
                # Get file size for UI hints
                size_mb = pq_file.stat().st_size / (1024 * 1024)
                logs.append({
                    "type": pq_file.stem,
                    "size_mb": round(size_mb, 2)
                })
            
            if logs:
                logs.sort(key=lambda x: x["type"])
                catalog[date_dir.name] = logs
    
    return catalog

@st.cache_data(ttl=600, show_spinner=False)
def load_single_log(parquet_root: Path, selected_date: str, log_type: str):
    """
    DUCKDB UPGRADE: Reads Parquet using DuckDB engine.
    This replaces standard Pandas IO for better performance.
    """
    path = parquet_root / selected_date / f"{log_type}.parquet"
    if path.exists():
        # Using DuckDB to read Parquet is significantly faster and uses less RAM
        try:
            return duckdb.read_parquet(str(path)).df()
        except Exception:
            # Fallback to pandas if file is weird/locked
            return pd.read_parquet(path)
            
    return pd.DataFrame()

def run_duckdb_query(query: str):
    """
    Execute raw SQL against an in-memory DuckDB instance.
    Useful for complex joins across multiple parquet files.
    """
    try:
        return duckdb.sql(query).df()
    except Exception as e:
        st.error(f"Query Error: {e}")
        return pd.DataFrame()

# =====================================================
# 5. DEBUGGING
# =====================================================

def debug_print_catalog(parquet_root: Path):
    """
    Prints the catalog structure to Streamlit without crashing memory.
    """
    catalog = get_parquet_catalog(parquet_root)
    
    if not catalog:
        st.warning("Cache is empty. Run Sync.")
        return

    st.markdown("### 🗂️ Data Catalog (Lazy Index)")
    
    # Iterate dates
    for date, files in catalog.items():
        with st.expander(f"📅 {date} ({len(files)} files)"):
            df_files = pd.DataFrame(files)
            st.dataframe(
                df_files, 
                column_config={
                    "type": "Log Type",
                    "size_mb": st.column_config.NumberColumn("Size (MB)", format="%.2f MB")
                },
                hide_index=True,
                use_container_width=True
            )