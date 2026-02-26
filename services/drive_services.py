import os
import re
import time
import tempfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import streamlit as st
import duckdb

from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from pydrive2.files import ApiRequestError

DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
PROXY_ENV_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


def _extract_date_from_dirname(name: str) -> Optional[str]:
    """Accept both YYYY-MM-DD and date=YYYY-MM-DD folder names."""
    base = (name or "").strip()
    if not base:
        return None

    if DATE_DIR_RE.match(base):
        return base

    if base.startswith("date="):
        tail = base.split("date=", 1)[1].strip()
        if DATE_DIR_RE.match(tail):
            return tail

    return None


def _parse_drive_modified_date(modified_date: str) -> Optional[str]:
    """
    Parse Google Drive modifiedDate safely and return YYYY-MM-DD.
    Keep the source date component (no local timezone shifting).
    """
    raw = (modified_date or "").strip()
    if not raw:
        return None

    try:
        dt_obj = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt_obj.date().strftime("%Y-%m-%d")
    except Exception:
        pass

    # Fallback for malformed values that still carry a prefix timestamp.
    try:
        dt_obj = datetime.strptime(raw.split(".")[0], "%Y-%m-%dT%H:%M:%S")
        return dt_obj.strftime("%Y-%m-%d")
    except Exception:
        return None


def _resolve_log_date(file_obj, folder_date_hint: Optional[str], default_date: str) -> str:
    if folder_date_hint:
        return folder_date_hint

    parsed_date = _parse_drive_modified_date(str(file_obj.get("modifiedDate", "")))
    return parsed_date or default_date


def _is_dead_loopback_proxy(proxy_value: str) -> bool:
    raw = (proxy_value or "").strip().lower()
    if not raw:
        return False
    return "127.0.0.1:9" in raw or "localhost:9" in raw


def _disable_dead_loopback_proxies() -> dict:
    disabled = {}
    for key in PROXY_ENV_KEYS:
        val = os.environ.get(key, "")
        if _is_dead_loopback_proxy(val):
            disabled[key] = val
            os.environ.pop(key, None)
    return disabled


def _restore_env_vars(values: dict):
    for key, val in values.items():
        os.environ[key] = val


# =====================================================
# 1) AUTHENTICATION (BOTH OPTIONS) + RETRY HELPERS
# =====================================================

@st.cache_resource
def authenticate_drive_oauth(client_secret_path: str, credentials_file: str) -> GoogleDrive:
    """
    OAuth flow:
    - First run: browser login
    - Next runs: silent (loads/saves token to credentials_file)
    """
    cred_path = Path(credentials_file)
    cred_path.parent.mkdir(parents=True, exist_ok=True)

    gauth = GoogleAuth()
    gauth.settings["client_config_file"] = client_secret_path
    gauth.settings["oauth_scope"] = ["https://www.googleapis.com/auth/drive.readonly"]

    # Needed to obtain refresh token (first login) so future runs don't prompt
    gauth.settings["get_refresh_token"] = True
    gauth.settings["access_type"] = "offline"
    # IMPORTANT: do NOT force consent every run
    gauth.settings["approval_prompt"] = "auto"

    # Load saved credentials if they exist
    if cred_path.exists():
        try:
            gauth.LoadCredentialsFile(str(cred_path))
        except Exception:
            # If the file is corrupted, ignore and re-auth once
            gauth.credentials = None

    # Authenticate / refresh silently if possible
    if gauth.credentials is None:
        # First time only -> opens browser
        gauth.LocalWebserverAuth()
    else:
        try:
            if gauth.access_token_expired:
                gauth.Refresh()
            else:
                gauth.Authorize()
        except Exception:
            # Revoked/expired tokens can fail refresh with invalid_grant.
            # Reset credentials and re-run OAuth to recover.
            gauth.credentials = None
            gauth.LocalWebserverAuth()

    # Save for future runs
    try:
        gauth.SaveCredentialsFile(str(cred_path))
    except Exception:
        # If it can't save (permissions), OAuth will re-prompt next run
        pass

    return GoogleDrive(gauth)


@st.cache_resource
def authenticate_drive_service_account(service_account_json_path: str) -> GoogleDrive:
    """
    Service account flow (NO browser login, ever).
    Requirement: the Drive folder must be shared with the service account email.
    """
    sa_path = Path(service_account_json_path)
    if not sa_path.exists():
        raise FileNotFoundError(f"Service account JSON not found: {service_account_json_path}")

    settings = {
        "client_config_backend": "service",
        "service_config": {"client_json_file_path": str(sa_path)},
        "oauth_scope": ["https://www.googleapis.com/auth/drive.readonly"],
    }
    gauth = GoogleAuth(settings=settings)
    gauth.ServiceAuth()
    return GoogleDrive(gauth)


def authenticate_drive_auto(
    mode: str,
    client_secret_path: str,
    oauth_credentials_file: str,
    service_account_file: str,
) -> GoogleDrive:
    """
    mode:
      - "service": always service account
      - "oauth": always oauth
      - "auto": try service first, fallback to oauth
    """
    mode = (mode or "auto").strip().lower()

    if mode == "service":
        return authenticate_drive_service_account(service_account_file)

    if mode == "oauth":
        return authenticate_drive_oauth(client_secret_path, oauth_credentials_file)

    # auto fallback: service -> oauth
    try:
        return authenticate_drive_service_account(service_account_file)
    except Exception:
        return authenticate_drive_oauth(client_secret_path, oauth_credentials_file)


def list_files_with_retry(drive: GoogleDrive, query: str, max_retries: int = 5):
    """
    Exponential backoff for Google Drive API 500/503 errors.
    """
    for n in range(max_retries):
        try:
            return drive.ListFile({"q": query}).GetList()
        except ApiRequestError as e:
            error_str = str(e)
            if "500" in error_str or "503" in error_str:
                time.sleep(2 ** n)
            else:
                raise
    return []


# =====================================================
# 2) STREAMING INGEST (LOG -> PARQUET)
# =====================================================

def stream_zeek_log_to_parquet(drive: GoogleDrive, file_obj, parquet_path: Path, chunk_size: int = 100_000):
    """
    Downloads a Zeek log, parses it line-by-line, and streams it
    into a Parquet file with Snappy compression.
    """
    parquet_path.parent.mkdir(parents=True, exist_ok=True)

    # create temp file for download (Windows safe)
    fd, tmp_path = tempfile.mkstemp()
    os.close(fd)

    try:
        # 1) Download Content
        file_obj.GetContentFile(tmp_path)

        rows = []
        headers = []
        writer = None

        # 2) Stream Parse
        with open(tmp_path, "r", errors="ignore", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#close"):
                    continue

                # Extract headers
                if line.startswith("#fields"):
                    headers = line.split("\t")[1:]
                    continue

                # Skip comments or until headers appear
                if line.startswith("#") or not headers:
                    continue

                parts = line.split("\t")

                # Pad missing columns with None
                if len(parts) < len(headers):
                    parts += [None] * (len(headers) - len(parts))

                rows.append(dict(zip(headers, parts)))

                # 3) Flush chunk
                if len(rows) >= chunk_size:
                    writer = _flush_chunk(rows, parquet_path, writer)
                    rows.clear()

        # 4) Flush remaining
        if rows:
            writer = _flush_chunk(rows, parquet_path, writer)

        # 5) Handle empty logs
        if writer is None and not parquet_path.exists():
            pd.DataFrame({"status": ["empty"]}).to_parquet(parquet_path)

        if writer:
            writer.close()

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def _flush_chunk(rows, path: Path, writer):
    """
    Helper: Writes a list of dicts to the Parquet writer.
    Initializes the writer if it doesn't exist.
    """
    if not rows:
        return writer

    df = pd.DataFrame(rows)
    table = pa.Table.from_pandas(df)

    if writer is None:
        writer = pq.ParquetWriter(path, table.schema, compression="snappy")

    writer.write_table(table)
    return writer


# =====================================================
# 3) ORCHESTRATION (INCREMENTAL SYNC)
# =====================================================

def sync_drive_to_parquet(
    client_secret_path: str,
    folder_id: str,
    parquet_root: Path,
    log_callback=None,
):
    """
    Sync Google Drive logs to local Parquet cache.
    - Skips historical logs that already exist.
    - Overwrites newest available date logs to capture rolling updates.
    """

    # Import config here to avoid circular imports elsewhere
    from config.client import DRIVE_AUTH_MODE, DRIVE_CREDENTIALS_FILE, SERVICE_ACCOUNT_FILE

    # Unified logger (toast in UI OR callback)
    def _log(msg: str):
        try:
            if callable(log_callback):
                log_callback(msg)
            else:
                st.toast(msg)
        except Exception:
            pass

    proxy_overrides = _disable_dead_loopback_proxies()
    if proxy_overrides:
        _log("Detected loopback proxy on port 9; bypassing proxy for Drive sync.")

    try:
        # Authenticate with chosen mode
        try:
            drive = authenticate_drive_auto(
                DRIVE_AUTH_MODE,
                client_secret_path=client_secret_path,
                oauth_credentials_file=DRIVE_CREDENTIALS_FILE,
                service_account_file=SERVICE_ACCOUNT_FILE,
            )
        except Exception as e:
            _log(f"❌ Drive authentication failed: {e}")
            raise

        default_date = datetime.now().strftime("%Y-%m-%d")
        files_processed = 0

        # Recursive generator
        def walk_folder(fid: str, inherited_date_hint: Optional[str] = None):
            items = list_files_with_retry(drive, f"'{fid}' in parents and trashed=false")
            for item in items:
                if item.get("mimeType") == "application/vnd.google-apps.folder":
                    folder_date_hint = _extract_date_from_dirname(str(item.get("title", "")))
                    next_hint = folder_date_hint or inherited_date_hint
                    yield from walk_folder(item["id"], next_hint)
                else:
                    yield item, inherited_date_hint

        log_candidates: List[Tuple[dict, str, str, str]] = []
        for f, folder_date_hint in walk_folder(folder_id):
            name = str(f.get("title", ""))

            # Filter: Only .log files, ignore summaries
            if not name.endswith(".log") or "conn-summary" in name:
                continue

            log_type = name.replace(".log", "")
            log_date = _resolve_log_date(f, folder_date_hint, default_date)
            log_candidates.append((f, name, log_type, log_date))

        if not log_candidates:
            _log("No Zeek .log files discovered in Drive.")
            return 0

        refresh_date = max(row[3] for row in log_candidates)
        _log(f"Refreshing rolling date partition: {refresh_date}")

        for f, name, log_type, log_date in log_candidates:
            target_path = parquet_root / log_date / f"{log_type}.parquet"

            # Incremental logic
            if target_path.exists():
                # Skip immutable historical dates; keep newest date hot.
                if log_date != refresh_date:
                    continue
                # Rebuild newest date logs to capture latest events.
                try:
                    os.remove(target_path)
                except OSError:
                    pass

            _log(f"📥 Ingesting: {log_date} / {name} ...")

            try:
                stream_zeek_log_to_parquet(drive, f, target_path)
                files_processed += 1
            except Exception as e:
                _log(f"❌ Error on {name}: {e}")

        if files_processed > 0:
            _log(f"✅ Sync Complete: {files_processed} new logs.")
        else:
            _log("⚡ Cache is up to date.")

        return files_processed
    finally:
        _restore_env_vars(proxy_overrides)


# =====================================================
# 4) LAZY LOADING & DUCKDB INTEGRATION (READ API)
# =====================================================

def get_parquet_catalog(parquet_root: Path):
    """
    Fast metadata scan. Returns a nested dict of what exists.
    Structure: { 'YYYY-MM-DD': [{type,size_mb}, ...] }
    """
    catalog = {}
    if not parquet_root.exists():
        return catalog

    for date_dir in sorted(parquet_root.iterdir(), reverse=True):
        if date_dir.is_dir():
            logs = []
            for pq_file in date_dir.glob("*.parquet"):
                size_mb = pq_file.stat().st_size / (1024 * 1024)
                logs.append({"type": pq_file.stem, "size_mb": round(size_mb, 2)})

            if logs:
                logs.sort(key=lambda x: x["type"])
                catalog[date_dir.name] = logs

    return catalog


@st.cache_data(ttl=600, show_spinner=False)
def load_single_log(parquet_root: Path, selected_date: str, log_type: str):
    """
    Reads Parquet using DuckDB (fast), with fallback to pandas.
    """
    path = parquet_root / selected_date / f"{log_type}.parquet"
    if path.exists():
        try:
            return duckdb.read_parquet(str(path)).df()
        except Exception:
            return pd.read_parquet(path)
    return pd.DataFrame()


def run_duckdb_query(query: str):
    """
    Execute raw SQL against an in-memory DuckDB instance.
    """
    try:
        return duckdb.sql(query).df()
    except Exception as e:
        st.error(f"Query Error: {e}")
        return pd.DataFrame()


# =====================================================
# 5) DEBUGGING
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

    for date, files in catalog.items():
        with st.expander(f"📅 {date} ({len(files)} files)"):
            df_files = pd.DataFrame(files)
            st.dataframe(
                df_files,
                column_config={
                    "type": "Log Type",
                    "size_mb": st.column_config.NumberColumn("Size (MB)", format="%.2f MB"),
                },
                hide_index=True,
                use_container_width=True,
            )
