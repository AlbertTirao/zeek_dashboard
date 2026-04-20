import os
import re
import time
import tempfile
import json
import webbrowser
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import streamlit as st
import duckdb

from config import client as client_config
from oauth2client.tools import ClientRedirectHandler, ClientRedirectServer
from pydrive2.auth import AuthenticationError, AuthenticationRejected, GoogleAuth
from pydrive2.drive import GoogleDrive
from pydrive2.files import ApiRequestError

DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DATE_TOKEN_RE = re.compile(r"(\d{4}-\d{1,2}-\d{1,2})")

# STRICTLY PARQUET ONLY
SUPPORTED_SOURCE_EXTS = {".parquet"}

PROXY_ENV_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


class DriveOAuthReauthRequired(RuntimeError):
    """Stored OAuth credentials expired and require an interactive re-login."""


def _extract_date_from_dirname(name: str) -> Optional[str]:
    """Accept YYYY-MM-DD date tokens, including date=YYYY-MM-DD and unpadded forms."""
    base = (name or "").strip()
    if not base:
        return None

    if DATE_DIR_RE.match(base):
        return base

    if base.startswith("date="):
        tail = base.split("date=", 1)[1].strip()
        if DATE_DIR_RE.match(tail):
            return tail

    token_match = DATE_TOKEN_RE.search(base)
    if token_match:
        try:
            return datetime.strptime(token_match.group(1), "%Y-%m-%d").strftime("%Y-%m-%d")
        except Exception:
            pass

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
    parsed_date = _parse_drive_modified_date(str(file_obj.get("modifiedDate", "")))
    if folder_date_hint and parsed_date:
        return max(folder_date_hint, parsed_date)
    if folder_date_hint:
        return folder_date_hint
    return parsed_date or default_date


def _supported_source_extension(file_name: str) -> Optional[str]:
    suffix = Path(str(file_name or "")).suffix.strip().lower()
    if suffix in SUPPORTED_SOURCE_EXTS:
        return suffix
    return None


def _drive_modified_ts_seconds(modified_date: str) -> float:
    raw = (modified_date or "").strip()
    if not raw:
        return 0.0
    try:
        return float(datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp())
    except Exception:
        pass
    try:
        parsed = datetime.strptime(raw.split(".")[0], "%Y-%m-%dT%H:%M:%S")
        return float(parsed.timestamp())
    except Exception:
        return 0.0


def _drive_file_size_bytes(file_obj) -> int:
    raw = str(file_obj.get("fileSize", "")).strip()
    if not raw:
        return 0
    try:
        return int(raw)
    except Exception:
        return 0


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


def _sync_state_path(parquet_root: Path) -> Path:
    return parquet_root / "_drive_sync_state.json"


def _load_sync_state(parquet_root: Path) -> Dict[str, dict]:
    path = _sync_state_path(parquet_root)
    if not path.exists():
        return {}

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    files = raw.get("files")
    return files if isinstance(files, dict) else {}


def _save_sync_state(parquet_root: Path, files_state: Dict[str, dict]) -> None:
    parquet_root.mkdir(parents=True, exist_ok=True)
    path = _sync_state_path(parquet_root)
    payload = {
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        "files": files_state,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _file_sync_key(file_obj, log_date: str, log_type: str) -> str:
    file_id = str(file_obj.get("id", "")).strip()
    if file_id:
        return file_id
    return f"{log_date}:{log_type}:{str(file_obj.get('title', '')).strip()}"


def _default_sync_dates() -> Tuple[str, ...]:
    # Empty tuple means "use scoped sync policy":
    # current date refresh + missing historical-date backfill.
    return tuple()


def _iter_local_parquet_dates(parquet_root: Path) -> set[str]:
    out: set[str] = set()
    if not parquet_root.exists():
        return out

    try:
        for p in parquet_root.iterdir():
            if not p.is_dir():
                continue
            name_l = p.name.lower()
            if name_l.startswith("_") or "cache" in name_l:
                continue
            d = _extract_date_from_dirname(p.name)
            if d:
                out.add(d)
    except Exception:
        return out
    return out


def _configure_drive_oauth(gauth: GoogleAuth, client_secret_path: str) -> GoogleAuth:
    gauth.settings["client_config_file"] = client_secret_path
    gauth.settings["oauth_scope"] = ["https://www.googleapis.com/auth/drive.readonly"]
    gauth.settings["get_refresh_token"] = True
    gauth.settings["access_type"] = "offline"
    gauth.settings["approval_prompt"] = "auto"
    return gauth


def _interactive_drive_oauth_code(
    gauth: GoogleAuth,
    *,
    host_name: str = "localhost",
    port_numbers: Optional[Tuple[int, ...]] = None,
    launch_browser: bool = True,
    timeout_seconds: int = 300,
) -> str:
    ports = tuple(port_numbers or (8080, 8090))
    httpd = None
    port_number = 0
    for port in ports:
        try:
            httpd = ClientRedirectServer((host_name, port), ClientRedirectHandler)
        except OSError:
            continue
        port_number = int(port)
        break

    if httpd is None:
        raise AuthenticationError(
            "Failed to start the local Google Drive login listener. Check whether ports 8080 or 8090 are blocked."
        )

    try:
        if gauth.flow is None:
            gauth.GetFlow()
        gauth.flow.redirect_uri = f"http://{host_name}:{port_number}/"
        authorize_url = gauth.GetAuthUrl()
        if launch_browser:
            webbrowser.open(authorize_url, new=1, autoraise=True)

        httpd.timeout = 1
        deadline = time.time() + max(int(timeout_seconds or 0), 30)
        while time.time() < deadline:
            httpd.handle_request()
            params = getattr(httpd, "query_params", {}) or {}
            if not params:
                continue
            if "error" in params:
                raise AuthenticationRejected("User rejected authentication")
            code = str(params.get("code", "") or "").strip()
            if code:
                return code

        raise AuthenticationError("Timed out waiting for the Google Drive login callback.")
    finally:
        try:
            httpd.server_close()
        except Exception:
            pass


def clear_drive_auth_caches() -> None:
    authenticate_drive_oauth.cache_clear()
    authenticate_drive_service_account.cache_clear()


def reauthenticate_drive_oauth_interactive(
    client_secret_path: str,
    credentials_file: str,
    *,
    launch_browser: bool = True,
) -> GoogleDrive:
    cred_path = Path(credentials_file)
    cred_path.parent.mkdir(parents=True, exist_ok=True)

    proxy_overrides = _disable_dead_loopback_proxies()
    try:
        clear_drive_auth_caches()
        gauth = _configure_drive_oauth(GoogleAuth(), client_secret_path)
        gauth.credentials = None
        code = _interactive_drive_oauth_code(gauth, launch_browser=launch_browser)
        gauth.Auth(code)

        try:
            gauth.SaveCredentialsFile(str(cred_path))
        except Exception:
            pass

        clear_drive_auth_caches()
        return GoogleDrive(gauth)
    finally:
        _restore_env_vars(proxy_overrides)


LOG_SYNC_PRIORITY = {
    "known_hosts": 0,
    "dhcp": 1,
    "conn": 2,
    "dns": 3,
    "http": 4,
    "ssl": 5,
    "files": 6,
    "notice": 7,
}


# =====================================================
# 1) AUTHENTICATION (BOTH OPTIONS) + RETRY HELPERS
# =====================================================

# Background sync runs in a worker thread, so these caches must stay independent of Streamlit runtime state.
@lru_cache(maxsize=None)
def authenticate_drive_oauth(
    client_secret_path: str,
    credentials_file: str,
    allow_interactive: bool = False,
) -> GoogleDrive:
    """
    OAuth flow for dashboard/server use:
    - Uses the saved credentials file silently.
    - Refreshes expired access tokens from the stored refresh token.
    - Does not open a browser unless allow_interactive=True.
    """
    cred_path = Path(credentials_file)
    cred_path.parent.mkdir(parents=True, exist_ok=True)

    gauth = _configure_drive_oauth(GoogleAuth(), client_secret_path)

    # Load saved credentials if they exist
    if cred_path.exists():
        try:
            gauth.LoadCredentialsFile(str(cred_path))
        except Exception:
            # If the file is corrupted, ignore and re-auth once
            gauth.credentials = None

    # Authenticate / refresh silently if possible
    if gauth.credentials is None:
        if not allow_interactive:
            raise RuntimeError(
                "Drive OAuth credentials are missing. Populate secrets/drive_credentials.json "
                "with a refresh_token-enabled credential file before starting the dashboard."
            )
        code = _interactive_drive_oauth_code(gauth)
        gauth.Auth(code)
    else:
        refresh_attempted = bool(gauth.access_token_expired)
        try:
            if gauth.access_token_expired:
                gauth.Refresh()
            else:
                gauth.Authorize()
        except Exception:
            # Never open a browser during dashboard reruns/server execution.
            # If silent refresh fails, require a one-time manual re-auth outside the app.
            if not allow_interactive:
                if refresh_attempted:
                    raise DriveOAuthReauthRequired(
                        "Drive OAuth session expired. Reconnect Google Drive to resume parquet sync."
                    )
                raise RuntimeError(
                    "Drive OAuth authorization failed. Check the client secret, stored credentials, "
                    "and Google Drive access, then retry."
                )
            gauth.credentials = None
            code = _interactive_drive_oauth_code(gauth)
            gauth.Auth(code)

    # Save for future runs
    try:
        gauth.SaveCredentialsFile(str(cred_path))
    except Exception:
        # If it can't save (permissions), OAuth will re-prompt next run
        pass

    return GoogleDrive(gauth)


@lru_cache(maxsize=None)
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
    allow_interactive_oauth: bool = False,
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
        return authenticate_drive_oauth(
            client_secret_path,
            oauth_credentials_file,
            allow_interactive=allow_interactive_oauth,
        )

    # auto fallback: service -> oauth
    try:
        return authenticate_drive_service_account(service_account_file)
    except Exception:
        return authenticate_drive_oauth(
            client_secret_path,
            oauth_credentials_file,
            allow_interactive=allow_interactive_oauth,
        )


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
# 2) STREAMING INGEST (PARQUET ONLY)
# =====================================================

def download_drive_parquet_to_path(file_obj, parquet_path: Path) -> None:
    """
    Downloads a Drive parquet object directly to the target parquet path.
    """
    parquet_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(suffix=".parquet")
    os.close(fd)

    try:
        file_obj.GetContentFile(tmp_path)
        os.replace(tmp_path, parquet_path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


# =====================================================
# 3) ORCHESTRATION (INCREMENTAL SYNC)
# =====================================================

def sync_drive_to_parquet(
    client_secret_path: str,
    folder_id: str,
    parquet_root: Path,
    target_dates: Optional[Tuple[str, ...]] = None,
    log_callback=None,
):
    """
    Sync Google Drive logs to local Parquet cache.
    Default policy (when target_dates is empty):
    - Refresh current-date logs.
    - Backfill historical dates only when missing locally.
    - Do not re-check historical modified timestamps.

    Explicit target_dates policy:
    - Sync only requested dates.
    - Re-download files when missing or Drive metadata changed.
    """

    drive_allow_interactive_oauth = bool(
        getattr(client_config, "DRIVE_ALLOW_INTERACTIVE_OAUTH", False)
    )
    drive_auth_mode = str(getattr(client_config, "DRIVE_AUTH_MODE", "oauth"))
    drive_credentials_file = str(
        getattr(client_config, "DRIVE_CREDENTIALS_FILE", "secrets/drive_credentials.json")
    )
    service_account_file = str(
        getattr(client_config, "SERVICE_ACCOUNT_FILE", "secrets/service_account.json")
    )

    # Keep the sync worker decoupled from Streamlit APIs.
    def _log(msg: str):
        try:
            if callable(log_callback):
                log_callback(msg)
            else:
                print(msg)
        except Exception:
            pass

    proxy_overrides = _disable_dead_loopback_proxies()
    if proxy_overrides:
        _log("Detected loopback proxy on port 9; bypassing proxy for Drive sync.")

    try:
        # Authenticate with chosen mode
        try:
            drive = authenticate_drive_auto(
                drive_auth_mode,
                client_secret_path=client_secret_path,
                oauth_credentials_file=drive_credentials_file,
                service_account_file=service_account_file,
                allow_interactive_oauth=drive_allow_interactive_oauth,
            )
        except Exception as e:
            _log(f"Drive authentication failed: {e}")
            raise

        default_date = datetime.now().strftime("%Y-%m-%d")
        if target_dates is None:
            desired_dates = tuple(_default_sync_dates())
        else:
            desired_dates = tuple(str(d).strip() for d in target_dates if str(d).strip())
        explicit_desired_date_set = {str(d).strip() for d in desired_dates if str(d).strip()}
        files_processed = 0
        sync_state = _load_sync_state(parquet_root)
        next_state: Dict[str, dict] = dict(sync_state)

        drive_dates: set[str] = set()

        # Pass 1: discover which dates exist in Drive without downloading file content.
        def walk_drive_dates(fid: str, inherited_date_hint: Optional[str] = None) -> None:
            items = list_files_with_retry(drive, f"'{fid}' in parents and trashed=false")
            for item in items:
                if item.get("mimeType") == "application/vnd.google-apps.folder":
                    folder_date_hint = _extract_date_from_dirname(str(item.get("title", "")))
                    if folder_date_hint:
                        drive_dates.add(folder_date_hint)
                    next_hint = folder_date_hint or inherited_date_hint
                    walk_drive_dates(item["id"], next_hint)
                else:
                    inferred = inherited_date_hint or _parse_drive_modified_date(str(item.get("modifiedDate", "")))
                    if inferred:
                        drive_dates.add(inferred)

        historical_missing_date_set: set[str] = set()
        if explicit_desired_date_set:
            effective_date_set = set(explicit_desired_date_set)
        else:
            walk_drive_dates(folder_id)
            local_dates = _iter_local_parquet_dates(parquet_root)
            historical_drive_dates = {d for d in drive_dates if d and d < default_date}
            historical_missing_date_set = historical_drive_dates - local_dates
            effective_date_set = set(historical_missing_date_set)
            # Always include "today" for hourly refreshes.
            effective_date_set.add(default_date)

            if historical_missing_date_set:
                _log(
                    "Historical backfill missing locally; syncing dates: "
                    + ", ".join(sorted(historical_missing_date_set))
                )

        # Pass 2: list only files under scoped dates (today + missing historical dates).
        def walk_folder(fid: str, inherited_date_hint: Optional[str] = None):
            if inherited_date_hint and inherited_date_hint not in effective_date_set:
                return
            items = list_files_with_retry(drive, f"'{fid}' in parents and trashed=false")
            for item in items:
                if item.get("mimeType") == "application/vnd.google-apps.folder":
                    folder_date_hint = _extract_date_from_dirname(str(item.get("title", "")))
                    next_hint = folder_date_hint or inherited_date_hint
                    if next_hint and next_hint not in effective_date_set:
                        continue
                    yield from walk_folder(item["id"], next_hint)
                else:
                    yield item, inherited_date_hint

        source_candidates: List[Tuple[dict, str, str, str, str]] = []
        for f, folder_date_hint in walk_folder(folder_id):
            name = str(f.get("title", ""))
            lower_name = name.lower()

            # Filter: only supported source files, ignore summaries.
            if "conn-summary" in lower_name:
                continue

            source_ext = _supported_source_extension(lower_name)
            if source_ext is None:
                continue

            log_type = Path(name).stem.strip()
            if not log_type:
                continue

            log_date = _resolve_log_date(f, folder_date_hint, default_date)
            if log_date not in effective_date_set:
                continue
            source_candidates.append((f, name, log_type, log_date, source_ext))

        # De-duplicate by (date, log_type)
        picked_candidates: Dict[Tuple[str, str], Tuple[Tuple[dict, str, str, str, str], Tuple[float, int, str]]] = {}
        for row in source_candidates:
            f, name, log_type, log_date, source_ext = row
            score = (
                _drive_modified_ts_seconds(str(f.get("modifiedDate", ""))),
                _drive_file_size_bytes(f),
                name.lower(),
            )
            key = (log_date, log_type)
            existing = picked_candidates.get(key)
            if existing is None or score > existing[1]:
                picked_candidates[key] = (row, score)

        sync_candidates = [entry[0] for entry in picked_candidates.values()]

        if not sync_candidates:
            if explicit_desired_date_set:
                _log(f"No Zeek .parquet files discovered in Drive for dates: {', '.join(desired_dates)}.")
            else:
                _log("No scoped Drive files found for hourly sync (today + missing historical dates).")
            _save_sync_state(parquet_root, next_state)
            return 0

        latest_drive_date = max(row[3] for row in sync_candidates)
        sync_candidates.sort(
            key=lambda row: (
                0 if row[3] == latest_drive_date else 1,
                row[3],
                LOG_SYNC_PRIORITY.get(row[2], 999),
                row[2],
            )
        )

        for f, name, log_type, log_date, source_ext in sync_candidates:
            target_path = parquet_root / log_date / f"{log_type}.parquet"
            file_key = _file_sync_key(f, log_date, log_type)
            modified_date = str(f.get("modifiedDate", "")).strip()
            state_entry = sync_state.get(file_key) or {}
            has_state = bool(state_entry)
            previous_target_raw = str(state_entry.get("target_path", "")).strip()
            previous_target = Path(previous_target_raw) if previous_target_raw else None
            target_missing = not target_path.exists()
            metadata_changed = has_state and (
                str(state_entry.get("modifiedDate", "")).strip() != modified_date
                or str(state_entry.get("log_date", "")).strip() != log_date
                or str(state_entry.get("title", "")).strip() != name
                or str(state_entry.get("source_ext", "")).strip() != source_ext
            )

            # Historical dates are immutable for this deployment:
            # - backfill only when missing locally
            # - do not re-check historical modifications
            is_hourly_today_sync = log_date == default_date
            if not explicit_desired_date_set and not is_hourly_today_sync:
                should_sync = target_missing
            else:
                should_sync = target_missing or metadata_changed or not has_state

            if should_sync and target_path.exists():
                try:
                    os.remove(target_path)
                except OSError:
                    pass

            if should_sync and previous_target and previous_target != target_path and previous_target.exists():
                try:
                    os.remove(previous_target)
                except OSError:
                    pass

            if not should_sync:
                next_state[file_key] = {
                    "title": name,
                    "log_type": log_type,
                    "log_date": log_date,
                    "modifiedDate": modified_date,
                    "target_path": str(target_path),
                    "source_ext": source_ext,
                }
                continue

            _log(f"Ingesting ({source_ext}): {log_date} / {name} ...")

            try:
                download_drive_parquet_to_path(f, target_path)
                files_processed += 1
                next_state[file_key] = {
                    "title": name,
                    "log_type": log_type,
                    "log_date": log_date,
                    "modifiedDate": modified_date,
                    "target_path": str(target_path),
                    "source_ext": source_ext,
                }
                _save_sync_state(parquet_root, next_state)
            except Exception as e:
                _log(f"Error on {name}: {e}")

        _save_sync_state(parquet_root, next_state)

        if files_processed > 0:
            _log(f"Sync complete: {files_processed} files updated.")
        else:
            _log("Cache is up to date.")

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

    st.markdown("### Data Catalog (Lazy Index)")

    for date, files in catalog.items():
        with st.expander(f"{date} ({len(files)} files)"):
            df_files = pd.DataFrame(files)
            st.dataframe(
                df_files,
                column_config={
                    "type": "Log Type",
                    "size_mb": st.column_config.NumberColumn("Size (MB)", format="%.2f MB"),
                },
                hide_index=True,
                width="stretch",
            )
