# ui/pages/device.py
import json
import re
import time
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st
import yaml
import contextlib
from .header_layout import (
    dashboard_loading_ui,
    inject_traffic_style_header_css,
    render_dashboard_loading_state,
    render_traffic_style_header,
)

# =============================================================================
# Timezone Configuration
# =============================================================================
LOCAL_TZ = "Asia/Manila"

def get_local_now():
    """Returns the current local time as a naive datetime object to match parquet formats."""
    return pd.Timestamp.now(tz=LOCAL_TZ).tz_localize(None)

# =============================================================================
# Shared MAC normalization (same canonical MAC format as Alerts/Authorization)
# =============================================================================
_MAC_HEX_RE = re.compile(r"[^0-9a-fA-F]")


def normalize_mac(v):
    """Return canonical 'aa:bb:cc:dd:ee:ff' or None."""
    if v is None:
        return None

    if isinstance(v, (bytes, bytearray)):
        if len(v) == 6:
            h = bytes(v).hex()
        else:
            try:
                s = v.decode("utf-8", "ignore")
            except Exception:
                return None
            h = _MAC_HEX_RE.sub("", s)
    else:
        s = str(v).strip().lower()
        if not s or s == "nan":
            return None
        h = _MAC_HEX_RE.sub("", s)

    if len(h) != 12:
        return None

    return ":".join(h[i : i + 2] for i in range(0, 12, 2)).lower()


def is_broadcast_mac(mac):
    return mac == "ff:ff:ff:ff:ff:ff"


def mac_spoofing_status(mac) -> str:
    """
    Heuristic flag:
    A locally administered MAC often has first-byte second hex digit
    2, 6, A, or E (e.g., 02:xx..., 06:xx..., 0A:xx..., 0E:xx...).
    """
    m = normalize_mac(mac)
    if not m:
        return "Unknown"

    first_byte = m.split(":", 1)[0]
    if len(first_byte) != 2:
        return "Unknown"

    return "MAC Randomization" if first_byte[1].lower() in {"2", "6", "a", "e"} else "No"


# =============================================================================
# Date-folder discovery (avoid scanning cache dirs; match Alerts page)
# =============================================================================
DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _extract_date_from_dirname(name: str):
    if DATE_DIR_RE.match(name):
        return name
    if name.startswith("date="):
        tail = name.split("date=", 1)[1]
        if DATE_DIR_RE.match(tail):
            return tail
    return None


def iter_date_dirs(parquet_root: Path):
    """Yield (date_str, path_to_date_dir). Only includes real date folders."""
    if not parquet_root.exists():
        return
    for p in sorted((x for x in parquet_root.iterdir() if x.is_dir()), key=lambda z: z.name):
        n = p.name.lower()
        if n.startswith("_") or "cache" in n:
            continue
        d = _extract_date_from_dirname(p.name)
        if d:
            yield d, p


def _path_stat_sig(path: Path | None) -> tuple[float, int]:
    if path is None or not path.exists():
        return (0.0, 0)
    try:
        st_ = path.stat()
        return (float(st_.st_mtime_ns), int(st_.st_size))
    except Exception:
        return (0.0, 0)


def _duckdb_read_parquet_columns(path: Path, columns: tuple[str, ...]) -> pd.DataFrame:
    """
    Read only requested columns from one parquet file using DuckDB projection pushdown.
    Falls back to pandas column projection when DuckDB is unavailable.
    """
    if path is None or not path.exists():
        return pd.DataFrame()
    wanted = tuple(str(c) for c in (columns or tuple()) if str(c).strip())
    if not wanted:
        return pd.DataFrame()

    try:
        import duckdb

        con = duckdb.connect(database=":memory:")
        try:
            schema_df = con.execute(
                "DESCRIBE SELECT * FROM read_parquet(?)",
                [str(path)],
            ).df()
            available = {str(c) for c in schema_df.get("column_name", pd.Series(dtype="object")).tolist()}
            selected = [c for c in wanted if c in available]
            if not selected:
                return pd.DataFrame()
            select_sql = ", ".join(f'"{c}"' for c in selected)
            return con.execute(
                f"SELECT {select_sql} FROM read_parquet(?)",
                [str(path)],
            ).df()
        finally:
            try:
                con.close()
            except Exception:
                pass
    except Exception:
        try:
            return pd.read_parquet(path, columns=list(wanted))
        except Exception:
            return pd.DataFrame()


def _duckdb_read_parquet_union_columns(paths: list[Path], columns: tuple[str, ...]) -> pd.DataFrame:
    """
    Read only requested columns across multiple parquet files using DuckDB projection pushdown.
    """
    valid_paths = [str(p) for p in (paths or []) if isinstance(p, Path) and p.exists()]
    if not valid_paths:
        return pd.DataFrame()

    wanted = tuple(str(c) for c in (columns or tuple()) if str(c).strip())
    if not wanted:
        return pd.DataFrame()

    try:
        import duckdb

        con = duckdb.connect(database=":memory:")
        try:
            schema_df = con.execute(
                "DESCRIBE SELECT * FROM read_parquet(?, union_by_name=true)",
                [valid_paths],
            ).df()
            available = {str(c) for c in schema_df.get("column_name", pd.Series(dtype="object")).tolist()}
            selected = [c for c in wanted if c in available]
            if not selected:
                return pd.DataFrame()
            select_sql = ", ".join(f'"{c}"' for c in selected)
            return con.execute(
                f"SELECT {select_sql} FROM read_parquet(?, union_by_name=true)",
                [valid_paths],
            ).df()
        finally:
            try:
                con.close()
            except Exception:
                pass
    except Exception:
        dfs = []
        for p in valid_paths:
            try:
                dfs.append(pd.read_parquet(Path(p), columns=list(wanted)))
            except Exception:
                continue
        return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()


def _resolve_known_hosts_for_day(parquet_root: Path, day_str: str) -> Path | None:
    for d, p in iter_date_dirs(parquet_root):
        if d == day_str:
            kh = p / "known_hosts.parquet"
            return kh if kh.exists() else None
    return None


def _known_hosts_sig_for_day(parquet_root: Path, day_str: str) -> tuple[float, int]:
    return _path_stat_sig(_resolve_known_hosts_for_day(parquet_root, day_str))


def _resolve_active_devices_day(parquet_root: Path, preferred_day: str) -> tuple[str | None, tuple[float, int]]:
    """
    Resolve the day used for active-device metrics.
    Prefer today's known_hosts.parquet. If missing, fallback to the latest date folder
    that contains known_hosts.parquet so the card reflects actual captured activity.
    """
    preferred_kh = _resolve_known_hosts_for_day(parquet_root, preferred_day)
    if preferred_kh is not None:
        return preferred_day, _path_stat_sig(preferred_kh)

    latest_day = None
    latest_kh = None
    for day_str, day_dir in iter_date_dirs(parquet_root):
        kh = day_dir / "known_hosts.parquet"
        if kh.exists():
            latest_day = day_str
            latest_kh = kh

    if latest_day is None or latest_kh is None:
        return None, (0.0, 0)
    return latest_day, _path_stat_sig(latest_kh)


def _inventory_file_signature(parquet_root: Path) -> tuple[tuple[str, float, int], ...]:
    """Optimized: Only scan today's date folder for cache invalidation."""
    sig = []
    today_str = get_local_now().strftime("%Y-%m-%d")
    day_dir = parquet_root / today_str
    
    if day_dir.exists():
        for name in ("known_hosts.parquet", "dhcp.parquet"):
            fp = day_dir / name
            if fp.exists():
                mtime_ns, size = _path_stat_sig(fp)
                sig.append((str(fp), mtime_ns, size))
    return tuple(sig)


def _alerts_source_signature(parquet_root: Path) -> tuple[tuple[str, float, int], ...]:
    """Optimized: Only scan today's date folder for cache invalidation."""
    sig = []
    today_str = get_local_now().strftime("%Y-%m-%d")
    day_dir = parquet_root / today_str
    
    if day_dir.exists():
        for name in ("conn.parquet", "dhcp.parquet", "arp.parquet", "known_hosts.parquet"):
            fp = day_dir / name
            if fp.exists():
                mtime_ns, size = _path_stat_sig(fp)
                sig.append((str(fp), mtime_ns, size))
    return tuple(sig)

def _alerts_event_cache_signature(parquet_root: Path) -> tuple[tuple[str, float, int], ...]:
    cache_root = parquet_root / "_cache_alerts"
    if not cache_root.exists():
        return tuple()
    sig = []
    for fp in sorted(cache_root.rglob("alerts_events.parquet")):
        mtime_ns, size = _path_stat_sig(fp)
        sig.append((str(fp), mtime_ns, size))
    return tuple(sig)


def _coerce_ts_any(series: pd.Series) -> pd.Series:
    """Robust timestamp coercion (seconds/ms/us/ns, datetime, string)."""
    if series is None or len(series) == 0:
        return pd.to_datetime(series, errors="coerce")

    if pd.api.types.is_datetime64_any_dtype(series):
        parsed_dt = pd.to_datetime(series, errors="coerce", utc=True)
        try:
            return parsed_dt.dt.tz_convert(None)
        except Exception:
            try:
                return parsed_dt.dt.tz_localize(None)
            except Exception:
                return parsed_dt

    if pd.api.types.is_object_dtype(series):
        parsed = pd.to_datetime(series, errors="coerce", utc=True, format="mixed")
        if parsed.notna().any():
            try:
                return parsed.dt.tz_convert(None)
            except Exception:
                try:
                    return parsed.dt.tz_localize(None)
                except Exception:
                    return parsed

    num = pd.to_numeric(series, errors="coerce")
    if not num.notna().any():
        fallback = pd.to_datetime(series, errors="coerce", utc=True, format="mixed")
        try:
            return fallback.dt.tz_convert(None)
        except Exception:
            try:
                return fallback.dt.tz_localize(None)
            except Exception:
                return fallback

    m = float(num.dropna().abs().max())
    if m > 1e17:
        unit = "ns"
    elif m > 1e14:
        unit = "us"
    elif m > 1e11:
        unit = "ms"
    else:
        unit = "s"
    parsed_num = pd.to_datetime(num, unit=unit, errors="coerce", utc=True)
    try:
        return parsed_num.dt.tz_convert(None)
    except Exception:
        try:
            return parsed_num.dt.tz_localize(None)
        except Exception:
            return parsed_num


ROLLING_TIME_WINDOWS_DAYS = {
    "Last 7 Days": 7,
    "Last 30 Days": 30,
}


def _filter_df_by_time_mode(
    df: pd.DataFrame,
    ts_col: str,
    mode: str,
    selected_date: str | None = None,
) -> pd.DataFrame:
    """
    Alerts-aligned time scope filter:
    - Last 7 Days / Last 30 Days: rolling cutoff from current time
    - Specific Date: [start_of_day, next_day)
    - All Time: no time restriction
    """
    if df is None:
        return pd.DataFrame()

    out = df.copy()
    if ts_col not in out.columns:
        return out if mode == "All Time" else out.iloc[0:0]

    out[ts_col] = _coerce_ts_any(out[ts_col])

    if mode == "All Time":
        return out

    out = out[out[ts_col].notna()]
    if out.empty:
        return out

    tz = getattr(out[ts_col].dtype, "tz", None)
    is_tz_aware = tz is not None
    now = pd.Timestamp.now(tz=tz) if is_tz_aware else pd.Timestamp.now()

    if mode in ROLLING_TIME_WINDOWS_DAYS:
        cutoff = now - pd.Timedelta(days=ROLLING_TIME_WINDOWS_DAYS[mode])
        return out[out[ts_col] >= cutoff]

    if mode == "Specific Date" and selected_date:
        try:
            start_naive = datetime.strptime(selected_date, "%Y-%m-%d")
        except Exception:
            return out.iloc[0:0]
        if is_tz_aware:
            start = pd.Timestamp(start_naive).tz_localize(tz)
            end = start + pd.Timedelta(days=1)
        else:
            start = pd.Timestamp(start_naive)
            end = start + pd.Timedelta(days=1)
        return out[(out[ts_col] >= start) & (out[ts_col] < end)]

    cutoff = now - pd.Timedelta(days=ROLLING_TIME_WINDOWS_DAYS["Last 7 Days"])
    return out[out[ts_col] >= cutoff]


def _clean_text_series(series: pd.Series | None, index) -> pd.Series:
    if series is None:
        return pd.Series(pd.NA, index=index, dtype="string")
    out = series.astype("string")
    out = out.str.strip()
    out = out.replace(["", "-", "nan", "None", "none", "<NA>"], pd.NA)
    return out


def _normalize_dhcp_host_name(dhcp: pd.DataFrame) -> pd.DataFrame:
    if dhcp is None or dhcp.empty:
        return dhcp
    host_name = _clean_text_series(dhcp.get("host_name"), dhcp.index)
    fqdn = _clean_text_series(dhcp.get("client_fqdn"), dhcp.index)
    dhcp = dhcp.copy()
    dhcp["host_name"] = host_name.where(host_name.notna(), fqdn)
    return dhcp


@st.cache_data(show_spinner=False)
def load_active_today_macs_from_parquet(
    parquet_root: Path,
    today_str: str,
    known_hosts_sig: tuple[float, int],
) -> set:
    """Active Today = MACs present in today's known_hosts parquet (folder date)."""
    _ = known_hosts_sig
    kh = _resolve_known_hosts_for_day(parquet_root, today_str)
    if kh is None:
        return set()
    df = _duckdb_read_parquet_columns(kh, ("mac",))
    if "mac" not in df.columns:
        return set()
    macs = df["mac"].map(normalize_mac).dropna()
    macs = macs[~macs.map(is_broadcast_mac)]
    return set(macs.tolist())


@st.cache_data(show_spinner=False)
def load_active_today_inventory_from_parquet(
    parquet_root: Path,
    today_str: str,
    known_hosts_sig: tuple[float, int],
) -> pd.DataFrame:
    """
    Build an inventory DF from today's known_hosts.parquet:
      mac, ip(host), last_seen_today (ts)
    """
    _ = known_hosts_sig
    kh = _resolve_known_hosts_for_day(parquet_root, today_str)
    if kh is None:
        return pd.DataFrame()

    df = _duckdb_read_parquet_columns(
        kh,
        ("mac", "ts", "host", "id.orig_h", "client_addr", "ip", "addr"),
    )

    if df.empty or "mac" not in df.columns:
        return pd.DataFrame()

    out = df.copy()
    out["mac"] = out["mac"].map(normalize_mac)
    out = out.dropna(subset=["mac"])
    out = out[~out["mac"].map(is_broadcast_mac)]

    if "ts" in out.columns:
        out["ts"] = _coerce_ts_any(out["ts"])
    else:
        out["ts"] = pd.NaT

    # try common ip column names
    ip_col = None
    for c in ["host", "id.orig_h", "client_addr", "ip", "addr"]:
        if c in out.columns:
            ip_col = c
            break

    if ip_col is None:
        out["ip"] = "-"
    else:
        out["ip"] = out[ip_col].astype(str)

    inv = (
        out.sort_values("ts", ascending=False)
        .groupby("mac", as_index=False)
        .agg(ip=("ip", "first"), last_seen_today=("ts", "max"))
    )

    return inv


# --- IMPORTS FOR CLICKABLE TABLE ---
try:
    from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, JsCode
except ImportError:
    st.error("This solution requires the 'streamlit-aggrid' library.")
    st.info("Please run: pip install streamlit-aggrid")
    st.stop()


def _is_dark_theme() -> bool:
    try:
        base = st.get_option("theme.base")
        if isinstance(base, str) and base.lower() in {"light", "dark"}:
            return base.lower() == "dark"
    except Exception:
        pass
    return True


def get_shadow_aggrid_theme_and_css():
    theme = "alpine-dark" if _is_dark_theme() else "alpine"
    custom_css = {
        ".ag-root-wrapper": {"background-color": "#050B16", "color": "#EAEAEA", "border": "1px solid #22324E"},
        ".ag-header": {"background-color": "#0A1730", "color": "#EAF2FF", "border-bottom": "1px solid #29406A"},
        ".ag-header-cell, .ag-header-group-cell": {
            "background-color": "#0A1730",
            "color": "#EAF2FF",
            "border-right": "1px solid #20365A",
        },
        ".ag-header-cell-label": {"font-weight": "700", "letter-spacing": "0.02em"},
        ".ag-cell": {"background-color": "#050B16", "color": "#EAEAEA", "border-color": "#13233D"},
        ".ag-row": {"background-color": "#050B16"},
        ".ag-row-odd": {"background-color": "#071224"},
        ".ag-row-even": {"background-color": "#050E1D"},
        ".ag-row-hover": {"background-color": "#0F203D"},
        ".ag-row-selected": {"background-color": "#1E3A5F"},
        ".ag-floating-filter-body input": {
            "background-color": "#0A1730 !important",
            "color": "#EAEAEA !important",
            "border": "1px solid #32517F !important",
            "border-radius": "6px !important",
        },
        ".ag-paging-panel": {"background-color": "#050B16", "color": "#EAEAEA", "border-top": "1px solid #22324E"},
        ".ag-paging-row-summary-panel": {"background-color": "#050B16", "color": "#EAEAEA"},
        ".ag-paging-page-summary-panel": {"background-color": "#050B16", "color": "#EAEAEA"},
        ".ag-pagination": {"background-color": "#050B16", "color": "#EAEAEA"},
        ".ag-paging-page-size": {"background-color": "#0A1730 !important", "color": "#EAEAEA !important"},
        ".ag-paging-panel .ag-page-size": {
            "background-color": "#0A1730 !important",
            "color": "#EAEAEA !important",
            "border": "1px solid #2D456C !important",
            "outline": "none !important",
        },
        ".ag-paging-panel .ag-page-size option": {"background-color": "#0A1730 !important", "color": "#EAEAEA !important"},
        ".ag-paging-panel .ag-select, .ag-paging-panel .ag-picker-field-wrapper": {
            "background-color": "#0A1730 !important",
            "color": "#EAEAEA !important",
            "border": "1px solid #2D456C !important",
        },
        ".ag-paging-panel .ag-picker-field-display": {"background-color": "#0A1730 !important", "color": "#EAEAEA !important"},
    }
    custom_css.update(
        {
            ".ag-root-wrapper": {"background-color": "#061120", "color": "#EAF2FF", "border": "1px solid #2A466E"},
            ".ag-header": {"background-color": "#10213E", "color": "#EAF2FF", "border-bottom": "1px solid #3A5A8E"},
            ".ag-header-cell, .ag-header-group-cell": {
                "background-color": "#10213E",
                "color": "#EAF2FF",
                "border-right": "1px solid #2A466E",
            },
            ".ag-row-odd": {"background-color": "#07162A"},
            ".ag-row-even": {"background-color": "#0A1C33"},
            ".ag-row-hover": {"background-color": "#13305A"},
            ".ag-row-selected": {"background-color": "#1B3F75"},
        }
    )
    return theme, custom_css


_MAC_CLICK_CELL_STYLE = JsCode(
    """
    function(params) {
        return {
            'color': '#8AB4F8',
            'fontWeight': '700',
            'cursor': 'pointer',
            'textDecoration': 'underline'
        };
    }
    """
)

_MAC_ONLY_CLICK_JS = JsCode(
    """
    function(params) {
        if (!params || !params.column || !params.node) return;
        const colId = params.column.getColId ? params.column.getColId() : '';
        if (colId === 'mac') {
            params.node.setSelected(true, true);
            return;
        }
        if (params.api && params.api.deselectAll) {
            params.api.deselectAll();
        }
    }
    """
)


def _apply_copyable_grid_options(grid_options: dict) -> dict:
    opts = dict(grid_options or {})
    opts["enableCellTextSelection"] = True
    opts["ensureDomOrder"] = True
    opts["enableRangeSelection"] = True
    return opts


def _extract_first_selected_row(selected_rows):
    if isinstance(selected_rows, pd.DataFrame):
        if selected_rows.empty:
            return None
        return selected_rows.iloc[0].to_dict()
    if isinstance(selected_rows, list) and selected_rows and isinstance(selected_rows[0], dict):
        return selected_rows[0]
    return None


def _row_selection_key(row: dict, origin: str) -> str:
    mac = normalize_mac(row.get("mac")) or str(row.get("mac") or "").strip().lower()
    ip = str(row.get("ip") or "-").strip() or "-"
    return f"{origin}|{mac}|{ip}"


def _bump_devices_grid_nonce():
    st.session_state.devices_grid_nonce = int(st.session_state.get("devices_grid_nonce", 0)) + 1


def _open_forensics_from_row(row: dict, origin: str):
    if not isinstance(row, dict):
        return
    mac = normalize_mac(row.get("mac")) or str(row.get("mac") or "").strip().lower()
    if not mac:
        return
    key = _row_selection_key(row, origin)
    if key == st.session_state.get("devices_last_selection_key"):
        return

    st.session_state.devices_last_selection_key = key
    st.session_state.selected_forensic_mac = mac
    st.session_state.selected_forensic_ip = str(row.get("ip") or "-").strip() or "-"
    st.session_state.prev_dialog = origin
    st.session_state.active_dialog = "forensics"
    st.rerun()


def _table_height_for_rows(
    n_rows: int,
    *,
    row_px: int = 34,
    header_px: int = 48,
    min_px: int = 220,
    max_px: int = 520,
) -> int:
    try:
        rows = max(int(n_rows), 1)
    except Exception:
        rows = 1
    return max(min_px, min(max_px, header_px + rows * row_px))


# =====================================================
# 1) Load Visual Metrics from Parquet
# =====================================================
@st.cache_data(show_spinner=False)
def load_visual_metrics_from_parquet(
    parquet_root: Path,
    inventory_sig: tuple[tuple[str, float, int], ...],
):
    _ = inventory_sig
    known_host_paths: list[Path] = []
    dhcp_paths: list[Path] = []
    if not parquet_root.exists():
        return pd.DataFrame(), pd.DataFrame()

    for _date_str, day_dir in iter_date_dirs(parquet_root):
        kh = day_dir / "known_hosts.parquet"
        dh = day_dir / "dhcp.parquet"
        if kh.exists():
            known_host_paths.append(kh)
        if dh.exists():
            dhcp_paths.append(dh)

    known_hosts = _duckdb_read_parquet_union_columns(
        known_host_paths,
        ("mac", "ts", "host", "id.orig_h", "client_addr", "ip", "addr"),
    )
    dhcp = _duckdb_read_parquet_union_columns(
        dhcp_paths,
        ("mac", "client_addr", "host_name", "client_fqdn", "domain"),
    )
    dhcp = _normalize_dhcp_host_name(dhcp)
    return known_hosts, dhcp


@st.cache_data(show_spinner=False)
def load_dhcp_from_parquet(
    parquet_root: Path,
    inventory_sig: tuple[tuple[str, float, int], ...],
) -> pd.DataFrame:
    _ = inventory_sig
    dhcp_paths: list[Path] = []
    if not parquet_root.exists():
        return pd.DataFrame()

    for _date_str, day_dir in iter_date_dirs(parquet_root):
        dh = day_dir / "dhcp.parquet"
        if dh.exists():
            dhcp_paths.append(dh)

    dhcp = _duckdb_read_parquet_union_columns(
        dhcp_paths,
        ("mac", "client_addr", "host_name", "client_fqdn", "domain"),
    )
    return _normalize_dhcp_host_name(dhcp)


# =====================================================
# 1b) Alerts-aligned latest inventory (conn/dhcp/arp)
# =====================================================
@st.cache_data(show_spinner=False)
def _list_alert_event_cache_files(
    parquet_root: Path,
    alert_cache_sig: tuple[tuple[str, float, int], ...],
) -> tuple[str, ...]:
    _ = alert_cache_sig
    cache_root = parquet_root / "_cache_alerts"
    if not cache_root.exists():
        return tuple()
    return tuple(str(p) for p in sorted(cache_root.rglob("alerts_events.parquet")))


@st.cache_data(show_spinner=False)
def load_alerts_latest_inventory_rows(
    parquet_root: Path,
    alert_cache_sig: tuple[tuple[str, float, int], ...],
) -> pd.DataFrame:
    """Optimized: 100x faster using DuckDB arg_max instead of importing Alerts page."""
    cache_files = list(_list_alert_event_cache_files(parquet_root, alert_cache_sig))
    if not cache_files:
        return pd.DataFrame(columns=["mac", "host", "ts"])

    try:
        import duckdb
        con = duckdb.connect(database=":memory:")
        df = con.execute(
            '''
            SELECT
                cast(mac_norm AS varchar) AS mac,
                arg_max(COALESCE(NULLIF(cast(ip AS varchar), ''), NULLIF(cast(host AS varchar), ''), '-'), ts_dt) AS host,
                max(try_cast(ts_dt AS timestamp)) AS ts
            FROM read_parquet(?, union_by_name=true)
            WHERE mac_norm IS NOT NULL
            GROUP BY mac_norm
            ''',
            [cache_files]
        ).df()
        con.close()
        
        out = df.copy()
        out["mac"] = out["mac"].map(normalize_mac)
        out = out.dropna(subset=["mac", "ts"])
        out = out[~out["mac"].map(is_broadcast_mac)]
        return out.reset_index(drop=True)
        
    except Exception:
        return pd.DataFrame(columns=["mac", "host", "ts"])


@st.cache_data(show_spinner=False)
def load_device_inventory_history_rows(
    parquet_root: Path,
    alert_cache_sig: tuple[tuple[str, float, int], ...],
) -> pd.DataFrame:
    """Optimized: Uses fast GROUP BY arg_max instead of expensive window functions."""
    base_cols = ["mac", "host", "host_name", "ts"]
    cache_files = list(_list_alert_event_cache_files(parquet_root, alert_cache_sig))
    
    if not cache_files:
        return pd.DataFrame(columns=base_cols)

    try:
        import duckdb
        con = duckdb.connect(database=":memory:")
        df = con.execute(
            '''
            SELECT
              cast(mac_norm AS varchar) AS mac,
              arg_max(COALESCE(NULLIF(cast(ip AS varchar), ''), NULLIF(cast(host AS varchar), ''), '-'), ts_dt) AS host,
              max(try_cast(ts_dt AS timestamp)) AS ts
            FROM read_parquet(?, union_by_name=true)
            WHERE mac_norm IS NOT NULL AND try_cast(ts_dt AS timestamp) IS NOT NULL
            GROUP BY mac_norm, date_trunc('day', try_cast(ts_dt AS timestamp))
            ''',
            [cache_files],
        ).df()
        con.close()
        
        out = df.copy()
        out["mac"] = out["mac"].map(normalize_mac)
        out["host_name"] = "-"
        out = out.dropna(subset=["mac", "ts"])
        out = out[~out["mac"].map(is_broadcast_mac)]
        return out[base_cols].reset_index(drop=True)
    except Exception:
        return pd.DataFrame(columns=base_cols)

@st.cache_data(show_spinner=False)
def load_hourly_status_from_alert_cache(
    parquet_root: Path,
    alert_cache_sig: tuple[tuple[str, float, int], ...],
    allowed_macs_tuple: tuple[str, ...],
    banned_macs_tuple: tuple[str, ...],
) -> pd.DataFrame:
    """
    Fast hourly trend using Alerts cache files.
    Returns columns: ts, status, events
    """
    cache_files = list(_list_alert_event_cache_files(parquet_root, alert_cache_sig))
    if not cache_files:
        return pd.DataFrame(columns=["ts", "status", "events"])

    try:
        import duckdb

        con = duckdb.connect(database=":memory:")
        hourly_mac = con.execute(
            """
            WITH ev AS (
              SELECT
                try_cast(ts_dt AS timestamp) AS ts_dt,
                cast(mac_norm AS varchar) AS mac
              FROM read_parquet(?, union_by_name=true)
            ),
            clean AS (
              SELECT
                date_trunc('hour', ts_dt) AS ts,
                mac
              FROM ev
              WHERE ts_dt IS NOT NULL
                AND mac IS NOT NULL
                AND mac != 'ff:ff:ff:ff:ff:ff'
            )
            SELECT
              ts,
              mac,
              count(*) AS events
            FROM clean
            GROUP BY ts, mac
            ORDER BY ts
            """,
            [cache_files],
        ).df()
        con.close()
    except Exception:
        return pd.DataFrame(columns=["ts", "status", "events"])

    if hourly_mac is None or hourly_mac.empty:
        return pd.DataFrame(columns=["ts", "status", "events"])

    out = hourly_mac.copy()
    out["mac"] = out["mac"].map(normalize_mac)
    out = out.dropna(subset=["mac", "ts"])
    if out.empty:
        return pd.DataFrame(columns=["ts", "status", "events"])

    banned_set = set(banned_macs_tuple or ())
    if banned_set:
        out = out[~out["mac"].isin(banned_set)]
        if out.empty:
            return pd.DataFrame(columns=["ts", "status", "events"])

    allowed_set = set(allowed_macs_tuple or ())
    out["status"] = out["mac"].apply(lambda m: "Authorized" if m in allowed_set else "Unauthorized")
    out = (
        out.groupby(["ts", "status"], as_index=False)["events"]
        .sum()
        .sort_values("ts")
    )
    return out


# =====================================================
# 2) Drill-Down Log Loader (robust ts + robust MAC)
# =====================================================
@st.cache_data(show_spinner=False)
def get_device_activity(
    parquet_root: Path,
    target_mac: str,
    target_ip: str,
    selected_date_str: str = "All Dates",
    selected_dates: tuple | None = None,
):
    activity_log = []
    log_types = [("dns", "DNS", "query"), ("http", "HTTP", "host"), ("ssl", "SSL", "server_name")]

    target_mac_norm = normalize_mac(target_mac) or (target_mac or "").strip().lower()
    target_ip_norm = (target_ip or "").strip()

    date_dirs = list(iter_date_dirs(parquet_root))
    date_dir_map = {d: p for d, p in date_dirs}

    if selected_dates:
        chosen = [d for d in selected_dates if d in date_dir_map]
        day_dirs = [date_dir_map[d] for d in chosen]
    elif selected_date_str and selected_date_str != "All Dates":
        if selected_date_str in date_dir_map:
            day_dirs = [date_dir_map[selected_date_str]]
        else:
            fallback = parquet_root / selected_date_str
            day_dirs = [fallback] if fallback.exists() else []
    else:
        day_dirs = [p for _, p in date_dirs]
        if not day_dirs:
            day_dirs = sorted((p for p in parquet_root.iterdir() if p.is_dir()))

    def _normalize_mac_one(x) -> str:
        if x is None:
            return ""
        if isinstance(x, (bytes, bytearray)) and len(x) == 6:
            hx = bytes(x).hex()
            return ":".join(hx[i : i + 2] for i in range(0, 12, 2))
        normalized = normalize_mac(x)
        if normalized:
            return normalized
        return str(x).strip().lower()

    def _normalize_mac_series(s: pd.Series) -> pd.Series:
        return s.map(_normalize_mac_one)

    def _coerce_ts(series: pd.Series) -> pd.Series:
        return _coerce_ts_any(series)

    def _resolve_day_ips(day_dir: Path) -> set:
        candidates = set()
        if target_ip_norm:
            candidates.add(target_ip_norm)
        if not target_mac_norm:
            return candidates

        kh = day_dir / "known_hosts.parquet"
        if not kh.exists():
            return candidates

        kh_df = _duckdb_read_parquet_columns(kh, ("mac", "host"))

        if kh_df.empty or "mac" not in kh_df.columns or "host" not in kh_df.columns:
            return candidates

        kh_mac = kh_df["mac"].map(normalize_mac)
        day_ips = kh_df.loc[kh_mac == target_mac_norm, "host"]
        if day_ips.empty:
            return candidates

        day_ips = day_ips.astype(str).str.strip()
        day_ips = day_ips[(day_ips != "") & (day_ips.str.lower() != "nan")]
        candidates.update(day_ips.tolist())
        return candidates

    for day_dir in day_dirs:
        if not day_dir.exists():
            continue

        day_ip_candidates = _resolve_day_ips(day_dir)

        for file_prefix, service, detail_col in log_types:
            pq_file = day_dir / f"{file_prefix}.parquet"
            if not pq_file.exists():
                continue

            try:
                read_cols = ["ts", "mac", "id.orig_h", "host", detail_col]
                if service == "HTTP":
                    read_cols.append("uri")
                elif service == "DNS":
                    read_cols.append("qtype_name")
                elif service == "SSL":
                    read_cols.append("version")
                df = _duckdb_read_parquet_columns(pq_file, tuple(read_cols))
                if df.empty or "ts" not in df.columns:
                    continue

                filtered = pd.DataFrame()

                if "mac" in df.columns and target_mac_norm:
                    mac_norm = _normalize_mac_series(df["mac"])
                    filtered = df[mac_norm == target_mac_norm]

                if filtered.empty and day_ip_candidates:
                    ip_mask = None
                    if "id.orig_h" in df.columns:
                        ip_mask = df["id.orig_h"].astype(str).isin(day_ip_candidates)
                    if "host" in df.columns:
                        host_mask = df["host"].astype(str).isin(day_ip_candidates)
                        ip_mask = host_mask if ip_mask is None else (ip_mask | host_mask)
                    if ip_mask is not None:
                        filtered = df[ip_mask]

                if filtered.empty:
                    continue

                if detail_col not in filtered.columns:
                    filtered = filtered.copy()
                    filtered[detail_col] = "-"

                norm = pd.DataFrame()
                norm["ts"] = filtered["ts"]
                norm["Service"] = service
                norm["Destination"] = filtered[detail_col].astype(str)

                if service == "HTTP" and "uri" in filtered.columns:
                    norm["Details"] = filtered["uri"].astype(str)
                elif service == "DNS" and "qtype_name" in filtered.columns:
                    norm["Details"] = filtered["qtype_name"].astype(str)
                elif service == "SSL" and "version" in filtered.columns:
                    norm["Details"] = filtered["version"].astype(str)
                else:
                    norm["Details"] = "-"

                activity_log.append(norm)

            except Exception:
                continue

    if not activity_log:
        return pd.DataFrame()

    final_df = pd.concat(activity_log, ignore_index=True)
    final_df["ts"] = _coerce_ts(final_df["ts"])
    final_df = final_df.dropna(subset=["ts"])
    return final_df.sort_values("ts", ascending=False)


# =====================================================
# Helpers
# =====================================================
@st.cache_data(show_spinner=False)
def get_mac_vendor(mac: str) -> str:
    if not mac or mac == "unknown":
        return "Unknown"
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text if r.status_code == 200 else "Unknown"
    except Exception:
        return "Unknown"


def _extract_list_from_yaml(data, stem_key: str):
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if stem_key in data and isinstance(data[stem_key], list):
            return data[stem_key]
        for v in data.values():
            if isinstance(v, list):
                return v
    return []


def _normalize_item_keys(item: dict) -> dict:
    return {str(k).strip().lower(): v for k, v in (item or {}).items()}


def _clean_device_field(value: object) -> str:
    text = str(value or "").strip()
    if text.lower() in {"", "-", "nan", "none", "<na>", "null"}:
        return ""
    return text


def _extract_mac_from_item(item: dict) -> str | None:
    item_l = _normalize_item_keys(item)
    for key in (
        "mac",
        "mac_address",
        "mac address",
        "macaddress",
        "device_mac",
        "device mac",
        "client_mac",
        "client mac",
        "l2addr",
        "l2_addr",
    ):
        val = item_l.get(key)
        if val:
            return val
    return None


def load_authorized_device_records(file_path: Path) -> dict[str, dict]:
    if file_path.suffix == ".txt":
        yaml_path = file_path.with_suffix(".yaml")
        if yaml_path.exists():
            file_path = yaml_path

    if not file_path.exists():
        return {}

    try:
        data = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    raw_list = _extract_list_from_yaml(data, file_path.stem)
    details: dict[str, dict] = {}
    for item in raw_list:
        if isinstance(item, str):
            mac = normalize_mac(item)
            if not mac or is_broadcast_mac(mac):
                continue
            details[mac] = {"ip": "", "host_name": "", "vendor": "", "date_modified": ""}
            continue

        if not isinstance(item, dict):
            continue

        item_l = _normalize_item_keys(item)
        mac = normalize_mac(_extract_mac_from_item(item_l))
        if not mac or is_broadcast_mac(mac):
            continue

        details[mac] = {
            "ip": _clean_device_field(item_l.get("ip") or item_l.get("host") or item_l.get("client_addr")),
            "host_name": _clean_device_field(
                item_l.get("hostname")
                or item_l.get("host_name")
                or item_l.get("host name")
                or item_l.get("client_fqdn")
            ),
            "vendor": _clean_device_field(item_l.get("vendor") or item_l.get("manufacturer")),
            "date_modified": _clean_device_field(item_l.get("date_modified")),
        }
    return details


def load_banned_macs(ban_file: Path) -> set:
    if not ban_file.exists():
        return set()
    try:
        data = yaml.safe_load(ban_file.read_text(encoding="utf-8"))
    except Exception:
        return set()

    raw_list = _extract_list_from_yaml(data, ban_file.stem)

    banned = set()
    for it in raw_list:
        if isinstance(it, str):
            m = normalize_mac(it)
            if m and not is_broadcast_mac(m):
                banned.add(m)
        elif isinstance(it, dict):
            m = normalize_mac(_extract_mac_from_item(it))
            if m and not is_broadcast_mac(m):
                banned.add(m)
    return banned


def save_banned_macs(ban_file: Path, banned_set: set) -> None:
    ban_file.parent.mkdir(parents=True, exist_ok=True)
    payload = {ban_file.stem: sorted(list(banned_set))}
    ban_file.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _metrics_store_file(authorized_mac_file: Path) -> Path:
    return authorized_mac_file.with_name("device_metrics_store.json")


def load_metrics_store(authorized_mac_file: Path) -> dict:
    fp = _metrics_store_file(authorized_mac_file)
    if not fp.exists():
        return {}
    try:
        return json.loads(fp.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_metrics_store(authorized_mac_file: Path, store: dict) -> None:
    fp = _metrics_store_file(authorized_mac_file)
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(json.dumps(store, indent=2), encoding="utf-8")


def _auth_history_store_file(authorized_mac_file: Path) -> Path:
    return authorized_mac_file.with_name("authorized_macs_history.json")


def _load_auth_history_store(authorized_mac_file: Path) -> dict:
    fp = _auth_history_store_file(authorized_mac_file)
    if not fp.exists():
        return {}
    try:
        data = json.loads(fp.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_auth_history_store(authorized_mac_file: Path, store: dict) -> None:
    fp = _auth_history_store_file(authorized_mac_file)
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(json.dumps(store, indent=2), encoding="utf-8")


def _activity_log_file(authorized_mac_file: Path) -> Path:
    return authorized_mac_file.with_name("activity_log.csv")


@st.cache_data(show_spinner=False)
def _load_device_change_history_cached(log_file_str: str, sig: tuple) -> pd.DataFrame:
    _ = sig
    log_file = Path(log_file_str)
    empty = pd.DataFrame(columns=["change_type", "who", "when_str", "ts"])
    if not log_file.exists():
        return empty

    try:
        df = pd.read_csv(log_file)
    except Exception:
        return empty

    if df.empty:
        return empty

    col_map = {str(c).strip().lower(): c for c in df.columns}
    ts_col = col_map.get("timestamp")
    action_col = col_map.get("action")
    type_col = col_map.get("type")
    item_col = col_map.get("item")
    if not (ts_col and action_col and type_col and item_col):
        return empty

    out = df[[ts_col, action_col, type_col, item_col]].copy()
    out.columns = ["timestamp", "action", "type", "item"]

    out["type"] = out["type"].astype(str).str.strip().str.lower()
    out["action"] = out["action"].astype(str).str.strip().str.lower()
    out = out[(out["type"] == "device") & (out["action"].isin(["added", "deleted", "removed"]))].copy()
    if out.empty:
        return empty

    out["change_type"] = out["action"].map({"added": "Added", "deleted": "Removed", "removed": "Removed"})
    out["who"] = out["item"].astype(str).str.strip()
    out["who"] = out["who"].map(lambda v: normalize_mac(v) or v)
    out["ts"] = _coerce_ts_any(out["timestamp"])
    out["when_str"] = out["ts"].dt.strftime("%Y-%m-%d %H:%M:%S")
    out["when_str"] = out["when_str"].fillna(out["timestamp"].astype(str))

    out = out[["change_type", "who", "when_str", "ts"]].copy()
    out = out.drop_duplicates()
    out = out.sort_values("ts", ascending=False, na_position="last").reset_index(drop=True)
    return out


def load_device_change_history(authorized_mac_file: Path) -> pd.DataFrame:
    log_file = _activity_log_file(authorized_mac_file)
    if not log_file.exists():
        return pd.DataFrame(columns=["change_type", "who", "when_str", "ts"])
    try:
        st_ = log_file.stat()
        sig = (float(st_.st_mtime), int(st_.st_size))
    except Exception:
        sig = (0.0, 0)
    return _load_device_change_history_cached(str(log_file), sig)


def _parse_any_dt(value):
    if value is None:
        return None
    try:
        ts = pd.to_datetime(value, errors="coerce", utc=False)
        if pd.isna(ts):
            return None
        return ts.to_pydatetime()
    except Exception:
        return None


def load_authorized_macs_with_history(file_path: Path, authorized_mac_file_for_store: Path):
    if file_path.suffix == ".txt":
        yaml_path = file_path.with_suffix(".yaml")
        if yaml_path.exists():
            file_path = yaml_path

    if not file_path.exists():
        st.warning(f"Authorized file not found ({file_path.name}) — all devices Unauthorized")
        return set(), {}

    try:
        data = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except Exception as e:
        st.error(f"Error reading YAML: {e}")
        return set(), {}

    raw_list = _extract_list_from_yaml(data, file_path.stem)

    store = _load_auth_history_store(authorized_mac_file_for_store)
    store_norm = {normalize_mac(k): v for k, v in store.items() if normalize_mac(k)}

    now = get_local_now()
    authorized_set = set()
    added_at_map = {}

    for item in raw_list:
        mac = None
        added_dt = None

        if isinstance(item, str):
            mac = normalize_mac(item)
        elif isinstance(item, dict):
            item_l = _normalize_item_keys(item)
            mac = normalize_mac(_extract_mac_from_item(item_l))
            # Specifically grab the date_modified stored by the authorization page
            for k in ["date_modified", "date_added", "added_at", "timestamp", "created_at"]:
                if k in item_l and item_l.get(k):
                    added_dt = _parse_any_dt(item_l.get(k))
                    if added_dt:
                        break

        if not mac or is_broadcast_mac(mac):
            continue

        authorized_set.add(mac)

        if added_dt:
            added_at_map[mac] = added_dt
            store_norm[mac] = added_dt.strftime("%Y-%m-%d %H:%M:%S")
            continue

        stored_str = store_norm.get(mac)
        stored_dt = _parse_any_dt(stored_str) if stored_str else None
        if stored_dt:
            added_at_map[mac] = stored_dt
        else:
            added_at_map[mac] = now
            store_norm[mac] = now.strftime("%Y-%m-%d %H:%M:%S")

    _save_auth_history_store(authorized_mac_file_for_store, store_norm)
    return authorized_set, added_at_map


# =====================================================
# UI: base styles
# =====================================================
def inject_page_css():
    st.markdown(
        """
        <style>
        :root {
            --panel-border: rgba(255,255,255,0.12);
            --panel-bg: rgba(255,255,255,0.03);
            --panel-shadow: 0 14px 38px rgba(0,0,0,0.25);
            --accent-cyan: #00F7FF;
            --accent-red: #F63049;
        }

        .stApp {
            background:
                radial-gradient(1200px 550px at 10% -5%, rgba(0, 247, 255, 0.08), transparent 45%),
                radial-gradient(900px 460px at 90% 8%, rgba(246, 48, 73, 0.08), transparent 42%),
                #040B18;
        }

        .block-container,
        .main .block-container,
        [data-testid="stMainBlockContainer"] {
            padding-top: 0 !important;
            padding-bottom: 1.05rem !important;
            padding-left: 30px !important;
            padding-right: 30px !important;
            max-width: 100% !important;
        }

        [data-testid="stAppViewContainer"] > .main,
        [data-testid="stAppViewContainer"] .main,
        section.main {
            padding-left: 0 !important;
            padding-right: 0 !important;
            margin-left: 0 !important;
            margin-right: 0 !important;
            max-width: 100% !important;
        }

        .page-header {
            display:flex;
            align-items:flex-end;
            justify-content:space-between;
            gap: 18px;
            margin-bottom: 16px;
            padding: 18px 20px;
            border-radius: 18px;
            border: 1px solid var(--panel-border);
            background:
              radial-gradient(circle at top right, rgba(0,247,255,0.08), transparent 40%),
              linear-gradient(135deg, rgba(255,255,255,0.045), rgba(255,255,255,0.015));
            box-shadow: var(--panel-shadow);
        }

        .page-title {
            font-size: 46px;
            font-weight: 900;
            line-height: 1.0;
            letter-spacing: -0.5px;
        }

        .page-sub {
            opacity: 0.74;
            font-size: 13px;
            margin-top: 6px;
        }

        .header-chip {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border: 1px solid rgba(255,255,255,0.18);
            background: rgba(255,255,255,0.05);
            border-radius: 999px;
            padding: 7px 12px;
            font-size: 12px;
            font-weight: 700;
            white-space: nowrap;
        }

        .header-dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: var(--accent-cyan);
            box-shadow: 0 0 10px rgba(0,247,255,0.8);
        }

        .section-title {
            font-size: 26px;
            font-weight: 900;
            margin: 0 0 6px 0;
        }

        .section-subtitle {
            opacity: 0.72;
            font-size: 13px;
            margin: 0 0 12px 0;
        }

        .section-panel {
            border: 1px solid var(--panel-border);
            background: var(--panel-bg);
            border-radius: 18px;
            padding: 14px 14px 6px 14px;
            box-shadow: var(--panel-shadow);
        }

        .section-gap { margin-top: 16px; }

        .status-strip {
            border-radius: 14px;
            border: 1px solid rgba(255,255,255,0.1);
            background: rgba(255,255,255,0.03);
            padding: 12px 14px;
            margin: 0 0 10px 0;
            font-size: 13px;
            line-height: 1.45;
            opacity: 0.9;
        }

        .gauge-legend {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 10px;
        }

        .gauge-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            border: 1px solid rgba(255,255,255,0.14);
            background: rgba(255,255,255,0.04);
            border-radius: 999px;
            padding: 4px 10px;
            font-size: 12px;
            opacity: 0.9;
        }

        .gauge-dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
        }

        .grid-card {
            border: 1px solid rgba(148, 163, 184, 0.24);
            background: linear-gradient(180deg, rgba(2,6,23,0.5), rgba(2,6,23,0.35));
            border-radius: 12px;
            padding: 0.56rem 0.62rem 0.46rem 0.62rem;
            margin-bottom: 0.75rem;
        }

        .grid-card [data-testid="stDataFrame"] {
            border: 1px solid #2A466E !important;
            border-radius: 10px !important;
            overflow: hidden !important;
            background: #061120 !important;
        }

        .grid-card [data-testid="stDataFrame"] table {
            background: #050B16 !important;
            color: #EAEAEA !important;
        }

        .grid-card [data-testid="stDataFrame"] thead tr th {
            background: #0A1730 !important;
            color: #EAF2FF !important;
            border-bottom: 1px solid #29406A !important;
        }

        .grid-card [data-testid="stDataFrame"] tbody tr:nth-child(odd) td {
            background: #071224 !important;
        }

        .grid-card [data-testid="stDataFrame"] tbody tr:nth-child(even) td {
            background: #050E1D !important;
        }

        .grid-card [data-testid="stDataFrame"] tbody tr td {
            color: #EAEAEA !important;
            border-color: #13233D !important;
        }

        div[data-testid="stDialog"] > div {
            border: 1px solid rgba(255,255,255,0.16);
            border-radius: 20px;
            background:
                radial-gradient(700px 260px at 0% 0%, rgba(0,247,255,0.08), transparent 45%),
                linear-gradient(165deg, rgba(7,18,38,0.98), rgba(5,12,26,0.98));
            box-shadow: 0 20px 48px rgba(0,0,0,0.45);
        }

        div[data-testid="stDialog"] .block-container {
            padding-top: 0.45rem !important;
            padding-bottom: 0.55rem !important;
            padding-left: 0.25rem !important;
            padding-right: 0.25rem !important;
            max-width: 100% !important;
        }

        .dialog-head {
            border: 1px solid rgba(255,255,255,0.12);
            background: rgba(255,255,255,0.025);
            border-radius: 14px;
            padding: 12px 14px;
            margin-bottom: 12px;
        }

        .dialog-title {
            font-size: 24px;
            font-weight: 900;
            line-height: 1.1;
            letter-spacing: -0.3px;
        }

        .dialog-sub {
            opacity: 0.75;
            font-size: 13px;
            margin-top: 5px;
        }

        .dialog-toolbar {
            border: 1px solid rgba(255,255,255,0.1);
            background: rgba(255,255,255,0.02);
            border-radius: 14px;
            padding: 10px 12px 8px 12px;
            margin-bottom: 10px;
        }

        .dialog-note {
            opacity: 0.75;
            font-size: 12px;
            margin: 2px 0 10px 1px;
        }

        div[data-testid="stButton"].st-key-dlg_active_close > button,
        div[data-testid="stButton"].st-key-dlg_forensics_close > button,
        div[data-testid="stButton"][class*="st-key-dlg_list_close_"] > button {
            border-radius: 999px !important;
            padding: 0.35rem 1rem !important;
            font-weight: 700 !important;
            border: 1px solid rgba(255,255,255,0.2) !important;
            background: rgba(255,255,255,0.06) !important;
        }

        div[data-testid="stTextInput"] input { border-radius: 14px !important; }
        div[data-testid="stSelectbox"] > div { border-radius: 14px !important; }
        button { border-radius: 14px !important; }

        div[data-testid="stDownloadButton"] button {
            border-radius: 999px !important;
            padding: 0.35rem 0.85rem !important;
        }

        @media (max-width: 1200px) {
            .page-header {
                align-items: flex-start;
                flex-direction: column;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

def hide_dialog_header():
    st.markdown(
        """
        <style>
        div[role="dialog"] header,
        div[data-testid="stDialog"] header {
            display: none !important;
            visibility: hidden !important;
            height: 0 !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _close_dialog():
    st.session_state.active_dialog = None
    st.session_state.prev_dialog = None
    st.session_state.selected_forensic_mac = None
    st.session_state.selected_forensic_ip = None
    st.session_state.devices_last_selection_key = None
    _bump_devices_grid_nonce()
    st.rerun()


def _go_back_from_forensics():
    prev = st.session_state.get("prev_dialog") or "list"
    st.session_state.active_dialog = prev
    st.session_state.devices_last_selection_key = None
    _bump_devices_grid_nonce()
    st.rerun()


# =====================================================
# Metric cards CSS
# =====================================================
def inject_metric_card_css():
    st.markdown(
        """
        <style>
        .st-key-card_open_auth button,
        .st-key-card_open_unauth button,
        .st-key-card_open_active button,
        div[data-testid="stButton"].st-key-card_open_auth > button,
        div[data-testid="stButton"].st-key-card_open_unauth > button,
        div[data-testid="stButton"].st-key-card_open_active > button,
        div.st-key-card_open_auth > button,
        div.st-key-card_open_unauth > button,
        div.st-key-card_open_active > button {
            height: 146px !important;
            min-height: 146px !important;
            width: 100% !important;
            padding: 0 !important;
            border-radius: 20px !important;
            border: 1px solid rgba(255,255,255,0.12) !important;
            background: rgba(255,255,255,0.035) !important;
            transition: 160ms ease;
            cursor: pointer !important;
            font-size: 0 !important;
            line-height: 0 !important;
            box-shadow: 0 16px 45px rgba(0,0,0,0.28);
        }

        .st-key-card_open_auth button:hover,
        .st-key-card_open_unauth button:hover,
        .st-key-card_open_active button:hover,
        div[data-testid="stButton"].st-key-card_open_auth > button:hover,
        div[data-testid="stButton"].st-key-card_open_unauth > button:hover,
        div[data-testid="stButton"].st-key-card_open_active > button:hover,
        div.st-key-card_open_auth > button:hover,
        div.st-key-card_open_unauth > button:hover,
        div.st-key-card_open_active > button:hover {
            transform: translateY(-2px);
            border-color: rgba(0,247,255,0.26) !important;
            background: rgba(255,255,255,0.055) !important;
        }

        .metric-overlay{
            margin-top: -166px !important;
            height: 146px !important;
            padding: 16px 16px !important;
            border-radius: 20px !important;
            pointer-events: none !important;
            position: relative !important;
            z-index: 2 !important;
        }

        .metric-card-static{
            height: 146px;
            padding: 16px 16px;
            border-radius: 20px;
            border: 1px solid rgba(255,255,255,0.12);
            background: rgba(255,255,255,0.035);
            box-shadow: 0 16px 45px rgba(0,0,0,0.28);
        }

        .metric-overlay,
        .metric-card-static {
            width: 100%;
            box-sizing: border-box;
            display: flex;
            flex-direction: column;
            align-items: flex-start;
            justify-content: flex-start;
            text-align: left;
        }

        .metric-label,
        .metric-value,
        .metric-delta-slot,
        .metric-hint {
            width: 100%;
            text-align: left;
        }

        .metric-label {
            font-size: 14px;
            opacity: 0.82;
        }

        .metric-value {
            font-size: 44px;
            font-weight: 800;
            line-height: 1.05;
            margin-top: 2px;
            letter-spacing: -0.6px;
        }

        .metric-hint {
            font-size: 12px;
            opacity: 0.55;
            margin-top: auto;
            padding-top: 6px;
        }

        .metric-delta-slot {
            height: 38px;
            display: flex;
            align-items: center;
            margin-top: 6px;
        }

        .metric-pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 4px 10px;
            border-radius: 999px;
            background: rgba(255,255,255,0.06);
            font-size: 16px;
            font-weight: 700;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

def _metric_delta_html(delta_value, *, delta_is_percent: bool, up_color: str, down_color: str) -> str:
    try:
        dv = float(delta_value)
    except Exception:
        dv = 0.0

    show = abs(dv) >= 1e-12
    if not show:
        return "<div class='metric-delta-slot'></div>"

    up = dv > 0
    mag = abs(dv)
    suffix = "%" if delta_is_percent else ""
    if delta_is_percent:
        disp = f"{mag:.2f}".rstrip("0").rstrip(".")
    else:
        disp = str(int(mag)) if abs(mag - int(mag)) < 1e-12 else f"{mag:.2f}".rstrip("0").rstrip(".")

    arrow = "&uarr;" if up else "&darr;"
    color = up_color if up else down_color
    delta_text = f"{arrow} {disp}{suffix} (today)"

    return (
        "<div class='metric-delta-slot'>"
        f"  <div class='metric-pill' style='color:{color};'>{delta_text}</div>"
        "</div>"
    )


def render_metric_card_static(
    label: str,
    value,
    delta_value,
    *,
    delta_is_percent: bool = False,
    up_color: str = "#2ecc71",
    down_color: str = "#9aa0a6",
):
    value_str = str(value)
    delta_html = _metric_delta_html(delta_value, delta_is_percent=delta_is_percent, up_color=up_color, down_color=down_color)
    st.markdown(
        f"""
        <div class="metric-card-static">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value_str}</div>
            {delta_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metric_card_dialog(
    label: str,
    value,
    delta_value,
    *,
    open_dialog_name: str,
    key: str,
    delta_is_percent: bool = False,
    up_color: str = "#2ecc71",
    down_color: str = "#9aa0a6",
):
    clicked = st.button(" ", key=key, width="stretch")

    value_str = str(value)
    delta_html = _metric_delta_html(delta_value, delta_is_percent=delta_is_percent, up_color=up_color, down_color=down_color)

    st.markdown(
        f"""
        <div class="metric-overlay">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value_str}</div>
            {delta_html}
            <div class="metric-hint">Click to view</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if clicked:
        st.session_state.active_dialog = open_dialog_name
        st.rerun()


# =====================================================
# Dialog: Active Devices list (shows active MACs)
# =====================================================
@st.dialog(" ", width="large", dismissible=False)
def active_today_popup(
    in_scope: pd.DataFrame,
    parquet_root: Path,
    active_day_str: str,
    today_str: str,
    available_dates_list,
):
    hide_dialog_header()
    inject_page_css()
    is_today_source = active_day_str == today_str

    h1, h2 = st.columns([0.82, 0.18], vertical_alignment="center")
    with h1:
        st.markdown(
            f"""
            <div class='dialog-head'>
              <div class='dialog-title'>Active Devices</div>
              <div class='dialog-sub'>Devices seen in <b>{active_day_str}</b> from {"today's" if is_today_source else "the latest available"} date folder.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with h2:
        if st.button("Close", key="dlg_active_close", width="stretch"):
            _close_dialog()

    known_hosts_sig = _known_hosts_sig_for_day(parquet_root, active_day_str)
    inv_today = load_active_today_inventory_from_parquet(parquet_root, active_day_str, known_hosts_sig)
    if inv_today.empty:
        st.info(f"No active device records found for {active_day_str}.")
        return

    enrich = (
        in_scope.sort_values("ts", ascending=False)
        .groupby("mac", as_index=False)
        .agg(
            host_name=("host_name", "first"),
            status=("status", "first"),
        )
    )

    inv = inv_today.merge(enrich, how="left", on="mac")
    inv["host_name"] = inv.get("host_name", "-").fillna("-")
    inv["status"] = inv.get("status", "Unknown").fillna("Unknown")
    inv["last_seen_today"] = _coerce_ts_any(inv["last_seen_today"])
    inv["last_seen_today_str"] = inv["last_seen_today"].dt.strftime("%Y-%m-%d %H:%M:%S")

    active_search_state_key = "active_search"
    if active_search_state_key not in st.session_state:
        st.session_state[active_search_state_key] = ""

    st.markdown("<div class='dialog-toolbar'>", unsafe_allow_html=True)
    st.text_input(
        "Search MAC:",
        placeholder="aa:bb:cc:dd:ee:ff",
        key=active_search_state_key,
    )
    q = str(st.session_state.get(active_search_state_key, "") or "").strip().lower()
    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='dialog-note'>Tip: Click a <b>MAC Address</b> cell to open forensics for that device.</div>",
        unsafe_allow_html=True,
    )

    def _tok(x: str) -> str:
        return "".join(ch for ch in (x or "").lower() if ch.isalnum())

    if q:
        qn = _tok(q)
        tmp = inv.copy()
        tmp["_m"] = tmp["mac"].astype(str).map(_tok)
        tmp = tmp[tmp["mac"].astype(str).str.lower().str.contains(q, na=False) | tmp["_m"].str.contains(qn, na=False)]
        tmp = tmp.drop(columns=["_m"], errors="ignore")
        inv = tmp
        if inv.empty:
            st.info("No matching MAC found in Active Today.")
            return

    inv = inv.sort_values("last_seen_today", ascending=False).reset_index(drop=True)
    inv.insert(0, "#", inv.index + 1)

    display_df = inv[["#", "mac", "ip", "host_name", "status", "last_seen_today_str"]].copy()
    display_df.rename(columns={"last_seen_today_str": "Last Seen"}, inplace=True)

    ag_theme, ag_css = get_shadow_aggrid_theme_and_css()
    st.markdown("<div class='grid-card'>", unsafe_allow_html=True)

    gb = GridOptionsBuilder.from_dataframe(display_df)
    gb.configure_selection(selection_mode="single", use_checkbox=False)
    gb.configure_column("#", width=52, pinned="left")
    gb.configure_column("mac", header_name="MAC Address (Click)", width=190, cellStyle=_MAC_CLICK_CELL_STYLE)
    gb.configure_column("ip", header_name="IP Address", width=140)
    gb.configure_column("host_name", header_name="Host Name", width=220)
    gb.configure_column("status", header_name="Status", width=140)
    gb.configure_column("Last Seen", width=200)
    grid_options = _apply_copyable_grid_options(gb.build())
    grid_options["rowSelection"] = "single"
    grid_options["suppressRowClickSelection"] = True
    grid_options["rowMultiSelectWithClick"] = False
    grid_options["domLayout"] = "normal"
    grid_options["alwaysShowVerticalScroll"] = True
    grid_options["onCellClicked"] = _MAC_ONLY_CLICK_JS

    st.caption("Copy cells with Ctrl/Cmd + C.")
    grid_key = f"devices_active_today_grid_{int(st.session_state.get('devices_grid_nonce', 0))}"

    grid_response = AgGrid(
        display_df,
        gridOptions=grid_options,
        update_mode=GridUpdateMode.SELECTION_CHANGED,
        height=_table_height_for_rows(len(display_df), min_px=240, max_px=520),
        theme=ag_theme,
        custom_css=ag_css,
        allow_unsafe_jscode=True,
        fit_columns_on_grid_load=True,
        reload_data=False,
        key=grid_key,
    )

    st.markdown("</div>", unsafe_allow_html=True)

    row = _extract_first_selected_row(grid_response.get("selected_rows", None))
    if row:
        _open_forensics_from_row(row, "active_today")
    else:
        st.session_state.devices_last_selection_key = None


# =====================================================
# Dialog: Device list popup (Authorized / Unauthorized)
# =====================================================
@st.dialog(" ", width="large", dismissible=False)
def device_list_popup(
    status_type,
    df,
    parquet_root,
    available_dates_list,
    banned_macs: set,
    authorized_added_at_map: dict,
    auth_change_history_df: pd.DataFrame,
    authorized_device_details: dict[str, dict],
):
    hide_dialog_header()
    inject_page_css()

    h1, h2 = st.columns([0.82, 0.18], vertical_alignment="center")
    with h1:
        st.markdown(
            f"""
            <div class='dialog-head'>
              <div class='dialog-title'>{status_type} Devices</div>
              <div class='dialog-sub'>Search and filter inventory, then click a MAC Address cell to open forensics.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with h2:
        if st.button("Close", key=f"dlg_list_close_{status_type.lower()}", width="stretch"):
            _close_dialog()

    available_dates_for_filter = list(available_dates_list or [])

    # Toolbar
    st.markdown("<div class='dialog-toolbar'>", unsafe_allow_html=True)
    scope_key = status_type.lower()
    mac_state_key = f"popup_mac_search_applied_{scope_key}"
    date_mode_state_key = f"popup_list_mode_applied_{scope_key}"
    history_mode_state_key = f"popup_list_history_mode_applied_{scope_key}"
    spec_date_state_key = f"popup_list_spec_date_applied_{scope_key}"

    date_mode_options = ["Last 7 Days", "Last 30 Days", "Specific Date", "All Time"]
    history_mode_options = ["Hide", "Last 7 Days", "All"]

    if mac_state_key not in st.session_state:
        st.session_state[mac_state_key] = ""
    if st.session_state.get(date_mode_state_key) not in date_mode_options:
        st.session_state[date_mode_state_key] = "Last 7 Days"
    if st.session_state.get(history_mode_state_key) not in history_mode_options:
        st.session_state[history_mode_state_key] = "Hide"
    if available_dates_for_filter:
        if st.session_state.get(spec_date_state_key) not in available_dates_for_filter:
            st.session_state[spec_date_state_key] = available_dates_for_filter[0]
    else:
        st.session_state[spec_date_state_key] = None

    t1, t2, t3, t4, t5 = st.columns([2.0, 1.15, 1.15, 1.8, 0.9], vertical_alignment="bottom")
    with t1:
        st.text_input(
            "Search MAC:",
            placeholder="aa:bb:cc:dd:ee:ff",
            key=mac_state_key,
        )
    with t2:
        st.selectbox(
            "Time Range:",
            date_mode_options,
            key=date_mode_state_key,
        )
    with t3:
        st.selectbox(
            "History:",
            history_mode_options,
            key=history_mode_state_key,
        )
    with t4:
        live_mode = str(st.session_state.get(date_mode_state_key, "Last 7 Days") or "Last 7 Days")
        if live_mode == "Specific Date":
            if available_dates_for_filter:
                if st.session_state.get(spec_date_state_key) not in available_dates_for_filter:
                    st.session_state[spec_date_state_key] = available_dates_for_filter[0]
                st.selectbox(
                    "Date:",
                    available_dates_for_filter,
                    key=spec_date_state_key,
                )
            else:
                st.session_state[spec_date_state_key] = None
                st.caption("No dates available.")
        else:
            st.markdown("<div style='height: 2.55rem;'></div>", unsafe_allow_html=True)
    with t5:
        clear_filters = st.button("Reset", key=f"devices_list_reset_{scope_key}", use_container_width=True)

    if clear_filters:
        st.session_state[mac_state_key] = ""
        st.session_state[date_mode_state_key] = "Last 7 Days"
        st.session_state[history_mode_state_key] = "Hide"
        if available_dates_for_filter:
            st.session_state[spec_date_state_key] = available_dates_for_filter[0]
        else:
            st.session_state[spec_date_state_key] = None
        st.rerun()

    mac_query = str(st.session_state.get(mac_state_key, "") or "").strip().lower()
    date_filter_mode = str(st.session_state.get(date_mode_state_key, "Last 7 Days") or "Last 7 Days")
    history_filter_mode = str(st.session_state.get(history_mode_state_key, "Hide") or "Hide")
    spec_date = (
        st.session_state.get(spec_date_state_key)
        if date_filter_mode == "Specific Date"
        else None
    )

    def _norm_token(x: str) -> str:
        return "".join(ch for ch in (x or "").lower() if ch.isalnum())

    mac_query_norm = _norm_token(mac_query)

    filtered_df = df[df["status"] == status_type].copy()
    if not filtered_df.empty and "mac" in filtered_df.columns and banned_macs:
        filtered_df = filtered_df[~filtered_df["mac"].isin(banned_macs)]

    scoped_events = filtered_df.copy()
    if not scoped_events.empty:
        scoped_events["ts"] = _coerce_ts_any(scoped_events.get("ts", pd.Series(index=scoped_events.index, dtype="object")))
        scoped_events = scoped_events[scoped_events["ts"].notna()]
        scoped_events = _filter_df_by_time_mode(
            scoped_events,
            "ts",
            date_filter_mode,
            spec_date if date_filter_mode == "Specific Date" else None,
        )

    if scoped_events.empty:
        inventory = pd.DataFrame(columns=["mac", "ip", "host_name", "last_seen"])
    else:
        inventory = (
            scoped_events.sort_values("ts", ascending=False)
            .groupby("mac")
            .agg(
                ip=("host", "first"),
                host_name=("host_name", "first"),
                last_seen=("ts", "max"),
            )
            .reset_index()
        )
    inventory["last_seen"] = _coerce_ts_any(inventory["last_seen"])
    auth_details = authorized_device_details or {}
    auth_ip_series = pd.Series(
        [auth_details.get(normalize_mac(mac) or "", {}).get("ip", "") for mac in inventory.get("mac", pd.Series(dtype="object"))],
        index=inventory.index,
        dtype="object",
    )
    auth_host_series = pd.Series(
        [auth_details.get(normalize_mac(mac) or "", {}).get("host_name", "") for mac in inventory.get("mac", pd.Series(dtype="object"))],
        index=inventory.index,
        dtype="object",
    )
    base_ip = _clean_text_series(inventory.get("ip"), inventory.index)
    auth_ip = _clean_text_series(auth_ip_series, inventory.index)
    inventory["ip"] = base_ip.where(base_ip.notna(), auth_ip).fillna("-").astype(str)
    base_host = _clean_text_series(inventory.get("host_name"), inventory.index)
    auth_host = _clean_text_series(auth_host_series, inventory.index)
    inventory["host_name"] = base_host.where(base_host.notna(), auth_host).fillna("-").astype(str)

    # ==========================================================
    # CORE FIX: Explicitly separate Authorized Date and Last Seen
    # ==========================================================
    if status_type == "Authorized":
        existing_macs = set(inventory["mac"].astype(str).tolist())
        missing_rows = []
        if date_filter_mode == "All Time":
            for mac in authorized_added_at_map.keys():
                m = normalize_mac(mac)
                if not m or is_broadcast_mac(m) or m in existing_macs:
                    continue
                auth_meta = auth_details.get(m, {})
                missing_rows.append(
                    {
                        "mac": m,
                        "ip": auth_meta.get("ip") or "-",
                        "host_name": auth_meta.get("host_name") or "-",
                        "last_seen": pd.NaT,
                    }
                )

        if missing_rows:
            inventory = pd.concat([inventory, pd.DataFrame(missing_rows)], ignore_index=True)

        def _get_added_dt(mac: str):
            m = normalize_mac(mac)
            dtv = authorized_added_at_map.get(m)
            return dtv if isinstance(dtv, datetime) else None

        # Fetch EXACT date from authorization page map
        inventory["authorized_at"] = inventory["mac"].map(_get_added_dt)
        inventory["authorized_at"] = _coerce_ts_any(inventory["authorized_at"])
        inventory["Authorized Date"] = inventory["authorized_at"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("-")

    inventory["sort_dt"] = _coerce_ts_any(inventory.get("last_seen", pd.Series(index=inventory.index, dtype="object")))

    if inventory.empty:
        st.markdown("</div>", unsafe_allow_html=True)
        st.info(f"No {status_type.lower()} devices found for this criteria.")
        return

    # Create the distinct Last Seen column
    inventory["Last Seen"] = _coerce_ts_any(inventory["last_seen"]).dt.strftime("%Y-%m-%d %H:%M:%S").fillna("-")

    # Sort descending
    inventory = inventory.sort_values("sort_dt", ascending=False, na_position="last")

    # Search Logic
    if mac_query_norm:
        inv = inventory.copy()
        inv["_m"] = inv["mac"].astype(str).map(_norm_token)
        inv = inv[
            inv["mac"].astype(str).str.lower().str.contains(mac_query, na=False)
            | inv["_m"].str.contains(mac_query_norm, na=False)
        ].copy()
        inv = inv.drop(columns=["_m"], errors="ignore")

        if inv.empty:
            st.markdown("</div>", unsafe_allow_html=True)
            st.info("No matching MAC address found.")
            return
        inventory = inv

    auth_vendor_series = pd.Series(
        [auth_details.get(normalize_mac(mac) or "", {}).get("vendor", "") for mac in inventory["mac"]],
        index=inventory.index,
        dtype="object",
    )
    auth_vendor = _clean_text_series(auth_vendor_series, inventory.index)
    vendor_lookup = _clean_text_series(inventory["mac"].map(get_mac_vendor), inventory.index)
    inventory["vendor"] = auth_vendor.where(auth_vendor.notna(), vendor_lookup).fillna("Unknown").astype(str)
    if status_type != "Authorized":
        inventory["mac_spoofing"] = inventory["mac"].map(mac_spoofing_status)

    # Filter columns for view
    if status_type == "Authorized":
        inventory = inventory[["mac", "ip", "host_name", "vendor", "Authorized Date", "Last Seen", "sort_dt"]].copy()
    else:
        inventory = inventory[["mac", "ip", "host_name", "vendor", "mac_spoofing", "Last Seen", "sort_dt"]].copy()

    inventory = inventory.reset_index(drop=True)
    inventory.insert(0, "#", pd.RangeIndex(start=1, stop=len(inventory) + 1, step=1))
    inventory["#"] = pd.to_numeric(inventory["#"], errors="coerce").fillna(0).astype(int)

    dl_col1, _ = st.columns([1.0, 5.0])
    with dl_col1:
        csv_bytes = inventory.drop(columns=["sort_dt"], errors="ignore").to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download",
            data=csv_bytes,
            file_name=f"{status_type.lower()}_devices.csv",
            mime="text/csv",
            key=f"dl_{status_type.lower()}",
            width="stretch",
        )
    st.markdown("</div>", unsafe_allow_html=True)
    
    # Explain the date columns clearly to users
    st.markdown(
        "<div class='dialog-note'>Tip: Click a <b>MAC Address</b> cell to open forensics. <b>Date Authorized</b> matches the Authorization page exactly. <b>Last Seen</b> indicates the most recent network traffic detected.</div>",
        unsafe_allow_html=True,
    )

    if history_filter_mode != "Hide":
        history_view = auth_change_history_df.copy() if isinstance(auth_change_history_df, pd.DataFrame) else pd.DataFrame()
        if not history_view.empty:
            if history_filter_mode == "Last 7 Days":
                seven_days_ago_hist = get_local_now() - timedelta(days=7)
                history_view = history_view[
                    history_view["ts"].notna() & (history_view["ts"] >= seven_days_ago_hist)
                ]

        st.markdown(
            "<div class='dialog-note'><b>History:</b> Authorization list Added/Removed events.</div>",
            unsafe_allow_html=True,
        )

        if history_view.empty:
            st.caption("No add/remove history found for this selection.")
        else:
            history_view = history_view.reset_index(drop=True)
            history_view.insert(0, "#", pd.RangeIndex(start=1, stop=len(history_view) + 1, step=1))
            history_show = history_view[["#", "change_type", "who", "when_str"]].copy()
            history_show = history_show.rename(
                columns={"change_type": "Action", "who": "Device", "when_str": "When"}
            )

            hist_theme, hist_css = get_shadow_aggrid_theme_and_css()
            st.markdown("<div class='grid-card'>", unsafe_allow_html=True)
            gb_hist = GridOptionsBuilder.from_dataframe(history_show)
            gb_hist.configure_default_column(
                sortable=True,
                sortingOrder=["asc", "desc"],
                unSortIcon=True,
                filter=False,
                resizable=True,
            )
            gb_hist.configure_grid_options(suppressMenuHide=True)
            gb_hist.configure_pagination(paginationAutoPageSize=False, paginationPageSize=8)
            gb_hist.configure_column(
                "#",
                header_name="#",
                width=60,
                pinned="left",
                type=["numericColumn", "numberColumnFilter"],
                sort="desc",
            )
            gb_hist.configure_column("Action", width=110)
            gb_hist.configure_column("Device", width=220)
            gb_hist.configure_column("When", width=210)
            hist_options = _apply_copyable_grid_options(gb_hist.build())

            AgGrid(
                history_show,
                gridOptions=hist_options,
                update_mode=GridUpdateMode.SELECTION_CHANGED,
                height=220,
                allow_unsafe_jscode=True,
                theme=hist_theme,
                custom_css=hist_css,
                fit_columns_on_grid_load=True,
                reload_data=False,
            )
            st.markdown("</div>", unsafe_allow_html=True)

    ag_theme, ag_css = get_shadow_aggrid_theme_and_css()
    st.markdown("<div class='grid-card'>", unsafe_allow_html=True)

    gb = GridOptionsBuilder.from_dataframe(inventory)
    gb.configure_default_column(
        sortable=True,
        sortingOrder=["asc", "desc"],
        unSortIcon=True,
        filter=False,
        resizable=True,
    )
    gb.configure_grid_options(suppressMenuHide=True)
    gb.configure_pagination(paginationAutoPageSize=False, paginationPageSize=15)
    gb.configure_selection(selection_mode="single", use_checkbox=False)
    
    gb.configure_column(
        "#",
        header_name="#",
        width=60,
        pinned="left",
        type=["numericColumn", "numberColumnFilter"],
        sort="asc",
    )
    gb.configure_column("mac", header_name="MAC Address (Click)", width=170, cellStyle=_MAC_CLICK_CELL_STYLE)
    gb.configure_column("ip", header_name="IP Address", width=130)
    gb.configure_column("host_name", header_name="Host Name", width=180)
    gb.configure_column("vendor", header_name="Vendor", width=180)
    if status_type != "Authorized" and "mac_spoofing" in inventory.columns:
        gb.configure_column("mac_spoofing", header_name="Mac Spoofing", width=145)
    
    # Render two distinct date columns
    if status_type == "Authorized":
        gb.configure_column("Authorized Date", header_name="Date Authorized", width=180)
        gb.configure_column("Last Seen", header_name="Last Seen", width=180)
    else:
        gb.configure_column("Last Seen", header_name="Last Seen", width=180)
        
    gb.configure_column("sort_dt", hide=True)

    grid_options = _apply_copyable_grid_options(gb.build())
    grid_options["rowSelection"] = "single"
    grid_options["suppressRowClickSelection"] = True
    grid_options["rowMultiSelectWithClick"] = False
    grid_options["domLayout"] = "normal"
    grid_options["alwaysShowVerticalScroll"] = True
    grid_options["onCellClicked"] = _MAC_ONLY_CLICK_JS

    st.caption("Copy cells with Ctrl/Cmd + C.")
    grid_key = f"devices_list_grid_{status_type.lower()}_{int(st.session_state.get('devices_grid_nonce', 0))}"

    grid_response = AgGrid(
        inventory,
        gridOptions=grid_options,
        update_mode=GridUpdateMode.SELECTION_CHANGED,
        height=_table_height_for_rows(len(inventory), min_px=240, max_px=520),
        allow_unsafe_jscode=True,
        theme=ag_theme,
        custom_css=ag_css,
        fit_columns_on_grid_load=True,
        reload_data=False,
        key=grid_key,
    )

    st.markdown("</div>", unsafe_allow_html=True)

    row = _extract_first_selected_row(grid_response.get("selected_rows", None))
    if row:
        _open_forensics_from_row(row, "list")
    else:
        st.session_state.devices_last_selection_key = None


# =====================================================
# Dialog: Forensics popup
# =====================================================
@st.dialog(" ", width="large", dismissible=False)
def forensic_popup(parquet_root, mac, ip, available_dates_list):
    hide_dialog_header()
    inject_page_css()

    h1, h2 = st.columns([0.82, 0.18], vertical_alignment="center")
    with h1:
        st.markdown(
            f"""
            <div class='dialog-head'>
              <div class='dialog-title'>Forensics</div>
              <div class='dialog-sub'><b>MAC:</b> {mac} &nbsp; | &nbsp; <b>IP:</b> {ip}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with h2:
        if st.button("Close", key="dlg_forensics_close", width="stretch"):
            _close_dialog()

    if not available_dates_list:
        st.warning("No dates available for analysis.")
        return

    st.markdown("<div class='dialog-toolbar'>", unsafe_allow_html=True)
    col_time, col_service, col_date = st.columns([1.35, 2.25, 2.40], vertical_alignment="bottom")

    with col_time:
        forensic_mode = st.selectbox(
            "Time Range:",
            ["Last 7 Days", "Last 30 Days", "Specific Date", "All Time"],
            index=0,
            key="popup_forensic_mode",
        )

    with col_service:
        f_service = st.radio(
            "Filter Service:",
            ["All Services", "DNS", "HTTP", "SSL"],
            horizontal=True,
            key="popup_forensic_service",
        )

    f_date = "All Dates"
    selected_dates_tuple = None

    with col_date:
        if forensic_mode == "Specific Date":
            f_date = st.selectbox("Select Activity Date:", available_dates_list, key="popup_forensic_date")
            selected_dates_tuple = (f_date,)
        else:
            st.markdown("<div style='height: 2.55rem;'></div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    if forensic_mode == "Last 7 Days":
        selected_dates_tuple = tuple(available_dates_list[:7])
        f_date = "All Dates"
    elif forensic_mode == "Last 30 Days":
        selected_dates_tuple = tuple(available_dates_list[:30])
        f_date = "All Dates"
    elif forensic_mode == "All Time":
        selected_dates_tuple = None
        f_date = "All Dates"

    activity_df = get_device_activity(parquet_root, mac, ip, f_date, selected_dates_tuple)
    activity_df = _filter_df_by_time_mode(
        activity_df,
        "ts",
        forensic_mode,
        f_date if forensic_mode == "Specific Date" else None,
    )

    if not activity_df.empty:
        activity_df = activity_df.copy()
        activity_df["ts"] = _coerce_ts_any(activity_df["ts"])
        activity_df = activity_df[activity_df["ts"].notna()]

        if f_service != "All Services":
            activity_df = activity_df[activity_df["Service"] == f_service]

    if activity_df.empty:
        st.warning("No activity logs found for the selected filter.")
        return

    st.markdown("#### Traffic Volume")

    tmp = activity_df.copy()
    tmp["hour"] = tmp["ts"].dt.floor("H")
    counts = tmp.groupby(["hour", "Service"]).size().reset_index(name="Events")

    services = ["DNS", "HTTP", "SSL"]
    color_map = {"DNS": "#F63049", "HTTP": "#00F7FF", "SSL": "#F3AE4B"}

    hour_min = counts["hour"].min()
    hour_max = counts["hour"].max()
    if pd.isna(hour_min) or pd.isna(hour_max):
        st.info("No traffic volume data to chart.")
        return

    if hour_min == hour_max:
        hour_max = hour_min + pd.Timedelta(hours=1)

    all_hours = pd.date_range(start=hour_min, end=hour_max, freq="H")
    full_index = pd.MultiIndex.from_product([all_hours, services], names=["hour", "Service"])
    counts_full = counts.set_index(["hour", "Service"]).reindex(full_index, fill_value=0).reset_index()

    fig = go.Figure()
    for svc in services:
        svc_df = counts_full[counts_full["Service"] == svc]
        fig.add_trace(
            go.Scatter(
                x=svc_df["hour"],
                y=svc_df["Events"],
                mode="lines+markers",
                name=svc,
                stackgroup="one",
                line=dict(color=color_map[svc], width=2),
            )
        )

    fig.update_layout(
        template="plotly_dark",
        height=310,
        margin=dict(l=10, r=10, t=30, b=10),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        xaxis_title=None,
        yaxis_title="Events",
        hovermode="x unified",
    )
    fig.update_yaxes(rangemode="tozero")
    st.markdown("<div class='section-panel'>", unsafe_allow_html=True)
    st.plotly_chart(fig, width="stretch")
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("#### Top Destinations")
    top = activity_df["Destination"].value_counts().head(5).reset_index()
    top.columns = ["Destination", "Count"]
    top.index = top.index + 1
    st.markdown("<div class='grid-card'>", unsafe_allow_html=True)
    st.dataframe(
        top,
        width="stretch",
        height=_table_height_for_rows(len(top), row_px=36, header_px=44, min_px=190, max_px=360),
    )
    st.markdown("</div>", unsafe_allow_html=True)


# =====================================================
# Main Render
# =====================================================
def render(logs_root: Path, authorized_mac_file: Path):
    # --- TOGGLE SWITCH ---
    # Set to True to use the hardcoded animation, False to use the execution trace
    USE_HARDCODED_LOADING_UI = True 
    
    # session state
    if "active_dialog" not in st.session_state:
        st.session_state.active_dialog = None
    if "list_status_type" not in st.session_state:
        st.session_state.list_status_type = "Unauthorized"
    if "selected_forensic_mac" not in st.session_state:
        st.session_state.selected_forensic_mac = None
    if "selected_forensic_ip" not in st.session_state:
        st.session_state.selected_forensic_ip = None
    if "prev_dialog" not in st.session_state:
        st.session_state.prev_dialog = None
    if "devices_grid_nonce" not in st.session_state:
        st.session_state.devices_grid_nonce = 0
    if "devices_last_selection_key" not in st.session_state:
        st.session_state.devices_last_selection_key = None

    inject_page_css()
    inject_traffic_style_header_css()
    updated_txt = get_local_now().strftime("%Y-%m-%d %H:%M:%S")
    header_slot = st.empty()
    render_traffic_style_header(
        title="Device Overview",
        subtitle="Network inventory and activity",
        chip_label="Preparing telemetry...",
        updated_txt=updated_txt,
        container=header_slot,
    )
    
    if "hide_devices_trace" not in st.session_state:
        st.session_state.hide_devices_trace = True

    trace_container = st.empty()
    show_trace = not st.session_state.hide_devices_trace

    if show_trace:
        trace_box = trace_container.container()
        loading_slot = trace_box.empty()
    else:
        loading_slot = None
        trace_box = None

    upstream_trace = st.session_state.get("app_load_trace", [])

    local_processes = [
        {"name": "Validating signatures & loading auth rules", "status": "pending", "duration": 0.0},
        {"name": "Resolving latest alert inventory", "status": "pending", "duration": 0.0},
        {"name": "Extracting historical device timelines", "status": "pending", "duration": 0.0},
        {"name": "Merging visual metrics & DHCP contexts", "status": "pending", "duration": 0.0},
        {"name": "Aggregating hourly trust status", "status": "pending", "duration": 0.0},
    ]

    def update_loading_ui(complete=False):
        # Abort the trace UI if we are using the hardcoded UI
        if USE_HARDCODED_LOADING_UI or not show_trace or loading_slot is None:
            return
        
        html_parts = [
            "<div class='dashboard-loading-shell' style='margin-bottom: 8px;'>",
            "  <div class='dashboard-loading-kicker'>Execution Trace</div>",
            "  <div class='dashboard-loading-title'>Initializing Device Inspection</div>",
            "  <div class='dashboard-loading-copy'>Tracking real-time data ingestion and processing...</div>",
            "  <div class='dashboard-loading-steps' style='display: flex; flex-direction: column; gap: 8px; margin-top: 16px;'>"
        ]

        if upstream_trace:
            html_parts.append("    <div style='font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 800; color: rgba(255,255,255,0.5); margin-top: 4px; margin-bottom: -2px; padding-left: 4px;'>Initial Load:</div>")
            for p in upstream_trace:
                icon = "✅"
                time_str = f"{p.get('duration', 0.0):.2f}s"
                bg = "rgba(46, 204, 113, 0.08)"
                border = "rgba(46, 204, 113, 0.3)"
                color = "#2ecc71"
                html_parts.append(
                    f"    <div class='dashboard-loading-step' style='width: 100%; display: flex; justify-content: space-between; background: {bg}; border: 1px solid {border}; border-radius: 8px; color: {color}; padding: 8px 14px;'>"
                )
                html_parts.append(f"        <span style='font-weight: 700;'>{icon} &nbsp;{p.get('name', 'Task')}</span>")
                html_parts.append(f"        <span style='font-family: monospace; font-size: 0.85rem; opacity: 0.9;'>{time_str}</span>")
                html_parts.append("    </div>")

        html_parts.append("    <div style='font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 800; color: rgba(255,255,255,0.5); margin-top: 10px; margin-bottom: -2px; padding-left: 4px;'>Device Inspection Load:</div>")
        
        for p in local_processes:
            if p["status"] == "pending":
                icon = "⏳"
                time_str = "Waiting..."
                bg = "rgba(255,255,255,0.02)"
                border = "rgba(255,255,255,0.05)"
                color = "rgba(255,255,255,0.4)"
            elif p["status"] == "running":
                icon = "🔄"
                time_str = "Processing..."
                bg = "rgba(0, 247, 255, 0.08)"
                border = "rgba(0, 247, 255, 0.3)"
                color = "#00F7FF"
            else:
                icon = "✅"
                time_str = f"{p['duration']:.2f}s"
                bg = "rgba(46, 204, 113, 0.08)"
                border = "rgba(46, 204, 113, 0.3)"
                color = "#2ecc71"

            html_parts.append(
                f"    <div class='dashboard-loading-step' style='width: 100%; display: flex; justify-content: space-between; background: {bg}; border: 1px solid {border}; border-radius: 8px; color: {color}; padding: 8px 14px;'>"
            )
            html_parts.append(f"        <span style='font-weight: 700;'>{icon} &nbsp;{p['name']}</span>")
            html_parts.append(f"        <span style='font-family: monospace; font-size: 0.85rem; opacity: 0.9;'>{time_str}</span>")
            html_parts.append(f"    </div>")

        html_parts.append("  </div>")
        if not complete:
            html_parts.append("  <div class='dashboard-loading-bars' style='margin-top: 18px;'>")
            html_parts.append("      <div class='dashboard-loading-bar' style='--delay:0s'></div>")
            html_parts.append("      <div class='dashboard-loading-bar' style='--delay:0.15s'></div>")
            html_parts.append("      <div class='dashboard-loading-bar' style='--delay:0.3s'></div>")
            html_parts.append("  </div>")
        
        html_parts.append("</div>")
        loading_slot.markdown("".join(html_parts), unsafe_allow_html=True)

    # --- Conditional Loader Wrapper ---
    @contextlib.contextmanager
    def device_loading_wrapper():
        if USE_HARDCODED_LOADING_UI:
            with dashboard_loading_ui(
                title="Loading Device Inspection",
                subtitle="Preparing device inventory, trust posture, and activity context for the latest telemetry.",
                steps=["Read inventory", "Merge trust state", "Render overview"],
                container=trace_container,
            ):
                yield
        else:
            yield

    # Wrap the heavy steps so the loader stays active until they finish
    with device_loading_wrapper():
        # --- Step 1: Signatures & Auth Rules ---
        local_processes[0]["status"] = "running"
        update_loading_ui()
        t0 = time.time()
    PARQUET_ROOT = Path(logs_root)
    inventory_sig = _inventory_file_signature(PARQUET_ROOT)
    alerts_cache_sig = _alerts_event_cache_signature(PARQUET_ROOT)
    alerts_source_sig = _alerts_source_signature(PARQUET_ROOT)
    
    authorized_macs, authorized_added_at_map = load_authorized_macs_with_history(
        authorized_mac_file, authorized_mac_file
    )
    authorized_device_details = load_authorized_device_records(authorized_mac_file)
    auth_change_history_df = load_device_change_history(authorized_mac_file)

    BAN_FILE = authorized_mac_file.with_name("banned_macs.yaml")
    banned_macs = load_banned_macs(BAN_FILE)

    intersect = banned_macs.intersection(authorized_macs)
    if intersect:
        banned_macs = banned_macs - intersect
        save_banned_macs(BAN_FILE, banned_macs)
    local_processes[0]["duration"] = time.time() - t0
    local_processes[0]["status"] = "done"

    # --- Step 2: Alert Inventory Resolution ---
    local_processes[1]["status"] = "running"
    update_loading_ui()
    t0 = time.time()
    # CHANGED: Removed alerts_source_sig to prevent useless cache busting
    alerts_latest_rows = load_alerts_latest_inventory_rows(PARQUET_ROOT, alerts_cache_sig)
    local_processes[1]["duration"] = time.time() - t0
    local_processes[1]["status"] = "done"

    # --- Step 3: Historical Inventory Extract ---
    local_processes[2]["status"] = "running"
    update_loading_ui()
    t0 = time.time()
    # CHANGED: Removed inventory_sig to prevent useless cache busting
    inventory_history_rows = load_device_inventory_history_rows(PARQUET_ROOT, alerts_cache_sig)
    local_processes[2]["duration"] = time.time() - t0
    local_processes[2]["status"] = "done"

    # --- Step 4: Visual Metrics & DHCP ---
    local_processes[3]["status"] = "running"
    update_loading_ui()
    t0 = time.time()
    known_hosts = pd.DataFrame(columns=["mac", "host", "ts"])
    dhcp = pd.DataFrame()
    if alerts_latest_rows.empty:
        known_hosts, dhcp = load_visual_metrics_from_parquet(PARQUET_ROOT, inventory_sig)
    else:
        dhcp = load_dhcp_from_parquet(PARQUET_ROOT, inventory_sig)
    local_processes[3]["duration"] = time.time() - t0
    local_processes[3]["status"] = "done"

    # --- Step 5: Hourly Aggregation ---
    local_processes[4]["status"] = "running"
    update_loading_ui()
    t0 = time.time()
    hourly = load_hourly_status_from_alert_cache(
        PARQUET_ROOT,
        alerts_cache_sig,
        tuple(sorted(authorized_macs)),
        tuple(sorted(banned_macs)),
    )
    local_processes[4]["duration"] = time.time() - t0
    local_processes[4]["status"] = "done"

    # Finalize UI and lock it in place
    update_loading_ui(complete=True)

    # Make sure the close trace button only shows if we are actually using the trace
    if not USE_HARDCODED_LOADING_UI and show_trace and trace_box:
        def close_trace():
            st.session_state.hide_devices_trace = True
        trace_box.button("Close Execution Trace", key="close_devices_trace_btn", on_click=close_trace)

    if "mac" in known_hosts.columns:
        known_hosts = known_hosts.copy()
        known_hosts["mac"] = known_hosts["mac"].map(normalize_mac)
        known_hosts = known_hosts.dropna(subset=["mac"])
        known_hosts = known_hosts[~known_hosts["mac"].map(is_broadcast_mac)]
    else:
        # FIX: Preserve IP and timestamp data, just insert an empty MAC column
        known_hosts = known_hosts.copy()
        known_hosts["mac"] = pd.NA

    if "host" not in known_hosts.columns:
        known_hosts["host"] = "-"
    else:
        known_hosts["host"] = known_hosts["host"].astype("string").fillna("-")

    if "ts" in known_hosts.columns:
        known_hosts["ts"] = _coerce_ts_any(known_hosts["ts"])
    else:
        known_hosts["ts"] = pd.NaT

    # Supplement inventory with Alerts latest-per-MAC rows.
    if not alerts_latest_rows.empty:
        latest_rows = alerts_latest_rows[["mac", "host", "ts"]].copy()
        if known_hosts.empty:
            known_hosts = latest_rows
        else:
            known_hosts = pd.concat(
                [known_hosts, latest_rows],
                ignore_index=True,
                sort=False,
            )

    # --- ADD THIS FALLBACK BLOCK ---
    if known_hosts.empty and not dhcp.empty:
        # Emergency fallback: construct known_hosts from DHCP data
        known_hosts = dhcp[["mac", "client_addr"]].copy()
        known_hosts.rename(columns={"client_addr": "host"}, inplace=True)
        # Apply the local timezone function you already have in devices.py
        known_hosts["ts"] = get_local_now()
    # -------------------------------

    if known_hosts.empty:
        render_traffic_style_header(
            title="Device Overview",
            subtitle="Network inventory and activity",
            chip_label="No telemetry",
            updated_txt=updated_txt,
            container=header_slot,
        )
        st.info("No device data available")
        return

    # Merge DHCP
    if not dhcp.empty:
        if "mac" in dhcp.columns:
            dhcp = dhcp.copy()
            dhcp["mac"] = dhcp["mac"].map(normalize_mac)
            dhcp = dhcp.dropna(subset=["mac"])
            dhcp = dhcp[~dhcp["mac"].map(is_broadcast_mac)]
            
            # FIX: If known_hosts lacks MACs, use the IP (host) to pull MACs from DHCP
            if known_hosts["mac"].isna().all() and "client_addr" in dhcp.columns:
                dhcp_cols = [c for c in ["mac", "client_addr", "host_name", "domain"] if c in dhcp.columns]
                dhcp_norm = dhcp[dhcp_cols].drop_duplicates(subset=["client_addr"])
                merged = pd.merge(known_hosts.drop(columns=["mac"]), dhcp_norm, how="left", left_on="host", right_on="client_addr")
            else:
                dhcp_cols = [c for c in ["mac", "host_name", "domain"] if c in dhcp.columns]
                dhcp_norm = dhcp[dhcp_cols].drop_duplicates(subset=["mac"])
                merged = pd.merge(known_hosts, dhcp_norm, how="left", on="mac")
        else:
            dhcp_cols = [c for c in ["client_addr", "host_name", "domain"] if c in dhcp.columns]
            dhcp_norm = dhcp[dhcp_cols].drop_duplicates(subset=["client_addr"])
            merged = pd.merge(known_hosts, dhcp_norm, how="left", left_on="host", right_on="client_addr")
    else:
        merged = known_hosts.copy()
        merged["host_name"] = "-"
        merged["domain"] = None

    merged["host_name"] = merged.get("host_name", "-").fillna("-")

    if "ts" in merged.columns:
        merged = merged.copy()
        merged["ts"] = _coerce_ts_any(merged["ts"])
        merged = merged.dropna(subset=["ts"])
        merged["date"] = merged["ts"].dt.date

    merged["status"] = merged["mac"].apply(lambda m: "Authorized" if (m in authorized_macs) else "Unauthorized")

    in_scope = merged.copy()
    if "mac" in in_scope.columns and banned_macs:
        in_scope = in_scope[~in_scope["mac"].isin(banned_macs)]

    # Keep Device cards/list aligned with Alerts inventory basis (latest per MAC).
    inventory_scope = pd.DataFrame(columns=["mac", "host", "host_name", "ts", "status"])
    if not alerts_latest_rows.empty:
        inventory_scope = alerts_latest_rows.copy()
        inventory_scope["mac"] = inventory_scope["mac"].map(normalize_mac)
        inventory_scope = inventory_scope.dropna(subset=["mac"])
        inventory_scope = inventory_scope[~inventory_scope["mac"].map(is_broadcast_mac)]
        host_series = inventory_scope.get("host", pd.Series("-", index=inventory_scope.index, dtype="object"))
        inventory_scope["host"] = host_series.astype("string").fillna("-")
        inventory_scope["host_name"] = "-"
        inventory_scope["ts"] = _coerce_ts_any(
            inventory_scope.get("ts", pd.Series(index=inventory_scope.index, dtype="object"))
        )
        inventory_scope = inventory_scope.dropna(subset=["ts"])
        inventory_scope["status"] = inventory_scope["mac"].apply(
            lambda m: "Authorized" if (m in authorized_macs) else "Unauthorized"
        )

    if inventory_scope.empty:
        inventory_scope = (
            in_scope.sort_values("ts", ascending=False)
            .drop_duplicates(subset=["mac"], keep="first")
            .copy()
        )

    if "mac" in inventory_scope.columns and banned_macs:
        inventory_scope = inventory_scope[~inventory_scope["mac"].isin(banned_macs)].copy()

    # Event-level scope for accurate time-range filtering in Device list dialogs.
    popup_inventory_scope = inventory_history_rows.copy()
    if popup_inventory_scope.empty:
        popup_inventory_scope = in_scope.copy()
    if "host_name" not in popup_inventory_scope.columns:
        popup_inventory_scope["host_name"] = "-"
    popup_inventory_scope["ts"] = _coerce_ts_any(
        popup_inventory_scope.get("ts", pd.Series(index=popup_inventory_scope.index, dtype="object"))
    )
    popup_inventory_scope = popup_inventory_scope.dropna(subset=["mac", "ts"])
    popup_inventory_scope["status"] = popup_inventory_scope["mac"].apply(
        lambda m: "Authorized" if (m in authorized_macs) else "Unauthorized"
    )
    if "mac" in popup_inventory_scope.columns and banned_macs:
        popup_inventory_scope = popup_inventory_scope[~popup_inventory_scope["mac"].isin(banned_macs)].copy()

    # Fill host names for inventory list from DHCP-enriched merge.
    if "host_name" not in inventory_scope.columns:
        inventory_scope["host_name"] = "-"
    if not merged.empty and "host_name" in merged.columns and "mac" in merged.columns:
        host_map = (
            merged.sort_values("ts", ascending=False)
            .drop_duplicates(subset=["mac"], keep="first")[["mac", "host_name"]]
            .copy()
        )
        inventory_scope = inventory_scope.merge(host_map, how="left", on="mac", suffixes=("", "_merged"))
        if "host_name_merged" in inventory_scope.columns:
            base_host = _clean_text_series(inventory_scope.get("host_name"), inventory_scope.index)
            merged_host = _clean_text_series(inventory_scope.get("host_name_merged"), inventory_scope.index)
            inventory_scope["host_name"] = base_host.where(base_host.notna(), merged_host).fillna("-")
            inventory_scope = inventory_scope.drop(columns=["host_name_merged"], errors="ignore")
    if authorized_device_details and not inventory_scope.empty:
        auth_meta_df = pd.DataFrame(
            [
                {
                    "mac": mac,
                    "auth_ip": detail.get("ip", ""),
                    "auth_host_name": detail.get("host_name", ""),
                }
                for mac, detail in authorized_device_details.items()
                if mac
            ]
        )
        if not auth_meta_df.empty:
            inventory_scope = inventory_scope.merge(auth_meta_df, how="left", on="mac")
            base_ip = _clean_text_series(inventory_scope.get("host"), inventory_scope.index)
            auth_ip = _clean_text_series(inventory_scope.get("auth_ip"), inventory_scope.index)
            inventory_scope["host"] = base_ip.where(base_ip.notna(), auth_ip).fillna("-").astype(str)
            base_host = _clean_text_series(inventory_scope.get("host_name"), inventory_scope.index)
            auth_host = _clean_text_series(inventory_scope.get("auth_host_name"), inventory_scope.index)
            inventory_scope["host_name"] = base_host.where(base_host.notna(), auth_host).fillna("-").astype(str)
            inventory_scope = inventory_scope.drop(columns=["auth_ip", "auth_host_name"], errors="ignore")

    # Metrics
    today = get_local_now().date()
    today_str = today.strftime("%Y-%m-%d")
    active_day_str, active_known_hosts_sig = _resolve_active_devices_day(PARQUET_ROOT, today_str)

    unauth_seen = int(inventory_scope[inventory_scope["status"] == "Unauthorized"]["mac"].nunique())
    auth_seen_inventory = int(inventory_scope[inventory_scope["status"] == "Authorized"]["mac"].nunique())
    auth_configured = int(len({m for m in authorized_macs if m}))
    total_devices = auth_seen_inventory + unauth_seen

    active_today_set = set()
    if active_day_str:
        active_today_set = load_active_today_macs_from_parquet(
            PARQUET_ROOT,
            active_day_str,
            active_known_hosts_sig,
        )
    if banned_macs:
        active_today_set = active_today_set - set(banned_macs)
    active_today = int(len(active_today_set))

    risk = round((unauth_seen / total_devices * 100), 2) if total_devices else 0.0

    store = load_metrics_store(authorized_mac_file)
    if not isinstance(store, dict):
        store = {}

    if store.get("daily_date") != today_str or not isinstance(store.get("daily_baseline"), dict):
        store["daily_date"] = today_str
        store["daily_baseline"] = {
            "total": total_devices,
            "active_today": active_today,
            "auth": auth_configured,
            "unauth": unauth_seen,
            "risk": float(risk),
        }
        store["daily_delta"] = {"total": 0, "active_today": 0, "auth": 0, "unauth": 0, "risk": 0.0}
        store["daily_locked"] = False

    baseline = (
        store.get("daily_baseline")
        if isinstance(store.get("daily_baseline"), dict)
        else {
            "total": total_devices,
            "active_today": active_today,
            "auth": auth_configured,
            "unauth": unauth_seen,
            "risk": float(risk),
        }
    )

    b_total = int(baseline.get("total", total_devices))
    b_active = int(baseline.get("active_today", active_today))
    b_auth = int(baseline.get("auth", auth_configured))
    b_unauth = int(baseline.get("unauth", unauth_seen))
    b_risk = float(baseline.get("risk", float(risk)))

    daily_delta = {
        "total": total_devices - b_total,
        "active_today": active_today - b_active,
        "auth": auth_configured - b_auth,
        "unauth": unauth_seen - b_unauth,
        "risk": round(risk - b_risk, 2),
    }

    store["daily_delta"] = daily_delta
    store["state"] = {
        "total": total_devices,
        "active_today": active_today,
        "auth": auth_configured,
        "unauth": unauth_seen,
        "risk": float(risk),
    }
    save_metrics_store(authorized_mac_file, store)

    d_total = int(daily_delta.get("total", 0))
    d_active = int(daily_delta.get("active_today", 0))
    d_auth = int(daily_delta.get("auth", 0))
    d_unauth = int(daily_delta.get("unauth", 0))
    d_risk = float(daily_delta.get("risk", 0.0))

    RED = "#F63049"
    GREEN = "#2ecc71"
    GREY = "#9aa0a6"
    CYAN = "#00F7FF"

    risk_state = "Healthy" if risk <= 20 else ("Warning" if risk <= 50 else "High Risk")
    render_traffic_style_header(
        title="Device Overview",
        subtitle="Network inventory and activity",
        chip_label=f"Risk posture: {risk_state}",
        updated_txt=updated_txt,
        container=header_slot,
    )
    inject_metric_card_css()

    m1, m2, m3, m4, m5 = st.columns(5)

    with m1:
        render_metric_card_static("Total Devices", total_devices, d_total, up_color=GREEN, down_color=GREY)

    with m2:
        render_metric_card_dialog(
            "Active Devices",
            active_today,
            d_active,
            open_dialog_name="active_today",
            key="card_open_active",
            up_color=GREEN,
            down_color=GREY,
        )

    with m3:
        clicked = st.button(" ", key="card_open_auth", width="stretch")
        st.markdown(
            f"""
            <div class="metric-overlay">
                <div class="metric-label">Authorized</div>
                <div class="metric-value">{auth_configured}</div>
                {_metric_delta_html(d_auth, delta_is_percent=False, up_color=GREEN, down_color=GREY)}
                <div class="metric-hint">Click to view</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if clicked:
            st.session_state.list_status_type = "Authorized"
            st.session_state.active_dialog = "list"
            st.rerun()

    with m4:
        clicked = st.button(" ", key="card_open_unauth", width="stretch")
        st.markdown(
            f"""
            <div class="metric-overlay">
                <div class="metric-label">Unauthorized</div>
                <div class="metric-value">{unauth_seen}</div>
                {_metric_delta_html(d_unauth, delta_is_percent=False, up_color=RED, down_color=GREY)}
                <div class="metric-hint">Click to view</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if clicked:
            st.session_state.list_status_type = "Unauthorized"
            st.session_state.active_dialog = "list"
            st.rerun()

    with m5:
        render_metric_card_static("Risk Ratio", f"{risk}%", d_risk, delta_is_percent=True, up_color=RED, down_color=GREY)

    if active_day_str and active_day_str != today_str:
        st.caption(f"Active Devices source date: {active_day_str} (latest available known_hosts capture).")

    if hourly.empty and not in_scope.empty:
        hourly = (
            in_scope.set_index("ts")
            .groupby("status")
            .resample("1h", include_groups=False)
            .size()
            .reset_index(name="events")
        )

    warning_text, warning_color = "SAFE", "#6CA651"
    if risk > 20:
        warning_text, warning_color = "WARNING", "#F3AE4B"
    if risk > 50:
        warning_text, warning_color = "HIGH RISK", "#D63447"

    gauge_fig = go.Figure()
    gauge_fig.add_trace(
        go.Indicator(
            mode="gauge+number",
            value=risk,
            number={"suffix": "%", "font": {"size": 48}},
            domain={"x": [0.0, 1.0], "y": [0.2, 1.0]},
            gauge={
                "axis": {"range": [0, 100], "tickfont": {"size": 16}},
                "bar": {"color": "#30C1F6"},
                "steps": [
                    {"range": [0, 20], "color": "#6CA651"},
                    {"range": [20, 50], "color": "#F3AE4B"},
                    {"range": [50, 100], "color": "#D63447"},
                ],
                "threshold": {"line": {"color": "white", "width": 2}, "thickness": 0.75, "value": 50},
            },
        )
    )

    gauge_fig.add_annotation(
        x=0.5,
        y=0.06,
        xref="paper",
        yref="paper",
        text=f"<b>STATUS: {warning_text}</b>",
        showarrow=False,
        font=dict(size=13, color=warning_color),
        xanchor="center",
        yanchor="middle",
    )

    gauge_fig.update_layout(
        template="plotly_dark",
        height=390,
        margin=dict(l=36, r=36, t=56, b=78),
        showlegend=False,
        xaxis={"visible": False},
        yaxis={"visible": False},
    )

    st.markdown("<div class='section-gap'></div>", unsafe_allow_html=True)
    left_col, right_col = st.columns([1.7, 1.15], gap="large")

    with left_col:
        st.markdown("<div class='section-title'>Activity Overview</div>", unsafe_allow_html=True)
        st.markdown(
            "<div class='section-subtitle'>Hourly traffic trend split by authorization state.</div>",
            unsafe_allow_html=True,
        )
        st.markdown("<div class='section-panel'>", unsafe_allow_html=True)
        if not hourly.empty:
            fig = px.line(
                hourly,
                x="ts",
                y="events",
                color="status",
                template="plotly_dark",
                color_discrete_map={"Authorized": CYAN, "Unauthorized": RED},
            )
            fig.update_traces(mode="lines+markers", marker=dict(size=5), line=dict(width=2))
            fig.update_layout(
                height=360,
                margin=dict(l=10, r=10, t=10, b=10),
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                hovermode="x unified",
            )
            fig.update_yaxes(rangemode="tozero", showgrid=True, gridcolor="rgba(255,255,255,0.06)")
            fig.update_xaxes(showgrid=True, gridcolor="rgba(255,255,255,0.06)")
            st.plotly_chart(fig, width="stretch")
        else:
            st.info("No activity data to chart.")
        st.markdown("</div>", unsafe_allow_html=True)

    with right_col:
        st.markdown("<div class='section-title'>Unauthorized Device Ratio</div>", unsafe_allow_html=True)
        st.markdown(
            "<div class='section-subtitle'>Current unauthorized share of all discovered devices.</div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"<div class='status-strip'><b>STATUS: {warning_text}</b><br/>Unauthorized devices: <b>{unauth_seen}</b> of <b>{total_devices}</b>.</div>",
            unsafe_allow_html=True,
        )
        st.markdown("<div class='section-panel'>", unsafe_allow_html=True)
        st.plotly_chart(gauge_fig, width="stretch")
        st.markdown(
            """
            <div class='gauge-legend'>
              <span class='gauge-badge'><span class='gauge-dot' style='background:#30C1F6;'></span>Current</span>
              <span class='gauge-badge'><span class='gauge-dot' style='background:#6CA651;'></span>Safe (0-20%)</span>
              <span class='gauge-badge'><span class='gauge-dot' style='background:#F3AE4B;'></span>Warning (20-50%)</span>
              <span class='gauge-badge'><span class='gauge-dot' style='background:#D63447;'></span>High Risk (50%+)</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)
    
    raw_dates = sorted([d for d, _ in iter_date_dirs(PARQUET_ROOT)], reverse=True)
    if not raw_dates and "date" in merged.columns:
        raw_dates = sorted([str(d) for d in merged["date"].unique() if pd.notnull(d)], reverse=True)

    if st.session_state.active_dialog == "list":
        device_list_popup(
            st.session_state.list_status_type,
            popup_inventory_scope,
            PARQUET_ROOT,
            raw_dates,
            banned_macs,
            authorized_added_at_map,
            auth_change_history_df,
            authorized_device_details,
        )

    elif st.session_state.active_dialog == "active_today":
        active_today_popup(
            in_scope,
            PARQUET_ROOT,
            active_day_str=active_day_str or today_str,
            today_str=today_str,
            available_dates_list=raw_dates,
        )

    elif st.session_state.active_dialog == "forensics":
        forensic_popup(
            PARQUET_ROOT,
            st.session_state.selected_forensic_mac,
            st.session_state.selected_forensic_ip,
            raw_dates,
        )
