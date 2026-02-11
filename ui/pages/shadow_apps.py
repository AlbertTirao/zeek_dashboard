# ui/pages/shadow_app.py
import os
import re
import time
from datetime import datetime as _dt
import numpy as np
import streamlit as st
import pandas as pd
import plotly.express as px
import duckdb
from pathlib import Path
from urllib.parse import urlparse
import yaml

from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode

# =============================================================================
# PERFORMANCE STRATEGY (FAST LOAD)
# =============================================================================

CACHE_VERSION = "shadow-cache-v1"

# -----------------------------
# Config
# -----------------------------
WHITELIST_FILE = Path(__file__).resolve().parents[2] / "whitelist_domains.yaml"
RISK_POLICY_FILE = Path(__file__).resolve().parents[2] / "risk_policy.yaml"
CACHE_DIRNAME = "_shadow_cache"

LICENSE_REGISTRY = {
    "office.com": None,
    "microsoft.com": None,
    "github.com": None,
    "zoom.us": None,
    "slack.com": None,
}

RISK_SCORE = {"Safe": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
SCORE_TO_RISK = {v: k for k, v in RISK_SCORE.items()}


def risk_score(val: str) -> int:
    return int(RISK_SCORE.get(str(val), 0))


def score_to_risk(score: int) -> str:
    return SCORE_TO_RISK.get(int(score), "Safe")


def _mark_dialog_origin():
    """
    One-shot token used to keep the dialog open only on reruns triggered
    from inside the dialog widgets.
    """
    st.session_state["shadow_dialog_origin"] = "dialog"


def risk_multiselect(label: str, key: str, default=None, on_change=None):
    if default is None:
        default = ["Critical", "High", "Medium", "Low"]
    return st.multiselect(
        label,
        ["Critical", "High", "Medium", "Low", "Safe"],
        default=default,
        key=key,
        on_change=on_change,
    )


def _close_shadow_dialog(reset_grid: bool = True):
    st.session_state["shadow_dialog_open"] = False
    st.session_state["shadow_dialog_mac"] = None
    st.session_state["shadow_last_selected_mac"] = None
    st.session_state.pop("shadow_dialog_origin", None)

    if reset_grid:
        st.session_state["shadow_grid_nonce"] = int(st.session_state.get("shadow_grid_nonce", 0)) + 1


# -----------------------------
# Theme helpers
# -----------------------------
def _is_dark_theme() -> bool:
    try:
        base = st.get_option("theme.base")
        if isinstance(base, str) and base.lower() in {"light", "dark"}:
            return base.lower() == "dark"
    except Exception:
        pass
    return True


def get_aggrid_theme_and_css():
    dark = _is_dark_theme()
    theme = "alpine-dark" if dark else "alpine"

    custom_css = {
        ".ag-root-wrapper": {"background-color": "#000000", "color": "#EAEAEA", "border": "1px solid #222222"},
        ".ag-header": {"background-color": "#0B0B0B", "color": "#FFFFFF", "border-bottom": "1px solid #222222"},
        ".ag-header-cell, .ag-header-group-cell": {
            "background-color": "#0B0B0B",
            "color": "#FFFFFF",
            "border-right": "1px solid #1E1E1E",
        },
        ".ag-cell": {"background-color": "#000000", "color": "#EAEAEA", "border-color": "#1A1A1A"},
        ".ag-row": {"background-color": "#000000"},
        ".ag-row-hover": {"background-color": "#111111"},
        ".ag-row-selected": {"background-color": "#1F2937"},
        ".ag-paging-panel": {"background-color": "#000000", "color": "#EAEAEA", "border-top": "1px solid #222222"},
        ".ag-paging-row-summary-panel": {"background-color": "#000000", "color": "#EAEAEA"},
        ".ag-paging-page-summary-panel": {"background-color": "#000000", "color": "#EAEAEA"},
        ".ag-pagination": {"background-color": "#000000", "color": "#EAEAEA"},
        ".ag-paging-page-size": {"background-color": "#000000 !important", "color": "#EAEAEA !important"},
        ".ag-paging-panel .ag-page-size": {
            "background-color": "#000000 !important",
            "color": "#EAEAEA !important",
            "border": "1px solid #333333 !important",
            "outline": "none !important",
        },
        ".ag-paging-panel .ag-page-size option": {"background-color": "#000000 !important", "color": "#EAEAEA !important"},
        ".ag-paging-panel .ag-select, .ag-paging-panel .ag-picker-field-wrapper": {
            "background-color": "#000000 !important",
            "color": "#EAEAEA !important",
            "border": "1px solid #333333 !important",
        },
        ".ag-paging-panel .ag-picker-field-display": {"background-color": "#000000 !important", "color": "#EAEAEA !important"},
    }
    return theme, custom_css


# -----------------------------
# DuckDB connection
# -----------------------------
@st.cache_resource
def get_db_connection():
    conn = duckdb.connect(database=":memory:")
    try:
        conn.execute("SET memory_limit='4GB'")
    except Exception:
        pass
    try:
        conn.execute("SET threads TO 4")
    except Exception:
        pass
    try:
        conn.execute("PRAGMA enable_object_cache")
    except Exception:
        pass
    try:
        conn.execute("PRAGMA enable_progress_bar=false")
    except Exception:
        pass
    return conn


LOG_TYPES = ["http", "ssl", "dns", "files", "conn", "software", "weird", "notice"]


@st.cache_data(show_spinner=False)
def list_available_dates(parquet_root: Path):
    """
    Only return real day folders (YYYY-MM-DD) and EXCLUDE _shadow_cache.
    """
    if not parquet_root.exists():
        return []

    out = []
    for d in parquet_root.iterdir():
        if not d.is_dir():
            continue
        if d.name == CACHE_DIRNAME:
            continue
        try:
            _dt.strptime(d.name, "%Y-%m-%d")
            out.append(d.name)
        except ValueError:
            continue

    return sorted(out, reverse=True)


@st.cache_data(show_spinner=False)
def collect_parquet_files(parquet_root: Path, target_dates: tuple):
    dhcp_files = []
    log_files = []
    for d in target_dates:
        d_path = parquet_root / d
        if not d_path.exists():
            continue

        dhcp_p = d_path / "dhcp.parquet"
        if dhcp_p.exists():
            dhcp_files.append(str(dhcp_p))

        for l in LOG_TYPES:
            l_path = d_path / f"{l}.parquet"
            if l_path.exists():
                log_files.append(str(l_path))

    return dhcp_files, log_files


def _stat_sig(path: Path):
    try:
        st_ = path.stat()
        return int(st_.st_mtime), int(st_.st_size)
    except Exception:
        return 0, 0


def _paths_max_mtime(paths: list[str]) -> int:
    m = 0
    for p in paths:
        try:
            m = max(m, int(os.path.getmtime(p)))
        except Exception:
            pass
    return m


def cache_dir(parquet_root: Path) -> Path:
    return parquet_root / CACHE_DIRNAME


def cache_events_path(parquet_root: Path, date_str: str) -> Path:
    return cache_dir(parquet_root) / f"date={date_str}" / "shadow_events.parquet"


def cache_meta_path(parquet_root: Path, date_str: str) -> Path:
    return cache_dir(parquet_root) / f"date={date_str}" / "meta.yaml"


def read_yaml(path: Path):
    try:
        if not path.exists():
            return {}
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def write_yaml(path: Path, data: dict):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, sort_keys=False)
    except Exception:
        pass


def whitelist_state():
    m, s = _stat_sig(WHITELIST_FILE)
    return {"whitelist_mtime": m, "whitelist_size": s}


def risk_policy_state():
    m, s = _stat_sig(RISK_POLICY_FILE)
    return {"risk_policy_mtime": m, "risk_policy_size": s}


def extract_domain(url: str):
    if not url:
        return ""
    url = str(url).strip().lower()
    if url in ["nan", "none", "", "unknown"] or pd.isna(url):
        return ""
    if "://" in url:
        try:
            url = urlparse(url).hostname or ""
        except Exception:
            pass
    if url.startswith("www."):
        url = url[4:]
    return url.split(":")[0].rstrip(".")


def load_allowlist():
    if not WHITELIST_FILE.exists():
        return []
    approved = set()
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if data is None:
                return []

            raw_list = []
            if isinstance(data, list):
                raw_list = data
            elif isinstance(data, dict):
                target_key = WHITELIST_FILE.stem
                if target_key in data and isinstance(data[target_key], list):
                    raw_list = data[target_key]
                else:
                    for val in data.values():
                        if isinstance(val, list):
                            raw_list = val
                            break

            for item in raw_list:
                domain = extract_domain(str(item))
                if domain:
                    approved.add(domain)
    except Exception:
        pass
    return sorted(list(approved))


def compile_allow_regex(approved: list[str]):
    if not approved:
        return None
    safe = []
    for d in approved:
        d = extract_domain(d)
        if d:
            safe.append(re.escape(d))
    if not safe:
        return None
    pattern = r"(?:^|\.)(%s)$" % "|".join(sorted(set(safe), key=len, reverse=True))
    try:
        return re.compile(pattern, flags=re.IGNORECASE)
    except Exception:
        return None


def load_risk_policy():
    if not RISK_POLICY_FILE.exists():
        return {}
    try:
        with open(RISK_POLICY_FILE, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def query_shadow_logs_raw(_conn, dhcp_files: list[str], log_files: list[str]) -> pd.DataFrame:
    if not log_files:
        return pd.DataFrame()

    # DHCP view
    if dhcp_files:
        try:
            _conn.execute(
                "CREATE OR REPLACE VIEW raw_dhcp_files AS "
                f"SELECT * FROM read_parquet({dhcp_files}, union_by_name=True)"
            )
            dhcp_cols = [r[0] for r in _conn.execute("DESCRIBE raw_dhcp_files").fetchall()]
            dhcp_ip = next((c for c in ["client_addr", "assigned_addr", "requested_addr", "ip"] if c in dhcp_cols), None)
            dhcp_mac = next((c for c in ["mac", "client_chaddr", "hardware_address"] if c in dhcp_cols), None)

            if dhcp_ip and dhcp_mac:
                _conn.execute(
                    f"""
                    CREATE OR REPLACE VIEW v_dhcp AS
                    SELECT DISTINCT
                        "{dhcp_ip}" as ip_addr,
                        "{dhcp_mac}" as mac_addr
                    FROM raw_dhcp_files
                    WHERE "{dhcp_ip}" IS NOT NULL AND "{dhcp_mac}" IS NOT NULL
                    """
                )
            else:
                _conn.execute("CREATE OR REPLACE VIEW v_dhcp AS SELECT '0.0.0.0' as ip_addr, 'Unknown' as mac_addr")
        except Exception:
            _conn.execute("CREATE OR REPLACE VIEW v_dhcp AS SELECT '0.0.0.0' as ip_addr, 'Unknown' as mac_addr")
    else:
        _conn.execute("CREATE OR REPLACE VIEW v_dhcp AS SELECT '0.0.0.0' as ip_addr, 'Unknown' as mac_addr")

    # logs view
    try:
        _conn.execute(
            "CREATE OR REPLACE VIEW raw_logs AS "
            f"SELECT * FROM read_parquet({log_files}, union_by_name=True, filename='source_file_path')"
        )
        existing_cols = set([r[0] for r in _conn.execute("DESCRIBE raw_logs").fetchall()])

        def get_coalesce(candidates, fallback="'Unknown'"):
            valid = [f'"{c}"' for c in candidates if c in existing_cols]
            return f"COALESCE({', '.join(valid)}, {fallback})" if valid else fallback

        def get_cast_coalesce(candidates, cast_type, fallback="0"):
            valid = [f'try_cast("{c}" as {cast_type})' for c in candidates if c in existing_cols]
            return f"COALESCE({', '.join(valid)}, {fallback})" if valid else fallback

        sql_ip = get_coalesce(["id.orig_h", "orig_h", "src_ip", "ip"], "'0.0.0.0'")
        sql_mac = get_coalesce(["mac", "orig_mac", "id.orig_mac", "src_mac"], "NULL")
        sql_port = get_cast_coalesce(["id.resp_p", "dst_port", "resp_p"], "INT")
        sql_sent = get_cast_coalesce(["orig_bytes", "id.orig_bytes"], "BIGINT")
        sql_recv = get_cast_coalesce(["resp_bytes", "id.resp_bytes"], "BIGINT")
        sql_app = get_coalesce(
            ["host", "server_name", "query", "filename", "service", "unparsed_version", "name", "note"],
            "'-'",
        )

        info_parts = []
        if "method" in existing_cols and "uri" in existing_cols:
            info_parts.append("concat(method, ' ', uri)")
        if "mime_type" in existing_cols:
            info_parts.append("mime_type")
        if "addl" in existing_cols:
            info_parts.append("addl")
        if "msg" in existing_cols:
            info_parts.append("msg")
        if "proto" in existing_cols and "id.resp_p" in existing_cols:
            info_parts.append('concat(proto, \'/\', "id.resp_p")')
        sql_info = f"COALESCE({', '.join(info_parts)}, '-')" if info_parts else "'-'"

        query = f"""
        SELECT
            try_cast(ts as DOUBLE) as ts,
            {sql_ip} as ip,
            COALESCE({sql_mac}, d.mac_addr, 'Unknown') as mac,
            {sql_port} as dst_port,
            {sql_sent} as bytes_sent,
            {sql_recv} as bytes_received,
            {sql_app} as app_identifier,
            {sql_info} as Info,
            upper(regexp_extract(source_file_path, '([a-z]+)\\.parquet', 1)) as source_log
        FROM raw_logs r
        LEFT JOIN v_dhcp d ON {sql_ip} = d.ip_addr
        """
        return _conn.execute(query).df()
    except Exception:
        return pd.DataFrame()


def cache_is_fresh(parquet_root: Path, date_str: str, sources_max_mtime: int) -> bool:
    meta = read_yaml(cache_meta_path(parquet_root, date_str))
    if not meta:
        return False
    if not cache_events_path(parquet_root, date_str).exists():
        return False
    if meta.get("cache_version") != CACHE_VERSION:
        return False
    if int(meta.get("sources_max_mtime", 0)) != int(sources_max_mtime):
        return False

    ws = whitelist_state()
    rs = risk_policy_state()
    if int(meta.get("whitelist_mtime", 0)) != int(ws["whitelist_mtime"]):
        return False
    if int(meta.get("risk_policy_mtime", 0)) != int(rs["risk_policy_mtime"]):
        return False
    return True


def vectorized_behavior(df: pd.DataFrame) -> pd.Series:
    sent = pd.to_numeric(df["bytes_sent"], errors="coerce").fillna(0).astype("int64")
    recv = pd.to_numeric(df["bytes_received"], errors="coerce").fillna(0).astype("int64")
    slog = df["source_log"].astype(str).str.upper()
    conds = [sent > 10_000_000, recv > 100_000_000, slog.eq("WEIRD")]
    choices = ["Potential Exfiltration", "Heavy Download", "Protocol Anomaly"]
    return pd.Series(np.select(conds, choices, default="Standard Traffic"), index=df.index)


def vectorized_risk(df: pd.DataFrame, policy: dict):
    score = pd.Series(-1, index=df.index, dtype="int16")
    basis = pd.Series("", index=df.index, dtype="object")

    port = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0).astype("int64")
    slog = df["source_log"].astype(str).str.upper()
    status = df["App Status"].astype(str)
    behavior = df["Behavior"].astype(str)

    m = behavior.eq("Potential Exfiltration") & score.eq(-1)
    score[m] = 4
    basis[m] = "Behavior: Potential Exfiltration (bytes_sent threshold)"

    m = behavior.eq("Protocol Anomaly") & score.eq(-1)
    score[m] = 3
    basis[m] = "Behavior: Protocol Anomaly (WEIRD log)"

    m = behavior.eq("Heavy Download") & score.eq(-1)
    score[m] = 2
    basis[m] = "Behavior: Heavy Download (bytes_received threshold)"

    def _logs(level: str):
        return set(str(x).upper() for x in (policy.get(level, {}).get("source_logs", []) or []))

    def _ports(level: str):
        out = set()
        for p in (policy.get(level, {}).get("ports", []) or []):
            try:
                out.add(int(p))
            except Exception:
                pass
        return out

    crit_logs, crit_ports = _logs("critical"), _ports("critical")
    high_logs, high_ports = _logs("high"), _ports("high")
    med_logs, med_ports = _logs("medium"), _ports("medium")

    if crit_logs:
        m = slog.isin(crit_logs) & score.eq(-1)
        score[m] = 4
        basis[m] = "Policy: critical.source_logs matched (" + slog[m] + ")"
    if crit_ports:
        m = port.isin(crit_ports) & score.eq(-1)
        score[m] = 4
        basis[m] = "Policy: critical.ports matched (" + port[m].astype(str) + ")"

    if high_logs:
        m = slog.isin(high_logs) & score.eq(-1)
        score[m] = 3
        basis[m] = "Policy: high.source_logs matched (" + slog[m] + ")"
    if high_ports:
        m = port.isin(high_ports) & score.eq(-1)
        score[m] = 3
        basis[m] = "Policy: high.ports matched (" + port[m].astype(str) + ")"

    if med_logs:
        m = slog.isin(med_logs) & score.eq(-1)
        score[m] = 2
        basis[m] = "Policy: medium.source_logs matched (" + slog[m] + ")"
    if med_ports:
        m = port.isin(med_ports) & score.eq(-1)
        score[m] = 2
        basis[m] = "Policy: medium.ports matched (" + port[m].astype(str) + ")"

    low_statuses = set(policy.get("low", {}).get("app_status", []) or [])
    if low_statuses:
        m = status.isin(low_statuses) & score.eq(-1)
        score[m] = 1
        basis[m] = "Policy: low.app_status matched (" + status[m].astype(str) + ")"

    default_str = str(policy.get("default", "Safe")) if policy else "Safe"
    default_score = int(RISK_SCORE.get(default_str, 0))
    m = score.eq(-1)
    score[m] = default_score
    basis[m] = f"Default policy applied ({default_str})" if policy else "No policy loaded (fallback Safe)"

    risk_level = score.map(lambda s: SCORE_TO_RISK.get(int(s), "Safe")).astype(str)
    return risk_level, basis, score.astype("int16")


def build_daily_cache(conn, parquet_root: Path, date_str: str, allow_re, risk_policy: dict):
    dhcp_files, log_files = collect_parquet_files(parquet_root, (date_str,))
    sources = list(dhcp_files) + list(log_files)
    sources_max_mtime = _paths_max_mtime(sources)

    if cache_is_fresh(parquet_root, date_str, sources_max_mtime):
        return

    raw_df = query_shadow_logs_raw(conn, dhcp_files=dhcp_files, log_files=log_files)
    if raw_df is None or raw_df.empty:
        meta = {
            "cache_version": CACHE_VERSION,
            "date": date_str,
            "rows": 0,
            "sources_max_mtime": int(sources_max_mtime),
            **whitelist_state(),
            **risk_policy_state(),
            "built_at": int(time.time()),
            "note": "No events found for this date",
        }
        write_yaml(cache_meta_path(parquet_root, date_str), meta)
        return

    df = raw_df.copy()
    df["datetime"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")
    df = df.dropna(subset=["datetime"])

    df["ip"] = df["ip"].fillna("Unknown").astype(str)
    df["mac"] = df["mac"].fillna("Unknown").astype(str).str.lower()

    df["domain_clean"] = df["app_identifier"].apply(extract_domain)
    mask_empty = df["domain_clean"].eq("") | df["domain_clean"].isna()
    df.loc[mask_empty, "domain_clean"] = df.loc[mask_empty, "app_identifier"].astype(str)
    df["domain_clean"] = df["domain_clean"].fillna("unidentified_activity")

    if allow_re is not None:
        allowed_mask = df["domain_clean"].astype(str).str.contains(allow_re, na=False)
    else:
        allowed_mask = pd.Series(False, index=df.index)

    df["App Status"] = np.where(allowed_mask, "Authorized", "Unauthorized")
    df["Behavior"] = vectorized_behavior(df)
    risk_level, risk_basis, risk_score_int = vectorized_risk(df, risk_policy)
    df["Risk Level"] = risk_level
    df["Risk Basis"] = risk_basis
    df["_risk_score"] = risk_score_int
    df["date"] = str(date_str)

    keep_cols = [
        "date",
        "datetime",
        "ip",
        "mac",
        "domain_clean",
        "app_identifier",
        "source_log",
        "dst_port",
        "bytes_sent",
        "bytes_received",
        "Info",
        "App Status",
        "Behavior",
        "Risk Level",
        "Risk Basis",
        "_risk_score",
    ]
    df = df[[c for c in keep_cols if c in df.columns]].copy()

    out_path = cache_events_path(parquet_root, date_str)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out_path, index=False)

    meta = {
        "cache_version": CACHE_VERSION,
        "date": date_str,
        "rows": int(len(df)),
        "sources_max_mtime": int(sources_max_mtime),
        **whitelist_state(),
        **risk_policy_state(),
        "built_at": int(time.time()),
        "events_file": str(out_path.name),
    }
    write_yaml(cache_meta_path(parquet_root, date_str), meta)


def ensure_cache(conn, parquet_root: Path, target_dates: list[str], allow_re, risk_policy: dict):
    if not target_dates:
        return
    prog = st.progress(0, text="Preparing optimized cache...")
    total = len(target_dates)
    for i, d in enumerate(target_dates, start=1):
        try:
            build_daily_cache(conn, parquet_root, d, allow_re, risk_policy)
        except Exception:
            pass
        prog.progress(int(i / total * 100), text="Preparing optimized cache...")
    prog.empty()


def read_cached_files(parquet_root: Path, target_dates: list[str]) -> list[str]:
    files = []
    for d in target_dates:
        p = cache_events_path(parquet_root, d)
        if p.exists():
            files.append(str(p))
    return files


def register_shadow_view(conn, cached_files: list[str]):
    if not cached_files:
        conn.execute("CREATE OR REPLACE VIEW shadow_events AS SELECT 1 WHERE false")
        return
    file_list_sql = "[" + ",".join("'" + f.replace("'", "''") + "'" for f in cached_files) + "]"
    conn.execute(
        f"""
        CREATE OR REPLACE VIEW shadow_events AS
        SELECT * FROM read_parquet({file_list_sql}, union_by_name=True)
        """
    )


def color_risk(val):
    color_map = {
        "Critical": "color: #FF0000; font-weight: 800;",
        "High": "color: #FF4500; font-weight: 800;",
        "Medium": "color: #FFA500; font-weight: 700;",
        "Low": "color: #FFD700; font-weight: 700;",
        "Safe": "color: #00FF00; font-weight: 700;",
    }
    return color_map.get(str(val), "")


def _build_in_clause(values: list, params: list):
    if not values:
        return None
    placeholders = ",".join(["?"] * len(values))
    params.extend(values)
    return f"({placeholders})"


def _sql_fetch_df(conn, sql: str, params=None) -> pd.DataFrame:
    try:
        if params is None:
            return conn.execute(sql).df()
        return conn.execute(sql, params).df()
    except Exception:
        return pd.DataFrame()


# =============================================================================
# Dialog (FIXED: closes properly + doesn't auto-pop on page revisit)
# =============================================================================
@st.dialog("Shadow App Forensics Details", width="large")
def show_forensics_dialog(conn):
    # Mark that reruns from widgets inside this dialog should keep it open
    # (via on_change callbacks)
    target_mac = st.session_state.get("shadow_dialog_mac")

    top = st.columns([1, 6])
    with top[0]:
        if st.button("Close", use_container_width=True, type="primary"):
            _close_shadow_dialog(reset_grid=True)
            st.rerun()

    with top[1]:
        st.caption(f"Forensic analysis for MAC Address: **{target_mac}**")

    if not target_mac:
        st.info("No MAC selected.")
        return

    chk = conn.execute("SELECT COUNT(*) FROM shadow_events WHERE mac = ?", [target_mac]).fetchone()
    if not chk or int(chk[0]) == 0:
        st.warning("No data found for this specific MAC address.")
        return

    f_col1, f_col2, f_col3 = st.columns([2, 1, 1])
    with f_col1:
        view_type = st.radio(
            "Activity Type",
            ["App Run (Connectivity)", "App Usage (Interaction)", "App Install (Files)", "Suspicious Behavior"],
            horizontal=True,
            key=f"dlg_view_{target_mac}",
            on_change=_mark_dialog_origin,
        )
    with f_col2:
        src_df = _sql_fetch_df(conn, "SELECT DISTINCT source_log FROM shadow_events WHERE mac = ? ORDER BY 1", [target_mac])
        f_raw_sources = src_df["source_log"].dropna().tolist() if not src_df.empty else []
        selected_f_source = st.selectbox(
            "Filter Source",
            ["All"] + f_raw_sources,
            key=f"dlg_src_{target_mac}",
            on_change=_mark_dialog_origin,
        )
    with f_col3:
        forensic_risk = risk_multiselect(
            "Filter Risk",
            key=f"dlg_risk_{target_mac}",
            default=["Critical", "High", "Medium", "Low", "Safe"],
            on_change=_mark_dialog_origin,
        )

    where = ["mac = ?"]
    params = [target_mac]

    if "App Run" in view_type:
        where.append("source_log IN ('CONN','DNS')")
    elif "App Usage" in view_type:
        where.append("source_log IN ('HTTP','SSL')")
    elif "App Install" in view_type:
        where.append("source_log IN ('FILES','SOFTWARE')")
    elif "Suspicious" in view_type:
        where.append("""("App Status"='Unauthorized' OR "Risk Level" IN ('Critical','High','Medium'))""")

    if selected_f_source != "All":
        where.append("source_log = ?")
        params.append(selected_f_source)

    if forensic_risk:
        in_clause = _build_in_clause(forensic_risk, params)
        where.append(f""""Risk Level" IN {in_clause}""")

    where_sql = " AND ".join(where)

    forensic_df = _sql_fetch_df(
        conn,
        f"""
        SELECT
            datetime, mac, ip, domain_clean, source_log, Info, dst_port,
            bytes_sent, bytes_received, Behavior, "App Status", "Risk Level", "Risk Basis"
        FROM shadow_events
        WHERE {where_sql}
        ORDER BY datetime DESC
        LIMIT 200000
        """,
        params,
    )

    if forensic_df.empty:
        st.warning("No events match your filters for this MAC.")
        return

    st.markdown("#### Activity Timeline")
    timeline = forensic_df.copy()
    timeline["datetime"] = pd.to_datetime(timeline["datetime"], errors="coerce")
    timeline = timeline.dropna(subset=["datetime"])
    if not timeline.empty:
        f_line = timeline.set_index("datetime").resample("10min").size().reset_index(name="hits")
        fig_f = px.area(f_line, x="datetime", y="hits", template="plotly_dark", title=f"Activity: {view_type}")
        st.plotly_chart(fig_f, use_container_width=True)
    else:
        st.warning("No valid timestamps for timeline.")

    low_col1, low_col2 = st.columns([1, 2])
    with low_col1:
        st.markdown("#### Top Destinations")
        top_dest = forensic_df["domain_clean"].value_counts().head(10).reset_index()
        top_dest.columns = ["Destination", "Count"]
        st.table(top_dest)

    with low_col2:
        st.markdown(f"#### Detailed Logs ({view_type})")
        final_df = forensic_df.head(500).copy()
        st.dataframe(
            final_df.style.map(color_risk, subset=["Risk Level"]),
            column_config={
                "datetime": st.column_config.DatetimeColumn("Time", format="YYYY-MM-DD HH:mm:ss"),
                "Info": "Context",
                "domain_clean": "Dest",
                "dst_port": "Port",
                "Risk Level": "Risk",
                "Risk Basis": "Risk Basis",
            },
            use_container_width=True,
            hide_index=True,
        )

def hide_dialog_x_button():
    st.markdown(
        """
        <style>
        /* Hide the built-in X close button on Streamlit dialogs */
        div[role="dialog"] button[aria-label="Close"],
        div[role="dialog"] button[title="Close"],
        div[data-testid="stDialog"] button[aria-label="Close"],
        div[data-testid="stDialog"] button[title="Close"] {
            display: none !important;
            visibility: hidden !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

# =============================================================================
# Main Render
# =============================================================================
def render_shadow_apps(parquet_root: Path):
    st.markdown("#### Shadow Apps Overview")

    hide_dialog_x_button() 

    # --- init state ---
    st.session_state.setdefault("shadow_dialog_open", False)
    st.session_state.setdefault("shadow_dialog_mac", None)
    st.session_state.setdefault("shadow_last_selected_mac", None)
    st.session_state.setdefault("shadow_grid_nonce", 0)

    # --- auto-close stale dialogs ---
    # Keep the dialog open ONLY when the rerun was triggered by:
    #   - a grid click (origin='grid')
    #   - a dialog widget interaction (origin='dialog')
    origin = st.session_state.pop("shadow_dialog_origin", None)
    if st.session_state.get("shadow_dialog_open") and origin not in ("grid", "dialog"):
        _close_shadow_dialog(reset_grid=False)

    available_dates = list_available_dates(parquet_root)
    if not available_dates:
        st.warning("No log directories found.")
        return

    # Day-by-day ONLY (no All Dates, and no _shadow_cache)
    def _on_day_change():
        _close_shadow_dialog(reset_grid=True)

    selected_day = st.selectbox(
        "Select Day (YYYY-MM-DD)",
        available_dates,
        index=0,
        key="shadow_day_select",
        on_change=_on_day_change,
    )
    target_dates = [selected_day]

    approved = load_allowlist()
    allow_re = compile_allow_regex(approved)
    risk_policy = load_risk_policy()

    conn = get_db_connection()
    with st.spinner("Optimizing logs for fast load..."):
        ensure_cache(conn, parquet_root, target_dates, allow_re, risk_policy)

    cached_files = read_cached_files(parquet_root, target_dates)
    if not cached_files:
        st.info("No cached shadow files available for selected day.")
        return

    register_shadow_view(conn, cached_files)

    # --- render dialog only when allowed for this rerun ---
    if st.session_state.get("shadow_dialog_open") and st.session_state.get("shadow_dialog_mac") and origin in ("grid", "dialog"):
        show_forensics_dialog(conn)

    # Metrics
    stats = conn.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN "App Status"='Authorized' THEN 1 ELSE 0 END) AS authorized,
            SUM(CASE WHEN "App Status"='Unauthorized' THEN 1 ELSE 0 END) AS unauthorized,
            SUM(CASE WHEN "Risk Level" IN ('Critical','High') THEN 1 ELSE 0 END) AS crit_high
        FROM shadow_events
        """
    ).df()

    total_events = int(stats.loc[0, "total"]) if not stats.empty else 0
    authorized_count = int(stats.loc[0, "authorized"]) if not stats.empty else 0
    unauthorized_count = int(stats.loc[0, "unauthorized"]) if not stats.empty else 0
    crit_high_count = int(stats.loc[0, "crit_high"]) if not stats.empty else 0
    unauth_pct = (unauthorized_count / total_events * 100) if total_events else 0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", total_events)
    col2.metric("Authorized Events", authorized_count)
    col3.metric("Unauthorized Events", unauthorized_count, f"{int(unauth_pct)}% of total", delta_color="inverse")
    col4.metric("Critical / High Risk", crit_high_count, delta_color="inverse")

    st.divider()

    # Charts
    c1, c2 = st.columns([2, 1])
    with c1:
        st.markdown("### Activity Over Time")
        df_line = _sql_fetch_df(
            conn,
            """
            SELECT
                date_trunc('hour', datetime) AS datetime,
                "App Status" AS "App Status",
                COUNT(*) AS count
            FROM shadow_events
            GROUP BY 1,2
            ORDER BY 1
            """,
        )
        if not df_line.empty:
            fig = px.line(
                df_line,
                x="datetime",
                y="count",
                color="App Status",
                color_discrete_map={"Authorized": "#00FF00", "Unauthorized": "#FF0000"},
                template="plotly_dark",
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data for timeline chart.")

    with c2:
        st.markdown("### Source Distribution")
        df_pie = _sql_fetch_df(
            conn,
            """
            SELECT source_log, COUNT(*) AS "Log Count"
            FROM shadow_events
            GROUP BY 1
            ORDER BY 2 DESC
            """,
        )
        if not df_pie.empty:
            fig_pie = px.pie(df_pie, values="Log Count", names="source_log", template="plotly_dark", hole=0.4)
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No data for source chart.")

    t1, t2 = st.tabs(["Authorized Applications & License Audit", "Unauthorized Applications"])

    # =============================================================================
    # TAB 1: AgGrid (CLICK ROW -> OPEN DIALOG)
    # =============================================================================
    with t1:
        st.markdown("### Application Audit Log")
        st.info("Click any row to open the Shadow App Forensics popup for that device.")

        filter_col1, filter_col2, filter_col3 = st.columns([3, 2, 2])
        with filter_col1:
            search_query_audit = st.text_input(
                "Search (MAC, IP, Domain)",
                placeholder="Search...",
                key="audit_search",
            ).strip()
        with filter_col2:
            status_filter = st.radio(
                "Filter Status",
                ["All", "Authorized", "Unauthorized"],
                horizontal=True,
                key="audit_status_filter",
            )
        with filter_col3:
            audit_risk_filter = risk_multiselect(
                "Filter Risk",
                key="audit_risk_filter",
                default=["Critical", "High", "Medium", "Low", "Safe"],
            )

        where = []
        params = []

        if status_filter != "All":
            where.append(""""App Status" = ?""")
            params.append(status_filter)

        if audit_risk_filter:
            in_clause = _build_in_clause(audit_risk_filter, params)
            where.append(f""""Risk Level" IN {in_clause}""")

        if search_query_audit:
            q = f"%{search_query_audit}%"
            where.append("(mac ILIKE ? OR ip ILIKE ? OR domain_clean ILIKE ?)")
            params.extend([q, q, q])

        where_sql = "WHERE " + " AND ".join(where) if where else ""

        audit_sql = f"""
        WITH base AS (
            SELECT
                domain_clean,
                mac,
                ip,
                source_log,
                "App Status" AS "App Status",
                datetime,
                _risk_score,
                "Risk Basis" AS risk_basis
            FROM shadow_events
            {where_sql}
        ),
        agg AS (
            SELECT
                domain_clean,
                mac,
                ip,
                source_log,
                "App Status",
                MIN(datetime) AS First_Seen,
                MAX(datetime) AS Last_Seen,
                COUNT(*) AS Hits,
                MAX(_risk_score) AS Max_Risk_Score
            FROM base
            GROUP BY 1,2,3,4,5
        ),
        pick_basis AS (
            SELECT
                domain_clean,
                mac,
                ip,
                source_log,
                "App Status",
                risk_basis AS Max_Risk_Basis,
                ROW_NUMBER() OVER (
                    PARTITION BY domain_clean, mac, ip, source_log, "App Status"
                    ORDER BY _risk_score DESC, datetime DESC
                ) AS rn
            FROM base
        )
        SELECT
            a.domain_clean,
            a.mac,
            a.ip,
            a.source_log,
            a."App Status",
            a.First_Seen,
            a.Last_Seen,
            a.Hits,
            CASE a.Max_Risk_Score
                WHEN 4 THEN 'Critical'
                WHEN 3 THEN 'High'
                WHEN 2 THEN 'Medium'
                WHEN 1 THEN 'Low'
                ELSE 'Safe'
            END AS Max_Risk,
            b.Max_Risk_Basis
        FROM agg a
        LEFT JOIN (SELECT * FROM pick_basis WHERE rn = 1) b
            ON a.domain_clean=b.domain_clean AND a.mac=b.mac AND a.ip=b.ip AND a.source_log=b.source_log AND a."App Status"=b."App Status"
        ORDER BY a.Max_Risk_Score DESC, a.Hits DESC
        LIMIT 1000
        """

        display_df = _sql_fetch_df(conn, audit_sql, params)

        if display_df.empty:
            st.info("No logs match your filter.")
        else:
            gb = GridOptionsBuilder.from_dataframe(display_df)
            gb.configure_selection(selection_mode="single", use_checkbox=False)

            mac_cellstyle = JsCode(
                """
                function(params) {
                    return {
                        'color': '#8AB4F8',
                        'fontWeight': '700',
                        'cursor': 'pointer',
                        'textDecoration': 'underline'
                    }
                }
                """
            )

            risk_cellstyle = JsCode(
                """
                function(params) {
                    const v = (params.value || '').toString();
                    let color = '#00FF00';
                    let weight = '700';
                    if (v === 'Critical') { color = '#FF0000'; weight = '900'; }
                    else if (v === 'High') { color = '#FF4500'; weight = '900'; }
                    else if (v === 'Medium') { color = '#FFA500'; weight = '800'; }
                    else if (v === 'Low') { color = '#FFD700'; weight = '800'; }
                    else if (v === 'Safe') { color = '#00FF00'; weight = '800'; }
                    return { 'color': color, 'fontWeight': weight };
                }
                """
            )

            gb.configure_column("mac", header_name="MAC Address (Click)", cellStyle=mac_cellstyle)
            gb.configure_column("Max_Risk", header_name="Risk Level", cellStyle=risk_cellstyle)

            grid_options = gb.build()
            grid_options["rowSelection"] = "single"
            grid_options["suppressRowClickSelection"] = False
            grid_options["rowMultiSelectWithClick"] = False

            ag_theme, ag_css = get_aggrid_theme_and_css()

            grid_key = f"shadow_audit_grid_{int(st.session_state.get('shadow_grid_nonce', 0))}"

            grid_response = AgGrid(
                display_df,
                gridOptions=grid_options,
                update_mode=GridUpdateMode.SELECTION_CHANGED,
                data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
                height=520,
                theme=ag_theme,
                custom_css=ag_css,
                allow_unsafe_jscode=True,
                fit_columns_on_grid_load=True,
                reload_data=False,
                key=grid_key,
            )

            # ---- selection -> open dialog (ONLY when selection changes) ----
            selected_rows = grid_response.get("selected_rows", None)
            selected_mac = None

            if isinstance(selected_rows, pd.DataFrame):
                if not selected_rows.empty and "mac" in selected_rows.columns:
                    selected_mac = selected_rows.iloc[0]["mac"]
            elif isinstance(selected_rows, list):
                if len(selected_rows) > 0 and isinstance(selected_rows[0], dict):
                    selected_mac = selected_rows[0].get("mac")

            if selected_mac:
                selected_mac = str(selected_mac).strip().lower()
                prev = st.session_state.get("shadow_last_selected_mac")

                if selected_mac != prev:
                    st.session_state["shadow_last_selected_mac"] = selected_mac
                    st.session_state["shadow_dialog_mac"] = selected_mac
                    st.session_state["shadow_dialog_open"] = True
                    st.session_state["shadow_dialog_origin"] = "grid"
                    st.rerun()
            else:
                # If user cleared selection (or grid reset), allow re-clicking same MAC later
                st.session_state["shadow_last_selected_mac"] = None

        # License Compliance (unchanged)
        st.markdown("### License Compliance Audit")
        usage_rows = []
        for software in LICENSE_REGISTRY.keys():
            cnt = conn.execute(
                """
                SELECT COUNT(DISTINCT mac)
                FROM shadow_events
                WHERE domain_clean ILIKE ?
                """,
                [f"%{software}%"],
            ).fetchone()
            unique_users = int(cnt[0]) if cnt else 0
            status = "Usage Detected" if unique_users > 0 else "No Usage"
            usage_rows.append({"Software": software, "Active Devices Count": unique_users, "Status": status})

        usage_df = pd.DataFrame(usage_rows)
        table_col, chart_col = st.columns([1.7, 1])
        with table_col:
            st.dataframe(
                usage_df.style.map(
                    lambda x: "color: #FF4B4B; font-weight: 600;"
                    if x == "Usage Detected"
                    else "color: #00CC96; font-weight: 600;",
                    subset=["Status"],
                ),
                use_container_width=True,
                hide_index=True,
            )
        with chart_col:
            fig = px.bar(
                usage_df,
                x="Software",
                y="Active Devices Count",
                text_auto=True,
                template="plotly_dark",
                color="Active Devices Count",
                color_continuous_scale="RdYlGn_r",
            )
            fig.update_layout(xaxis_title=None, yaxis_title="Active Devices", height=420, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

    # =============================================================================
    # TAB 2
    # =============================================================================
    with t2:
        st.markdown("## Unauthorized Threat Dashboard")

        unauth_stats = _sql_fetch_df(
            conn,
            """
            SELECT
                COUNT(*) AS unauthorized_events,
                COUNT(DISTINCT domain_clean) AS unauthorized_apps,
                COUNT(*) FILTER (WHERE "Risk Level" IN ('Critical','High')) AS crit_high,
                SUM(COALESCE(bytes_sent,0)) AS total_sent,
                SUM(COALESCE(bytes_received,0)) AS total_recv
            FROM shadow_events
            WHERE "App Status"='Unauthorized'
            """,
        )

        unauth_events = int(unauth_stats.loc[0, "unauthorized_events"]) if not unauth_stats.empty else 0
        if unauth_events == 0:
            st.success("No Unauthorized applications detected. System is clean.")
            return

        unauth_apps = int(unauth_stats.loc[0, "unauthorized_apps"])
        crit_high_unauth = int(unauth_stats.loc[0, "crit_high"])
        total_sent_gb = float(unauth_stats.loc[0, "total_sent"]) / 1_000_000_000
        total_recv_gb = float(unauth_stats.loc[0, "total_recv"]) / 1_000_000_000

        top_off = _sql_fetch_df(
            conn,
            """
            SELECT mac, COUNT(*) AS cnt
            FROM shadow_events
            WHERE "App Status"='Unauthorized'
            GROUP BY 1
            ORDER BY 2 DESC
            LIMIT 1
            """,
        )
        top_offender = str(top_off.loc[0, "mac"]) if not top_off.empty else "Unknown"
        top_offender_cnt = int(top_off.loc[0, "cnt"]) if not top_off.empty else 0

        u_metrics1, u_metrics2, u_metrics3 = st.columns(3)
        with u_metrics1:
            st.metric("Active Unauthorized Apps", unauth_apps)
        with u_metrics2:
            st.metric("Top Offender (MAC)", top_offender, delta=f"{top_offender_cnt} Events", delta_color="inverse")
        with u_metrics3:
            st.metric("Critical / High Risks", crit_high_unauth, delta="Requires Attention", delta_color="inverse")

        st.divider()

        with st.expander("Data Exfiltration Monitor (High Volume Traffic)", expanded=True):
            exfil_c1, exfil_c2 = st.columns(2)

            with exfil_c1:
                st.metric("Total Unauthorized Upload", f"{total_sent_gb:.2f} GB", delta="Potential Leak", delta_color="inverse")
                st.metric("Total Unauthorized Download", f"{total_recv_gb:.2f} GB")

            with exfil_c2:
                exfil_points = _sql_fetch_df(
                    conn,
                    """
                    SELECT dst_port, bytes_sent, Behavior, domain_clean, mac, "Risk Level"
                    FROM shadow_events
                    WHERE "App Status"='Unauthorized' AND COALESCE(bytes_sent,0) > 0
                    ORDER BY bytes_sent DESC
                    LIMIT 5000
                    """,
                )
                if not exfil_points.empty:
                    fig_exfil = px.scatter(
                        exfil_points,
                        x="dst_port",
                        y="bytes_sent",
                        size="bytes_sent",
                        color="Behavior",
                        hover_data=["domain_clean", "mac", "Risk Level"],
                        title="Outbound Data Volume by Port (Top 5000 Events)",
                        template="plotly_dark",
                    )
                    st.plotly_chart(fig_exfil, use_container_width=True)
                else:
                    st.info("No significant outbound traffic detected.")

        st.divider()

        u_chart1, u_chart2 = st.columns([2, 1])
        with u_chart1:
            st.markdown("#### Top Unauthorized Domains")
            top_unauth = _sql_fetch_df(
                conn,
                """
                SELECT domain_clean AS Domain, COUNT(*) AS Hits
                FROM shadow_events
                WHERE "App Status"='Unauthorized'
                GROUP BY 1
                ORDER BY 2 DESC
                LIMIT 10
                """,
            )
            if not top_unauth.empty:
                fig_u1 = px.bar(
                    top_unauth,
                    x="Hits",
                    y="Domain",
                    orientation="h",
                    template="plotly_dark",
                    color_discrete_sequence=["#FF4500"],
                )
                fig_u1.update_layout(yaxis={"categoryorder": "total ascending"})
                st.plotly_chart(fig_u1, use_container_width=True)
            else:
                st.info("No unauthorized domains found.")

        with u_chart2:
            st.markdown("#### Risk Distribution")
            risk_counts = _sql_fetch_df(
                conn,
                """
                SELECT "Risk Level" AS Risk, COUNT(*) AS Count
                FROM shadow_events
                WHERE "App Status"='Unauthorized'
                GROUP BY 1
                ORDER BY 2 DESC
                """,
            )
            if not risk_counts.empty:
                risk_colors = {"Critical": "#FF0000", "High": "#FF4500", "Medium": "#FFA500", "Low": "#FFD700", "Safe": "#00FF00"}
                fig_u2 = px.pie(
                    risk_counts,
                    values="Count",
                    names="Risk",
                    color="Risk",
                    color_discrete_map=risk_colors,
                    template="plotly_dark",
                    hole=0.6,
                )
                st.plotly_chart(fig_u2, use_container_width=True)
            else:
                st.info("No risk distribution data.")

        st.divider()

        st.markdown("### Threat Details")
        af_1, af_2, af_3 = st.columns([1, 1, 2])

        with af_1:
            filter_risk = risk_multiselect("Filter by Risk", key="unauth_risk_filter", default=["Critical", "High", "Medium", "Low"])

        with af_2:
            src_list = _sql_fetch_df(
                conn,
                """
                SELECT DISTINCT source_log
                FROM shadow_events
                WHERE "App Status"='Unauthorized'
                ORDER BY 1
                """,
            )
            sources = src_list["source_log"].dropna().tolist() if not src_list.empty else []
            filter_source = st.multiselect("Filter by Log Source", sources, default=sources)

        with af_3:
            search_query_unauth = st.text_input("Search (IP, MAC, Domain)", placeholder="Search threat details...", key="unauth_search").strip()

        where = [""""App Status"='Unauthorized'"""]
        params = []

        if filter_risk:
            in_clause = _build_in_clause(filter_risk, params)
            where.append(f""""Risk Level" IN {in_clause}""")

        if filter_source:
            in_clause = _build_in_clause(filter_source, params)
            where.append(f"source_log IN {in_clause}")

        if search_query_unauth:
            q = f"%{search_query_unauth}%"
            where.append("(mac ILIKE ? OR ip ILIKE ? OR domain_clean ILIKE ?)")
            params.extend([q, q, q])

        where_sql = " AND ".join(where)

        detail_table = _sql_fetch_df(
            conn,
            f"""
            SELECT
                datetime,
                mac,
                ip,
                domain_clean,
                source_log,
                Info,
                dst_port,
                bytes_sent,
                bytes_received,
                Behavior,
                "Risk Level",
                "Risk Basis"
            FROM shadow_events
            WHERE {where_sql}
            ORDER BY datetime DESC
            LIMIT 1000
            """,
            params,
        )

        if detail_table.empty:
            st.info("No rows match your filters.")
        else:
            styled_unauth = detail_table.style.map(color_risk, subset=["Risk Level"])
            st.dataframe(
                styled_unauth,
                column_config={
                    "datetime": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
                    "mac": "MAC Address",
                    "ip": "IP Address",
                    "domain_clean": "Unauthorized Domain",
                    "source_log": "Source",
                    "Info": "Context",
                    "dst_port": "Port",
                    "bytes_sent": "Upload (Bytes)",
                    "bytes_received": "Download (Bytes)",
                    "Behavior": "Behavior Tag",
                    "Risk Level": "Threat Risk",
                    "Risk Basis": "Risk Basis",
                },
                use_container_width=True,
                hide_index=True,
            )
