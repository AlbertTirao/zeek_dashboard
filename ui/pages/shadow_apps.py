# ui/pages/shadow_apps.py  
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

# Bump version so old cached parquet (without hostname) gets rebuilt automatically
CACHE_VERSION = "shadow-cache-v2-hostname"

# -----------------------------
# Config
# -----------------------------
WHITELIST_FILE = Path(__file__).resolve().parents[2] / "whitelist_domains.yaml"
RISK_POLICY_FILE = Path(__file__).resolve().parents[2] / "risk_policy.yaml"
CACHE_DIRNAME = "_shadow_cache_apps"

LICENSE_REGISTRY = {
    "office.com": None,
    "microsoft.com": None,
    "github.com": None,
    "zoom.us": None,
    "slack.com": None,
}

RISK_SCORE = {"Safe": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
SCORE_TO_RISK = {v: k for k, v in RISK_SCORE.items()}
RISK_COLORS = {
    "Critical": "#ef4444",
    "High": "#f97316",
    "Medium": "#f59e0b",
    "Low": "#eab308",
    "Safe": "#22c55e",
}
STATUS_COLORS = {"Authorized": "#22c55e", "Unauthorized": "#ef4444"}

_MAC_HEX_RE = re.compile(r"[^0-9a-fA-F]")


def normalize_mac(x) -> str:
    """Normalize MAC to aa:bb:cc:dd:ee:ff when possible; fallback to lower string."""
    if x is None or (isinstance(x, float) and np.isnan(x)):
        return "unknown"
    try:
        if isinstance(x, (bytes, bytearray)) and len(x) == 6:
            hx = bytes(x).hex()
        else:
            hx = _MAC_HEX_RE.sub("", str(x))
        if len(hx) == 12:
            return ":".join(hx[i:i + 2] for i in range(0, 12, 2)).lower()
    except Exception:
        pass
    s = str(x).strip().lower()
    return s if s else "unknown"


def risk_score(val: str) -> int:
    return int(RISK_SCORE.get(str(val), 0))


def score_to_risk(score: int) -> str:
    return SCORE_TO_RISK.get(int(score), "Safe")


def _mark_dialog_origin():
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
    return theme, custom_css


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


def get_plotly_template() -> str:
    return "plotly_dark" if _is_dark_theme() else "plotly_white"


def style_plotly_figure(fig, *, height: int = 360, show_legend: bool = True):
    fig.update_layout(
        template=get_plotly_template(),
        height=height,
        margin=dict(l=12, r=12, t=40, b=12),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        legend=dict(orientation="h", y=1.02, x=1.0, xanchor="right", yanchor="bottom"),
    )
    if not show_legend:
        fig.update_layout(showlegend=False)
    return fig


def inject_shadow_apps_css():
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

        .shadow-day-chip {
            border: 1px solid rgba(255,255,255,0.18);
            background: rgba(255,255,255,0.05);
            border-radius: 999px;
            padding: 7px 12px;
            margin-top: 1.72rem;
            font-size: 12px;
            font-weight: 700;
            line-height: 1.2;
            display: inline-flex;
            align-items: center;
        }

        .shadow-callout {
            border: 1px solid var(--panel-border);
            background: var(--panel-bg);
            border-radius: 10px;
            padding: 0.5rem 0.72rem;
            font-size: 0.84rem;
            margin-bottom: 0.45rem;
        }

        .shadow-filter-shell {
            border: 1px solid rgba(148, 163, 184, 0.28);
            background: linear-gradient(135deg, rgba(15,23,42,0.66), rgba(2,6,23,0.62));
            border-radius: 12px;
            padding: 0.72rem 0.85rem 0.55rem 0.85rem;
            margin-bottom: 0.72rem;
        }

        .shadow-filter-hint {
            font-size: 0.76rem;
            color: #9fb1c8;
            margin-top: 0.2rem;
            margin-bottom: 0.2rem;
        }

        .shadow-filter-shell [data-testid="stWidgetLabel"] p {
            font-size: 0.76rem;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            color: #bfd1ea;
            font-weight: 700;
        }

        .shadow-filter-shell [data-testid="stTextInput"] input,
        .shadow-filter-shell [data-testid="stTextArea"] textarea {
            background: rgba(8, 20, 40, 0.8) !important;
            border: 1px solid #35517d !important;
            color: #e5eefc !important;
        }

        .shadow-filter-shell [data-testid="stSelectbox"] div[data-baseweb="select"] > div,
        .shadow-filter-shell [data-testid="stMultiSelect"] div[data-baseweb="select"] > div {
            background: rgba(8, 20, 40, 0.8) !important;
            border: 1px solid #35517d !important;
            color: #e5eefc !important;
            min-height: 2.42rem;
        }

        .shadow-filter-shell div[role="radiogroup"] label {
            background: rgba(8, 20, 40, 0.75) !important;
            border: 1px solid #35517d !important;
            border-radius: 8px !important;
            padding: 0.3rem 0.5rem !important;
        }

        .shadow-table-shell {
            border: 1px solid rgba(148, 163, 184, 0.24);
            background: linear-gradient(180deg, rgba(2,6,23,0.5), rgba(2,6,23,0.35));
            border-radius: 12px;
            padding: 0.56rem 0.62rem 0.46rem 0.62rem;
            margin-bottom: 0.75rem;
        }

        .shadow-dialog-banner {
            border: 1px solid rgba(56, 189, 248, 0.42);
            background: linear-gradient(120deg, rgba(14,116,144,0.25), rgba(15,23,42,0.62));
            border-radius: 10px;
            padding: 0.5rem 0.74rem;
            font-size: 0.84rem;
            margin-bottom: 0.45rem;
        }

        [data-testid="stMetric"] {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 12px;
            padding: 0.55rem 0.75rem;
        }

        div[data-testid="stDialog"] [data-testid="stMetric"] {
            border-color: rgba(56, 189, 248, 0.32);
            background: rgba(15, 23, 42, 0.52);
        }

        [data-testid="stMetricLabel"] p {
            font-size: 0.75rem;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            font-weight: 600;
        }

        [data-testid="stMetricValue"] {
            line-height: 1.1;
        }

        .stTabs [data-baseweb="tab-list"] {
            gap: 0.45rem;
            margin-bottom: 0.35rem;
        }

        .stTabs [data-baseweb="tab"] {
            border: 1px solid var(--panel-border);
            border-radius: 999px;
            background: rgba(255,255,255,0.03);
            padding: 0.38rem 0.88rem;
            font-size: 0.86rem;
            height: auto;
        }

        .stTabs [data-baseweb="tab"][aria-selected="true"] {
            background: rgba(255,255,255,0.08);
            border-color: rgba(255,255,255,0.2);
            font-weight: 700;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


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
    Only return real day folders (YYYY-MM-DD) and EXCLUDE _shadow_cache_apps.
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
    known_hosts_files = []
    log_files = []
    for d in target_dates:
        d_path = parquet_root / d
        if not d_path.exists():
            continue

        dhcp_p = d_path / "dhcp.parquet"
        if dhcp_p.exists():
            dhcp_files.append(str(dhcp_p))

        kh_p = d_path / "known_hosts.parquet"
        if kh_p.exists():
            known_hosts_files.append(str(kh_p))

        for l in LOG_TYPES:
            l_path = d_path / f"{l}.parquet"
            if l_path.exists():
                log_files.append(str(l_path))

    return dhcp_files, known_hosts_files, log_files


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


def _describe_cols(conn, obj_name: str) -> list[str]:
    try:
        return [r[0] for r in conn.execute(f"DESCRIBE {obj_name}").fetchall()]
    except Exception:
        try:
            df = conn.execute(f"DESCRIBE {obj_name}").df()
            return df.iloc[:, 0].astype(str).tolist()
        except Exception:
            return []


def query_shadow_logs_raw(_conn, dhcp_files: list[str], known_hosts_files: list[str], log_files: list[str]) -> pd.DataFrame:
    """
    Returns event rows with mapping ip -> mac + hostname (DHCP/known_hosts).
    Output columns include: ts, ip, mac, hostname, dst_port, bytes_sent, bytes_received, app_identifier, Info, source_log
    """
    if not log_files:
        return pd.DataFrame()

    # ---- DHCP mapping view ----
    if dhcp_files:
        try:
            _conn.execute(
                "CREATE OR REPLACE VIEW raw_dhcp_files AS "
                f"SELECT * FROM read_parquet({dhcp_files}, union_by_name=True)"
            )
            dhcp_cols = _describe_cols(_conn, "raw_dhcp_files")

            dhcp_ip = next((c for c in ["client_addr", "assigned_addr", "requested_addr", "ip", "id.orig_h", "orig_h"] if c in dhcp_cols), None)
            dhcp_mac = next((c for c in ["mac", "client_chaddr", "hardware_address", "hwaddr", "chaddr"] if c in dhcp_cols), None)
            dhcp_host = next((c for c in ["host_name", "hostname", "client_hostname", "client_fqdn", "client_name"] if c in dhcp_cols), None)
            dhcp_ts = next((c for c in ["ts", "timestamp", "seen_ts", "time"] if c in dhcp_cols), None)

            if dhcp_ip and dhcp_mac:
                host_expr = f'CAST("{dhcp_host}" AS VARCHAR)' if dhcp_host else "'Unknown'"
                if dhcp_ts:
                    _conn.execute(
                        f"""
                        CREATE OR REPLACE VIEW v_dhcp AS
                        WITH base AS (
                            SELECT
                                CAST("{dhcp_ip}" AS VARCHAR) AS ip_addr,
                                CAST("{dhcp_mac}" AS VARCHAR) AS mac_raw,
                                {host_expr} AS host_raw,
                                try_cast("{dhcp_ts}" AS DOUBLE) AS ts
                            FROM raw_dhcp_files
                            WHERE "{dhcp_ip}" IS NOT NULL AND "{dhcp_mac}" IS NOT NULL
                        )
                        SELECT
                            ip_addr,
                            arg_max(mac_raw, ts) AS mac_addr,
                            COALESCE(NULLIF(arg_max(host_raw, ts), ''), 'Unknown') AS hostname
                        FROM base
                        GROUP BY ip_addr
                        """
                    )
                else:
                    _conn.execute(
                        f"""
                        CREATE OR REPLACE VIEW v_dhcp AS
                        SELECT
                            CAST("{dhcp_ip}" AS VARCHAR) AS ip_addr,
                            any_value(CAST("{dhcp_mac}" AS VARCHAR)) AS mac_addr,
                            COALESCE(NULLIF(any_value({host_expr}), ''), 'Unknown') AS hostname
                        FROM raw_dhcp_files
                        WHERE "{dhcp_ip}" IS NOT NULL AND "{dhcp_mac}" IS NOT NULL
                        GROUP BY 1
                        """
                    )
            else:
                _conn.execute("CREATE OR REPLACE VIEW v_dhcp AS SELECT NULL::VARCHAR as ip_addr, NULL::VARCHAR as mac_addr, 'Unknown'::VARCHAR as hostname WHERE false")
        except Exception:
            _conn.execute("CREATE OR REPLACE VIEW v_dhcp AS SELECT NULL::VARCHAR as ip_addr, NULL::VARCHAR as mac_addr, 'Unknown'::VARCHAR as hostname WHERE false")
    else:
        _conn.execute("CREATE OR REPLACE VIEW v_dhcp AS SELECT NULL::VARCHAR as ip_addr, NULL::VARCHAR as mac_addr, 'Unknown'::VARCHAR as hostname WHERE false")

    # ---- known_hosts mapping view (fallback) ----
    if known_hosts_files:
        try:
            _conn.execute(
                "CREATE OR REPLACE VIEW raw_known_hosts_files AS "
                f"SELECT * FROM read_parquet({known_hosts_files}, union_by_name=True)"
            )
            kh_cols = _describe_cols(_conn, "raw_known_hosts_files")

            kh_ip = next((c for c in ["host", "ip", "ip_addr", "addr", "id.orig_h", "orig_h"] if c in kh_cols), None)
            kh_mac = next((c for c in ["mac", "mac_addr", "hwaddr", "client_chaddr"] if c in kh_cols), None)
            kh_host = next((c for c in ["host_name", "hostname", "name", "device_name"] if c in kh_cols), None)
            kh_ts = next((c for c in ["ts", "timestamp", "seen_ts", "time"] if c in kh_cols), None)

            if kh_ip and kh_mac:
                host_expr = f'CAST("{kh_host}" AS VARCHAR)' if kh_host else "'Unknown'"
                if kh_ts:
                    _conn.execute(
                        f"""
                        CREATE OR REPLACE VIEW v_known AS
                        WITH base AS (
                            SELECT
                                CAST("{kh_ip}" AS VARCHAR) AS ip_addr,
                                CAST("{kh_mac}" AS VARCHAR) AS mac_raw,
                                {host_expr} AS host_raw,
                                try_cast("{kh_ts}" AS DOUBLE) AS ts
                            FROM raw_known_hosts_files
                            WHERE "{kh_ip}" IS NOT NULL AND "{kh_mac}" IS NOT NULL
                        )
                        SELECT
                            ip_addr,
                            arg_max(mac_raw, ts) AS mac_addr,
                            COALESCE(NULLIF(arg_max(host_raw, ts), ''), 'Unknown') AS hostname
                        FROM base
                        GROUP BY ip_addr
                        """
                    )
                else:
                    _conn.execute(
                        f"""
                        CREATE OR REPLACE VIEW v_known AS
                        SELECT
                            CAST("{kh_ip}" AS VARCHAR) AS ip_addr,
                            any_value(CAST("{kh_mac}" AS VARCHAR)) AS mac_addr,
                            COALESCE(NULLIF(any_value({host_expr}), ''), 'Unknown') AS hostname
                        FROM raw_known_hosts_files
                        WHERE "{kh_ip}" IS NOT NULL AND "{kh_mac}" IS NOT NULL
                        GROUP BY 1
                        """
                    )
            else:
                _conn.execute("CREATE OR REPLACE VIEW v_known AS SELECT NULL::VARCHAR as ip_addr, NULL::VARCHAR as mac_addr, 'Unknown'::VARCHAR as hostname WHERE false")
        except Exception:
            _conn.execute("CREATE OR REPLACE VIEW v_known AS SELECT NULL::VARCHAR as ip_addr, NULL::VARCHAR as mac_addr, 'Unknown'::VARCHAR as hostname WHERE false")
    else:
        _conn.execute("CREATE OR REPLACE VIEW v_known AS SELECT NULL::VARCHAR as ip_addr, NULL::VARCHAR as mac_addr, 'Unknown'::VARCHAR as hostname WHERE false")

    # Merge mapping
    _conn.execute(
        """
        CREATE OR REPLACE VIEW v_ip_map AS
        SELECT
            COALESCE(d.ip_addr, k.ip_addr) AS ip_addr,
            COALESCE(NULLIF(d.mac_addr,''), NULLIF(k.mac_addr,''), 'Unknown') AS mac_addr,
            COALESCE(NULLIF(d.hostname,''), NULLIF(k.hostname,''), 'Unknown') AS hostname
        FROM v_dhcp d
        FULL OUTER JOIN v_known k
            ON d.ip_addr = k.ip_addr
        """
    )

    # ---- Logs view ----
    try:
        _conn.execute(
            "CREATE OR REPLACE VIEW raw_logs AS "
            f"SELECT * FROM read_parquet({log_files}, union_by_name=True, filename='source_file_path')"
        )
        existing_cols = set(_describe_cols(_conn, "raw_logs"))

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
            COALESCE({sql_mac}, m.mac_addr, 'Unknown') as mac,
            COALESCE(NULLIF(m.hostname,''), 'Unknown') as hostname,
            {sql_port} as dst_port,
            {sql_sent} as bytes_sent,
            {sql_recv} as bytes_received,
            {sql_app} as app_identifier,
            {sql_info} as Info,
            upper(regexp_extract(source_file_path, '([a-z]+)\\.parquet', 1)) as source_log
        FROM raw_logs r
        LEFT JOIN v_ip_map m ON {sql_ip} = m.ip_addr
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
        basis.loc[m] = "Policy: critical.source_logs matched (" + slog.loc[m].astype(str) + ")"
    if crit_ports:
        m = port.isin(crit_ports) & score.eq(-1)
        score[m] = 4
        basis.loc[m] = "Policy: critical.ports matched (" + port.loc[m].astype(str) + ")"

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
    dhcp_files, known_hosts_files, log_files = collect_parquet_files(parquet_root, (date_str,))
    sources = list(dhcp_files) + list(known_hosts_files) + list(log_files)
    sources_max_mtime = _paths_max_mtime(sources)

    if cache_is_fresh(parquet_root, date_str, sources_max_mtime):
        return

    raw_df = query_shadow_logs_raw(
        conn,
        dhcp_files=dhcp_files,
        known_hosts_files=known_hosts_files,
        log_files=log_files,
    )
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
    df["mac"] = df["mac"].apply(normalize_mac)
    df["hostname"] = df.get("hostname", "Unknown").fillna("Unknown").astype(str)
    df["hostname"] = df["hostname"].replace({"": "Unknown"})
    df.loc[df["hostname"].str.lower().isin(["nan", "none"]), "hostname"] = "Unknown"

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
        "hostname",  # ✅ persist
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

    # Create base view from parquet
    conn.execute(
        f"""
        CREATE OR REPLACE VIEW shadow_events AS
        SELECT * FROM read_parquet({file_list_sql}, union_by_name=True)
        """
    )

    # Hard fallback: if cached parquet still doesn't have hostname, inject it so SQL never breaks
    cols = set(_describe_cols(conn, "shadow_events"))
    if "hostname" not in cols:
        conn.execute(
            f"""
            CREATE OR REPLACE VIEW shadow_events AS
            SELECT *, 'Unknown'::VARCHAR AS hostname
            FROM read_parquet({file_list_sql}, union_by_name=True)
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


def color_status(val):
    v = str(val)
    if v == "Unauthorized":
        return "color: #ef4444; font-weight: 800;"
    if v == "Authorized":
        return "color: #22c55e; font-weight: 700;"
    return ""


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
# Dialog
# =============================================================================
@st.dialog("Shadow App Forensics Details", width="large", dismissible=False)
def show_forensics_dialog(conn):
    target_mac = st.session_state.get("shadow_dialog_mac")

    # ---- Make dialog a little wider (Streamlit dialog width is limited; CSS widens container) ----
    st.markdown(
        """
        <style>
        div[data-testid="stDialog"] > div[role="dialog"] {
            width: min(95vw, 1500px) !important;
            max-width: min(95vw, 1500px) !important;
        }
        div[data-testid="stDialog"] div[role="dialog"] .stDialogContent {
            padding-left: 1.25rem !important;
            padding-right: 1.25rem !important;
        }
        div[data-testid="stDialog"] [data-testid="stMarkdownContainer"] h4 {
            color: #dbeafe;
            letter-spacing: 0.01em;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    top = st.columns([1, 6])
    with top[0]:
        if st.button("Close", use_container_width=True, type="primary"):
            _close_shadow_dialog(reset_grid=True)
            st.rerun()

    with top[1]:
        st.markdown(
            f"<div class='shadow-dialog-banner'>Forensic analysis scope: <strong>{target_mac}</strong></div>",
            unsafe_allow_html=True,
        )

    if not target_mac:
        st.info("No MAC selected.")
        return

    chk = conn.execute("SELECT COUNT(*) FROM shadow_events WHERE lower(mac) = lower(?)", [target_mac]).fetchone()
    if not chk or int(chk[0]) == 0:
        st.warning("No data found for this specific MAC address.")
        return

    st.markdown("<div class='shadow-filter-shell'>", unsafe_allow_html=True)
    f_top_left, f_top_right = st.columns([2.8, 1.2])
    with f_top_left:
        view_type = st.radio(
            "Activity Type",
            ["App Run (Connectivity)", "App Usage (Interaction)", "App Install (Files)", "Suspicious Behavior"],
            horizontal=True,
            key=f"dlg_view_{target_mac}",
            on_change=_mark_dialog_origin,
        )
    with f_top_right:
        src_df = _sql_fetch_df(
            conn,
            "SELECT DISTINCT source_log FROM shadow_events WHERE lower(mac) = lower(?) ORDER BY 1",
            [target_mac],
        )
        f_raw_sources = src_df["source_log"].dropna().tolist() if not src_df.empty else []
        selected_f_source = st.selectbox(
            "Filter Source",
            ["All"] + f_raw_sources,
            key=f"dlg_src_{target_mac}",
            on_change=_mark_dialog_origin,
        )
    f_bottom_left, f_bottom_right = st.columns([1.4, 2.6])
    with f_bottom_left:
        forensic_risk = risk_multiselect(
            "Filter Risk",
            key=f"dlg_risk_{target_mac}",
            default=["Critical", "High", "Medium", "Low", "Safe"],
            on_change=_mark_dialog_origin,
        )
    with f_bottom_right:
        forensic_search = st.text_input(
            "Quick Search",
            placeholder="IP, domain, context...",
            key=f"dlg_search_{target_mac}",
            on_change=_mark_dialog_origin,
        ).strip()
    st.markdown("</div>", unsafe_allow_html=True)

    risk_summary = ", ".join(forensic_risk) if forensic_risk else "None"
    source_summary = selected_f_source if selected_f_source != "All" else "All Sources"
    st.markdown(
        f"<div class='shadow-filter-hint'>View: <strong>{view_type}</strong> | Source: <strong>{source_summary}</strong> | Risk: <strong>{risk_summary}</strong> | Search: <strong>{'On' if forensic_search else 'Off'}</strong></div>",
        unsafe_allow_html=True,
    )

    where = ["lower(mac) = lower(?)"]
    params = [target_mac]

    if "App Run" in view_type:
        where.append("upper(source_log) IN ('CONN','DNS')")
    elif "App Usage" in view_type:
        where.append("upper(source_log) IN ('HTTP','SSL')")
    elif "App Install" in view_type:
        where.append("upper(source_log) IN ('FILES','SOFTWARE')")
    elif "Suspicious" in view_type:
        where.append("""("App Status"='Unauthorized' OR "Risk Level" IN ('Critical','High','Medium'))""")

    if selected_f_source != "All":
        where.append("upper(source_log) = upper(?)")
        params.append(selected_f_source)

    if forensic_risk:
        in_clause = _build_in_clause(forensic_risk, params)
        where.append(f""""Risk Level" IN {in_clause}""")

    if forensic_search:
        q = f"%{forensic_search}%"
        where.append("(domain_clean ILIKE ? OR ip ILIKE ? OR Info ILIKE ? OR hostname ILIKE ?)")
        params.extend([q, q, q, q])

    where_sql = " AND ".join(where)

    forensic_df = _sql_fetch_df(
        conn,
        f"""
        SELECT
            datetime, mac, hostname, ip, domain_clean, source_log, Info, dst_port,
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

    forensic_total = int(len(forensic_df))
    forensic_domains = int(forensic_df["domain_clean"].nunique(dropna=True))
    forensic_unauthorized = int((forensic_df["App Status"] == "Unauthorized").sum())
    forensic_critical_high = int(forensic_df["Risk Level"].isin(["Critical", "High"]).sum())

    d1, d2, d3, d4 = st.columns(4)
    d1.metric("Events", f"{forensic_total:,}")
    d2.metric("Unique Destinations", f"{forensic_domains:,}")
    d3.metric("Unauthorized", f"{forensic_unauthorized:,}")
    d4.metric("Critical / High", f"{forensic_critical_high:,}")

    # =============================================================================
    # Dialog analytics: Timeline + Top Destinations + Detailed Logs
    # =============================================================================
    st.markdown("#### Activity Timeline")
    tl_cfg_1, tl_cfg_2 = st.columns([1.2, 1.8])
    with tl_cfg_1:
        timeline_grain = st.selectbox(
            "Time Bucket",
            ["5 min", "10 min", "30 min", "1 hour"],
            index=1,
            key=f"dlg_time_bucket_{target_mac}",
            on_change=_mark_dialog_origin,
        )
    with tl_cfg_2:
        timeline_mode = st.radio(
            "Timeline View",
            ["Total Events", "Status Split"],
            horizontal=True,
            key=f"dlg_timeline_mode_{target_mac}",
            on_change=_mark_dialog_origin,
        )

    bucket_rule = {"5 min": "5min", "10 min": "10min", "30 min": "30min", "1 hour": "1H"}[timeline_grain]
    timeline = forensic_df.copy()
    timeline["datetime"] = pd.to_datetime(timeline["datetime"], errors="coerce")
    timeline = timeline.dropna(subset=["datetime"])

    if not timeline.empty:
        if timeline_mode == "Status Split":
            f_line = (
                timeline.set_index("datetime")
                .groupby("App Status")
                .resample(bucket_rule)
                .size()
                .reset_index(name="hits")
            )
            fig_f = px.area(
                f_line,
                x="datetime",
                y="hits",
                color="App Status",
                color_discrete_map=STATUS_COLORS,
                title=f"Activity ({timeline_grain})",
            )
            style_plotly_figure(fig_f, height=320)
        else:
            f_line = timeline.set_index("datetime").resample(bucket_rule).size().reset_index(name="hits")
            fig_f = px.area(
                f_line,
                x="datetime",
                y="hits",
                title=f"Activity ({timeline_grain})",
                color_discrete_sequence=["#60a5fa"],
            )
            style_plotly_figure(fig_f, height=320, show_legend=False)

        fig_f.update_xaxes(title=None)
        fig_f.update_yaxes(title="Events")
        st.plotly_chart(fig_f, use_container_width=True)
    else:
        st.warning("No valid timestamps for timeline.")

    low_col1, low_col2 = st.columns([1.15, 1.85])
    with low_col1:
        st.markdown("#### Top Destinations")
        top_dest = (
            forensic_df.assign(domain_clean=forensic_df["domain_clean"].fillna("Unknown"))
            .groupby("domain_clean", as_index=False)
            .size()
            .rename(columns={"size": "Hits", "domain_clean": "Destination"})
            .sort_values("Hits", ascending=False)
            .head(10)
        )
        if not top_dest.empty:
            fig_dest = px.bar(
                top_dest,
                x="Hits",
                y="Destination",
                orientation="h",
                color="Hits",
                color_continuous_scale="Blues",
            )
            style_plotly_figure(fig_dest, height=330, show_legend=False)
            fig_dest.update_layout(yaxis_title=None, xaxis_title="Hits", coloraxis_showscale=False)
            fig_dest.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(fig_dest, use_container_width=True)
        else:
            st.info("No destination data for the selected filters.")

    with low_col2:
        st.markdown(f"#### Detailed Logs ({view_type})")
        final_df = forensic_df.head(1000).copy()
        final_df["datetime"] = pd.to_datetime(final_df["datetime"], errors="coerce")
        final_df["datetime"] = final_df["datetime"].dt.strftime("%Y-%m-%d %H:%M:%S")
        final_df["datetime"] = final_df["datetime"].fillna("")
        dialog_cols = [
            "datetime",
            "source_log",
            "ip",
            "domain_clean",
            "dst_port",
            "Behavior",
            "App Status",
            "Risk Level",
            "Info",
            "Risk Basis",
        ]
        dialog_cols = [c for c in dialog_cols if c in final_df.columns]
        final_df = final_df[dialog_cols]

        dlg_risk_style = JsCode(
            """
            function(params) {
                const v = (params.value || '').toString();
                if (v === 'Critical') return {color: '#ef4444', fontWeight: '800'};
                if (v === 'High') return {color: '#f97316', fontWeight: '800'};
                if (v === 'Medium') return {color: '#f59e0b', fontWeight: '700'};
                if (v === 'Low') return {color: '#eab308', fontWeight: '700'};
                if (v === 'Safe') return {color: '#22c55e', fontWeight: '700'};
                return {};
            }
            """
        )
        dlg_status_style = JsCode(
            """
            function(params) {
                const v = (params.value || '').toString();
                if (v === 'Unauthorized') return {color: '#ef4444', fontWeight: '800'};
                if (v === 'Authorized') return {color: '#22c55e', fontWeight: '700'};
                return {};
            }
            """
        )

        gb_dlg = GridOptionsBuilder.from_dataframe(final_df)
        gb_dlg.configure_default_column(filter=True, sortable=True, resizable=True, minWidth=150)
        gb_dlg.configure_pagination(paginationAutoPageSize=False, paginationPageSize=20)
        if "datetime" in final_df.columns:
            gb_dlg.configure_column("datetime", header_name="Time", width=150)
        if "source_log" in final_df.columns:
            gb_dlg.configure_column("source_log", header_name="Source", width=92)
        if "ip" in final_df.columns:
            gb_dlg.configure_column("ip", header_name="IP", width=122)
        if "domain_clean" in final_df.columns:
            gb_dlg.configure_column(
                "domain_clean",
                header_name="Destination",
                minWidth=165,
                flex=1.15,
                tooltipField="domain_clean",
            )
        if "dst_port" in final_df.columns:
            gb_dlg.configure_column("dst_port", header_name="Port", width=78)
        if "Behavior" in final_df.columns:
            gb_dlg.configure_column("Behavior", header_name="Behavior", minWidth=108, flex=0.85)
        if "App Status" in final_df.columns:
            gb_dlg.configure_column("App Status", header_name="Status", width=102, cellStyle=dlg_status_style)
        if "Risk Level" in final_df.columns:
            gb_dlg.configure_column("Risk Level", header_name="Risk", width=96, cellStyle=dlg_risk_style)
        if "Info" in final_df.columns:
            gb_dlg.configure_column(
                "Info",
                header_name="Context",
                minWidth=175,
                flex=1.2,
                wrapText=True,
                autoHeight=True,
                tooltipField="Info",
            )
        if "Risk Basis" in final_df.columns:
            gb_dlg.configure_column(
                "Risk Basis",
                header_name="Risk Basis",
                minWidth=175,
                flex=1.2,
                wrapText=True,
                autoHeight=True,
                tooltipField="Risk Basis",
            )

        ag_theme, ag_css = get_aggrid_theme_and_css()
        dlg_grid_options = gb_dlg.build()
        dlg_grid_options["suppressHorizontalScroll"] = False
        dlg_grid_options["alwaysShowHorizontalScroll"] = True
        dlg_grid_options["domLayout"] = "normal"
        dlg_grid_options["alwaysShowVerticalScroll"] = True
        dlg_grid_options["tooltipShowDelay"] = 0
        risk_key = "-".join(sorted(forensic_risk)) if forensic_risk else "none"
        dlg_key_src = f"{view_type}|{selected_f_source}|{risk_key}|{forensic_search.lower()}"
        dlg_key_suffix = re.sub(r"[^0-9A-Za-z_]+", "_", dlg_key_src).strip("_")[:96]
        st.markdown("<div class='shadow-table-shell'>", unsafe_allow_html=True)
        AgGrid(
            final_df,
            gridOptions=dlg_grid_options,
            update_mode=GridUpdateMode.NO_UPDATE,
            data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
            height=_table_height_for_rows(len(final_df), min_px=240, max_px=520),
            theme=ag_theme,
            custom_css=ag_css,
            allow_unsafe_jscode=True,
            fit_columns_on_grid_load=False,
            reload_data=False,
            key=f"dlg_logs_grid_{target_mac}_{dlg_key_suffix}",
        )
        st.markdown("</div>", unsafe_allow_html=True)
        st.caption(f"{len(final_df):,} rows shown in detailed logs (limited to top 1,000).")

    # =============================================================================
    # MOVED: Applications / Software inventory table (BOTTOM)
    # =============================================================================
    st.divider()
    st.markdown("#### Applications / Software Observed (This MAC)")

    inv_where = ["lower(mac) = lower(?)"]
    inv_params = [target_mac]

    # Keep inventory aligned with user filters (source + risk)
    if selected_f_source != "All":
        inv_where.append("upper(source_log) = upper(?)")
        inv_params.append(selected_f_source)

    if forensic_risk:
        inv_in = _build_in_clause(forensic_risk, inv_params)
        inv_where.append(f""""Risk Level" IN {inv_in}""")

    inv_where_sql = " AND ".join(inv_where)

    inventory_df = _sql_fetch_df(
        conn,
        f"""
        WITH base AS (
            SELECT
                domain_clean,
                app_identifier,
                source_log,
                "App Status" AS app_status,
                _risk_score,
                datetime
            FROM shadow_events
            WHERE {inv_where_sql}
              AND domain_clean IS NOT NULL
              AND domain_clean <> ''
        ),
        agg AS (
            SELECT
                domain_clean,
                COALESCE(NULLIF(app_identifier,''), domain_clean) AS app_identifier,
                STRING_AGG(DISTINCT source_log, ', ' ORDER BY source_log) AS sources,
                MIN(datetime) AS first_seen,
                MAX(datetime) AS last_seen,
                COUNT(*) AS hits,
                MAX(_risk_score) AS max_risk_score,
                CASE WHEN SUM(CASE WHEN app_status='Unauthorized' THEN 1 ELSE 0 END) > 0
                     THEN 'Unauthorized' ELSE 'Authorized' END AS status
            FROM base
            GROUP BY 1,2
        )
        SELECT
            domain_clean AS destination,
            app_identifier AS application_or_identifier,
            sources,
            status,
            first_seen,
            last_seen,
            hits,
            CASE max_risk_score
                WHEN 4 THEN 'Critical'
                WHEN 3 THEN 'High'
                WHEN 2 THEN 'Medium'
                WHEN 1 THEN 'Low'
                ELSE 'Safe'
            END AS max_risk
        FROM agg
        ORDER BY
            max_risk_score DESC,
            hits DESC,
            last_seen DESC
        """,
        inv_params,
    )

    if inventory_df.empty:
        st.info("No application inventory could be derived for this MAC (with current filters).")
    else:
        inv_grid = inventory_df.copy()
        inv_grid.insert(0, "#", range(1, len(inv_grid) + 1))
        inv_grid["first_seen"] = pd.to_datetime(inv_grid["first_seen"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")
        inv_grid["last_seen"] = pd.to_datetime(inv_grid["last_seen"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")
        inv_grid["first_seen"] = inv_grid["first_seen"].fillna("")
        inv_grid["last_seen"] = inv_grid["last_seen"].fillna("")

        inv_risk_style = JsCode(
            """
            function(params) {
                const v = (params.value || '').toString();
                if (v === 'Critical') return {color: '#ef4444', fontWeight: '800'};
                if (v === 'High') return {color: '#f97316', fontWeight: '800'};
                if (v === 'Medium') return {color: '#f59e0b', fontWeight: '700'};
                if (v === 'Low') return {color: '#eab308', fontWeight: '700'};
                if (v === 'Safe') return {color: '#22c55e', fontWeight: '700'};
                return {};
            }
            """
        )
        inv_status_style = JsCode(
            """
            function(params) {
                const v = (params.value || '').toString();
                if (v === 'Unauthorized') return {color: '#ef4444', fontWeight: '800'};
                if (v === 'Authorized') return {color: '#22c55e', fontWeight: '700'};
                return {};
            }
            """
        )

        gb_inv = GridOptionsBuilder.from_dataframe(inv_grid)
        gb_inv.configure_default_column(filter=True, sortable=True, resizable=True, minWidth=88)
        gb_inv.configure_pagination(paginationAutoPageSize=False, paginationPageSize=15)
        gb_inv.configure_column("#", header_name="#", width=52, pinned="left", suppressMovable=True)
        gb_inv.configure_column(
            "destination",
            header_name="Destination",
            minWidth=155,
            flex=1.15,
            tooltipField="destination",
        )
        gb_inv.configure_column(
            "application_or_identifier",
            header_name="Application / Identifier",
            minWidth=185,
            flex=1.35,
            wrapText=True,
            autoHeight=True,
            tooltipField="application_or_identifier",
        )
        gb_inv.configure_column(
            "sources",
            header_name="Source Logs",
            minWidth=135,
            flex=1.0,
            wrapText=True,
            autoHeight=True,
            tooltipField="sources",
        )
        gb_inv.configure_column("status", header_name="Status", width=104, cellStyle=inv_status_style)
        gb_inv.configure_column("first_seen", header_name="First Seen", width=152)
        gb_inv.configure_column("last_seen", header_name="Last Seen", width=152)
        gb_inv.configure_column("hits", header_name="Hits", width=72)
        gb_inv.configure_column("max_risk", header_name="Max Risk", width=94, cellStyle=inv_risk_style)

        ag_theme, ag_css = get_aggrid_theme_and_css()
        inv_grid_options = gb_inv.build()
        inv_grid_options["suppressHorizontalScroll"] = False
        inv_grid_options["alwaysShowHorizontalScroll"] = True
        inv_grid_options["domLayout"] = "normal"
        inv_grid_options["alwaysShowVerticalScroll"] = True
        inv_grid_options["tooltipShowDelay"] = 0

        st.markdown("<div class='shadow-table-shell'>", unsafe_allow_html=True)
        AgGrid(
            inv_grid,
            gridOptions=inv_grid_options,
            update_mode=GridUpdateMode.NO_UPDATE,
            data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
            height=_table_height_for_rows(len(inv_grid), min_px=240, max_px=520),
            theme=ag_theme,
            custom_css=ag_css,
            allow_unsafe_jscode=True,
            fit_columns_on_grid_load=False,
            reload_data=False,
            key=f"dlg_inventory_grid_{target_mac}",
        )
        st.markdown("</div>", unsafe_allow_html=True)
        st.caption(f"{len(inv_grid):,} rows shown in application inventory.")

        st.download_button(
            "Download Application Inventory CSV",
            data=inventory_df.to_csv(index=False).encode("utf-8"),
            file_name=f"shadow_app_inventory_{target_mac}.csv",
            mime="text/csv",
        )

def hide_dialog_x_button():
    st.markdown(
        """
        <style>
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

def inject_license_white_text_css():
    st.markdown(
        """
        <style>
        /* Make text white inside License section and streamlit widgets */
        .license-section, .license-section * {
            color: #EAEAEA !important;
        }

        /* Fix Streamlit dataframe/table text in dark background */
        .license-section [data-testid="stDataFrame"] * {
            color: #EAEAEA !important;
        }
        .license-section table * {
            color: #EAEAEA !important;
        }

        /* Inputs / selects inside license area */
        .license-section input, 
        .license-section textarea, 
        .license-section select {
            color: #EAEAEA !important;
            background: #000 !important;
        }

        /* Streamlit expander header text */
        .license-section [data-testid="stExpander"] summary * {
            color: #EAEAEA !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

# =============================================================================
# Main Render
# =============================================================================
def render_shadow_apps(parquet_root: Path):
    hide_dialog_x_button()
    inject_shadow_apps_css()

    # --- init state ---
    st.session_state.setdefault("shadow_dialog_open", False)
    st.session_state.setdefault("shadow_dialog_mac", None)
    st.session_state.setdefault("shadow_last_selected_mac", None)
    st.session_state.setdefault("shadow_grid_nonce", 0)

    # --- auto-close stale dialogs ---
    origin = st.session_state.pop("shadow_dialog_origin", None)
    if st.session_state.get("shadow_dialog_open") and origin not in ("grid", "dialog"):
        _close_shadow_dialog(reset_grid=False)

    available_dates = list_available_dates(parquet_root)
    if not available_dates:
        st.warning("No log directories found.")
        return

    def _on_day_change():
        _close_shadow_dialog(reset_grid=True)

    day_col, day_hint_col = st.columns([1.2, 2])
    with day_col:
        selected_day = st.selectbox(
            "Dataset Day",
            available_dates,
            index=0,
            key="shadow_day_select",
            on_change=_on_day_change,
        )
    with day_hint_col:
        st.markdown(
            f"<div class='shadow-day-chip'>Active date: &nbsp; <strong>{selected_day}</strong></div>",
            unsafe_allow_html=True,
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
    auth_pct = (authorized_count / total_events * 100) if total_events else 0
    unauth_pct = (unauthorized_count / total_events * 100) if total_events else 0
    crit_high_pct = (crit_high_count / total_events * 100) if total_events else 0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", f"{total_events:,}")
    col2.metric("Authorized Events", f"{authorized_count:,}", f"{auth_pct:.1f}% of total")
    col3.metric("Unauthorized Events", f"{unauthorized_count:,}", f"{unauth_pct:.1f}% of total", delta_color="inverse")
    col4.metric("Critical / High Risk", f"{crit_high_count:,}", f"{crit_high_pct:.1f}% of total", delta_color="inverse")

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
                color_discrete_map=STATUS_COLORS,
                markers=True,
            )
            style_plotly_figure(fig, height=345)
            fig.update_xaxes(title=None)
            fig.update_yaxes(title="Events")
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
            fig_pie = px.pie(
                df_pie,
                values="Log Count",
                names="source_log",
                hole=0.45,
                color_discrete_sequence=px.colors.qualitative.Bold,
            )
            style_plotly_figure(fig_pie, height=345)
            fig_pie.update_traces(textposition="inside", textinfo="percent+label")
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No data for source chart.")

    t1, t2 = st.tabs(["Application Audit & License", "Data Exfiltration Threats"])

    # =============================================================================
    # TAB 1: AgGrid (CLICK ROW -> OPEN DIALOG)
    # =============================================================================
    with t1:
        st.markdown("### Application Audit Log")
        st.markdown(
            "<div class='shadow-callout'>Click a row to open the per-device forensics dialog for that MAC address.</div>",
            unsafe_allow_html=True,
        )

        st.markdown("<div class='shadow-filter-shell'>", unsafe_allow_html=True)
        top_filter_col1, top_filter_col2 = st.columns([3.2, 1.8])
        with top_filter_col1:
            search_query_audit = st.text_input(
                "Search (MAC, Hostname, IP, Domain)",
                placeholder="e.g., 192.168.1.14 or github.com",
                key="audit_search",
            ).strip()
        with top_filter_col2:
            status_filter = st.radio(
                "Filter Status",
                ["All", "Authorized", "Unauthorized"],
                horizontal=True,
                key="audit_status_filter",
            )
        bottom_filter_col1, bottom_filter_col2 = st.columns([2.2, 2.2])
        with bottom_filter_col1:
            audit_risk_filter = risk_multiselect(
                "Filter Risk",
                key="audit_risk_filter",
                default=["Critical", "High", "Medium", "Low", "Safe"],
            )
        with bottom_filter_col2:
            # Pull available sources from the data (for the selected day already loaded into shadow_events)
            src_df_audit = _sql_fetch_df(conn, "SELECT DISTINCT source_log FROM shadow_events ORDER BY 1")
            audit_sources = src_df_audit["source_log"].dropna().tolist() if not src_df_audit.empty else []
            audit_source_filter = st.multiselect(
                "Filter Source",
                audit_sources,
                default=audit_sources,   # default = all
                key="audit_source_filter",
            )
        st.markdown("</div>", unsafe_allow_html=True)

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
            where.append("(mac ILIKE ? OR hostname ILIKE ? OR ip ILIKE ? OR domain_clean ILIKE ?)")
            params.extend([q, q, q, q])

        if audit_source_filter:
            in_clause = _build_in_clause(audit_source_filter, params)
            where.append(f"source_log IN {in_clause}")

        risk_summary = ", ".join(audit_risk_filter) if audit_risk_filter else "None"
        source_summary = f"{len(audit_source_filter)} selected" if audit_source_filter else "None"
        search_summary = "On" if search_query_audit else "Off"
        st.markdown(
            f"<div class='shadow-filter-hint'>Status: <strong>{status_filter}</strong> | Risk: <strong>{risk_summary}</strong> | Sources: <strong>{source_summary}</strong> | Search: <strong>{search_summary}</strong></div>",
            unsafe_allow_html=True,
        )

        where_sql = "WHERE " + " AND ".join(where) if where else ""

        audit_sql = f"""
        WITH base AS (
            SELECT
                domain_clean,
                mac,
                hostname,
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
                hostname,
                ip,
                source_log,
                "App Status",
                MIN(datetime) AS First_Seen,
                MAX(datetime) AS Last_Seen,
                COUNT(*) AS Hits,
                MAX(_risk_score) AS Max_Risk_Score
            FROM base
            GROUP BY 1,2,3,4,5,6
        ),
        pick_basis AS (
            SELECT
                domain_clean,
                mac,
                hostname,
                ip,
                source_log,
                "App Status",
                risk_basis AS Max_Risk_Basis,
                ROW_NUMBER() OVER (
                    PARTITION BY domain_clean, mac, hostname, ip, source_log, "App Status"
                    ORDER BY _risk_score DESC, datetime DESC
                ) AS rn
            FROM base
        )
        SELECT
            a.domain_clean,
            a.mac,
            a.hostname,
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
            ON a.domain_clean=b.domain_clean
           AND a.mac=b.mac
           AND a.hostname=b.hostname
           AND a.ip=b.ip
           AND a.source_log=b.source_log
           AND a."App Status"=b."App Status"
        ORDER BY a.Max_Risk_Score DESC, a.Hits DESC
        LIMIT 1000
        """

        display_df = _sql_fetch_df(conn, audit_sql, params)

        if display_df.empty:
            st.info("No logs match your filter.")
        else:
            # Add row index column like license grid (optional but makes it feel identical)
            df_grid = display_df.copy()
            df_grid.insert(0, "#", range(1, len(df_grid) + 1))

            gb = GridOptionsBuilder.from_dataframe(df_grid)

            # Make it behave like the License Users grid (filter/sort/resize + footer pagination)
            gb.configure_default_column(filter=True, sortable=True, resizable=True)

            # IMPORTANT: pagination gives you the bottom footer bar (what you called "bottom header")
            gb.configure_pagination(paginationAutoPageSize=False, paginationPageSize=15)

            # Keep single-row selection
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
                    let color = '#22c55e';
                    let weight = '700';
                    if (v === 'Critical') { color = '#ef4444'; weight = '900'; }
                    else if (v === 'High') { color = '#f97316'; weight = '900'; }
                    else if (v === 'Medium') { color = '#f59e0b'; weight = '800'; }
                    else if (v === 'Low') { color = '#eab308'; weight = '800'; }
                    else if (v === 'Safe') { color = '#22c55e'; weight = '800'; }
                    return { 'color': color, 'fontWeight': weight };
                }
                """
            )

            status_cellstyle = JsCode(
                """
                function(params) {
                    const v = (params.value || '').toString();
                    if (v === 'Unauthorized') {
                        return { 'color': '#ef4444', 'fontWeight': '800' };
                    }
                    if (v === 'Authorized') {
                        return { 'color': '#22c55e', 'fontWeight': '700' };
                    }
                    return {};
                }
                """
            )

            # Column formatting (match)
            gb.configure_column("#", header_name="#", width=70, pinned="left", suppressMovable=True, resizable=False)
            gb.configure_column("mac", header_name="MAC Address (Click)", cellStyle=mac_cellstyle)
            gb.configure_column("App Status", header_name="Status", cellStyle=status_cellstyle, width=125)
            gb.configure_column("Max_Risk", header_name="Risk Level", cellStyle=risk_cellstyle)

            # Optional: tighten these widths (feel more like a fixed enterprise table)
            gb.configure_column("domain_clean", header_name="Domain", minWidth=220)
            gb.configure_column("hostname", header_name="Hostname", minWidth=160)
            gb.configure_column("ip", header_name="IP", minWidth=130)
            gb.configure_column("source_log", header_name="Source", width=110)
            gb.configure_column("Hits", header_name="Hits", width=90)
            gb.configure_column("First_Seen", header_name="First Seen", width=170)
            gb.configure_column("Last_Seen", header_name="Last Seen", width=170)

            grid_options = gb.build()
            grid_options["rowSelection"] = "single"
            grid_options["suppressRowClickSelection"] = False
            grid_options["rowMultiSelectWithClick"] = False
            grid_options["domLayout"] = "normal"
            grid_options["alwaysShowVerticalScroll"] = True
            grid_options["suppressHorizontalScroll"] = False
            grid_options["alwaysShowHorizontalScroll"] = True

            ag_theme, ag_css = get_aggrid_theme_and_css()
            audit_ag_css = dict(ag_css)
            audit_ag_css.update(
                {
                    ".ag-root-wrapper": {"background-color": "#061120", "color": "#EAF2FF", "border": "1px solid #2A466E"},
                    ".ag-header": {"background-color": "#10213E", "color": "#EAF2FF", "border-bottom": "1px solid #3A5A8E"},
                    ".ag-header-cell, .ag-header-group-cell": {"background-color": "#10213E", "color": "#EAF2FF", "border-right": "1px solid #2A466E"},
                    ".ag-row-odd": {"background-color": "#07162A"},
                    ".ag-row-even": {"background-color": "#0A1C33"},
                    ".ag-row-hover": {"background-color": "#13305A"},
                    ".ag-row-selected": {"background-color": "#1B3F75"},
                }
            )

            grid_key = f"shadow_audit_grid_{int(st.session_state.get('shadow_grid_nonce', 0))}"

            st.markdown("<div class='shadow-table-shell'>", unsafe_allow_html=True)
            grid_response = AgGrid(
                df_grid,
                gridOptions=grid_options,
                update_mode=GridUpdateMode.SELECTION_CHANGED,
                data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
                height=_table_height_for_rows(len(df_grid), min_px=240, max_px=520),
                theme=ag_theme,
                custom_css=audit_ag_css,
                allow_unsafe_jscode=True,
                fit_columns_on_grid_load=False,
                reload_data=False,
                key=grid_key,
            )
            st.markdown("</div>", unsafe_allow_html=True)
            st.caption(f"{len(df_grid):,} grouped rows shown (limited to top 1,000).")

            # selection -> open dialog
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
                st.session_state["shadow_last_selected_mac"] = None

        # =============================================================================
        # License Compliance (NO DROPDOWN - TABLE)
        # =============================================================================
        st.divider()
        st.markdown("### License Compliance Audit")

        # summary + details
        usage_rows = []
        details_all = []

        # ensure hostname exists (fallback view already injects it)
        shadow_cols = set(_describe_cols(conn, "shadow_events"))
        has_hostname = "hostname" in shadow_cols

        for software in LICENSE_REGISTRY.keys():
            cnt = conn.execute(
                """
                SELECT COUNT(DISTINCT mac)
                FROM shadow_events
                WHERE domain_clean ILIKE ?
                  AND mac IS NOT NULL AND mac <> '' AND lower(mac) <> 'unknown'
                """,
                [f"%{software}%"],
            ).fetchone()
            unique_users = int(cnt[0]) if cnt else 0
            status = "Usage Detected" if unique_users > 0 else "No Usage"
            usage_rows.append({"Software": software, "Active Devices Count": unique_users, "Status": status})

            # details per software
            if has_hostname:
                df_sw = conn.execute(
                    """
                    SELECT
                        ? AS Software,
                        mac AS mac,
                        arg_max(hostname, datetime) AS hostname,
                        MAX(datetime) AS last_seen,
                        COUNT(*) AS events
                    FROM shadow_events
                    WHERE domain_clean ILIKE ?
                      AND mac IS NOT NULL AND mac <> '' AND lower(mac) <> 'unknown'
                    GROUP BY mac
                    ORDER BY last_seen DESC NULLS LAST
                    """,
                    [software, f"%{software}%"],
                ).df()
            else:
                df_sw = conn.execute(
                    """
                    SELECT
                        ? AS Software,
                        mac AS mac,
                        'Unknown' AS hostname,
                        MAX(datetime) AS last_seen,
                        COUNT(*) AS events
                    FROM shadow_events
                    WHERE domain_clean ILIKE ?
                      AND mac IS NOT NULL AND mac <> '' AND lower(mac) <> 'unknown'
                    GROUP BY mac
                    ORDER BY last_seen DESC NULLS LAST
                    """,
                    [software, f"%{software}%"],
                ).df()

            if not df_sw.empty:
                df_sw["mac"] = df_sw["mac"].apply(normalize_mac)
                df_sw["hostname"] = df_sw["hostname"].fillna("Unknown").astype(str).replace({"": "Unknown"})
                df_sw["last_seen"] = pd.to_datetime(df_sw["last_seen"], errors="coerce")
                details_all.append(df_sw)

        usage_df = pd.DataFrame(usage_rows)
        in_use_count = int((usage_df["Status"] == "Usage Detected").sum())
        tracked_software = int(len(usage_df))
        active_licensed_devices = int(usage_df["Active Devices Count"].sum())

        l1, l2, l3 = st.columns(3)
        l1.metric("Software Tracked", f"{tracked_software:,}")
        l2.metric("Software In Use", f"{in_use_count:,}")
        l3.metric("Total Active Devices", f"{active_licensed_devices:,}")

        table_col, chart_col = st.columns([1.7, 1])

        with table_col:
            st.markdown("<div class='shadow-table-shell'>", unsafe_allow_html=True)
            st.dataframe(
                usage_df.style.map(
                    lambda x: "color: #FF4B4B; font-weight: 600;"
                    if x == "Usage Detected"
                    else "color: #00CC96; font-weight: 600;",
                    subset=["Status"],
                ),
                use_container_width=True,
                hide_index=True,
                height=_table_height_for_rows(len(usage_df), row_px=36, header_px=44, min_px=190, max_px=360),
            )
            st.markdown("</div>", unsafe_allow_html=True)

        with chart_col:
            usage_chart_df = usage_df.sort_values("Active Devices Count", ascending=False)
            fig = px.bar(
                usage_chart_df,
                x="Software",
                y="Active Devices Count",
                text_auto=True,
                color="Status",
                color_discrete_map={"Usage Detected": "#f97316", "No Usage": "#22c55e"},
            )
            style_plotly_figure(fig, height=420)
            fig.update_layout(xaxis_title=None, yaxis_title="Active Devices", legend_title=None)
            st.plotly_chart(fig, use_container_width=True)

        st.markdown("#### License Users")
        if details_all:
            license_df = pd.concat(details_all, ignore_index=True)

            gb2 = GridOptionsBuilder.from_dataframe(license_df)
            gb2.configure_default_column(filter=True, sortable=True, resizable=True)
            gb2.configure_pagination(paginationAutoPageSize=False, paginationPageSize=15)
            license_grid_options = gb2.build()
            license_grid_options["domLayout"] = "normal"
            license_grid_options["alwaysShowVerticalScroll"] = True
            license_grid_options["suppressHorizontalScroll"] = False
            license_grid_options["alwaysShowHorizontalScroll"] = True

            ag_theme, ag_css = get_aggrid_theme_and_css()

            st.markdown("<div class='shadow-table-shell'>", unsafe_allow_html=True)
            AgGrid(
                license_df,
                gridOptions=license_grid_options,
                update_mode=GridUpdateMode.NO_UPDATE,
                data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
                height=_table_height_for_rows(len(license_df), min_px=240, max_px=520),
                theme=ag_theme,
                custom_css=ag_css,
                allow_unsafe_jscode=False,
                fit_columns_on_grid_load=False,
                reload_data=False,
                key="license_devices_grid",
            )
            st.markdown("</div>", unsafe_allow_html=True)

            st.download_button(
                "Download License Users CSV",
                data=license_df.to_csv(index=False).encode("utf-8"),
                file_name="license_users.csv",
                mime="text/csv",
            )
        else:
            st.info("No license usage detected for the selected day.")

    # =============================================================================
    # TAB 2 (kept: your existing content can remain here)
    # =============================================================================
    with t2:
        st.markdown("### Unauthorized Threat Dashboard")
        st.markdown(
            "<div class='shadow-callout'>Focused view of unauthorized apps, exfiltration indicators, and risk concentration.</div>",
            unsafe_allow_html=True,
        )

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
            st.metric("Active Unauthorized Apps", f"{unauth_apps:,}")
        with u_metrics2:
            st.metric("Top Offender (MAC)", top_offender, delta=f"{top_offender_cnt:,} events", delta_color="inverse")
        with u_metrics3:
            st.metric("Critical / High Risks", f"{crit_high_unauth:,}", delta="Requires attention", delta_color="inverse")

        st.divider()

        exfil_scope_where_sql = """"App Status"='Unauthorized'"""
        exfil_scope_params = []

        with st.expander("Data Exfiltration Monitor (High Volume Traffic)", expanded=True):
            st.markdown("<div class='shadow-filter-shell'>", unsafe_allow_html=True)
            exf_top_1, exf_top_2, exf_top_3 = st.columns([1.4, 1.6, 2.2])
            with exf_top_1:
                exfil_risk_filter = risk_multiselect(
                    "Exfiltration Risk",
                    key="exfil_risk_filter",
                    default=["Critical", "High", "Medium", "Low", "Safe"],
                )
            with exf_top_2:
                behavior_df = _sql_fetch_df(
                    conn,
                    """
                    SELECT DISTINCT COALESCE(Behavior, 'Unknown') AS Behavior
                    FROM shadow_events
                    WHERE "App Status"='Unauthorized'
                    ORDER BY 1
                    """,
                )
                behavior_options = behavior_df["Behavior"].dropna().tolist() if not behavior_df.empty else []
                exfil_behavior_filter = st.multiselect(
                    "Behavior",
                    behavior_options,
                    default=behavior_options,
                    key="exfil_behavior_filter",
                )
            with exf_top_3:
                exfil_search = st.text_input(
                    "Search Exfiltration (MAC/IP/Domain/Host)",
                    placeholder="e.g., suspicious.com or 192.168.1.44",
                    key="exfil_search",
                ).strip()

            max_bytes_df = _sql_fetch_df(
                conn,
                """
                SELECT COALESCE(MAX(bytes_sent), 0) AS max_bytes
                FROM shadow_events
                WHERE "App Status"='Unauthorized' AND COALESCE(bytes_sent,0) > 0
                """,
            )
            max_bytes = int(max_bytes_df.loc[0, "max_bytes"]) if not max_bytes_df.empty else 0
            max_mb = int(max(10, min(5000, max_bytes / 1_000_000 if max_bytes > 0 else 10)))

            exf_bottom_1, exf_bottom_2 = st.columns([1.4, 2.0])
            with exf_bottom_1:
                exfil_min_mb = st.slider("Min Upload (MB)", 0, max_mb, min(5, max_mb), key="exfil_min_mb")
            with exf_bottom_2:
                exfil_chart_mode = st.radio(
                    "Graph Type",
                    ["Bubble by Port", "Hourly Upload Trend"],
                    horizontal=True,
                    key="exfil_chart_mode",
                )
            st.markdown("</div>", unsafe_allow_html=True)

            exfil_scope_where = [""""App Status"='Unauthorized'"""]
            exfil_scope_params = []
            if exfil_risk_filter:
                in_clause = _build_in_clause(exfil_risk_filter, exfil_scope_params)
                exfil_scope_where.append(f""""Risk Level" IN {in_clause}""")
            if exfil_behavior_filter:
                in_clause = _build_in_clause(exfil_behavior_filter, exfil_scope_params)
                exfil_scope_where.append(f"COALESCE(Behavior, 'Unknown') IN {in_clause}")
            if exfil_search:
                q = f"%{exfil_search}%"
                exfil_scope_where.append("(mac ILIKE ? OR hostname ILIKE ? OR ip ILIKE ? OR domain_clean ILIKE ?)")
                exfil_scope_params.extend([q, q, q, q])

            exfil_scope_where_sql = " AND ".join(exfil_scope_where)
            exfil_where = list(exfil_scope_where)
            exfil_params = list(exfil_scope_params)
            min_upload_bytes = int(exfil_min_mb * 1_000_000)
            if min_upload_bytes > 0:
                exfil_where.append("COALESCE(bytes_sent,0) >= ?")
                exfil_params.append(min_upload_bytes)
            else:
                exfil_where.append("COALESCE(bytes_sent,0) > 0")

            exfil_where_sql = " AND ".join(exfil_where)
            exfil_points = _sql_fetch_df(
                conn,
                f"""
                SELECT datetime, dst_port, bytes_sent, bytes_received, COALESCE(Behavior,'Unknown') AS Behavior,
                       domain_clean, mac, hostname, "Risk Level"
                FROM shadow_events
                WHERE {exfil_where_sql}
                ORDER BY bytes_sent DESC
                LIMIT 5000
                """,
                exfil_params,
            )

            filtered_sent_gb = float(exfil_points["bytes_sent"].sum()) / 1_000_000_000 if not exfil_points.empty else 0.0
            filtered_recv_gb = float(exfil_points["bytes_received"].sum()) / 1_000_000_000 if not exfil_points.empty else 0.0

            st.markdown(
                f"<div class='shadow-filter-hint'>Risk: <strong>{', '.join(exfil_risk_filter) if exfil_risk_filter else 'None'}</strong> | Behavior: <strong>{len(exfil_behavior_filter)} selected</strong> | Search: <strong>{'On' if exfil_search else 'Off'}</strong> | Min Upload: <strong>{exfil_min_mb} MB</strong></div>",
                unsafe_allow_html=True,
            )

            exfil_c1, exfil_c2 = st.columns([1, 2])
            with exfil_c1:
                st.metric("Filtered Upload", f"{filtered_sent_gb:.2f} GB", delta="Potential leak", delta_color="inverse")
                st.metric("Filtered Download", f"{filtered_recv_gb:.2f} GB")
                st.metric("Filtered Events", f"{len(exfil_points):,}")

            with exfil_c2:
                if not exfil_points.empty:
                    if exfil_chart_mode == "Bubble by Port":
                        fig_exfil = px.scatter(
                            exfil_points,
                            x="dst_port",
                            y="bytes_sent",
                            size="bytes_sent",
                            color="Risk Level",
                            color_discrete_map=RISK_COLORS,
                            hover_data=["domain_clean", "mac", "hostname", "Behavior"],
                            title="Outbound Data Volume by Port",
                        )
                        style_plotly_figure(fig_exfil, height=360)
                        fig_exfil.update_xaxes(title="Destination Port")
                        fig_exfil.update_yaxes(title="Bytes Sent")
                    else:
                        trend = exfil_points.copy()
                        trend["datetime"] = pd.to_datetime(trend["datetime"], errors="coerce")
                        trend = trend.dropna(subset=["datetime"])
                        if trend.empty:
                            fig_exfil = None
                        else:
                            trend["hour"] = trend["datetime"].dt.floor("1H")
                            trend = trend.groupby("hour", as_index=False)["bytes_sent"].sum()
                            fig_exfil = px.line(
                                trend,
                                x="hour",
                                y="bytes_sent",
                                markers=True,
                                color_discrete_sequence=["#38bdf8"],
                                title="Hourly Outbound Upload Volume",
                            )
                            style_plotly_figure(fig_exfil, height=360, show_legend=False)
                            fig_exfil.update_xaxes(title=None)
                            fig_exfil.update_yaxes(title="Bytes Sent")

                    if fig_exfil is None:
                        st.info("No timestamped events available for trend graph.")
                    else:
                        st.plotly_chart(fig_exfil, use_container_width=True)
                else:
                    st.info("No significant outbound traffic detected with current filters.")

        st.divider()

        u_chart1, u_chart2 = st.columns([2, 1])
        with u_chart1:
            st.markdown("#### Top Unauthorized Domains")
            top_unauth = _sql_fetch_df(
                conn,
                f"""
                SELECT domain_clean AS Domain, COUNT(*) AS Hits
                FROM shadow_events
                WHERE {exfil_scope_where_sql}
                GROUP BY 1
                ORDER BY 2 DESC
                LIMIT 10
                """,
                exfil_scope_params,
            )
            if not top_unauth.empty:
                fig_u1 = px.bar(
                    top_unauth,
                    x="Hits",
                    y="Domain",
                    orientation="h",
                    color_discrete_sequence=["#f97316"],
                )
                style_plotly_figure(fig_u1, height=360, show_legend=False)
                fig_u1.update_layout(yaxis={"categoryorder": "total ascending"})
                st.plotly_chart(fig_u1, use_container_width=True)
            else:
                st.info("No unauthorized domains found.")

        with u_chart2:
            st.markdown("#### Risk Distribution")
            risk_counts = _sql_fetch_df(
                conn,
                f"""
                SELECT "Risk Level" AS Risk, COUNT(*) AS Count
                FROM shadow_events
                WHERE {exfil_scope_where_sql}
                GROUP BY 1
                ORDER BY 2 DESC
                """,
                exfil_scope_params,
            )
            if not risk_counts.empty:
                fig_u2 = px.pie(
                    risk_counts,
                    values="Count",
                    names="Risk",
                    color="Risk",
                    color_discrete_map=RISK_COLORS,
                    hole=0.6,
                )
                style_plotly_figure(fig_u2, height=360)
                st.plotly_chart(fig_u2, use_container_width=True)
            else:
                st.info("No risk distribution data.")

        st.divider()

        st.markdown("### Threat Details")
        st.markdown("<div class='shadow-filter-shell'>", unsafe_allow_html=True)
        af_top_1, af_top_2 = st.columns([1.25, 1.75])
        af_bottom_1, _ = st.columns([3, 1])

        with af_top_1:
            filter_risk = risk_multiselect("Filter by Risk", key="unauth_risk_filter", default=["Critical", "High", "Medium", "Low"])

        with af_top_2:
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

        with af_bottom_1:
            search_query_unauth = st.text_input(
                "Search (IP, MAC, Domain)",
                placeholder="e.g., be:18:78:9d:3f:b1 or suspicious-domain.com",
                key="unauth_search",
            ).strip()
        st.markdown("</div>", unsafe_allow_html=True)

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
            where.append("(mac ILIKE ? OR hostname ILIKE ? OR ip ILIKE ? OR domain_clean ILIKE ?)")
            params.extend([q, q, q, q])

        threat_risk_summary = ", ".join(filter_risk) if filter_risk else "None"
        threat_source_summary = f"{len(filter_source)} selected" if filter_source else "None"
        threat_search_summary = "On" if search_query_unauth else "Off"
        st.markdown(
            f"<div class='shadow-filter-hint'>Risk: <strong>{threat_risk_summary}</strong> | Sources: <strong>{threat_source_summary}</strong> | Search: <strong>{threat_search_summary}</strong></div>",
            unsafe_allow_html=True,
        )

        where_sql = " AND ".join(where)

        detail_table = _sql_fetch_df(
            conn,
            f"""
            SELECT
                datetime,
                mac,
                hostname,
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
            detail_grid = detail_table.copy()
            detail_grid["datetime"] = pd.to_datetime(detail_grid["datetime"], errors="coerce")
            detail_grid["datetime"] = detail_grid["datetime"].dt.strftime("%Y-%m-%d %H:%M:%S")
            detail_grid["datetime"] = detail_grid["datetime"].fillna("")

            threat_risk_style = JsCode(
                """
                function(params) {
                    const v = (params.value || '').toString();
                    if (v === 'Critical') return {color: '#ef4444', fontWeight: '800'};
                    if (v === 'High') return {color: '#f97316', fontWeight: '800'};
                    if (v === 'Medium') return {color: '#f59e0b', fontWeight: '700'};
                    if (v === 'Low') return {color: '#eab308', fontWeight: '700'};
                    if (v === 'Safe') return {color: '#22c55e', fontWeight: '700'};
                    return {};
                }
                """
            )
            bytes_style = JsCode(
                """
                function(params) {
                    const v = Number(params.value || 0);
                    if (v > 100000000) return {color: '#fb7185', fontWeight: '700'};
                    if (v > 10000000) return {color: '#f59e0b', fontWeight: '700'};
                    return {color: '#93c5fd'};
                }
                """
            )

            gb_threat = GridOptionsBuilder.from_dataframe(detail_grid)
            gb_threat.configure_default_column(filter=True, sortable=True, resizable=True)
            gb_threat.configure_pagination(paginationAutoPageSize=False, paginationPageSize=20)
            gb_threat.configure_column("datetime", header_name="Timestamp", width=170)
            gb_threat.configure_column("domain_clean", header_name="Unauthorized Domain", minWidth=210)
            gb_threat.configure_column("source_log", header_name="Source", width=110)
            gb_threat.configure_column("Info", header_name="Context", minWidth=230)
            gb_threat.configure_column("dst_port", header_name="Port", width=90)
            gb_threat.configure_column("bytes_sent", header_name="Upload (Bytes)", width=140, cellStyle=bytes_style)
            gb_threat.configure_column("bytes_received", header_name="Download (Bytes)", width=150, cellStyle=bytes_style)
            gb_threat.configure_column("Risk Level", header_name="Threat Risk", width=118, cellStyle=threat_risk_style)
            gb_threat.configure_column("Risk Basis", header_name="Risk Basis", minWidth=220)
            threat_grid_options = gb_threat.build()
            threat_grid_options["domLayout"] = "normal"
            threat_grid_options["alwaysShowVerticalScroll"] = True
            threat_grid_options["suppressHorizontalScroll"] = False
            threat_grid_options["alwaysShowHorizontalScroll"] = True

            ag_theme, ag_css = get_aggrid_theme_and_css()
            st.markdown("<div class='shadow-table-shell'>", unsafe_allow_html=True)
            AgGrid(
                detail_grid,
                gridOptions=threat_grid_options,
                update_mode=GridUpdateMode.NO_UPDATE,
                data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
                height=_table_height_for_rows(len(detail_grid), min_px=240, max_px=520),
                theme=ag_theme,
                custom_css=ag_css,
                allow_unsafe_jscode=True,
                fit_columns_on_grid_load=False,
                reload_data=False,
                key="exfil_threat_details_grid",
            )
            st.markdown("</div>", unsafe_allow_html=True)
            st.caption(f"{len(detail_table):,} threat events shown (limited to 1,000).")
