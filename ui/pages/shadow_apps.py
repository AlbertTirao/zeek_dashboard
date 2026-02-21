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

# Bump version so old cached parquet (without app_software / readable risk basis) gets rebuilt automatically
CACHE_VERSION = "shadow-cache-v4-app-software"

# -----------------------------
# Config
# -----------------------------
WHITELIST_FILE = Path(__file__).resolve().parents[2] / "whitelist_domains.yaml"
RISK_POLICY_FILE = Path(__file__).resolve().parents[2] / "risk_policy.yaml"
CACHE_DIRNAME = "_shadow_cache_apps"

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
RISK_OPTIONS = ["Critical", "High", "Medium", "Low", "Safe"]

# Behavior-driven thresholds (applied before policy-based matching).
EXFIL_BYTES_SENT_THRESHOLD = 10_000_000
HEAVY_DOWNLOAD_BYTES_RECEIVED_THRESHOLD = 100_000_000
PROTOCOL_ANOMALY_SOURCE_LOG = "WEIRD"

_MAC_HEX_RE = re.compile(r"[^0-9a-fA-F]")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_APP_SOFTWARE_NULLS = {"", "-", "unknown", "nan", "none", "null", "n/a", "unidentified_activity"}


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


def _fmt_mb_threshold(num_bytes: int) -> str:
    mb = float(num_bytes) / 1_000_000.0
    if mb.is_integer():
        return f"{int(mb)} MB"
    return f"{mb:.1f} MB"


def _policy_section(policy: dict, level: str) -> dict:
    if not isinstance(policy, dict):
        return {}
    section = policy.get(level, {})
    return section if isinstance(section, dict) else {}


def _policy_logs(policy: dict, level: str) -> set[str]:
    section = _policy_section(policy, level)
    out = set()
    for x in (section.get("source_logs", []) or []):
        s = str(x).strip()
        if s:
            out.add(s.upper())
    return out


def _policy_ports(policy: dict, level: str) -> set[int]:
    section = _policy_section(policy, level)
    out = set()
    for p in (section.get("ports", []) or []):
        try:
            out.add(int(p))
        except Exception:
            pass
    return out


def _policy_statuses(policy: dict, level: str) -> set[str]:
    section = _policy_section(policy, level)
    out = set()
    for x in (section.get("app_status", []) or []):
        s = str(x).strip()
        if s:
            out.add(s)
    return out


def build_risk_policy_reference(policy: dict) -> pd.DataFrame:
    rows = [
        {
            "Order": 1,
            "Risk Level": "Critical",
            "Rule Source": "Behavior",
            "Trigger": (
                "Potential Exfiltration: bytes_sent > "
                f"{EXFIL_BYTES_SENT_THRESHOLD:,} ({_fmt_mb_threshold(EXFIL_BYTES_SENT_THRESHOLD)})"
            ),
        },
        {
            "Order": 2,
            "Risk Level": "High",
            "Rule Source": "Behavior",
            "Trigger": f"Protocol Anomaly: source_log = {PROTOCOL_ANOMALY_SOURCE_LOG}",
        },
        {
            "Order": 3,
            "Risk Level": "Medium",
            "Rule Source": "Behavior",
            "Trigger": (
                "Heavy Download: bytes_received > "
                f"{HEAVY_DOWNLOAD_BYTES_RECEIVED_THRESHOLD:,} ({_fmt_mb_threshold(HEAVY_DOWNLOAD_BYTES_RECEIVED_THRESHOLD)})"
            ),
        },
    ]

    order = 4
    for lvl_key, lvl_name in (("critical", "Critical"), ("high", "High"), ("medium", "Medium")):
        logs = sorted(_policy_logs(policy, lvl_key))
        ports = sorted(_policy_ports(policy, lvl_key))
        if logs:
            rows.append(
                {
                    "Order": order,
                    "Risk Level": lvl_name,
                    "Rule Source": "risk_policy.yaml",
                    "Trigger": f"{lvl_key}.source_logs contains source_log ({', '.join(logs)})",
                }
            )
            order += 1
        if ports:
            rows.append(
                {
                    "Order": order,
                    "Risk Level": lvl_name,
                    "Rule Source": "risk_policy.yaml",
                    "Trigger": f"{lvl_key}.ports contains destination port ({', '.join(str(p) for p in ports)})",
                }
            )
            order += 1

    low_statuses = sorted(_policy_statuses(policy, "low"))
    if low_statuses:
        rows.append(
            {
                "Order": order,
                "Risk Level": "Low",
                "Rule Source": "risk_policy.yaml",
                "Trigger": f"low.app_status contains App Status ({', '.join(low_statuses)})",
            }
        )
        order += 1

    default_raw = str(policy.get("default", "Safe")) if isinstance(policy, dict) and policy else "Safe"
    default_risk = score_to_risk(risk_score(default_raw))
    if policy:
        rows.append(
            {
                "Order": order,
                "Risk Level": default_risk,
                "Rule Source": "risk_policy.yaml",
                "Trigger": f"default = '{default_raw}' (used when no rule above matches)",
            }
        )
    else:
        rows.append(
            {
                "Order": order,
                "Risk Level": "Safe",
                "Rule Source": "Fallback",
                "Trigger": "No risk_policy.yaml loaded; fallback to Safe",
            }
        )

    return pd.DataFrame(rows)


def _mark_dialog_origin():
    st.session_state["shadow_dialog_origin"] = "dialog"


def risk_multiselect(label: str, key: str, default=None, on_change=None):
    if default is None:
        default = ["Critical", "High", "Medium", "Low"]
    return st.multiselect(
        label,
        RISK_OPTIONS,
        default=default,
        key=key,
        on_change=on_change,
    )


def summarize_multiselect(selected, all_options, *, all_label="All", none_label="None") -> str:
    selected_list = [str(v).strip() for v in (selected or []) if str(v).strip()]
    all_list = [str(v).strip() for v in (all_options or []) if str(v).strip()]
    if not selected_list:
        return none_label
    if all_list and set(selected_list) == set(all_list):
        return all_label
    return ", ".join(selected_list)


def _close_shadow_dialog(reset_grid: bool = True):
    st.session_state["shadow_dialog_open"] = False
    st.session_state["shadow_dialog_mac"] = None
    st.session_state["shadow_last_selected_mac"] = None
    st.session_state.pop("shadow_dialog_origin", None)
    _close_inventory_allow_dialog()
    _close_inventory_app_dialog()

    if reset_grid:
        st.session_state["shadow_grid_nonce"] = int(st.session_state.get("shadow_grid_nonce", 0)) + 1


def _close_inventory_allow_dialog():
    st.session_state["shadow_allow_dialog_open"] = False
    st.session_state.pop("shadow_allow_candidate", None)


def _open_inventory_allow_dialog(candidate: dict):
    st.session_state["shadow_allow_candidate"] = candidate
    st.session_state["shadow_allow_dialog_open"] = True
    st.session_state["shadow_dialog_origin"] = "dialog"


def _close_inventory_app_dialog():
    st.session_state["shadow_app_detail_dialog_open"] = False
    st.session_state.pop("shadow_app_detail_context", None)
    st.session_state["shadow_inv_grid_nonce"] = int(st.session_state.get("shadow_inv_grid_nonce", 0)) + 1


def _open_inventory_app_dialog(context: dict):
    st.session_state["shadow_app_detail_context"] = context
    st.session_state["shadow_app_detail_dialog_open"] = True
    st.session_state["shadow_dialog_origin"] = "dialog"


def _coerce_bool(v) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    s = str(v).strip().lower()
    return s in {"1", "true", "yes", "y", "on"}


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
        ".ag-root-wrapper ::-webkit-scrollbar-button": {
            "display": "none !important",
            "width": "0 !important",
            "height": "0 !important",
        },
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


def _apply_shadow_grid_filter_sort(grid_options: dict) -> dict:
    opts = dict(grid_options or {})
    default_col_def = dict(opts.get("defaultColDef") or {})

    # Match shadow_sharings filtering/sorting behavior.
    default_col_def["sortable"] = True
    default_col_def["filter"] = "agSetColumnFilter"
    default_col_def["floatingFilter"] = False
    default_col_def.setdefault("minWidth", 96)
    default_col_def["menuTabs"] = ["filterMenuTab", "generalMenuTab"]
    default_col_def["suppressMenu"] = False

    filter_params = dict(default_col_def.get("filterParams") or {})
    filter_params.setdefault("excelMode", "windows")
    filter_params.setdefault("buttons", ["apply", "clear", "cancel"])
    filter_params.setdefault("closeOnApply", True)
    filter_params.setdefault("suppressMiniFilter", False)
    default_col_def["filterParams"] = filter_params

    opts["defaultColDef"] = default_col_def
    opts["suppressMenuHide"] = False
    opts["enableCellTextSelection"] = True
    opts["ensureDomOrder"] = True
    opts["enableRtl"] = False
    opts["suppressColumnVirtualisation"] = True

    autosize_js = JsCode(
        """
        function(params) {
            setTimeout(function() {
                if (!params || !params.columnApi) return;
                const cols = params.columnApi.getAllColumns ? params.columnApi.getAllColumns() : [];
                const colIds = cols
                    .map(function(c) { return c.getColId ? c.getColId() : c.colId; })
                    .filter(Boolean);
                if (!colIds.length) return;
                try {
                    params.columnApi.autoSizeColumns(colIds, false);
                } catch (e) {}
            }, 0);
        }
        """
    )
    opts["onFirstDataRendered"] = autosize_js
    opts["onGridSizeChanged"] = autosize_js
    return opts


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

        [data-testid="stDataFrame"] ::-webkit-scrollbar-button {
            display: none !important;
            width: 0 !important;
            height: 0 !important;
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


def normalize_app_software(app_value: str, source_log: str) -> str:
    s = "" if app_value is None else str(app_value).strip()
    if not s:
        return ""
    low = s.lower().strip()
    if low in _APP_SOFTWARE_NULLS:
        return ""

    # Remove obvious URL framing and query fragments.
    s = s.strip().strip("'").strip('"').split("?", 1)[0].strip()
    if "://" in s:
        try:
            parsed = urlparse(s)
            s = (parsed.path or parsed.hostname or "").strip()
        except Exception:
            pass
    if not s:
        return ""

    # If this is a filesystem path, keep only the filename segment.
    s = s.replace("\\", "/")
    if "/" in s:
        s = s.rsplit("/", 1)[-1].strip()
    if not s:
        return ""

    low = s.lower()
    if low in _APP_SOFTWARE_NULLS:
        return ""
    if _IPV4_RE.match(low):
        return ""

    # Drop pure domains/hosts from the software column.
    host_like = low.split(":", 1)[0].rstrip(".")
    if host_like.startswith("www."):
        host_like = host_like[4:]
    if "." in host_like and host_like == extract_domain(host_like):
        return ""

    # Non-software logs usually provide identifiers/domains, not software names.
    if str(source_log).upper() in {"DNS", "HTTP", "SSL"} and "." in low and " " not in low:
        return ""

    if not re.search(r"[a-zA-Z]", s):
        return ""
    return re.sub(r"\s+", " ", s).strip()[:120]


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


def _pick_allowlist_key(data: dict) -> str:
    preferred = [
        "trusted_domains",
        "whitelist_domains",
        "domains",
        "allowed_domains",
        "whitelist",
        "allowlist",
        WHITELIST_FILE.stem,
    ]
    for k in preferred:
        if isinstance(data.get(k), list):
            return k
    for k, v in data.items():
        if isinstance(v, list):
            return str(k)
    return "trusted_domains"


def add_domain_to_allowlist(domain_value: str) -> tuple[bool, str]:
    domain = extract_domain(domain_value)
    if not domain or domain in {"unknown", "unidentified_activity", "-"}:
        return False, "Invalid application/domain for allowlist."

    data = read_yaml(WHITELIST_FILE)
    if not isinstance(data, dict):
        data = {}

    allow_key = _pick_allowlist_key(data)
    existing_list = data.get(allow_key)
    if not isinstance(existing_list, list):
        existing_list = []

    existing_norm = []
    existing_set = set()
    for item in existing_list:
        d = extract_domain(str(item))
        if d and d not in existing_set:
            existing_set.add(d)
            existing_norm.append(d)

    if domain in existing_set:
        return True, f"{domain} is already allowlisted."

    existing_norm.append(domain)
    data[allow_key] = existing_norm
    write_yaml(WHITELIST_FILE, data)
    return True, f"{domain} added to allowlist."


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
        sql_app_software_raw = get_coalesce(
            ["name", "service", "unparsed_version", "filename"],
            "''",
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
            {sql_app_software_raw} as app_software_raw,
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
    conds = [
        sent > EXFIL_BYTES_SENT_THRESHOLD,
        recv > HEAVY_DOWNLOAD_BYTES_RECEIVED_THRESHOLD,
        slog.eq(PROTOCOL_ANOMALY_SOURCE_LOG),
    ]
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
    basis[m] = (
        "Critical: Potential Exfiltration because bytes_sent exceeded "
        f"{EXFIL_BYTES_SENT_THRESHOLD:,} ({_fmt_mb_threshold(EXFIL_BYTES_SENT_THRESHOLD)})."
    )

    m = behavior.eq("Protocol Anomaly") & score.eq(-1)
    score[m] = 3
    basis[m] = f"High: Protocol Anomaly detected from source_log={PROTOCOL_ANOMALY_SOURCE_LOG}."

    m = behavior.eq("Heavy Download") & score.eq(-1)
    score[m] = 2
    basis[m] = (
        "Medium: Heavy Download because bytes_received exceeded "
        f"{HEAVY_DOWNLOAD_BYTES_RECEIVED_THRESHOLD:,} ({_fmt_mb_threshold(HEAVY_DOWNLOAD_BYTES_RECEIVED_THRESHOLD)})."
    )

    crit_logs, crit_ports = _policy_logs(policy, "critical"), _policy_ports(policy, "critical")
    high_logs, high_ports = _policy_logs(policy, "high"), _policy_ports(policy, "high")
    med_logs, med_ports = _policy_logs(policy, "medium"), _policy_ports(policy, "medium")

    if crit_logs:
        m = slog.isin(crit_logs) & score.eq(-1)
        score[m] = 4
        basis.loc[m] = (
            "Critical: source_log matched risk_policy.critical.source_logs ("
            + slog.loc[m].astype(str)
            + ")."
        )
    if crit_ports:
        m = port.isin(crit_ports) & score.eq(-1)
        score[m] = 4
        basis.loc[m] = (
            "Critical: destination port matched risk_policy.critical.ports ("
            + port.loc[m].astype(str)
            + ")."
        )

    if high_logs:
        m = slog.isin(high_logs) & score.eq(-1)
        score[m] = 3
        basis[m] = "High: source_log matched risk_policy.high.source_logs (" + slog[m] + ")."
    if high_ports:
        m = port.isin(high_ports) & score.eq(-1)
        score[m] = 3
        basis[m] = "High: destination port matched risk_policy.high.ports (" + port[m].astype(str) + ")."

    if med_logs:
        m = slog.isin(med_logs) & score.eq(-1)
        score[m] = 2
        basis[m] = "Medium: source_log matched risk_policy.medium.source_logs (" + slog[m] + ")."
    if med_ports:
        m = port.isin(med_ports) & score.eq(-1)
        score[m] = 2
        basis[m] = "Medium: destination port matched risk_policy.medium.ports (" + port[m].astype(str) + ")."

    low_statuses = _policy_statuses(policy, "low")
    if low_statuses:
        m = status.isin(low_statuses) & score.eq(-1)
        score[m] = 1
        basis[m] = "Low: App Status matched risk_policy.low.app_status (" + status[m].astype(str) + ")."

    default_str = str(policy.get("default", "Safe")) if isinstance(policy, dict) and policy else "Safe"
    default_score = int(RISK_SCORE.get(default_str, 0))
    default_risk = score_to_risk(default_score)
    m = score.eq(-1)
    score[m] = default_score
    basis[m] = (
        f"{default_risk}: No higher-priority rule matched; fallback to risk_policy.default ('{default_str}')."
        if policy
        else "Safe: No risk_policy.yaml loaded; fallback default applied."
    )

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
    soft_raw_series = df.get("app_software_raw", pd.Series("", index=df.index))
    df["app_software"] = [
        normalize_app_software(soft_raw, src) or normalize_app_software(app_val, src)
        for soft_raw, app_val, src in zip(
            soft_raw_series.tolist(),
            df["app_identifier"].tolist(),
            df["source_log"].tolist(),
        )
    ]

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
        "app_software",
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
@st.dialog("Allow Application / Software", width="small", dismissible=False)
def show_inventory_allow_dialog():
    candidate = st.session_state.get("shadow_allow_candidate") or {}
    target_mac = str(candidate.get("mac") or "").strip().lower()
    destination_raw = str(candidate.get("destination") or "").strip()
    app_or_id = str(candidate.get("application_or_identifier") or "").strip()
    destination = extract_domain(destination_raw)
    invalid_target = destination in {"", "unknown", "unidentified_activity", "-"}

    st.markdown(
        f"Confirm allowlisting for MAC `{target_mac or 'unknown'}`."
    )
    st.markdown(f"- Destination: `{destination_raw or '-'}`")
    st.markdown(f"- Application / Software: `{app_or_id or '-'}`")
    st.caption(
        "This will update whitelist_domains.yaml and refresh statuses to Authorized after cache rebuild."
    )

    if invalid_target:
        st.error("This row has no valid destination domain to allowlist.")

    c1, c2 = st.columns(2)
    with c1:
        if st.button(
            "Allow This App/Software",
            type="primary",
            use_container_width=True,
            disabled=invalid_target,
            key="shadow_allow_confirm_btn",
        ):
            ok, message = add_domain_to_allowlist(destination)
            if ok:
                st.session_state["shadow_dialog_origin"] = "dialog"
                _close_inventory_allow_dialog()
                st.success(message)
                st.rerun()
            st.error(message)
    with c2:
        if st.button("Cancel", use_container_width=True, key="shadow_allow_cancel_btn"):
            st.session_state["shadow_dialog_origin"] = "dialog"
            _close_inventory_allow_dialog()
            st.rerun()


@st.dialog("Application Usage Details", width="large", dismissible=False)
def show_inventory_app_dialog(conn):
    ctx = st.session_state.get("shadow_app_detail_context") or {}
    target_mac = str(ctx.get("mac") or "").strip().lower()
    sel_dest = str(ctx.get("destination") or "").strip()
    sel_app = str(ctx.get("application_or_identifier") or "").strip()
    selected_f_source = str(ctx.get("selected_f_source") or "All").strip() or "All"
    forensic_risk = ctx.get("forensic_risk") or []
    if not isinstance(forensic_risk, list):
        forensic_risk = []
    forensic_search = str(ctx.get("forensic_search") or "").strip()

    top = st.columns([1, 6])
    with top[0]:
        if st.button("Close", use_container_width=True, type="primary", key="shadow_app_detail_close_btn"):
            st.session_state["shadow_dialog_origin"] = "dialog"
            _close_inventory_app_dialog()
            st.rerun()
    with top[1]:
        st.caption(f"Application usage scope: {sel_app or '-'}")

    if not target_mac or not sel_dest or not sel_app:
        st.warning("Missing application context. Please select an Application / Software row again.")
        return

    app_where = [
        "lower(mac) = lower(?)",
        "domain_clean = ?",
        "app_software = ?",
    ]
    app_params = [target_mac, sel_dest, sel_app]

    if selected_f_source != "All":
        app_where.append("upper(source_log) = upper(?)")
        app_params.append(selected_f_source)

    if forensic_risk:
        app_in = _build_in_clause(forensic_risk, app_params)
        app_where.append(f""""Risk Level" IN {app_in}""")

    if forensic_search:
        q = f"%{forensic_search}%"
        app_where.append("(domain_clean ILIKE ? OR app_software ILIKE ? OR ip ILIKE ? OR hostname ILIKE ? OR Info ILIKE ?)")
        app_params.extend([q, q, q, q, q])

    app_where_sql = " AND ".join(app_where)
    app_df = _sql_fetch_df(
        conn,
        f"""
        SELECT
            datetime,
            source_log,
            "Risk Level",
            "Risk Basis",
            "Behavior",
            "App Status",
            bytes_sent,
            bytes_received,
            dst_port,
            Info
        FROM shadow_events
        WHERE {app_where_sql}
        ORDER BY datetime DESC
        """,
        app_params,
    )

    if app_df.empty:
        st.info("No events found for this application with current filters.")
        return

    app_df["datetime"] = pd.to_datetime(app_df["datetime"], errors="coerce")
    invalid_ts = int(app_df["datetime"].isna().sum())
    if invalid_ts > 0:
        st.warning(f"{invalid_ts:,} events were excluded from trend charts due to invalid timestamps.")

    app_metrics = st.columns(4)
    app_metrics[0].metric("Events", f"{len(app_df):,}")
    app_metrics[1].metric("Unauthorized", f"{int((app_df['App Status'] == 'Unauthorized').sum()):,}")
    app_metrics[2].metric("Critical / High", f"{int(app_df['Risk Level'].isin(['Critical', 'High']).sum()):,}")
    app_metrics[3].metric("Distinct Sources", f"{int(app_df['source_log'].nunique(dropna=True)):,}")

    trend = app_df.dropna(subset=["datetime"]).copy()
    trend = trend.set_index("datetime").resample("1H").size().reset_index(name="events")

    risk_counts = (
        app_df.assign(**{"Risk Level": app_df["Risk Level"].fillna("Safe").astype(str)})
        .groupby("Risk Level", as_index=False)
        .size()
        .rename(columns={"size": "Events"})
    )
    if not risk_counts.empty:
        risk_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Safe": 0}
        risk_counts["rank"] = risk_counts["Risk Level"].map(risk_order).fillna(-1)
        risk_counts = risk_counts.sort_values(["rank", "Events"], ascending=[False, False])

    usage_col, risk_col = st.columns([1.8, 1.2])
    with usage_col:
        st.markdown("#### Usage Over Time (Hourly)")
        if not trend.empty:
            fig_app_usage = px.area(
                trend,
                x="datetime",
                y="events",
                title="Application usage trend",
                color_discrete_sequence=["#60a5fa"],
            )
            style_plotly_figure(fig_app_usage, height=310, show_legend=False)
            fig_app_usage.update_xaxes(title=None)
            fig_app_usage.update_yaxes(title="Events")
            st.plotly_chart(fig_app_usage, use_container_width=True)
        else:
            st.info("No valid timestamps for this application usage trend.")

    with risk_col:
        st.markdown("#### Risk Level Distribution")
        if not risk_counts.empty:
            fig_app_risk = px.bar(
                risk_counts,
                x="Risk Level",
                y="Events",
                color="Risk Level",
                color_discrete_map=RISK_COLORS,
            )
            style_plotly_figure(fig_app_risk, height=310, show_legend=False)
            fig_app_risk.update_xaxes(categoryorder="array", categoryarray=["Critical", "High", "Medium", "Low", "Safe"])
            st.plotly_chart(fig_app_risk, use_container_width=True)
        else:
            st.info("No risk-level data available.")

    st.markdown("#### Why This Risk Level")
    reason_df = (
        app_df.assign(
            risk_reason=app_df["Risk Basis"].fillna("").astype(str).str.strip().replace("", "No explicit reason captured"),
            risk_level=app_df["Risk Level"].fillna("Safe").astype(str),
        )
        .groupby(["risk_level", "risk_reason"], as_index=False)
        .size()
        .rename(columns={"size": "Events", "risk_level": "Risk Level", "risk_reason": "Risk Reason"})
        .sort_values("Events", ascending=False)
        .head(12)
    )
    if not reason_df.empty:
        top_reason = reason_df.iloc[0]
        st.caption(
            f"Top observed cause: {top_reason['Risk Level']} - {top_reason['Risk Reason']} ({int(top_reason['Events']):,} events)."
        )
        st.dataframe(reason_df, use_container_width=True, hide_index=True)
    else:
        st.info("No risk reason details available for this application.")


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
        forensic_scope_line = st.empty()
        forensic_summary_line = st.empty()
        forensic_note_line = st.empty()

    if not target_mac:
        st.info("No MAC selected.")
        return

    chk = conn.execute("SELECT COUNT(*) FROM shadow_events WHERE lower(mac) = lower(?)", [target_mac]).fetchone()
    if not chk or int(chk[0]) == 0:
        st.warning("No data found for this specific MAC address.")
        return

    src_df = _sql_fetch_df(
        conn,
        "SELECT DISTINCT source_log FROM shadow_events WHERE lower(mac) = lower(?) ORDER BY 1",
        [target_mac],
    )
    f_raw_sources = src_df["source_log"].dropna().tolist() if not src_df.empty else []
    forensic_search = st.text_input(
        "Quick Search",
        placeholder="IP, domain, context...",
        key=f"dlg_search_{target_mac}",
        on_change=_mark_dialog_origin,
    ).strip()
    f_bottom_left, f_bottom_right = st.columns([2.6, 1.4])
    with f_bottom_left:
        forensic_risk = risk_multiselect(
            "Filter Risk",
            key=f"dlg_risk_{target_mac}",
            default=RISK_OPTIONS,
            on_change=_mark_dialog_origin,
        )
    with f_bottom_right:
        selected_f_source = st.selectbox(
            "Filter Source",
            ["All"] + f_raw_sources,
            key=f"dlg_src_{target_mac}",
            on_change=_mark_dialog_origin,
        )

    is_all_risk_selected = bool(forensic_risk) and set(forensic_risk) == set(RISK_OPTIONS)
    risk_summary = summarize_multiselect(forensic_risk, RISK_OPTIONS, all_label="All")
    source_summary = "All" if selected_f_source == "All" else selected_f_source
    forensic_scope_line.caption(f"Forensic analysis scope: {target_mac}")
    forensic_summary_line.caption(
        f"Source: {source_summary} | Risk: {risk_summary} | Search: {'On' if forensic_search else 'Off'}"
    )
    forensic_note_line.caption("Graphs below are computed from the current MAC + Source/Risk/Search filters.")

    where = ["lower(mac) = lower(?)"]
    params = [target_mac]

    if selected_f_source != "All":
        where.append("upper(source_log) = upper(?)")
        params.append(selected_f_source)

    if forensic_risk and not is_all_risk_selected:
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

    forensic_df["datetime"] = pd.to_datetime(forensic_df["datetime"], errors="coerce")
    invalid_timestamps = int(forensic_df["datetime"].isna().sum())
    if invalid_timestamps > 0:
        st.warning(
            f"{invalid_timestamps:,} events were excluded from the timeline due to invalid timestamps."
        )

    d1, d2, d3, d4 = st.columns(4)
    d1.metric("Events", f"{forensic_total:,}")
    d2.metric("Unique Destinations", f"{forensic_domains:,}")
    d3.metric("Unauthorized", f"{forensic_unauthorized:,}")
    d4.metric("Critical / High", f"{forensic_critical_high:,}")

    # =============================================================================
    # Dialog analytics: Timeline + Top Destinations
    # =============================================================================
    st.markdown("#### Activity Timeline")
    timeline_mode = st.radio(
        "Timeline View",
        ["Total Events", "Status Split"],
        horizontal=True,
        key=f"dlg_timeline_mode_{target_mac}",
        on_change=_mark_dialog_origin,
    )

    bucket_rule = "10min"
    timeline_label = "10 min"
    timeline = forensic_df.dropna(subset=["datetime"]).copy()

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
                title=f"Activity ({timeline_label})",
            )
            style_plotly_figure(fig_f, height=320)
        else:
            f_line = timeline.set_index("datetime").resample(bucket_rule).size().reset_index(name="hits")
            fig_f = px.area(
                f_line,
                x="datetime",
                y="hits",
                title=f"Activity ({timeline_label})",
                color_discrete_sequence=["#60a5fa"],
            )
            style_plotly_figure(fig_f, height=320, show_legend=False)

        fig_f.update_xaxes(title=None)
        fig_f.update_yaxes(title="Events")
        st.plotly_chart(fig_f, use_container_width=True)
    else:
        st.warning("No valid timestamps for timeline.")

    st.markdown("#### Top Destinations")
    top_dest = (
        forensic_df.assign(
            domain_clean=forensic_df["domain_clean"]
            .fillna("Unknown")
            .astype(str)
            .str.strip()
            .replace("", "Unknown")
        )
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

    if forensic_risk and not is_all_risk_selected:
        inv_in = _build_in_clause(forensic_risk, inv_params)
        inv_where.append(f""""Risk Level" IN {inv_in}""")

    if forensic_search:
        q_inv = f"%{forensic_search}%"
        inv_where.append("(domain_clean ILIKE ? OR app_software ILIKE ?)")
        inv_params.extend([q_inv, q_inv])

    inv_where_sql = " AND ".join(inv_where)

    inventory_df = _sql_fetch_df(
        conn,
        f"""
        WITH base AS (
            SELECT
                domain_clean,
                app_software,
                source_log,
                "App Status" AS app_status,
                _risk_score,
                datetime
            FROM shadow_events
            WHERE {inv_where_sql}
              AND domain_clean IS NOT NULL
              AND domain_clean <> ''
              AND app_software IS NOT NULL
              AND trim(app_software) <> ''
        ),
        agg AS (
            SELECT
                domain_clean,
                app_software,
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
            app_software AS application_or_identifier,
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
        st.info("No application/software names were detected for this MAC with the current filters.")
    else:
        inv_grid = inventory_df.copy()
        inv_grid.insert(0, "#", range(1, len(inv_grid) + 1))
        inv_grid["Allowed"] = inv_grid["status"].astype(str).str.lower().eq("authorized")
        inv_grid["_allow_key"] = (
            inv_grid["destination"].fillna("").astype(str).str.lower().str.strip()
            + "|"
            + inv_grid["application_or_identifier"].fillna("").astype(str).str.lower().str.strip()
        )
        inv_original_allowed = {
            str(k): _coerce_bool(v) for k, v in zip(inv_grid["_allow_key"].tolist(), inv_grid["Allowed"].tolist())
        }
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
        inv_allow_editable = JsCode(
            """
            function(params) {
                const status = (params.data && params.data.status ? params.data.status : '').toString().toLowerCase();
                return status !== 'authorized';
            }
            """
        )
        inv_app_click_style = JsCode(
            """
            function(params) {
                return {
                    color: '#8AB4F8',
                    fontWeight: '700',
                    cursor: 'pointer',
                    textDecoration: 'underline'
                };
            }
            """
        )
        inv_app_only_click_js = JsCode(
            """
            function(params) {
                if (!params || !params.column || !params.node) return;
                const colId = params.column.getColId ? params.column.getColId() : '';
                if (colId === 'application_or_identifier') {
                    params.node.setSelected(true, true);
                }
            }
            """
        )

        gb_inv = GridOptionsBuilder.from_dataframe(inv_grid)
        gb_inv.configure_default_column(
            filter=True,
            sortable=True,
            resizable=True,
            minWidth=88,
            suppressMenu=False,
        )
        gb_inv.configure_selection(selection_mode="single", use_checkbox=False)
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
            header_name="Application / Software",
            minWidth=185,
            flex=1.35,
            wrapText=True,
            autoHeight=True,
            tooltipField="application_or_identifier",
            cellStyle=inv_app_click_style,
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
        gb_inv.configure_column(
            "Allowed",
            header_name="Allowed",
            width=96,
            editable=inv_allow_editable,
            cellRenderer="agCheckboxCellRenderer",
            cellEditor="agCheckboxCellEditor",
            singleClickEdit=True,
            filter=False,
            sortable=False,
        )
        gb_inv.configure_column("status", header_name="Status", width=104, cellStyle=inv_status_style)
        gb_inv.configure_column("first_seen", header_name="First Seen", width=152)
        gb_inv.configure_column("last_seen", header_name="Last Seen", width=152)
        gb_inv.configure_column("hits", header_name="Hits", width=72)
        gb_inv.configure_column("max_risk", header_name="Max Risk", width=94, cellStyle=inv_risk_style)
        gb_inv.configure_column("_allow_key", hide=True)

        ag_theme, ag_css = get_aggrid_theme_and_css()
        inv_grid_options = _apply_shadow_grid_filter_sort(gb_inv.build())
        inv_grid_options["suppressHorizontalScroll"] = False
        inv_grid_options["alwaysShowHorizontalScroll"] = True
        inv_grid_options["domLayout"] = "normal"
        inv_grid_options["alwaysShowVerticalScroll"] = True
        inv_grid_options["tooltipShowDelay"] = 0
        inv_grid_options["suppressRowClickSelection"] = True
        inv_grid_options["onCellClicked"] = inv_app_only_click_js

        inv_grid_response = AgGrid(
            inv_grid,
            gridOptions=inv_grid_options,
            update_mode=GridUpdateMode.MODEL_CHANGED,
            data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
            height=_table_height_for_rows(len(inv_grid), min_px=240, max_px=520),
            theme=ag_theme,
            custom_css=ag_css,
            allow_unsafe_jscode=True,
            enable_enterprise_modules=True,
            fit_columns_on_grid_load=True,
            reload_data=False,
            key=f"dlg_inventory_grid_{target_mac}_{int(st.session_state.get('shadow_inv_grid_nonce', 0))}",
        )
        st.caption("Click only Application / Software to open a popup dialog with app usage and risk-cause details.")
        st.caption("Check Allowed for an unauthorized row to open allowlist confirmation.")
        st.caption(f"{len(inv_grid):,} rows shown in application inventory.")

        edited_inv = inv_grid_response.get("data", None)
        if isinstance(edited_inv, pd.DataFrame):
            edited_df = edited_inv.copy()
        elif isinstance(edited_inv, list):
            edited_df = pd.DataFrame(edited_inv)
        else:
            edited_df = pd.DataFrame()

        if (
            not edited_df.empty
            and "Allowed" in edited_df.columns
            and "_allow_key" in edited_df.columns
            and not st.session_state.get("shadow_allow_dialog_open")
        ):
            edited_df["Allowed"] = edited_df["Allowed"].apply(_coerce_bool)
            edited_df["_was_allowed"] = edited_df["_allow_key"].astype(str).map(
                lambda k: bool(inv_original_allowed.get(k, False))
            )
            newly_allowed = edited_df[(edited_df["Allowed"]) & (~edited_df["_was_allowed"])]
            if not newly_allowed.empty:
                pick = newly_allowed.iloc[0]
                _open_inventory_allow_dialog(
                    {
                        "mac": target_mac,
                        "destination": str(pick.get("destination", "")),
                        "application_or_identifier": str(pick.get("application_or_identifier", "")),
                    }
                )
                st.rerun()

        selected_rows_inv = inv_grid_response.get("selected_rows", None)
        selected_inv = None
        if isinstance(selected_rows_inv, pd.DataFrame):
            if not selected_rows_inv.empty:
                selected_inv = selected_rows_inv.iloc[0].to_dict()
        elif isinstance(selected_rows_inv, list):
            if selected_rows_inv and isinstance(selected_rows_inv[0], dict):
                selected_inv = selected_rows_inv[0]

        if (
            isinstance(selected_inv, dict)
            and not st.session_state.get("shadow_allow_dialog_open")
            and not st.session_state.get("shadow_app_detail_dialog_open")
        ):
            sel_dest = str(selected_inv.get("destination", "") or "").strip()
            sel_app = str(selected_inv.get("application_or_identifier", "") or "").strip()
            if sel_dest and sel_app:
                _open_inventory_app_dialog(
                    {
                        "mac": target_mac,
                        "destination": sel_dest,
                        "application_or_identifier": sel_app,
                        "selected_f_source": selected_f_source,
                        "forensic_risk": list(forensic_risk),
                        "forensic_search": forensic_search,
                    }
                )
                st.rerun()

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
    st.session_state.setdefault("shadow_inv_grid_nonce", 0)
    st.session_state.setdefault("shadow_allow_dialog_open", False)
    st.session_state.setdefault("shadow_allow_candidate", None)
    st.session_state.setdefault("shadow_app_detail_dialog_open", False)
    st.session_state.setdefault("shadow_app_detail_context", None)

    # --- auto-close stale dialogs ---
    origin = st.session_state.pop("shadow_dialog_origin", None)
    if st.session_state.get("shadow_dialog_open") and origin not in ("grid", "dialog"):
        _close_shadow_dialog(reset_grid=False)

    available_dates = list_available_dates(parquet_root)
    if not available_dates:
        st.warning("No log directories found.")
        return

    selected_day = available_dates[0]
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
    if st.session_state.get("shadow_allow_dialog_open") and st.session_state.get("shadow_allow_candidate"):
        show_inventory_allow_dialog()
    elif st.session_state.get("shadow_app_detail_dialog_open") and st.session_state.get("shadow_app_detail_context"):
        show_inventory_app_dialog(conn)
    elif st.session_state.get("shadow_dialog_open") and st.session_state.get("shadow_dialog_mac") and origin in ("grid", "dialog"):
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

    with st.expander("How Risk Is Calculated", expanded=False):
        st.markdown(
            "<div class='shadow-callout'>Rules are evaluated top-to-bottom per event. The first match sets the Risk Level.</div>",
            unsafe_allow_html=True,
        )
        ref_df = build_risk_policy_reference(risk_policy)
        st.dataframe(ref_df, use_container_width=True, hide_index=True)
        if risk_policy:
            st.caption(
                f"Policy source: `{RISK_POLICY_FILE.name}`. Update that file to tune ports/log sources/status defaults."
            )
        else:
            st.caption("No risk_policy.yaml found. Only behavior rules and Safe fallback are active.")

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

    tab_main = st.container()

    # =============================================================================
    # TAB 1: AgGrid (CLICK MAC CELL -> OPEN DIALOG)
    # =============================================================================
    with tab_main:
        st.markdown("### Application Audit Log")

        st.markdown("<div class='shadow-filter-shell'>", unsafe_allow_html=True)
        search_query_audit = st.text_input(
            "Search (MAC, Hostname, IP, Domain)",
            placeholder="e.g., 192.168.1.14 or github.com",
            key="audit_search",
        ).strip()
        bottom_filter_col1, bottom_filter_col2 = st.columns([2.2, 2.2])
        with bottom_filter_col1:
            audit_risk_filter = risk_multiselect(
                "Filter Risk",
                key="audit_risk_filter",
                default=RISK_OPTIONS,
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

        is_all_risk_selected = bool(audit_risk_filter) and set(audit_risk_filter) == set(RISK_OPTIONS)
        is_all_sources_selected = bool(audit_sources) and set(audit_source_filter) == set(audit_sources)

        if audit_risk_filter and not is_all_risk_selected:
            in_clause = _build_in_clause(audit_risk_filter, params)
            where.append(f""""Risk Level" IN {in_clause}""")

        if search_query_audit:
            q = f"%{search_query_audit}%"
            where.append("(mac ILIKE ? OR hostname ILIKE ? OR ip ILIKE ? OR domain_clean ILIKE ?)")
            params.extend([q, q, q, q])

        if audit_source_filter and not is_all_sources_selected:
            in_clause = _build_in_clause(audit_source_filter, params)
            where.append(f"source_log IN {in_clause}")

        where_sql = "WHERE " + " AND ".join(where) if where else ""

        audit_sql = f"""
        WITH base AS (
            SELECT
                domain_clean,
                mac,
                hostname,
                ip,
                source_log,
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
                hostname,
                ip,
                source_log,
                risk_basis AS Max_Risk_Reason,
                ROW_NUMBER() OVER (
                    PARTITION BY domain_clean, mac, hostname, ip, source_log
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
            b.Max_Risk_Reason
        FROM agg a
        LEFT JOIN (SELECT * FROM pick_basis WHERE rn = 1) b
            ON a.domain_clean=b.domain_clean
           AND a.mac=b.mac
           AND a.hostname=b.hostname
           AND a.ip=b.ip
           AND a.source_log=b.source_log
        ORDER BY a.Max_Risk_Score DESC, a.Hits DESC
        LIMIT 1000
        """

        display_df = _sql_fetch_df(conn, audit_sql, params)

        if display_df.empty:
            st.info("No logs match your filter.")
        else:
            # Add row index column for easier navigation.
            df_grid = display_df.copy()
            df_grid.insert(0, "#", range(1, len(df_grid) + 1))

            gb = GridOptionsBuilder.from_dataframe(df_grid)

            # Enable filter/sort/resize.
            gb.configure_default_column(filter=True, sortable=True, resizable=True)

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
            mac_only_click_js = JsCode(
                """
                function(params) {
                    if (!params || !params.column || !params.node) return;
                    const colId = params.column.getColId ? params.column.getColId() : '';
                    if (colId === 'mac') {
                        params.node.setSelected(true, true);
                    }
                }
                """
            )

            # Column formatting (match)
            gb.configure_column("#", header_name="#", width=70, pinned="left", suppressMovable=True, resizable=False)
            gb.configure_column("mac", header_name="MAC Address (Click)", cellStyle=mac_cellstyle)
            gb.configure_column("Max_Risk", header_name="Risk Level", cellStyle=risk_cellstyle)
            gb.configure_column(
                "Max_Risk_Reason",
                header_name="Risk Reason",
                minWidth=260,
                flex=1.4,
                wrapText=True,
                autoHeight=True,
                tooltipField="Max_Risk_Reason",
            )

            # Optional: tighten these widths (feel more like a fixed enterprise table)
            gb.configure_column("domain_clean", header_name="Domain", minWidth=220)
            gb.configure_column("hostname", header_name="Hostname", minWidth=160)
            gb.configure_column("ip", header_name="IP", minWidth=130)
            gb.configure_column("source_log", header_name="Source", width=110)
            gb.configure_column("Hits", header_name="Hits", width=90)
            gb.configure_column("First_Seen", header_name="First Seen", width=170)
            gb.configure_column("Last_Seen", header_name="Last Seen", width=170)

            grid_options = _apply_shadow_grid_filter_sort(gb.build())
            grid_options["rowSelection"] = "single"
            grid_options["suppressRowClickSelection"] = True
            grid_options["rowMultiSelectWithClick"] = False
            grid_options["domLayout"] = "normal"
            grid_options["alwaysShowVerticalScroll"] = True
            grid_options["suppressHorizontalScroll"] = False
            grid_options["alwaysShowHorizontalScroll"] = True
            grid_options["onCellClicked"] = mac_only_click_js

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
                    ".ag-root-wrapper ::-webkit-scrollbar-button": {
                        "display": "none !important",
                        "width": "0 !important",
                        "height": "0 !important",
                    },
                }
            )

            grid_key = f"shadow_audit_grid_{int(st.session_state.get('shadow_grid_nonce', 0))}"

            st.caption("Click on any MAC Address to show device forensics dialog.")
            grid_response = AgGrid(
                df_grid,
                gridOptions=grid_options,
                update_mode=GridUpdateMode.SELECTION_CHANGED,
                data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
                height=_table_height_for_rows(len(df_grid), min_px=240, max_px=520),
                theme=ag_theme,
                custom_css=audit_ag_css,
                allow_unsafe_jscode=True,
                enable_enterprise_modules=True,
                fit_columns_on_grid_load=True,
                reload_data=False,
                key=grid_key,
            )
            st.caption(
                f"{len(df_grid):,} grouped rows shown. Rows are built by grouping filtered events on "
                "Domain + MAC + Hostname + IP + Source, then computing First Seen, Last Seen, Hits, and "
                "the max risk; groups are sorted by max risk score and hit count, and only the top 1,000 are displayed."
            )

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

