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

# Bump version so old cached parquet gets rebuilt automatically when ingestion logic changes.
CACHE_VERSION = "shadow-cache-v14-risk-engine-escalation"

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
UPLOAD_SPIKE_BYTES_SENT_THRESHOLD = 2_500_000
UPLOAD_SPIKE_BYTES_RECEIVED_MAX = 250_000
MULTI_SIGNAL_ESCALATION_MIN_INDICATORS = 2
_UNIDENTIFIED_DEST_VALUES = {
    "",
    "unknown",
    "unidentified_activity",
    "-",
    "*",
    "nan",
    "none",
    "null",
    "n/a",
    "(empty)",
    "[]",
    "unresolved_destination",
}

_MAC_HEX_RE = re.compile(r"[^0-9a-fA-F]")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_APP_SOFTWARE_NULLS = {"", "-", "unknown", "nan", "none", "null", "n/a", "unidentified_activity"}
_HOSTNAME_NULLS = {"", "-", "unknown", "nan", "none", "null", "n/a"}
_MAC_UNKNOWNS = {"", "unknown", "nan", "none", "null"}
_SOFTWARE_LOG_SOURCES = {"SOFTWARE", "FILES"}
_DOMAIN_LOG_SOURCES = {"HTTP", "SSL", "DNS"}
_DOMAIN_INFER_EXCLUDED_SOURCES = {"NOTICE"}
_DOMAIN_INFER_IP_UNKNOWN = {"", "unknown", "0.0.0.0", "nan", "none", "null"}
_DOMAIN_INFER_TOLERANCE_SECONDS = 2
_APP_IDENTITY_INFER_TOLERANCE_SECONDS = 2
_SHADOW_SHARINGS_EMPTY_REPLACEMENTS = {"nan": "", "None": "", "none": "", "*": ""}


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


def normalize_source_log_value(value) -> str:
    s = "" if value is None else str(value).strip().upper()
    return s if s else "UNKNOWN"


def _is_real_destination_series(values: pd.Series) -> pd.Series:
    s = _normalize_destination_display_series(values)
    low = s.str.lower().str.strip(".")
    invalid = _UNIDENTIFIED_DEST_VALUES | {"unresolved_destination", "unknown host"}
    strict_domain = low.apply(extract_domain_strict)
    com_domain = strict_domain.str.endswith(".com")
    return (
        s.ne("")
        & ~low.isin(invalid)
        & ~s.str.match(_IPV4_RE, na=False)
        & ~low.str.match(r"^port/\d+$", na=False)
        & ~low.str.contains(r"\s|/|\\", regex=True)
        & com_domain
    )


def _is_real_identifier_series(values: pd.Series) -> pd.Series:
    s = _normalize_application_display_series(values)
    low = s.str.lower()
    invalid = _UNIDENTIFIED_DEST_VALUES | {"conn telemetry", "unmapped"}
    com_domain = low.apply(_to_com_root_domain).ne("")
    human_readable_app = (
        low.str.match(r"^[a-z0-9][a-z0-9 ._:+()&-]{1,119}$", na=False)
        & low.str.contains(r"[a-z]", na=False)
        & ~low.str.contains(r"://|/|\\|\\?|#", regex=True)
        & s.str.split().str.len().fillna(0).le(8)
    )
    return (
        s.ne("")
        & ~low.isin(invalid)
        & ~low.str.match(_IPV4_RE, na=False)
        & ~low.str.match(r"^conn port\s+\d+$", na=False)
        & ~low.str.match(r"^port/\d+$", na=False)
        & (com_domain | human_readable_app)
    )


def _format_duration_seconds(value) -> str:
    try:
        sec = float(value)
    except Exception:
        return "0s"
    if pd.isna(sec) or sec < 0:
        sec = 0.0
    total = int(round(sec))
    hours, rem = divmod(total, 3600)
    mins, secs = divmod(rem, 60)
    if hours > 0:
        return f"{hours}h {mins}m {secs}s"
    if mins > 0:
        return f"{mins}m {secs}s"
    return f"{secs}s"


def _normalize_destination_display_series(values: pd.Series) -> pd.Series:
    s = values.fillna("").astype(str).str.strip().replace(_SHADOW_SHARINGS_EMPTY_REPLACEMENTS)
    s = s.str.strip().str.strip(".")
    domain_norm = s.str.lower().apply(extract_domain_strict)
    m_domain = domain_norm.ne("")
    if m_domain.any():
        s.loc[m_domain] = domain_norm.loc[m_domain]
    return s


def _to_com_root_domain(value) -> str:
    d = extract_domain_strict(value)
    if not d or not d.endswith(".com"):
        return ""
    parts = d.split(".")
    if len(parts) < 2:
        return d
    return ".".join(parts[-2:])


def _normalize_application_display_series(values: pd.Series, destination_values: pd.Series | None = None) -> pd.Series:
    s = values.fillna("").astype(str).str.strip().replace(_SHADOW_SHARINGS_EMPTY_REPLACEMENTS)
    s = s.str.strip().str.strip(".")

    # For domain-like identifiers, mirror Shadow Sharings Domain style (root .com).
    domain_norm = s.str.lower().apply(_to_com_root_domain)
    m_domain = domain_norm.ne("")
    if m_domain.any():
        s.loc[m_domain] = domain_norm.loc[m_domain]

    # When app/software is missing, derive root .com domain from destination.
    if destination_values is not None:
        dest_norm = _normalize_destination_display_series(destination_values).str.lower().apply(_to_com_root_domain)
        m_empty = s.eq("")
        if m_empty.any():
            s.loc[m_empty] = dest_norm.loc[m_empty]
    if destination_values is not None:
        dest_domain = _normalize_destination_display_series(destination_values).str.lower().apply(_to_com_root_domain)
        app_domain = s.str.lower().apply(_to_com_root_domain)
        m_same_as_dest = app_domain.eq(dest_domain) & dest_domain.ne("")
        if m_same_as_dest.any():
            s.loc[m_same_as_dest] = dest_domain.loc[m_same_as_dest]
    return s


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
            "Risk Level": "High",
            "Rule Source": "Behavior",
            "Trigger": (
                "Asymmetric Upload Spike: Unauthorized traffic with bytes_sent > "
                f"{UPLOAD_SPIKE_BYTES_SENT_THRESHOLD:,} ({_fmt_mb_threshold(UPLOAD_SPIKE_BYTES_SENT_THRESHOLD)}) and "
                f"bytes_received <= {UPLOAD_SPIKE_BYTES_RECEIVED_MAX:,} ({_fmt_mb_threshold(UPLOAD_SPIKE_BYTES_RECEIVED_MAX)})."
            ),
        },
        {
            "Order": 4,
            "Risk Level": "Medium",
            "Rule Source": "Behavior",
            "Trigger": (
                "Heavy Download: bytes_received > "
                f"{HEAVY_DOWNLOAD_BYTES_RECEIVED_THRESHOLD:,} ({_fmt_mb_threshold(HEAVY_DOWNLOAD_BYTES_RECEIVED_THRESHOLD)})"
            ),
        },
        {
            "Order": 5,
            "Risk Level": "Medium",
            "Rule Source": "Heuristic",
            "Trigger": "Unauthorized traffic with unresolved destination/domain context (unidentified_activity).",
        },
    ]

    order = 6
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

    rows.append(
        {
            "Order": order,
            "Risk Level": "Escalation",
            "Rule Source": "Heuristic",
            "Trigger": (
                "Unauthorized events with >= "
                f"{MULTI_SIGNAL_ESCALATION_MIN_INDICATORS} medium/high indicators are elevated by +1 risk level (max Critical)."
            ),
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
        ".ag-header-cell-menu-button, .ag-header-cell-filter-button": {
            "opacity": "1 !important",
            "visibility": "visible !important",
            "display": "inline-flex !important",
            "align-items": "center !important",
            "justify-content": "center !important",
            "color": "#FFFFFF !important",
        },
        ".ag-header-cell-menu-button .ag-icon, .ag-header-cell-filter-button .ag-icon, .ag-header-cell-menu-button .ag-icon-menu": {
            "opacity": "1 !important",
            "color": "#FFFFFF !important",
        },
        ".ag-header-cell-label": {"font-weight": "700", "letter-spacing": "0.02em"},
        ".ag-cell": {"background-color": "#050B16", "color": "#EAEAEA", "border-color": "#13233D"},
        ".ag-row": {"background-color": "#050B16"},
        ".ag-row-odd": {"background-color": "#071224"},
        ".ag-row-even": {"background-color": "#050E1D"},
        ".ag-row-hover": {"background-color": "#0F203D"},
        ".ag-row-selected": {"background-color": "#1E3A5F"},
        ".ag-menu, .ag-popup-child, .ag-filter, .ag-filter-body-wrapper, .ag-set-filter-list, .ag-virtual-list-viewport, .ag-rich-select-list": {
            "background-color": "#071224 !important",
            "color": "#EAF2FF !important",
            "border": "1px solid #2E4E7A !important",
        },
        ".ag-menu-option": {"background-color": "#071224 !important", "color": "#EAF2FF !important"},
        ".ag-menu-option:hover, .ag-menu-option.ag-menu-option-active, .ag-set-filter-item:hover": {
            "background-color": "#13305A !important",
            "color": "#EAF2FF !important",
        },
        ".ag-menu .ag-input-field-input, .ag-filter-body input, .ag-mini-filter input, .ag-floating-filter-input": {
            "background-color": "#0A1730 !important",
            "color": "#EAF2FF !important",
            "border": "1px solid #32517F !important",
        },
        ".ag-picker-field-wrapper, .ag-picker-field-display, .ag-select-list, .ag-list-item": {
            "background-color": "#071224 !important",
            "color": "#EAF2FF !important",
            "border-color": "#2E4E7A !important",
        },
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
    opts.setdefault("pagination", True)
    if opts.get("pagination"):
        opts.setdefault("paginationAutoPageSize", False)
        opts.setdefault("paginationPageSize", 25)
        opts.setdefault("paginationPageSizeSelector", [25, 50, 100])

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
                try {
                    if (params.api && params.api.sizeColumnsToFit) {
                        params.api.sizeColumnsToFit();
                    }
                } catch (e) {}
            }, 0);
        }
        """
    )
    opts["autoSizeStrategy"] = {"type": "fitCellContents"}
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
            min-height: 115px;
            height: 115px;
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

        /* Keep AG Grid overlays dark (never white) and make menu dots always visible. */
        .ag-theme-alpine .ag-root-wrapper,
        .ag-theme-alpine-dark .ag-root-wrapper,
        .ag-theme-alpine .ag-root-wrapper-body,
        .ag-theme-alpine-dark .ag-root-wrapper-body,
        .ag-theme-alpine .ag-center-cols-clipper,
        .ag-theme-alpine-dark .ag-center-cols-clipper {
            background: rgba(6, 17, 32, 0.95) !important;
        }
        .ag-theme-alpine .ag-menu,
        .ag-theme-alpine-dark .ag-menu,
        .ag-theme-alpine .ag-popup-child,
        .ag-theme-alpine-dark .ag-popup-child,
        .ag-theme-alpine .ag-filter,
        .ag-theme-alpine-dark .ag-filter,
        .ag-theme-alpine .ag-set-filter-list,
        .ag-theme-alpine-dark .ag-set-filter-list,
        .ag-theme-alpine .ag-virtual-list-viewport,
        .ag-theme-alpine-dark .ag-virtual-list-viewport {
            background: #071224 !important;
            color: #EAF2FF !important;
            border-color: #2E4E7A !important;
        }
        .ag-theme-alpine .ag-header-cell-menu-button,
        .ag-theme-alpine-dark .ag-header-cell-menu-button,
        .ag-theme-alpine .ag-header-cell-filter-button,
        .ag-theme-alpine-dark .ag-header-cell-filter-button {
            opacity: 1 !important;
            visibility: visible !important;
            display: inline-flex !important;
            color: #FFFFFF !important;
        }
        .ag-theme-alpine .ag-header-cell-menu-button .ag-icon,
        .ag-theme-alpine-dark .ag-header-cell-menu-button .ag-icon,
        .ag-theme-alpine .ag-header-cell-filter-button .ag-icon,
        .ag-theme-alpine-dark .ag-header-cell-filter-button .ag-icon {
            opacity: 1 !important;
            color: #FFFFFF !important;
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


LOG_TYPES = ["http", "ssl", "dns", "files", "conn", "software", "weird"]
POLICY_ALLOWED_SOURCE_LOGS = {str(x).strip().upper() for x in LOG_TYPES if str(x).strip()}


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


def extract_domain_strict(url: str) -> str:
    domain = extract_domain(url)
    if not domain:
        return ""
    d = domain.strip().lower()
    if d in _APP_SOFTWARE_NULLS:
        return ""
    if _IPV4_RE.match(d):
        return ""
    if ".." in d:
        return ""
    return d if _DOMAIN_RE.match(d) else ""


def normalize_identifier_hint(value) -> str:
    s = "" if value is None else str(value).strip()
    if not s:
        return ""
    low = s.lower()
    if low in _APP_SOFTWARE_NULLS or low in {"(empty)", "[]"}:
        return ""
    return re.sub(r"\s+", " ", s)[:120]


def extract_destination_hint(value) -> str:
    """
    Best-effort destination fallback when strict domain parsing fails.
    Accepts domain, IP, mDNS/service-like hostnames, and other host tokens.
    """
    normalized = normalize_identifier_hint(value)
    if not normalized:
        return ""

    host = extract_domain(normalized)
    host_low = host.lower().strip()
    if host and host_low not in _APP_SOFTWARE_NULLS and host_low not in {"*", "(empty)", "[]"}:
        return host[:253]

    if normalized.strip() == "*":
        return ""
    return normalized


def normalize_app_software(
    app_value: str,
    source_log: str,
    *,
    software_type: str = "",
    software_name: str = "",
) -> str:
    s = "" if app_value is None else str(app_value).strip()
    if not s:
        return ""
    src = str(source_log).upper().strip()
    if src not in _SOFTWARE_LOG_SOURCES:
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

    # SOFTWARE often emits "Name/Version"; keep name when available.
    if src == "SOFTWARE" and "/" in s:
        left, right = s.split("/", 1)
        left = left.strip()
        right = right.strip()
        if left and re.search(r"[a-zA-Z]", left) and re.fullmatch(r"[0-9a-zA-Z._-]+", right or ""):
            s = left

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

    sw_type = "" if software_type is None else str(software_type).strip()
    sw_name = "" if software_name is None else str(software_name).strip()
    sw_type_low = sw_type.lower()
    sw_name_low = sw_name.lower()
    if sw_type_low in _APP_SOFTWARE_NULLS:
        sw_type = ""
    if sw_name_low in _APP_SOFTWARE_NULLS:
        sw_name = ""

    if src == "SOFTWARE":
        name_part = sw_name or s
        if name_part and "/" in name_part:
            left, right = name_part.split("/", 1)
            left = left.strip()
            right = right.strip()
            if left and re.search(r"[a-zA-Z]", left) and re.fullmatch(r"[0-9a-zA-Z._-]+", right or ""):
                name_part = left
        name_part = re.sub(r"\s+", " ", str(name_part)).strip()
        if sw_type and name_part:
            combined = f"{sw_type} - {name_part}"
            if re.search(r"[a-zA-Z]", combined):
                return combined[:120]
        if name_part and re.search(r"[a-zA-Z]", name_part):
            return name_part[:120]
        if sw_type and re.search(r"[a-zA-Z]", sw_type):
            return sw_type[:120]

    # Drop pure domains/hosts from the software column.
    host_like = low.split(":", 1)[0].rstrip(".")
    if host_like.startswith("www."):
        host_like = host_like[4:]
    if "." in host_like and host_like == extract_domain(host_like):
        return ""

    if not re.search(r"[a-zA-Z]", s):
        return ""
    return re.sub(r"\s+", " ", s).strip()[:120]


def _asof_grouped_match(
    left_df: pd.DataFrame,
    right_df: pd.DataFrame,
    by_cols: list[str],
    right_value_cols: list[str],
    tolerance_seconds: int,
) -> pd.DataFrame:
    out_cols = ["row_idx", *right_value_cols]
    if left_df.empty or right_df.empty:
        return pd.DataFrame(columns=out_cols)
    tolerance = pd.Timedelta(seconds=int(tolerance_seconds))

    if not by_cols:
        left_sorted = left_df.sort_values(["datetime"]).copy()
        right_sorted = right_df.sort_values(["datetime"]).copy()
        joined = pd.merge_asof(
            left_sorted,
            right_sorted[["datetime", *right_value_cols]],
            on="datetime",
            direction="nearest",
            tolerance=tolerance,
        )
        return joined[out_cols]

    right_groups = right_df.groupby(by_cols, dropna=False, sort=False)
    matched_parts: list[pd.DataFrame] = []
    for key, left_part in left_df.groupby(by_cols, dropna=False, sort=False):
        try:
            right_part = right_groups.get_group(key)
        except KeyError:
            continue
        if left_part.empty or right_part.empty:
            continue
        left_sorted = left_part.sort_values(["datetime"]).copy()
        right_sorted = right_part.sort_values(["datetime"]).copy()
        joined = pd.merge_asof(
            left_sorted,
            right_sorted[["datetime", *right_value_cols]],
            on="datetime",
            direction="nearest",
            tolerance=tolerance,
        )
        matched_parts.append(joined[out_cols])

    if not matched_parts:
        return pd.DataFrame(columns=out_cols)
    return pd.concat(matched_parts, ignore_index=True)


def _asof_domain_match(
    left_df: pd.DataFrame,
    right_df: pd.DataFrame,
    by_cols: list[str],
    tolerance_seconds: int,
) -> pd.DataFrame:
    matched = _asof_grouped_match(
        left_df=left_df,
        right_df=right_df,
        by_cols=by_cols,
        right_value_cols=["domain_clean"],
        tolerance_seconds=tolerance_seconds,
    )
    if matched.empty:
        return pd.DataFrame(columns=["row_idx", "matched_domain"])
    matched["matched_domain"] = matched["domain_clean"].fillna("").astype(str).str.strip()
    return matched[["row_idx", "matched_domain"]]


def _asof_identity_match(
    left_df: pd.DataFrame,
    right_df: pd.DataFrame,
    by_cols: list[str],
    tolerance_seconds: int,
) -> pd.DataFrame:
    matched = _asof_grouped_match(
        left_df=left_df,
        right_df=right_df,
        by_cols=by_cols,
        right_value_cols=["app_identity"],
        tolerance_seconds=tolerance_seconds,
    )
    if matched.empty:
        return pd.DataFrame(columns=["row_idx", "matched_identity"])
    matched["matched_identity"] = matched["app_identity"].fillna("").astype(str).str.strip()
    return matched[["row_idx", "matched_identity"]]


def infer_missing_domains(df: pd.DataFrame) -> pd.Series:
    """
    Infer missing domains for CONN/SOFTWARE/FILES rows using nearest domain-bearing
    logs (HTTP/SSL/DNS) on the same MAC/IP and close timestamp.
    """
    inferred = pd.Series("", index=df.index, dtype="object")
    if df is None or df.empty:
        return inferred

    base = pd.DataFrame(index=df.index)
    base["datetime"] = pd.to_datetime(df.get("datetime"), errors="coerce")
    base["mac"] = df.get("mac", pd.Series("unknown", index=df.index)).fillna("unknown").astype(str).str.lower().str.strip()
    base["ip"] = df.get("ip", pd.Series("Unknown", index=df.index)).fillna("Unknown").astype(str).str.strip()
    base["source_log"] = (
        df.get("source_log", pd.Series("", index=df.index)).fillna("").astype(str).str.upper().str.strip()
    )
    base["domain_clean"] = df.get("domain_clean", pd.Series("", index=df.index)).fillna("").astype(str).str.strip()
    base["dst_port"] = pd.to_numeric(
        df.get("dst_port", pd.Series(0, index=df.index)),
        errors="coerce",
    ).fillna(0).astype("int64")

    anchor_mask = (
        base["datetime"].notna()
        & base["source_log"].isin(_DOMAIN_LOG_SOURCES)
        & base["domain_clean"].ne("")
        & ~base["domain_clean"].str.lower().eq("unidentified_activity")
    )
    anchors = base.loc[anchor_mask, ["datetime", "mac", "ip", "dst_port", "domain_clean"]].copy()
    if anchors.empty:
        return inferred

    target_mask = (
        base["datetime"].notna()
        & base["domain_clean"].eq("")
        & base["source_log"].ne("")
        & ~base["source_log"].isin(_DOMAIN_INFER_EXCLUDED_SOURCES)
    )
    if not target_mask.any():
        return inferred

    targets = base.loc[target_mask, ["datetime", "mac", "ip", "source_log", "dst_port"]].copy()
    targets["row_idx"] = targets.index
    unknown_ip_mask = targets["ip"].str.lower().isin(_DOMAIN_INFER_IP_UNKNOWN)

    def apply_matches(matches_df: pd.DataFrame):
        if matches_df.empty:
            return
        matched = matches_df.copy()
        matched["matched_domain"] = matched["matched_domain"].fillna("").astype(str).str.strip()
        matched = matched[matched["matched_domain"].ne("")]
        if matched.empty:
            return
        inferred.loc[matched["row_idx"].tolist()] = matched["matched_domain"].tolist()

    # Stage 1: strictest match for CONN with known port and known IP.
    stage1_left = targets.loc[
        targets["source_log"].eq("CONN") & targets["dst_port"].gt(0) & ~unknown_ip_mask,
        ["row_idx", "datetime", "mac", "ip", "dst_port"],
    ].copy()
    stage1_right = anchors.loc[anchors["dst_port"].gt(0), ["datetime", "mac", "ip", "dst_port", "domain_clean"]].copy()
    apply_matches(
        _asof_domain_match(
            stage1_left,
            stage1_right,
            ["mac", "ip", "dst_port"],
            _DOMAIN_INFER_TOLERANCE_SECONDS,
        )
    )

    pending = targets.loc[inferred.loc[targets["row_idx"]].eq("").values].copy()
    if pending.empty:
        return inferred
    pending_unknown_ip = pending["ip"].str.lower().isin(_DOMAIN_INFER_IP_UNKNOWN)

    # Stage 2: same MAC + IP within tolerance.
    stage2_left = pending.loc[
        ~pending_unknown_ip,
        ["row_idx", "datetime", "mac", "ip"],
    ].copy()
    stage2_right = anchors.loc[
        ~anchors["ip"].str.lower().isin(_DOMAIN_INFER_IP_UNKNOWN),
        ["datetime", "mac", "ip", "domain_clean"],
    ].copy()
    apply_matches(
        _asof_domain_match(
            stage2_left,
            stage2_right,
            ["mac", "ip"],
            _DOMAIN_INFER_TOLERANCE_SECONDS,
        )
    )

    pending = targets.loc[inferred.loc[targets["row_idx"]].eq("").values].copy()
    if pending.empty:
        return inferred
    pending_unknown_ip = pending["ip"].str.lower().isin(_DOMAIN_INFER_IP_UNKNOWN)

    # Stage 3: only for unknown-IP rows, fallback by MAC.
    stage3_left = pending.loc[pending_unknown_ip, ["row_idx", "datetime", "mac"]].copy()
    stage3_right = anchors.loc[:, ["datetime", "mac", "domain_clean"]].copy()
    apply_matches(
        _asof_domain_match(
            stage3_left,
            stage3_right,
            ["mac"],
            _DOMAIN_INFER_TOLERANCE_SECONDS,
        )
    )
    return inferred


def infer_missing_app_identities(df: pd.DataFrame) -> pd.Series:
    """
    Infer missing app identities (including WEIRD rows) from nearest events with
    known identities on the same MAC/IP/port and close timestamp.
    """
    inferred = pd.Series("", index=df.index, dtype="object")
    if df is None or df.empty:
        return inferred

    base = pd.DataFrame(index=df.index)
    base["datetime"] = pd.to_datetime(df.get("datetime"), errors="coerce")
    base["mac"] = df.get("mac", pd.Series("unknown", index=df.index)).fillna("unknown").astype(str).str.lower().str.strip()
    base["ip"] = df.get("ip", pd.Series("Unknown", index=df.index)).fillna("Unknown").astype(str).str.strip()
    base["dst_port"] = pd.to_numeric(
        df.get("dst_port", pd.Series(0, index=df.index)),
        errors="coerce",
    ).fillna(0).astype("int64")
    base["source_log"] = (
        df.get("source_log", pd.Series("", index=df.index)).fillna("").astype(str).str.upper().str.strip()
    )
    base["app_identity"] = (
        df.get("app_identity", pd.Series("", index=df.index)).fillna("").astype(str).str.strip()
    )
    base["app_identity_low"] = base["app_identity"].str.lower()

    invalid_identity_values = _UNIDENTIFIED_DEST_VALUES | {"conn telemetry", "unmapped", "unknown host"}
    known_identity_mask = (
        base["datetime"].notna()
        & base["app_identity"].ne("")
        & ~base["app_identity_low"].isin(invalid_identity_values)
        & ~base["app_identity_low"].str.match(r"^conn port\s+\d+$", na=False)
        & ~base["app_identity_low"].str.match(r"^port/\d+$", na=False)
    )
    anchors = base.loc[known_identity_mask, ["datetime", "mac", "ip", "dst_port", "app_identity"]].copy()
    if anchors.empty:
        return inferred

    missing_identity_mask = (
        base["datetime"].notna()
        & (
            base["app_identity"].eq("")
            | base["app_identity_low"].isin(invalid_identity_values)
            | base["app_identity_low"].str.match(r"^conn port\s+\d+$", na=False)
            | base["app_identity_low"].str.match(r"^port/\d+$", na=False)
        )
    )
    if not missing_identity_mask.any():
        return inferred

    targets = base.loc[missing_identity_mask, ["datetime", "mac", "ip", "dst_port", "source_log"]].copy()
    targets["row_idx"] = targets.index
    unknown_ip_mask = targets["ip"].str.lower().isin(_DOMAIN_INFER_IP_UNKNOWN)

    def apply_matches(matches_df: pd.DataFrame):
        if matches_df.empty:
            return
        matched = matches_df.copy()
        matched["matched_identity"] = matched["matched_identity"].fillna("").astype(str).str.strip()
        matched = matched[matched["matched_identity"].ne("")]
        if matched.empty:
            return
        inferred.loc[matched["row_idx"].tolist()] = matched["matched_identity"].tolist()

    # Stage 1: strictest match on MAC + IP + port.
    stage1_left = targets.loc[
        targets["dst_port"].gt(0) & ~unknown_ip_mask,
        ["row_idx", "datetime", "mac", "ip", "dst_port"],
    ].copy()
    stage1_right = anchors.loc[
        anchors["dst_port"].gt(0) & ~anchors["ip"].str.lower().isin(_DOMAIN_INFER_IP_UNKNOWN),
        ["datetime", "mac", "ip", "dst_port", "app_identity"],
    ].copy()
    apply_matches(
        _asof_identity_match(
            stage1_left,
            stage1_right,
            ["mac", "ip", "dst_port"],
            _APP_IDENTITY_INFER_TOLERANCE_SECONDS,
        )
    )

    pending = targets.loc[inferred.loc[targets["row_idx"]].eq("").values].copy()
    if pending.empty:
        return inferred
    pending_unknown_ip = pending["ip"].str.lower().isin(_DOMAIN_INFER_IP_UNKNOWN)

    # Stage 2: MAC + IP match.
    stage2_left = pending.loc[
        ~pending_unknown_ip,
        ["row_idx", "datetime", "mac", "ip"],
    ].copy()
    stage2_right = anchors.loc[
        ~anchors["ip"].str.lower().isin(_DOMAIN_INFER_IP_UNKNOWN),
        ["datetime", "mac", "ip", "app_identity"],
    ].copy()
    apply_matches(
        _asof_identity_match(
            stage2_left,
            stage2_right,
            ["mac", "ip"],
            _APP_IDENTITY_INFER_TOLERANCE_SECONDS,
        )
    )

    pending = targets.loc[inferred.loc[targets["row_idx"]].eq("").values].copy()
    if pending.empty:
        return inferred

    # Stage 3: MAC + port fallback when IP is noisy/missing.
    stage3_left = pending.loc[
        pending["dst_port"].gt(0),
        ["row_idx", "datetime", "mac", "dst_port"],
    ].copy()
    stage3_right = anchors.loc[
        anchors["dst_port"].gt(0),
        ["datetime", "mac", "dst_port", "app_identity"],
    ].copy()
    apply_matches(
        _asof_identity_match(
            stage3_left,
            stage3_right,
            ["mac", "dst_port"],
            _APP_IDENTITY_INFER_TOLERANCE_SECONDS,
        )
    )

    pending = targets.loc[inferred.loc[targets["row_idx"]].eq("").values].copy()
    if pending.empty:
        return inferred

    # Stage 4: last-resort MAC-level nearest event.
    stage4_left = pending.loc[:, ["row_idx", "datetime", "mac"]].copy()
    stage4_right = anchors.loc[:, ["datetime", "mac", "app_identity"]].copy()
    apply_matches(
        _asof_identity_match(
            stage4_left,
            stage4_right,
            ["mac"],
            _APP_IDENTITY_INFER_TOLERANCE_SECONDS,
        )
    )
    return inferred


def _normalize_hostname_value(value) -> str:
    s = "" if value is None else str(value).strip()
    if not s:
        return ""
    if s.lower() in _HOSTNAME_NULLS:
        return ""
    return re.sub(r"\s+", " ", s)[:120]


def backfill_unknown_hostnames(df: pd.DataFrame) -> pd.Series:
    if df is None or df.empty:
        return pd.Series(dtype="object")

    host = df.get("hostname", pd.Series("Unknown", index=df.index)).apply(_normalize_hostname_value)
    ip = df.get("ip", pd.Series("Unknown", index=df.index)).fillna("Unknown").astype(str).str.strip()
    mac = df.get("mac", pd.Series("unknown", index=df.index)).fillna("unknown").astype(str).str.lower().str.strip()
    dt = pd.to_datetime(df.get("datetime"), errors="coerce")

    out = host.copy()

    def _preferred_map(key_series: pd.Series, valid_key_mask: pd.Series) -> pd.Series:
        known = out.ne("")
        src = pd.DataFrame(
            {
                "key": key_series.loc[known & valid_key_mask].astype(str),
                "hostname": out.loc[known & valid_key_mask].astype(str),
                "datetime": dt.loc[known & valid_key_mask],
            }
        )
        if src.empty:
            return pd.Series(dtype="object")
        pref = (
            src.groupby(["key", "hostname"], as_index=False)
            .agg(hits=("hostname", "size"), last_seen=("datetime", "max"))
            .sort_values(["key", "hits", "last_seen", "hostname"], ascending=[True, False, False, True])
            .drop_duplicates(subset=["key"], keep="first")
            .set_index("key")["hostname"]
        )
        return pref

    ip_valid = ~ip.str.lower().isin(_DOMAIN_INFER_IP_UNKNOWN)
    ip_pref = _preferred_map(ip, ip_valid)
    if not ip_pref.empty:
        m_ip_fill = out.eq("") & ip_valid
        out.loc[m_ip_fill] = ip.loc[m_ip_fill].map(ip_pref).fillna("")

    mac_valid = ~mac.isin(_MAC_UNKNOWNS)
    mac_pref = _preferred_map(mac, mac_valid)
    if not mac_pref.empty:
        m_mac_fill = out.eq("") & mac_valid
        out.loc[m_mac_fill] = mac.loc[m_mac_fill].map(mac_pref).fillna("")

    out = out.fillna("").astype(str).str.strip()
    out.loc[out.eq("")] = "Unknown"
    return out


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


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _dedupe_keep_order(items):
    out = []
    seen = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _sanitize_risk_policy(policy: dict) -> dict:
    if not isinstance(policy, dict):
        return {}

    clean = dict(policy)

    for level in ("critical", "high", "medium"):
        section = policy.get(level, {})
        if not isinstance(section, dict):
            section = {}

        raw_logs = _as_list(section.get("source_logs", []))
        logs = []
        for raw in raw_logs:
            norm = normalize_source_log_value(raw)
            if norm in POLICY_ALLOWED_SOURCE_LOGS:
                logs.append(norm)

        raw_ports = _as_list(section.get("ports", []))
        ports = []
        for raw in raw_ports:
            try:
                p = int(raw)
                if 1 <= p <= 65535:
                    ports.append(p)
            except Exception:
                pass

        updated = dict(section)
        updated["source_logs"] = _dedupe_keep_order(logs)
        updated["ports"] = _dedupe_keep_order(ports)
        clean[level] = updated

    low_section = policy.get("low", {})
    if not isinstance(low_section, dict):
        low_section = {}
    low_statuses = []
    for raw in _as_list(low_section.get("app_status", [])):
        s = str(raw).strip()
        if s:
            low_statuses.append(s)
    low_updated = dict(low_section)
    low_updated["app_status"] = _dedupe_keep_order(low_statuses)
    clean["low"] = low_updated

    default_raw = str(policy.get("default", "Safe")).strip()
    default_norm = default_raw.title()
    clean["default"] = default_norm if default_norm in RISK_SCORE else "Safe"

    return clean


def load_risk_policy():
    if not RISK_POLICY_FILE.exists():
        return {}
    try:
        with open(RISK_POLICY_FILE, "r", encoding="utf-8") as f:
            return _sanitize_risk_policy(yaml.safe_load(f) or {})
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
        sql_software_type_raw = get_coalesce(
            ["software_type"],
            "''",
        )
        sql_software_name_raw = get_coalesce(
            ["name"],
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
            {sql_software_type_raw} as software_type_raw,
            {sql_software_name_raw} as software_name_raw,
            {sql_info} as Info,
            COALESCE(NULLIF(upper(regexp_extract(source_file_path, '([a-z]+)\\.parquet', 1)), ''), 'UNKNOWN') as source_log
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
    status_norm = (
        df.get("App Status", pd.Series("", index=df.index))
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
    )
    unauthorized = status_norm.eq("unauthorized")
    conds = [
        sent > EXFIL_BYTES_SENT_THRESHOLD,
        slog.eq(PROTOCOL_ANOMALY_SOURCE_LOG),
        unauthorized & sent.gt(UPLOAD_SPIKE_BYTES_SENT_THRESHOLD) & recv.le(UPLOAD_SPIKE_BYTES_RECEIVED_MAX),
        recv > HEAVY_DOWNLOAD_BYTES_RECEIVED_THRESHOLD,
    ]
    choices = ["Potential Exfiltration", "Protocol Anomaly", "Asymmetric Upload Spike", "Heavy Download"]
    return pd.Series(np.select(conds, choices, default="Standard Traffic"), index=df.index)


def vectorized_risk(df: pd.DataFrame, policy: dict):
    idx = df.index
    score = pd.Series(-1, index=idx, dtype="int16")
    basis = pd.Series("", index=idx, dtype="object")
    strong_signal_hits = pd.Series(0, index=idx, dtype="int16")

    port = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0).astype("int64")
    slog = df["source_log"].astype(str).str.upper()
    status = df["App Status"].astype(str)
    status_norm = status.str.strip().str.lower()
    behavior = df["Behavior"].astype(str)
    domain_clean = (
        df.get("domain_clean", pd.Series("", index=idx))
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
    )

    unauthorized = status_norm.eq("unauthorized")
    unresolved_destination = domain_clean.isin(_UNIDENTIFIED_DEST_VALUES) | domain_clean.str.match(_IPV4_RE, na=False)

    def apply_rule(mask: pd.Series, new_score: int, reason, *, strong_signal: bool = False):
        m = mask.fillna(False)
        if not m.any():
            return
        if strong_signal:
            strong_signal_hits.loc[m] = strong_signal_hits.loc[m] + 1

        promote = m & score.lt(int(new_score))
        if not promote.any():
            return

        score.loc[promote] = int(new_score)
        if isinstance(reason, pd.Series):
            reason_series = reason.reindex(idx).fillna("").astype(str)
            basis.loc[promote] = reason_series.loc[promote]
        else:
            basis.loc[promote] = str(reason)

    apply_rule(
        behavior.eq("Potential Exfiltration"),
        4,
        (
            "Critical: Potential Exfiltration because bytes_sent exceeded "
            f"{EXFIL_BYTES_SENT_THRESHOLD:,} ({_fmt_mb_threshold(EXFIL_BYTES_SENT_THRESHOLD)})."
        ),
        strong_signal=True,
    )
    apply_rule(
        behavior.eq("Protocol Anomaly"),
        3,
        f"High: Protocol Anomaly detected from source_log={PROTOCOL_ANOMALY_SOURCE_LOG}.",
        strong_signal=True,
    )
    apply_rule(
        behavior.eq("Asymmetric Upload Spike"),
        3,
        (
            "High: Unauthorized upload spike because bytes_sent exceeded "
            f"{UPLOAD_SPIKE_BYTES_SENT_THRESHOLD:,} ({_fmt_mb_threshold(UPLOAD_SPIKE_BYTES_SENT_THRESHOLD)}) and "
            f"bytes_received stayed at or below {UPLOAD_SPIKE_BYTES_RECEIVED_MAX:,} "
            f"({_fmt_mb_threshold(UPLOAD_SPIKE_BYTES_RECEIVED_MAX)})."
        ),
        strong_signal=True,
    )
    apply_rule(
        behavior.eq("Heavy Download"),
        2,
        (
            "Medium: Heavy Download because bytes_received exceeded "
            f"{HEAVY_DOWNLOAD_BYTES_RECEIVED_THRESHOLD:,} ({_fmt_mb_threshold(HEAVY_DOWNLOAD_BYTES_RECEIVED_THRESHOLD)})."
        ),
        strong_signal=True,
    )

    crit_logs, crit_ports = _policy_logs(policy, "critical"), _policy_ports(policy, "critical")
    high_logs, high_ports = _policy_logs(policy, "high"), _policy_ports(policy, "high")
    med_logs, med_ports = _policy_logs(policy, "medium"), _policy_ports(policy, "medium")

    if crit_logs:
        apply_rule(
            slog.isin(crit_logs),
            4,
            "Critical: source_log matched risk_policy.critical.source_logs (" + slog.astype(str) + ").",
            strong_signal=True,
        )
    if crit_ports:
        apply_rule(
            port.isin(crit_ports),
            4,
            "Critical: destination port matched risk_policy.critical.ports (" + port.astype(str) + ").",
            strong_signal=True,
        )

    if high_logs:
        apply_rule(
            slog.isin(high_logs),
            3,
            "High: source_log matched risk_policy.high.source_logs (" + slog.astype(str) + ").",
            strong_signal=True,
        )
    if high_ports:
        apply_rule(
            port.isin(high_ports),
            3,
            "High: destination port matched risk_policy.high.ports (" + port.astype(str) + ").",
            strong_signal=True,
        )

    if med_logs:
        apply_rule(
            slog.isin(med_logs),
            2,
            "Medium: source_log matched risk_policy.medium.source_logs (" + slog.astype(str) + ").",
            strong_signal=True,
        )
    if med_ports:
        apply_rule(
            port.isin(med_ports),
            2,
            "Medium: destination port matched risk_policy.medium.ports (" + port.astype(str) + ").",
            strong_signal=True,
        )

    apply_rule(
        unauthorized & unresolved_destination,
        2,
        "Medium: Unauthorized traffic with unresolved destination/domain context (unidentified_activity).",
        strong_signal=True,
    )

    low_statuses = _policy_statuses(policy, "low")
    if low_statuses:
        apply_rule(
            status.isin(low_statuses),
            1,
            "Low: App Status matched risk_policy.low.app_status (" + status.astype(str) + ").",
        )

    default_str = str(policy.get("default", "Safe")) if isinstance(policy, dict) and policy else "Safe"
    default_score = int(RISK_SCORE.get(default_str, 0))
    default_risk = score_to_risk(default_score)
    m_default = score.eq(-1)
    score.loc[m_default] = default_score
    basis.loc[m_default] = (
        f"{default_risk}: No explicit risk signal matched; fallback to risk_policy.default ('{default_str}')."
        if policy
        else "Safe: No risk_policy.yaml loaded; fallback default applied."
    )

    escalate_mask = (
        unauthorized
        & strong_signal_hits.ge(MULTI_SIGNAL_ESCALATION_MIN_INDICATORS)
        & score.ge(2)
        & score.lt(4)
    )
    if escalate_mask.any():
        prev_labels = score.loc[escalate_mask].map(lambda s: SCORE_TO_RISK.get(int(s), "Safe")).astype(str)
        score.loc[escalate_mask] = (score.loc[escalate_mask] + 1).clip(upper=4).astype("int16")
        new_labels = score.loc[escalate_mask].map(lambda s: SCORE_TO_RISK.get(int(s), "Safe")).astype(str)
        basis.loc[escalate_mask] = (
            new_labels
            + ": Escalated from "
            + prev_labels
            + " due to "
            + strong_signal_hits.loc[escalate_mask].astype(str)
            + " corroborating medium/high indicators on unauthorized traffic."
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
    df["source_log"] = df.get("source_log", pd.Series("", index=df.index)).apply(normalize_source_log_value)
    df["hostname"] = df.get("hostname", "Unknown").fillna("Unknown").astype(str)
    df["hostname"] = df["hostname"].replace({"": "Unknown"})
    df.loc[df["hostname"].str.lower().isin(["nan", "none"]), "hostname"] = "Unknown"
    df["hostname"] = backfill_unknown_hostnames(df)

    domain_strict = pd.Series(
        [
            extract_domain_strict(v) if str(src).upper().strip() in _DOMAIN_LOG_SOURCES else ""
            for v, src in zip(df["app_identifier"].tolist(), df["source_log"].tolist())
        ],
        index=df.index,
        dtype="object",
    )
    domain_hint = pd.Series(
        [
            extract_destination_hint(v) if str(src).upper().strip() in _DOMAIN_LOG_SOURCES else ""
            for v, src in zip(df["app_identifier"].tolist(), df["source_log"].tolist())
        ],
        index=df.index,
        dtype="object",
    )
    df["domain_clean"] = domain_strict.fillna("").astype(str).str.strip()
    m_domain_hint = df["domain_clean"].eq("") & domain_hint.fillna("").astype(str).str.strip().ne("")
    if m_domain_hint.any():
        df.loc[m_domain_hint, "domain_clean"] = domain_hint.loc[m_domain_hint].fillna("").astype(str).str.strip()

    inferred_domains = infer_missing_domains(df)
    m_infer_domain = df["domain_clean"].eq("") & inferred_domains.reindex(df.index).fillna("").ne("")
    df.loc[m_infer_domain, "domain_clean"] = inferred_domains.loc[m_infer_domain]
    df.loc[df["domain_clean"].eq(""), "domain_clean"] = "unidentified_activity"
    soft_raw_series = df.get("app_software_raw", pd.Series("", index=df.index))
    soft_type_series = df.get("software_type_raw", pd.Series("", index=df.index))
    soft_name_series = df.get("software_name_raw", pd.Series("", index=df.index))
    df["app_software"] = [
        normalize_app_software(soft_raw, src, software_type=soft_t, software_name=soft_n)
        or normalize_app_software(app_val, src, software_type=soft_t, software_name=soft_n)
        for soft_raw, app_val, src, soft_t, soft_n in zip(
            soft_raw_series.tolist(),
            df["app_identifier"].tolist(),
            df["source_log"].tolist(),
            soft_type_series.tolist(),
            soft_name_series.tolist(),
        )
    ]
    df["app_identity"] = df["app_software"].fillna("").astype(str).str.strip()
    app_identifier_hint = df["app_identifier"].apply(normalize_identifier_hint)
    m_hint_eligible_source = ~df["source_log"].astype(str).str.upper().eq("WEIRD")
    m_identifier_identity = df["app_identity"].eq("") & app_identifier_hint.ne("") & m_hint_eligible_source
    if m_identifier_identity.any():
        df.loc[m_identifier_identity, "app_identity"] = app_identifier_hint.loc[m_identifier_identity].astype(str)
    m_domain_identity = df["app_identity"].eq("") & df["domain_clean"].ne("unidentified_activity")
    df.loc[m_domain_identity, "app_identity"] = df.loc[m_domain_identity, "domain_clean"].astype(str)
    inferred_identities = infer_missing_app_identities(df)
    m_inferred_identity = df["app_identity"].eq("") & inferred_identities.reindex(df.index).fillna("").ne("")
    if m_inferred_identity.any():
        df.loc[m_inferred_identity, "app_identity"] = inferred_identities.loc[m_inferred_identity].astype(str)

    # Keep unresolved CONN identities empty here; UI/query layers will render
    # unresolved entries as 'unidentified_activity' instead of synthetic labels.

    if allow_re is not None:
        allowed_mask = df["domain_clean"].astype(str).str.contains(allow_re, na=False)
    else:
        allowed_mask = pd.Series(False, index=df.index)

    df["App Status"] = np.where(allowed_mask, "Authorized", "Unauthorized")
    df["Behavior"] = vectorized_behavior(df)
    risk_level, risk_basis, risk_score_int = vectorized_risk(df, risk_policy)
    df["_risk_score"] = pd.to_numeric(risk_score_int, errors="coerce").fillna(0).astype("int16")
    df["Risk Level"] = df["_risk_score"].map(lambda s: SCORE_TO_RISK.get(int(s), "Safe")).astype(str)
    df["Risk Basis"] = risk_basis.fillna("").astype(str).str.strip()
    m_missing_basis = df["Risk Basis"].eq("")
    if m_missing_basis.any():
        port_text = (
            pd.to_numeric(df.loc[m_missing_basis, "dst_port"], errors="coerce")
            .fillna(0)
            .astype("int64")
            .astype(str)
        )
        df.loc[m_missing_basis, "Risk Basis"] = (
            df.loc[m_missing_basis, "Risk Level"].astype(str)
            + ": Derived from source_log="
            + df.loc[m_missing_basis, "source_log"].astype(str)
            + ", dst_port="
            + port_text
            + "."
        )
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
        "app_identity",
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
        WHERE upper(COALESCE(source_log, '')) <> 'NOTICE'
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
            WHERE upper(COALESCE(source_log, '')) <> 'NOTICE'
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
@st.dialog("Allow Application / Identifier", width="small", dismissible=False)
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
    st.markdown(f"- Application / Identifier: `{app_or_id or '-'}`")
    st.caption(
        "This will update whitelist_domains.yaml and refresh statuses to Authorized after cache rebuild."
    )

    if invalid_target:
        st.error("This row has no valid destination domain to allowlist.")

    c1, c2 = st.columns(2)
    with c1:
        if st.button(
            "Allow This App/Domain",
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
    sel_dest_lookup = str(ctx.get("destination_lookup") or sel_dest).strip()
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

    # Make app-detail metrics a bit more compact for readability.
    st.markdown(
        """
        <style>
        div[data-testid="stDialog"] [data-testid="stMetricLabel"] p {
            font-size: 0.78rem !important;
            line-height: 1.05 !important;
        }
        div[data-testid="stDialog"] [data-testid="stMetricValue"] {
            font-size: 1.38rem !important;
            line-height: 1.08 !important;
        }
        div[data-testid="stDialog"] [data-testid="stMetricDelta"] {
            font-size: 0.72rem !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    if not target_mac or not sel_dest_lookup or not sel_app:
        st.warning("Missing application context. Please select an Application / Identifier row again.")
        return

    def _fetch_app_events(destination_key: str) -> pd.DataFrame:
        app_where = [
            "lower(destination_lookup) = lower(?)",
            "lower(app_identity_norm) = lower(?)",
        ]
        app_params = [target_mac, destination_key, sel_app]

        if selected_f_source != "All":
            app_where.append("upper(source_log) = upper(?)")
            app_params.append(selected_f_source)

        if not forensic_risk:
            app_where.append("1=0")
        elif set(forensic_risk) != set(RISK_OPTIONS):
            app_in = _build_in_clause(forensic_risk, app_params)
            app_where.append(f""""Risk Level" IN {app_in}""")

        if forensic_search:
            q = f"%{forensic_search}%"
            app_where.append(
                "(destination_lookup ILIKE ? OR app_identity_raw ILIKE ? OR ip ILIKE ? OR Info ILIKE ? OR hostname ILIKE ?)"
            )
            app_params.extend([q, q, q, q, q])

        app_where_sql = " AND ".join(app_where)
        return _sql_fetch_df(
            conn,
            f"""
            WITH app_base AS (
                SELECT
                    datetime,
                    COALESCE(NULLIF(trim(source_log), ''), 'UNKNOWN') AS source_log,
                    CASE COALESCE(try_cast(_risk_score AS INT), 0)
                        WHEN 4 THEN 'Critical'
                        WHEN 3 THEN 'High'
                        WHEN 2 THEN 'Medium'
                        WHEN 1 THEN 'Low'
                        ELSE 'Safe'
                    END AS "Risk Level",
                    CASE
                        WHEN "Risk Basis" IS NOT NULL AND trim("Risk Basis") <> '' THEN trim("Risk Basis")
                        ELSE
                            (
                                CASE COALESCE(try_cast(_risk_score AS INT), 0)
                                    WHEN 4 THEN 'Critical'
                                    WHEN 3 THEN 'High'
                                    WHEN 2 THEN 'Medium'
                                    WHEN 1 THEN 'Low'
                                    ELSE 'Safe'
                                END
                            )
                            || ': Derived from source_log='
                            || COALESCE(NULLIF(trim(source_log), ''), 'UNKNOWN')
                            || ', dst_port='
                            || CAST(COALESCE(try_cast(dst_port AS INT), 0) AS VARCHAR)
                            || '.'
                    END AS "Risk Basis",
                    "Behavior",
                    "App Status",
                    bytes_sent,
                    bytes_received,
                    dst_port,
                    COALESCE(NULLIF(trim(Info), ''), '-') AS Info,
                    COALESCE(NULLIF(trim(domain_clean), ''), 'unidentified_activity') AS destination_lookup,
                    COALESCE(NULLIF(trim(ip), ''), 'Unknown') AS ip,
                    COALESCE(NULLIF(trim(hostname), ''), 'Unknown') AS hostname,
                    COALESCE(NULLIF(trim(app_identity), ''), '') AS app_identity_raw,
                    CASE
                        WHEN app_identity IS NOT NULL
                         AND trim(app_identity) <> ''
                         AND lower(trim(app_identity)) <> 'conn telemetry'
                         AND lower(trim(app_identity)) NOT LIKE 'conn port %'
                            THEN trim(app_identity)
                        ELSE 'unidentified_activity'
                    END AS app_identity_norm
                FROM shadow_events
                WHERE lower(mac) = lower(?)
            )
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
            FROM app_base
            WHERE {app_where_sql}
            ORDER BY datetime DESC
            """,
            app_params,
        )

    matched_destination_key = sel_dest_lookup
    app_df = _fetch_app_events(matched_destination_key)
    if app_df.empty and sel_dest and sel_dest_lookup.lower() != sel_dest.lower():
        fallback_df = _fetch_app_events(sel_dest)
        if not fallback_df.empty:
            app_df = fallback_df
            matched_destination_key = sel_dest

    if app_df.empty:
        st.info("No events found for this application with current filters.")
        return
    st.caption(f"Matched destination: {matched_destination_key}")

    app_df["datetime"] = pd.to_datetime(app_df["datetime"], errors="coerce")
    invalid_ts = int(app_df["datetime"].isna().sum())
    if invalid_ts > 0:
        st.warning(f"{invalid_ts:,} events were excluded from trend charts due to invalid timestamps.")

    valid_time = app_df["datetime"].dropna()
    if not valid_time.empty:
        first_seen_ts = valid_time.min()
        last_seen_ts = valid_time.max()
        duration_seconds = max(float((last_seen_ts - first_seen_ts).total_seconds()), 0.0)
        first_seen_txt = first_seen_ts.strftime("%Y-%m-%d %H:%M:%S")
        last_seen_txt = last_seen_ts.strftime("%Y-%m-%d %H:%M:%S")
    else:
        duration_seconds = 0.0
        first_seen_txt = "-"
        last_seen_txt = "-"

    app_metrics = st.columns(5)
    app_metrics[0].metric("Events", f"{len(app_df):,}")
    app_metrics[1].metric("Unauthorized", f"{int((app_df['App Status'] == 'Unauthorized').sum()):,}")
    app_metrics[2].metric("Critical / High", f"{int(app_df['Risk Level'].isin(['Critical', 'High']).sum()):,}")
    app_metrics[3].metric("Distinct Source Logs", f"{int(app_df['source_log'].nunique(dropna=True)):,}")
    app_metrics[4].metric("Duration", _format_duration_seconds(duration_seconds))
    st.caption(f"First Seen: {first_seen_txt}")
    st.caption(f"Last Seen: {last_seen_txt}")

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
        """
        SELECT DISTINCT upper(trim(source_log)) AS source_log
        FROM shadow_events
        WHERE lower(mac) = lower(?)
          AND source_log IS NOT NULL
          AND trim(source_log) <> ''
        ORDER BY 1
        """,
        [target_mac],
    )
    f_raw_sources = src_df["source_log"].dropna().astype(str).str.strip().tolist() if not src_df.empty else []
    if "SOFTWARE" not in f_raw_sources:
        has_software = conn.execute(
            """
            SELECT 1
            FROM shadow_events
            WHERE upper(trim(source_log)) = 'SOFTWARE'
            LIMIT 1
            """
        ).fetchone()
        if has_software:
            f_raw_sources.append("SOFTWARE")
    f_raw_sources = sorted({s for s in f_raw_sources if s})
    forensic_search = st.text_input(
        "Quick Search",
        placeholder="IP, domain, context...",
        key=f"dlg_search_{target_mac}",
        on_change=_mark_dialog_origin,
    ).strip()
    f_bottom_left, f_bottom_right = st.columns([2.6, 1.4])
    with f_bottom_left:
        forensic_risk = risk_multiselect(
            "Risk Level",
            key=f"dlg_risk_{target_mac}",
            default=RISK_OPTIONS,
            on_change=_mark_dialog_origin,
        )
    with f_bottom_right:
        selected_f_source = st.selectbox(
            "Source Logs",
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

    if not forensic_risk:
        where.append("1=0")
    elif not is_all_risk_selected:
        in_clause = _build_in_clause(forensic_risk, params)
        where.append(f""""Risk Level" IN {in_clause}""")

    if forensic_search:
        q = f"%{forensic_search}%"
        where.append("(domain_clean ILIKE ? OR ip ILIKE ? OR Info ILIKE ? OR hostname ILIKE ? OR app_identity ILIKE ?)")
        params.extend([q, q, q, q, q])

    where_sql = " AND ".join(where)

    forensic_df = _sql_fetch_df(
        conn,
        f"""
        SELECT
            datetime, mac, hostname, ip, domain_clean, app_identity, source_log, Info, dst_port,
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
    forensic_domain_series = _normalize_destination_display_series(forensic_df["domain_clean"])
    forensic_domains = int(forensic_domain_series[_is_real_destination_series(forensic_domain_series)].nunique(dropna=True))
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
    timeline_controls = st.columns([1.6, 1.2, 2.2])
    with timeline_controls[0]:
        timeline_status_filter = st.selectbox(
            "Status Filter",
            ["All", "Authorized", "Unauthorized", "Unknown"],
            key=f"dlg_timeline_status_{target_mac}",
            on_change=_mark_dialog_origin,
        )
    with timeline_controls[1]:
        timeline_bucket_label = st.selectbox(
            "Bucket",
            ["5 min", "10 min", "30 min", "1 hour"],
            index=1,
            key=f"dlg_timeline_bucket_{target_mac}",
            on_change=_mark_dialog_origin,
        )
    timeline_mode = st.radio(
        "Timeline View",
        ["Total Events", "Status Split"],
        horizontal=True,
        key=f"dlg_timeline_mode_{target_mac}",
        on_change=_mark_dialog_origin,
    )

    bucket_map = {
        "5 min": ("5min", "5 min"),
        "10 min": ("10min", "10 min"),
        "30 min": ("30min", "30 min"),
        "1 hour": ("1H", "1 hour"),
    }
    bucket_rule, timeline_label = bucket_map.get(timeline_bucket_label, ("10min", "10 min"))
    timeline = forensic_df.dropna(subset=["datetime"]).copy()
    timeline["App Status"] = timeline["App Status"].fillna("Unknown").astype(str).str.strip().replace("", "Unknown")
    if timeline_status_filter != "All":
        timeline = timeline[timeline["App Status"].eq(timeline_status_filter)]

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
        st.warning("No timeline events match the selected status/bucket filters.")

    st.markdown("#### Top Destinations")
    top_dest_src = forensic_df.assign(
        domain_clean=_normalize_destination_display_series(forensic_df["domain_clean"])
    )
    top_dest_src = top_dest_src[_is_real_destination_series(top_dest_src["domain_clean"])].copy()
    top_dest = (
        top_dest_src
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
    st.markdown("#### Applications / Identifiers Observed (This MAC)")

    inv_where = ["lower(mac) = lower(?)"]
    inv_params = [target_mac]

    # Keep inventory aligned with user filters (source + risk)
    if selected_f_source != "All":
        inv_where.append("upper(source_log) = upper(?)")
        inv_params.append(selected_f_source)

    if not forensic_risk:
        inv_where.append("1=0")
    elif not is_all_risk_selected:
        inv_in = _build_in_clause(forensic_risk, inv_params)
        inv_where.append(f""""Risk Level" IN {inv_in}""")

    if forensic_search:
        q_inv = f"%{forensic_search}%"
        inv_where.append("(domain_clean ILIKE ? OR app_identity ILIKE ? OR ip ILIKE ? OR Info ILIKE ? OR hostname ILIKE ?)")
        inv_params.extend([q_inv, q_inv, q_inv, q_inv, q_inv])

    inv_where_sql = " AND ".join(inv_where)

    inventory_df = _sql_fetch_df(
        conn,
        f"""
        WITH base AS (
            SELECT
                domain_clean,
                CASE
                    WHEN app_identity IS NOT NULL AND trim(app_identity) <> ''
                        THEN trim(app_identity)
                    WHEN upper(source_log) = 'CONN' AND try_cast(dst_port AS INT) > 0
                        THEN 'CONN Port ' || CAST(try_cast(dst_port AS INT) AS VARCHAR)
                    WHEN upper(source_log) = 'CONN' THEN 'CONN Telemetry'
                    ELSE 'unidentified_activity'
                END AS app_identity_norm,
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
                app_identity_norm AS app_identity,
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
            app_identity AS application_or_identifier,
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

    if not inventory_df.empty:
        inventory_df["lookup_destination"] = inventory_df["destination"].fillna("").astype(str).str.strip()
        inventory_df["application_or_identifier"] = (
            inventory_df["application_or_identifier"].fillna("").astype(str).str.strip()
        )

        inv_dest = inventory_df["destination"].fillna("").astype(str).str.strip()
        inv_app_raw = inventory_df["application_or_identifier"].fillna("").astype(str).str.strip()
        inv_app = inv_app_raw.mask(
            inv_app_raw.str.match(r"(?i)^conn port\s+\d+$", na=False)
            | inv_app_raw.str.lower().eq("conn telemetry")
            | inv_app_raw.eq(""),
            "unidentified_activity",
        )
        inv_sources = inventory_df["sources"].fillna("").astype(str).str.upper()

        is_port = inv_sources.str.contains("CONN", regex=False) & inv_app.str.lower().eq("unidentified_activity")
        is_software = inv_sources.str.contains("SOFTWARE", regex=False)
        is_domain = (
            (~is_port)
            & (~is_software)
            & inv_dest.str.lower().ne("unidentified_activity")
            & inv_app.str.lower().eq(inv_dest.str.lower())
        )
        inventory_df["identity_type"] = np.select(
            [is_port, is_software, is_domain],
            ["Port", "Software", "Domain"],
            default="Application",
        )

        # Build accurate port lists from the currently filtered forensic events.
        port_df = forensic_df.copy()
        port_df["domain_clean"] = port_df["domain_clean"].fillna("").astype(str).str.strip()
        port_df["source_log"] = port_df["source_log"].fillna("").astype(str).str.upper().str.strip()
        port_df["app_identity"] = port_df["app_identity"].fillna("").astype(str).str.strip()
        port_df["dst_port"] = pd.to_numeric(port_df["dst_port"], errors="coerce").fillna(0).astype("int64")
        port_df["app_identity_norm"] = port_df["app_identity"]
        m_missing_identity = port_df["app_identity_norm"].eq("")
        m_conn_missing = m_missing_identity & port_df["source_log"].eq("CONN")
        m_conn_with_port = m_conn_missing & port_df["dst_port"].gt(0)
        port_df.loc[m_conn_with_port, "app_identity_norm"] = (
            "CONN Port " + port_df.loc[m_conn_with_port, "dst_port"].astype(str)
        )
        port_df.loc[m_conn_missing & ~m_conn_with_port, "app_identity_norm"] = "CONN Telemetry"
        port_df.loc[m_missing_identity & ~m_conn_missing, "app_identity_norm"] = "unidentified_activity"
        port_df = port_df[(port_df["domain_clean"] != "") & (port_df["app_identity_norm"] != "")]

        if not port_df.empty:
            port_map = (
                port_df.groupby(["domain_clean", "app_identity_norm"], as_index=False)["dst_port"]
                .agg(lambda s: ", ".join(str(v) for v in sorted({int(x) for x in s if int(x) > 0})))
                .rename(
                    columns={
                        "domain_clean": "destination",
                        "app_identity_norm": "application_or_identifier",
                        "dst_port": "conn_ports",
                    }
                )
            )
            inventory_df = inventory_df.merge(
                port_map,
                on=["destination", "application_or_identifier"],
                how="left",
            )
        else:
            inventory_df["conn_ports"] = ""
        if "conn_ports" in inventory_df.columns:
            inventory_df["conn_ports"] = inventory_df["conn_ports"].fillna("")

        # If a Software row has no native port or unresolved destination, infer
        # from nearest non-software events for this MAC within a tight time window.
        software_rows = inventory_df["identity_type"].eq("Software")
        software_missing_port = software_rows & inventory_df["conn_ports"].astype(str).str.strip().eq("")
        software_unknown_destination = software_rows & (
            inventory_df["destination"].fillna("").astype(str).str.strip().str.lower().eq("unidentified_activity")
        )
        software_needs_inference = software_missing_port | software_unknown_destination
        if software_needs_inference.any():
            sw_where = list(inv_where)
            sw_params = list(inv_params)
            sw_where.append("upper(source_log) = 'SOFTWARE'")
            sw_where.append("app_identity IS NOT NULL")
            sw_where.append("trim(app_identity) <> ''")
            sw_where_sql = " AND ".join(sw_where)

            sw_anchor_df = _sql_fetch_df(
                conn,
                f"""
                SELECT
                    datetime,
                    ip,
                    trim(app_identity) AS app_identity
                FROM shadow_events
                WHERE {sw_where_sql}
                ORDER BY datetime
                """,
                sw_params,
            )
            if not sw_anchor_df.empty:
                sw_anchor_df["datetime"] = pd.to_datetime(sw_anchor_df["datetime"], errors="coerce")
                sw_anchor_df["ip"] = sw_anchor_df["ip"].fillna("").astype(str).str.strip()
                sw_anchor_df["app_identity"] = sw_anchor_df["app_identity"].fillna("").astype(str).str.strip()
                sw_anchor_df = sw_anchor_df[
                    sw_anchor_df["datetime"].notna()
                    & sw_anchor_df["app_identity"].ne("")
                ]

                sw_keys = (
                    inventory_df.loc[software_needs_inference, ["application_or_identifier"]]
                    .copy()
                    .rename(columns={"application_or_identifier": "app_identity"})
                )
                sw_keys["app_identity"] = sw_keys["app_identity"].fillna("").astype(str).str.strip()
                sw_keys = sw_keys[sw_keys["app_identity"].ne("")].drop_duplicates()

                sw_anchor_df = sw_anchor_df.merge(sw_keys, on="app_identity", how="inner")

                if not sw_anchor_df.empty:
                    min_ts = sw_anchor_df["datetime"].min() - pd.Timedelta(seconds=2)
                    max_ts = sw_anchor_df["datetime"].max() + pd.Timedelta(seconds=2)
                    sw_candidates = _sql_fetch_df(
                        conn,
                        """
                        SELECT
                            datetime,
                            ip,
                            domain_clean,
                            try_cast(dst_port AS INT) AS dst_port
                        FROM shadow_events
                        WHERE lower(mac) = lower(?)
                          AND upper(source_log) <> 'SOFTWARE'
                          AND datetime >= ?
                          AND datetime <= ?
                          AND (
                                try_cast(dst_port AS INT) > 0
                                OR (
                                    domain_clean IS NOT NULL
                                    AND trim(domain_clean) <> ''
                                    AND lower(trim(domain_clean)) <> 'unidentified_activity'
                                )
                          )
                        ORDER BY datetime
                        """,
                        [target_mac, min_ts, max_ts],
                    )

                    if not sw_candidates.empty:
                        sw_anchor_df = sw_anchor_df.sort_values("datetime")
                        sw_candidates["datetime"] = pd.to_datetime(sw_candidates["datetime"], errors="coerce")
                        sw_candidates["ip"] = sw_candidates["ip"].fillna("").astype(str).str.strip()
                        sw_candidates["domain_clean"] = sw_candidates["domain_clean"].fillna("").astype(str).str.strip()
                        sw_candidates["dst_port"] = pd.to_numeric(
                            sw_candidates["dst_port"], errors="coerce"
                        ).fillna(0).astype("int64")
                        sw_candidates = sw_candidates[
                            sw_candidates["datetime"].notna()
                            & (
                                sw_candidates["dst_port"].gt(0)
                                | sw_candidates["domain_clean"].ne("")
                            )
                        ].copy()
                        sw_candidates = sw_candidates[
                            ~sw_candidates["domain_clean"].str.lower().eq("unidentified_activity")
                        ].sort_values("datetime")

                        if not sw_candidates.empty:
                            anchors = sw_anchor_df[["datetime", "ip", "app_identity"]].copy().reset_index(drop=True)
                            anchors["row_idx"] = anchors.index.astype("int64")
                            candidates = sw_candidates.rename(
                                columns={"domain_clean": "matched_domain", "dst_port": "matched_port"}
                            )

                            match_ip = pd.DataFrame()
                            if anchors["ip"].ne("").any() and candidates["ip"].ne("").any():
                                match_ip = _asof_grouped_match(
                                    left_df=anchors.loc[anchors["ip"].ne(""), ["row_idx", "datetime", "ip"]].copy(),
                                    right_df=candidates.loc[
                                        candidates["ip"].ne(""),
                                        ["ip", "datetime", "matched_domain", "matched_port"],
                                    ].copy(),
                                    by_cols=["ip"],
                                    right_value_cols=["matched_domain", "matched_port"],
                                    tolerance_seconds=2,
                                )
                            if match_ip.empty:
                                match_ip = anchors.copy()
                                match_ip["matched_domain"] = pd.NA
                                match_ip["matched_port"] = pd.NA
                            else:
                                match_ip = anchors.merge(match_ip, on="row_idx", how="left")
                            if "matched_domain" not in match_ip.columns:
                                match_ip["matched_domain"] = pd.NA
                            if "matched_port" not in match_ip.columns:
                                match_ip["matched_port"] = pd.NA

                            missing_match = match_ip["matched_domain"].isna() & match_ip["matched_port"].isna()
                            if missing_match.any():
                                fallback_left = match_ip.loc[missing_match, ["row_idx", "datetime"]].copy()
                                fallback_match = _asof_grouped_match(
                                    left_df=fallback_left,
                                    right_df=candidates[["datetime", "matched_domain", "matched_port"]].copy(),
                                    by_cols=[],
                                    right_value_cols=["matched_domain", "matched_port"],
                                    tolerance_seconds=2,
                                )
                                if not fallback_match.empty:
                                    fallback_map = fallback_match.set_index("row_idx")
                                    for col in ["matched_domain", "matched_port"]:
                                        match_ip.loc[missing_match, col] = (
                                            match_ip.loc[missing_match, "row_idx"].map(fallback_map[col]).values
                                        )

                            sw_nearest = match_ip.copy()
                            sw_nearest["matched_domain"] = (
                                sw_nearest["matched_domain"].fillna("").astype(str).str.strip()
                            )
                            sw_nearest["matched_port"] = pd.to_numeric(
                                sw_nearest["matched_port"], errors="coerce"
                            ).fillna(0).astype("int64")

                            if not sw_nearest.empty:
                                sw_domain_hits = (
                                    sw_nearest[sw_nearest["matched_domain"].ne("")]
                                    .groupby(["app_identity", "matched_domain"], as_index=False)
                                    .size()
                                    .rename(columns={"size": "hits"})
                                    .sort_values(
                                        ["app_identity", "hits", "matched_domain"],
                                        ascending=[True, False, True],
                                    )
                                )
                                if not sw_domain_hits.empty:
                                    sw_domain_map = (
                                        sw_domain_hits.groupby("app_identity", as_index=False)
                                        .head(1)
                                        .rename(
                                            columns={
                                                "app_identity": "application_or_identifier",
                                                "matched_domain": "inferred_destination",
                                            }
                                        )[
                                            ["application_or_identifier", "inferred_destination"]
                                        ]
                                    )
                                    inventory_df = inventory_df.merge(
                                        sw_domain_map,
                                        on="application_or_identifier",
                                        how="left",
                                    )
                                    inventory_df["inferred_destination"] = (
                                        inventory_df["inferred_destination"].fillna("").astype(str).str.strip()
                                    )
                                    software_unknown_destination = software_rows & (
                                        inventory_df["destination"]
                                        .fillna("")
                                        .astype(str)
                                        .str.strip()
                                        .str.lower()
                                        .eq("unidentified_activity")
                                    )
                                    inventory_df["destination"] = np.where(
                                        software_unknown_destination
                                        & inventory_df["inferred_destination"].ne(""),
                                        inventory_df["inferred_destination"],
                                        inventory_df["destination"],
                                    )

                                sw_port_hits = (
                                    sw_nearest[sw_nearest["matched_port"].gt(0)]
                                    .groupby(["app_identity", "matched_port"], as_index=False)
                                    .size()
                                    .rename(columns={"size": "hits"})
                                    .sort_values(
                                        ["app_identity", "hits", "matched_port"],
                                        ascending=[True, False, True],
                                    )
                                )
                                if not sw_port_hits.empty:
                                    sw_top_ports = (
                                        sw_port_hits.groupby("app_identity", as_index=False)
                                        .head(3)
                                        .groupby("app_identity", as_index=False)["matched_port"]
                                        .agg(lambda s: ", ".join(str(int(v)) for v in s))
                                        .rename(
                                            columns={
                                                "app_identity": "application_or_identifier",
                                                "matched_port": "inferred_ports",
                                            }
                                        )
                                    )
                                    inventory_df = inventory_df.merge(
                                        sw_top_ports,
                                        on="application_or_identifier",
                                        how="left",
                                    )
                                    inventory_df["inferred_ports"] = (
                                        inventory_df["inferred_ports"].fillna("").astype(str).str.strip()
                                    )
                                    software_missing_port = software_rows & (
                                        inventory_df["conn_ports"].astype(str).str.strip().eq("")
                                    )
                                    inventory_df["conn_ports"] = np.where(
                                        software_missing_port
                                        & inventory_df["inferred_ports"].ne(""),
                                        inventory_df["inferred_ports"] + " (inferred)",
                                        inventory_df["conn_ports"],
                                    )

                                inventory_df = inventory_df.drop(
                                    columns=["inferred_destination", "inferred_ports"],
                                    errors="ignore",
                                )

        # For CONN rows with unresolved destination, infer destination from
        # nearest non-CONN events for the same MAC (IP-priority, then fallback).
        conn_unknown_destination = (
            inventory_df["identity_type"].eq("Port")
            & inventory_df["destination"].fillna("").astype(str).str.strip().str.lower().eq("unidentified_activity")
        )
        if conn_unknown_destination.any():
            conn_anchor_df = forensic_df.copy()
            conn_anchor_df["datetime"] = pd.to_datetime(conn_anchor_df["datetime"], errors="coerce")
            conn_anchor_df["ip"] = conn_anchor_df["ip"].fillna("").astype(str).str.strip()
            conn_anchor_df["source_log"] = conn_anchor_df["source_log"].fillna("").astype(str).str.upper().str.strip()
            conn_anchor_df["app_identity"] = conn_anchor_df["app_identity"].fillna("").astype(str).str.strip()
            conn_anchor_df["dst_port"] = pd.to_numeric(conn_anchor_df["dst_port"], errors="coerce").fillna(0).astype("int64")
            conn_anchor_df = conn_anchor_df[
                conn_anchor_df["datetime"].notna() & conn_anchor_df["source_log"].eq("CONN")
            ]
            conn_anchor_df["app_identity_norm"] = conn_anchor_df["app_identity"]
            m_conn_missing_identity = conn_anchor_df["app_identity_norm"].eq("")
            m_conn_with_port = m_conn_missing_identity & conn_anchor_df["dst_port"].gt(0)
            conn_anchor_df.loc[m_conn_with_port, "app_identity_norm"] = (
                "CONN Port " + conn_anchor_df.loc[m_conn_with_port, "dst_port"].astype(str)
            )
            conn_anchor_df.loc[m_conn_missing_identity & ~m_conn_with_port, "app_identity_norm"] = "CONN Telemetry"
            conn_anchor_df = conn_anchor_df[conn_anchor_df["app_identity_norm"].ne("")]

            conn_keys = (
                inventory_df.loc[conn_unknown_destination, ["application_or_identifier"]]
                .copy()
                .rename(columns={"application_or_identifier": "app_identity_norm"})
            )
            conn_keys["app_identity_norm"] = conn_keys["app_identity_norm"].fillna("").astype(str).str.strip()
            conn_keys = conn_keys[conn_keys["app_identity_norm"].ne("")].drop_duplicates()

            conn_anchor_df = conn_anchor_df.merge(conn_keys, on="app_identity_norm", how="inner")
            if not conn_anchor_df.empty:
                min_ts = conn_anchor_df["datetime"].min() - pd.Timedelta(seconds=2)
                max_ts = conn_anchor_df["datetime"].max() + pd.Timedelta(seconds=2)
                conn_candidates = _sql_fetch_df(
                    conn,
                    """
                    SELECT
                        datetime,
                        ip,
                        domain_clean
                    FROM shadow_events
                    WHERE lower(mac) = lower(?)
                      AND upper(source_log) <> 'CONN'
                      AND datetime >= ?
                      AND datetime <= ?
                      AND domain_clean IS NOT NULL
                      AND trim(domain_clean) <> ''
                      AND lower(trim(domain_clean)) <> 'unidentified_activity'
                    ORDER BY datetime
                    """,
                    [target_mac, min_ts, max_ts],
                )
                if not conn_candidates.empty:
                    conn_candidates["datetime"] = pd.to_datetime(conn_candidates["datetime"], errors="coerce")
                    conn_candidates["ip"] = conn_candidates["ip"].fillna("").astype(str).str.strip()
                    conn_candidates["domain_clean"] = conn_candidates["domain_clean"].fillna("").astype(str).str.strip()
                    conn_candidates = conn_candidates[
                        conn_candidates["datetime"].notna() & conn_candidates["domain_clean"].ne("")
                    ].sort_values("datetime")

                    if not conn_candidates.empty:
                        conn_anchors = conn_anchor_df[["datetime", "ip", "app_identity_norm"]].copy().reset_index(drop=True)
                        conn_anchors["row_idx"] = conn_anchors.index.astype("int64")

                        conn_match_ip = pd.DataFrame()
                        if conn_anchors["ip"].ne("").any() and conn_candidates["ip"].ne("").any():
                            conn_match_ip = _asof_grouped_match(
                                left_df=conn_anchors.loc[
                                    conn_anchors["ip"].ne(""),
                                    ["row_idx", "datetime", "ip"],
                                ].copy(),
                                right_df=conn_candidates.loc[
                                    conn_candidates["ip"].ne(""),
                                    ["ip", "datetime", "domain_clean"],
                                ].copy(),
                                by_cols=["ip"],
                                right_value_cols=["domain_clean"],
                                tolerance_seconds=2,
                            )
                        if conn_match_ip.empty:
                            conn_match_ip = conn_anchors.copy()
                            conn_match_ip["domain_clean"] = pd.NA
                        else:
                            conn_match_ip = conn_anchors.merge(conn_match_ip, on="row_idx", how="left")
                        if "domain_clean" not in conn_match_ip.columns:
                            conn_match_ip["domain_clean"] = pd.NA

                        conn_match_ip["domain_clean"] = (
                            conn_match_ip["domain_clean"].fillna("").astype(str).str.strip()
                        )
                        conn_domain_hits = (
                            conn_match_ip[conn_match_ip["domain_clean"].ne("")]
                            .groupby(["app_identity_norm", "domain_clean"], as_index=False)
                            .size()
                            .rename(columns={"size": "hits"})
                            .sort_values(
                                ["app_identity_norm", "hits", "domain_clean"],
                                ascending=[True, False, True],
                            )
                        )
                        if not conn_domain_hits.empty:
                            conn_domain_map = (
                                conn_domain_hits.groupby("app_identity_norm", as_index=False)
                                .head(1)
                                .rename(
                                    columns={
                                        "app_identity_norm": "application_or_identifier",
                                        "domain_clean": "conn_inferred_destination",
                                    }
                                )[["application_or_identifier", "conn_inferred_destination"]]
                            )
                            inventory_df = inventory_df.merge(
                                conn_domain_map,
                                on="application_or_identifier",
                                how="left",
                            )
                            inventory_df["conn_inferred_destination"] = (
                                inventory_df["conn_inferred_destination"].fillna("").astype(str).str.strip()
                            )
                            conn_unknown_destination = (
                                inventory_df["identity_type"].eq("Port")
                                & inventory_df["destination"]
                                .fillna("")
                                .astype(str)
                                .str.strip()
                                .str.lower()
                                .eq("unidentified_activity")
                            )
                            inventory_df["destination"] = np.where(
                                conn_unknown_destination
                                & inventory_df["conn_inferred_destination"].ne(""),
                                inventory_df["conn_inferred_destination"],
                                inventory_df["destination"],
                            )
                            inventory_df = inventory_df.drop(
                                columns=["conn_inferred_destination"],
                                errors="ignore",
                            )

        # Finalize display destination while preserving raw lookup key for drill-down queries.
        inventory_df["destination"] = inventory_df["destination"].fillna("").astype(str).str.strip()
        inventory_df["application_or_identifier"] = (
            inventory_df["application_or_identifier"].fillna("").astype(str).str.strip()
        )
        inventory_df["lookup_destination"] = inventory_df["destination"]
        inventory_df["destination"] = (
            inventory_df["destination"]
            .str.replace("*", "", regex=False)
            .str.strip()
            .str.strip(".")
        )
        inventory_df["application_or_identifier"] = (
            inventory_df["application_or_identifier"]
            .str.replace("*", "", regex=False)
            .str.strip()
            .str.strip(".")
        )
        m_conn_placeholder_display = (
            inventory_df["application_or_identifier"].str.match(r"(?i)^conn port\s+\d+$", na=False)
            | inventory_df["application_or_identifier"].str.lower().eq("conn telemetry")
        )
        if m_conn_placeholder_display.any():
            inventory_df.loc[m_conn_placeholder_display, "application_or_identifier"] = "unidentified_activity"

        unknown_tokens = {
            "",
            "unidentified_activity",
            "unknown",
            "-",
            "*",
            "nan",
            "none",
            "null",
            "n/a",
            "(empty)",
            "[]",
            "unresolved_destination",
        }
        m_dest_is_ip = inventory_df["destination"].str.match(_IPV4_RE, na=False)
        m_unknown_dest = inventory_df["destination"].str.lower().isin(unknown_tokens) | m_dest_is_ip
        m_unknown_app = inventory_df["application_or_identifier"].str.lower().isin(unknown_tokens)

        # If a real identifier exists but destination is unresolved, display that identifier as destination.
        m_display_fallback = m_unknown_dest & ~m_unknown_app
        if m_display_fallback.any():
            inventory_df.loc[m_display_fallback, "destination"] = (
                inventory_df.loc[m_display_fallback, "application_or_identifier"]
            )

        m_dest_is_ip = inventory_df["destination"].str.match(_IPV4_RE, na=False)
        m_unknown_dest = inventory_df["destination"].str.lower().isin(unknown_tokens) | m_dest_is_ip
        m_unknown_app = inventory_df["application_or_identifier"].str.lower().isin(unknown_tokens)
        if m_unknown_dest.any():
            inventory_df.loc[m_unknown_dest, "destination"] = "unidentified_activity"
        if m_unknown_app.any():
            inventory_df.loc[m_unknown_app, "application_or_identifier"] = "unidentified_activity"

        # Add an explicit unmapped bucket so table Hits reconcile with Events.
        unmapped_base = forensic_df.copy()
        unmapped_base["domain_clean"] = unmapped_base["domain_clean"].fillna("").astype(str).str.strip()
        unmapped_base["source_log"] = unmapped_base["source_log"].fillna("").astype(str).str.upper().str.strip()
        unmapped_base["app_identity"] = unmapped_base["app_identity"].fillna("").astype(str).str.strip()
        unmapped_base["dst_port"] = pd.to_numeric(unmapped_base["dst_port"], errors="coerce").fillna(0).astype("int64")
        unmapped_base["app_identity_norm"] = unmapped_base["app_identity"]
        m_u_missing_identity = unmapped_base["app_identity_norm"].eq("")
        m_u_conn_missing = m_u_missing_identity & unmapped_base["source_log"].eq("CONN")
        m_u_conn_with_port = m_u_conn_missing & unmapped_base["dst_port"].gt(0)
        unmapped_base.loc[m_u_conn_with_port, "app_identity_norm"] = (
            "CONN Port " + unmapped_base.loc[m_u_conn_with_port, "dst_port"].astype(str)
        )
        unmapped_base.loc[m_u_conn_missing & ~m_u_conn_with_port, "app_identity_norm"] = "CONN Telemetry"
        mapped_mask = unmapped_base["domain_clean"].ne("") & unmapped_base["app_identity_norm"].ne("")
        unmapped_events = unmapped_base[~mapped_mask].copy()
        if not unmapped_events.empty:
            src_values = sorted({str(v).strip() for v in unmapped_events["source_log"].tolist() if str(v).strip()})
            source_text = ", ".join(src_values)
            t_series = pd.to_datetime(unmapped_events["datetime"], errors="coerce")
            first_seen = t_series.min()
            last_seen = t_series.max()
            status_vals = unmapped_events["App Status"].fillna("").astype(str).str.strip()
            status_label = "Unauthorized" if status_vals.eq("Unauthorized").any() else "Authorized"
            risk_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Safe": 0}
            risk_vals = unmapped_events["Risk Level"].fillna("Safe").astype(str).str.strip()
            risk_scores = risk_vals.map(risk_rank).fillna(0).astype(int)
            max_score = int(risk_scores.max()) if not risk_scores.empty else 0
            score_to_risk = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Safe"}
            unmapped_row = pd.DataFrame(
                [
                    {
                        "destination": "unidentified_activity",
                        "lookup_destination": "unidentified_activity",
                        "application_or_identifier": "unidentified_activity",
                        "sources": source_text,
                        "status": status_label,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "hits": int(len(unmapped_events)),
                        "max_risk": score_to_risk.get(max_score, "Safe"),
                        "identity_type": "Unknown",
                        "conn_ports": "",
                    }
                ]
            )
            inventory_df = pd.concat([inventory_df, unmapped_row], ignore_index=True, sort=False)
    if inventory_df.empty:
        unmapped_base = forensic_df.copy()
        unmapped_base["domain_clean"] = unmapped_base["domain_clean"].fillna("").astype(str).str.strip()
        unmapped_base["source_log"] = unmapped_base["source_log"].fillna("").astype(str).str.upper().str.strip()
        unmapped_base["app_identity"] = unmapped_base["app_identity"].fillna("").astype(str).str.strip()
        unmapped_base["dst_port"] = pd.to_numeric(unmapped_base["dst_port"], errors="coerce").fillna(0).astype("int64")
        unmapped_base["app_identity_norm"] = unmapped_base["app_identity"]
        m_u_missing_identity = unmapped_base["app_identity_norm"].eq("")
        m_u_conn_missing = m_u_missing_identity & unmapped_base["source_log"].eq("CONN")
        m_u_conn_with_port = m_u_conn_missing & unmapped_base["dst_port"].gt(0)
        unmapped_base.loc[m_u_conn_with_port, "app_identity_norm"] = (
            "CONN Port " + unmapped_base.loc[m_u_conn_with_port, "dst_port"].astype(str)
        )
        unmapped_base.loc[m_u_conn_missing & ~m_u_conn_with_port, "app_identity_norm"] = "CONN Telemetry"
        mapped_mask = unmapped_base["domain_clean"].ne("") & unmapped_base["app_identity_norm"].ne("")
        unmapped_events = unmapped_base[~mapped_mask].copy()
        if not unmapped_events.empty:
            src_values = sorted({str(v).strip() for v in unmapped_events["source_log"].tolist() if str(v).strip()})
            source_text = ", ".join(src_values)
            t_series = pd.to_datetime(unmapped_events["datetime"], errors="coerce")
            first_seen = t_series.min()
            last_seen = t_series.max()
            status_vals = unmapped_events["App Status"].fillna("").astype(str).str.strip()
            status_label = "Unauthorized" if status_vals.eq("Unauthorized").any() else "Authorized"
            risk_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Safe": 0}
            risk_vals = unmapped_events["Risk Level"].fillna("Safe").astype(str).str.strip()
            risk_scores = risk_vals.map(risk_rank).fillna(0).astype(int)
            max_score = int(risk_scores.max()) if not risk_scores.empty else 0
            score_to_risk = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Safe"}
            inventory_df = pd.DataFrame(
                [
                    {
                        "destination": "unidentified_activity",
                        "lookup_destination": "unidentified_activity",
                        "application_or_identifier": "unidentified_activity",
                        "sources": source_text,
                        "status": status_label,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "hits": int(len(unmapped_events)),
                        "max_risk": score_to_risk.get(max_score, "Safe"),
                        "identity_type": "Unknown",
                        "conn_ports": "",
                    }
                ]
            )

    if not inventory_df.empty:
        raw_destination = inventory_df.get("destination", pd.Series("", index=inventory_df.index))
        raw_application = inventory_df.get("application_or_identifier", pd.Series("", index=inventory_df.index))
        inventory_df["destination"] = _normalize_destination_display_series(raw_destination)
        inventory_df["application_or_identifier"] = _normalize_application_display_series(
            raw_application,
            inventory_df["destination"],
        )
        if "lookup_destination" not in inventory_df.columns:
            inventory_df["lookup_destination"] = inventory_df["destination"]
        inventory_df["lookup_destination"] = inventory_df["lookup_destination"].fillna("").astype(str).str.strip()

        first_seen_ts = pd.to_datetime(
            inventory_df.get("first_seen", pd.Series(pd.NaT, index=inventory_df.index)),
            errors="coerce",
        )
        last_seen_ts = pd.to_datetime(
            inventory_df.get("last_seen", pd.Series(pd.NaT, index=inventory_df.index)),
            errors="coerce",
        )
        inventory_df["duration_sec"] = (
            (last_seen_ts - first_seen_ts).dt.total_seconds().clip(lower=0).fillna(0).round(1)
        )

        real_dest_mask = _is_real_destination_series(inventory_df["destination"])
        real_identifier_mask = _is_real_identifier_series(inventory_df["application_or_identifier"])
        inventory_df = inventory_df[real_dest_mask & real_identifier_mask].copy()

    if inventory_df.empty:
        st.info("No valid application/software/domain identifiers were detected for this MAC with the current filters.")
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
        inv_grid["first_seen_ts"] = pd.to_datetime(inv_grid["first_seen"], errors="coerce")
        inv_grid["last_seen_ts"] = pd.to_datetime(inv_grid["last_seen"], errors="coerce")
        inv_grid["duration_sec"] = (
            (inv_grid["last_seen_ts"] - inv_grid["first_seen_ts"]).dt.total_seconds().clip(lower=0).fillna(0).round(1)
        )
        inv_grid["duration"] = inv_grid["duration_sec"].apply(_format_duration_seconds)
        inv_grid["first_seen"] = inv_grid["first_seen_ts"].dt.strftime("%Y-%m-%d %H:%M:%S")
        inv_grid["last_seen"] = inv_grid["last_seen_ts"].dt.strftime("%Y-%m-%d %H:%M:%S")
        inv_grid["first_seen"] = inv_grid["first_seen"].fillna("")
        inv_grid["last_seen"] = inv_grid["last_seen"].fillna("")
        preferred_col_order = [
            "#",
            "destination",
            "application_or_identifier",
            "Allowed",
            "sources",
            "identity_type",
            "conn_ports",
            "status",
            "first_seen",
            "last_seen",
            "duration",
            "hits",
            "max_risk",
            "lookup_destination",
            "_allow_key",
            "first_seen_ts",
            "last_seen_ts",
            "duration_sec",
        ]
        ordered_cols = [c for c in preferred_col_order if c in inv_grid.columns]
        remaining_cols = [c for c in inv_grid.columns if c not in ordered_cols]
        inv_grid = inv_grid[ordered_cols + remaining_cols].copy()

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
                const app = (params.data && params.data.application_or_identifier ? params.data.application_or_identifier : '').toString().toLowerCase();
                if (app === 'unmapped' || app === 'unidentified_activity') return false;
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
        gb_inv.configure_column("destination", header_name="Destination", minWidth=200, flex=1.2, suppressMovable=True)
        gb_inv.configure_column(
            "application_or_identifier",
            header_name="Application / Software / Domain",
            minWidth=185,
            flex=1.35,
            wrapText=True,
            autoHeight=True,
            tooltipField="application_or_identifier",
            cellStyle=inv_app_click_style,
            suppressMovable=True,
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
            suppressMovable=True,
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
        gb_inv.configure_column("identity_type", header_name="Identifier Type", width=128)
        gb_inv.configure_column("conn_ports", header_name="Port(s)", width=108)
        gb_inv.configure_column("status", header_name="Status", width=104, cellStyle=inv_status_style)
        gb_inv.configure_column("first_seen", header_name="First Seen", width=152)
        gb_inv.configure_column("last_seen", header_name="Last Seen", width=152)
        gb_inv.configure_column("duration", header_name="Duration", width=118)
        gb_inv.configure_column("hits", header_name="Hits", width=72)
        gb_inv.configure_column("max_risk", header_name="Max Risk", width=94, cellStyle=inv_risk_style)
        gb_inv.configure_column("first_seen_ts", hide=True)
        gb_inv.configure_column("last_seen_ts", hide=True)
        gb_inv.configure_column("duration_sec", hide=True)
        gb_inv.configure_column("lookup_destination", hide=True)
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
        inv_grid_options["maintainColumnOrder"] = True
        inv_grid_options["suppressMovableColumns"] = True

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
            fit_columns_on_grid_load=False,
            reload_data=False,
            key=f"dlg_inventory_grid_{target_mac}_{int(st.session_state.get('shadow_inv_grid_nonce', 0))}",
        )
        st.caption(
            f"{len(inv_grid):,} rows shown. Each row is an application/software/domain identifier for this MAC with current filters."
        )
        st.caption(
            "Rows are grouped by Destination + Application/Software/Domain. Sources, first/last seen, duration, and hits "
            "are aggregated per MAC while Status and Max Risk keep the highest-severity state."
        )
        st.caption("Only rows with real `.com` destinations and real application/software/domain identifiers are shown.")
        st.caption(
            "Software/CONN rows may use inferred domain context from nearest non-software events for this MAC (\u00b12s). "
            "Port(s) inferred are labeled '(inferred)'."
        )
        st.caption(
            "WEIRD and other logs without native application identity are matched to nearby events when possible; "
            "rows with no real destination+application after inference are excluded from this table."
        )

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
                        "destination": str(
                            pick.get("lookup_destination")
                            or pick.get("destination")
                            or pick.get("application_or_identifier")
                            or ""
                        ),
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
            sel_dest = str(
                selected_inv.get("destination")
                or selected_inv.get("lookup_destination")
                or selected_inv.get("application_or_identifier")
                or ""
            ).strip()
            sel_dest_lookup = str(selected_inv.get("lookup_destination", sel_dest) or "").strip()
            sel_app = str(selected_inv.get("application_or_identifier", "") or "").strip()
            if sel_dest and sel_app and sel_app.lower() not in {"unmapped", "unidentified_activity"}:
                _open_inventory_app_dialog(
                    {
                        "mac": target_mac,
                        "destination": sel_dest,
                        "destination_lookup": sel_dest_lookup,
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

    def _on_day_change():
        _close_shadow_dialog(reset_grid=True)

    selected_day = st.selectbox(
        "Dataset Scope",
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
            "Search (MAC, Hostname, IP, Destination, App/Software)",
            placeholder="e.g., 192.168.1.14",
            key="audit_search",
        ).strip()
        bottom_filter_col1, bottom_filter_col2 = st.columns([2.2, 2.2])
        with bottom_filter_col1:
            audit_risk_filter = risk_multiselect(
                "Risk Level",
                key="audit_risk_filter",
                default=RISK_OPTIONS,
            )
        with bottom_filter_col2:
            # Pull available sources from the data (for the selected day already loaded into shadow_events)
            src_df_audit = _sql_fetch_df(conn, "SELECT DISTINCT source_log FROM shadow_events ORDER BY 1")
            audit_sources = src_df_audit["source_log"].dropna().tolist() if not src_df_audit.empty else []
            audit_source_filter = st.multiselect(
                "Source Logs",
                audit_sources,
                default=audit_sources,   # default = all
                key="audit_source_filter",
            )
        st.markdown("</div>", unsafe_allow_html=True)

        where = []
        params = []

        is_all_risk_selected = bool(audit_risk_filter) and set(audit_risk_filter) == set(RISK_OPTIONS)
        is_all_sources_selected = bool(audit_sources) and set(audit_source_filter) == set(audit_sources)

        if not audit_risk_filter:
            where.append("1=0")
        elif not is_all_risk_selected:
            in_clause = _build_in_clause(audit_risk_filter, params)
            where.append(f""""Risk Level" IN {in_clause}""")

        if search_query_audit:
            q = f"%{search_query_audit}%"
            where.append("(mac ILIKE ? OR hostname ILIKE ? OR ip ILIKE ? OR domain_clean ILIKE ? OR app_identity ILIKE ?)")
            params.extend([q, q, q, q, q])

        if audit_sources and not audit_source_filter:
            where.append("1=0")
        elif audit_source_filter and not is_all_sources_selected:
            in_clause = _build_in_clause(audit_source_filter, params)
            where.append(f"source_log IN {in_clause}")

        where_sql = "WHERE " + " AND ".join(where) if where else ""

        audit_sql = f"""
        WITH raw AS (
            SELECT
                domain_clean,
                mac,
                hostname,
                ip,
                source_log,
                datetime,
                _risk_score,
                "Risk Basis" AS risk_basis,
                app_identity,
                dst_port
            FROM shadow_events
            {where_sql}
        ),
        host_counts AS (
            SELECT
                lower(trim(mac)) AS mac_key,
                trim(hostname) AS pref_hostname,
                COUNT(*) AS hits,
                MAX(datetime) AS last_seen
            FROM shadow_events
            WHERE mac IS NOT NULL
              AND trim(mac) <> ''
              AND lower(trim(mac)) NOT IN ('unknown', 'nan', 'none', 'null')
              AND hostname IS NOT NULL
              AND trim(hostname) <> ''
              AND lower(trim(hostname)) NOT IN ('unknown', 'nan', 'none', 'null', 'n/a', '-')
            GROUP BY 1,2
        ),
        host_pref AS (
            SELECT mac_key, pref_hostname
            FROM (
                SELECT
                    mac_key,
                    pref_hostname,
                    ROW_NUMBER() OVER (
                        PARTITION BY mac_key
                        ORDER BY hits DESC, last_seen DESC, pref_hostname ASC
                    ) AS rn
                FROM host_counts
            ) t
            WHERE rn = 1
        ),
        domain_counts AS (
            SELECT
                lower(trim(mac)) AS mac_key,
                lower(trim(ip)) AS ip_key,
                trim(domain_clean) AS pref_domain,
                COUNT(*) AS hits,
                MAX(datetime) AS last_seen
            FROM shadow_events
            WHERE mac IS NOT NULL
              AND trim(mac) <> ''
              AND lower(trim(mac)) NOT IN ('unknown', 'nan', 'none', 'null')
              AND ip IS NOT NULL
              AND trim(ip) <> ''
              AND lower(trim(ip)) NOT IN ('unknown', '0.0.0.0', 'nan', 'none', 'null')
              AND domain_clean IS NOT NULL
              AND trim(domain_clean) <> ''
              AND lower(trim(domain_clean)) <> 'unidentified_activity'
            GROUP BY 1,2,3
        ),
        domain_pref AS (
            SELECT mac_key, ip_key, pref_domain
            FROM (
                SELECT
                    mac_key,
                    ip_key,
                    pref_domain,
                    ROW_NUMBER() OVER (
                        PARTITION BY mac_key, ip_key
                        ORDER BY hits DESC, last_seen DESC, pref_domain ASC
                    ) AS rn
                FROM domain_counts
            ) t
            WHERE rn = 1
        ),
        base AS (
            SELECT
                CASE
                    WHEN r.domain_clean IS NOT NULL
                     AND trim(r.domain_clean) <> ''
                     AND lower(trim(r.domain_clean)) <> 'unidentified_activity'
                        THEN trim(r.domain_clean)
                    WHEN dp.pref_domain IS NOT NULL AND trim(dp.pref_domain) <> ''
                        THEN trim(dp.pref_domain)
                    WHEN r.app_identity IS NOT NULL
                     AND trim(r.app_identity) <> ''
                     AND lower(trim(r.app_identity)) NOT IN ('unknown', 'nan', 'none', 'null', 'n/a', '-', 'unidentified_activity')
                     AND lower(trim(r.app_identity)) <> 'conn telemetry'
                     AND lower(trim(r.app_identity)) NOT LIKE 'conn port %'
                        THEN trim(r.app_identity)
                    WHEN try_cast(r.dst_port AS INT) > 0
                        THEN 'port/' || CAST(try_cast(r.dst_port AS INT) AS VARCHAR)
                    WHEN r.ip IS NOT NULL
                     AND trim(r.ip) <> ''
                     AND lower(trim(r.ip)) NOT IN ('unknown', '0.0.0.0', 'nan', 'none', 'null')
                        THEN trim(r.ip)
                    WHEN hp.pref_hostname IS NOT NULL AND trim(hp.pref_hostname) <> ''
                        THEN trim(hp.pref_hostname)
                    ELSE 'unresolved_destination'
                END AS domain_clean,
                CASE
                    WHEN r.app_identity IS NOT NULL
                     AND trim(r.app_identity) <> ''
                     AND lower(trim(r.app_identity)) NOT IN ('unknown', 'nan', 'none', 'null', 'n/a', '-', 'unidentified_activity')
                     AND lower(trim(r.app_identity)) <> 'conn telemetry'
                     AND lower(trim(r.app_identity)) NOT LIKE 'conn port %'
                        THEN trim(r.app_identity)
                    WHEN try_cast(r.dst_port AS INT) > 0
                        THEN 'port/' || CAST(try_cast(r.dst_port AS INT) AS VARCHAR)
                    ELSE 'unidentified_activity'
                END AS application_or_identifier,
                COALESCE(NULLIF(trim(r.mac), ''), 'unknown') AS mac,
                CASE
                    WHEN r.hostname IS NOT NULL
                     AND trim(r.hostname) <> ''
                     AND lower(trim(r.hostname)) NOT IN ('unknown', 'nan', 'none', 'null', 'n/a', '-')
                        THEN trim(r.hostname)
                    WHEN hp.pref_hostname IS NOT NULL AND trim(hp.pref_hostname) <> ''
                        THEN trim(hp.pref_hostname)
                    ELSE 'Unknown'
                END AS hostname,
                COALESCE(NULLIF(trim(r.ip), ''), 'Unknown') AS ip,
                COALESCE(NULLIF(trim(r.source_log), ''), 'UNKNOWN') AS source_log,
                r.datetime,
                r._risk_score,
                r.risk_basis
            FROM raw r
            LEFT JOIN host_pref hp
              ON lower(trim(r.mac)) = hp.mac_key
            LEFT JOIN domain_pref dp
              ON lower(trim(r.mac)) = dp.mac_key
             AND lower(trim(r.ip)) = dp.ip_key
        ),
        agg AS (
            SELECT
                domain_clean,
                application_or_identifier,
                mac,
                hostname,
                ip,
                source_log,
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
                application_or_identifier,
                mac,
                hostname,
                ip,
                source_log,
                COALESCE(NULLIF(trim(risk_basis), ''), 'No explicit reason captured') AS Max_Risk_Reason,
                ROW_NUMBER() OVER (
                    PARTITION BY domain_clean, application_or_identifier, mac, hostname, ip, source_log
                    ORDER BY _risk_score DESC, datetime DESC
                ) AS rn
            FROM base
        )
        SELECT
            a.domain_clean,
            a.application_or_identifier,
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
            ON a.domain_clean IS NOT DISTINCT FROM b.domain_clean
           AND a.application_or_identifier IS NOT DISTINCT FROM b.application_or_identifier
           AND a.mac IS NOT DISTINCT FROM b.mac
           AND a.hostname IS NOT DISTINCT FROM b.hostname
           AND a.ip IS NOT DISTINCT FROM b.ip
           AND a.source_log IS NOT DISTINCT FROM b.source_log
        ORDER BY a.Max_Risk_Score DESC, a.Hits DESC
        LIMIT 1000
        """

        display_df = _sql_fetch_df(conn, audit_sql, params)
        if not display_df.empty:
            display_df["domain_clean"] = _normalize_destination_display_series(display_df["domain_clean"])
            display_df["application_or_identifier"] = _normalize_application_display_series(
                display_df["application_or_identifier"],
                display_df["domain_clean"],
            )
            display_df["mac"] = display_df["mac"].fillna("").astype(str).str.strip().str.lower()
            display_df["hostname"] = display_df["hostname"].fillna("").astype(str).str.strip()
            display_df["First_Seen"] = pd.to_datetime(display_df["First_Seen"], errors="coerce")
            display_df["Last_Seen"] = pd.to_datetime(display_df["Last_Seen"], errors="coerce")
            display_df["Duration_sec"] = (
                (display_df["Last_Seen"] - display_df["First_Seen"]).dt.total_seconds().clip(lower=0).fillna(0).round(1)
            )
            display_df["Duration"] = display_df["Duration_sec"].apply(_format_duration_seconds)

            mac_unknowns = _MAC_UNKNOWNS | {"ff:ff:ff:ff:ff:ff"}

            m_known_mac = ~display_df["mac"].str.lower().isin(mac_unknowns)
            m_known_domain = _is_real_destination_series(display_df["domain_clean"])
            m_known_identifier = _is_real_identifier_series(display_df["application_or_identifier"])

            display_df = display_df[m_known_mac & m_known_domain & m_known_identifier].copy()
            display_df["First_Seen"] = display_df["First_Seen"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("")
            display_df["Last_Seen"] = display_df["Last_Seen"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("")

        if not display_df.empty:
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
            gb.configure_column("domain_clean", header_name="Destination", minWidth=220)
            gb.configure_column(
                "application_or_identifier",
                header_name="Application / Software / Domain",
                minWidth=220,
                flex=1.25,
                wrapText=True,
                autoHeight=True,
                tooltipField="application_or_identifier",
            )
            gb.configure_column("hostname", header_name="Hostname", minWidth=160)
            gb.configure_column("ip", header_name="IP", minWidth=130)
            gb.configure_column("source_log", header_name="Source", width=110)
            gb.configure_column("Hits", header_name="Hits", width=90)
            gb.configure_column("First_Seen", header_name="First Seen", width=170)
            gb.configure_column("Last_Seen", header_name="Last Seen", width=170)
            gb.configure_column("Duration", width=110)
            gb.configure_column("Duration_sec", hide=True)

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
                fit_columns_on_grid_load=False,
                reload_data=False,
                key=grid_key,
            )
            st.caption(
                f"{len(df_grid):,} grouped rows shown. Rows are built by grouping filtered events on "
                "Destination + Application + MAC + Hostname + IP + Source, then computing First Seen, Last Seen, Duration, "
                "Hits, and max risk; groups are sorted by max risk score and hit count, and only the top 1,000 are displayed."
            )
            st.caption("Table excludes unresolved placeholders and keeps only real `.com` destinations with real app identifiers.")

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

        with st.expander("How Risk Is Calculated", expanded=False):
            st.markdown(
                "<div class='shadow-callout'>Risk uses highest-severity matching rules per event, plus multi-signal escalation for unauthorized traffic.</div>",
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

