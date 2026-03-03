

# ----------------------------------------------------------------------------
# Hard filters for destination display
# ----------------------------------------------------------------------------
INVALID_DEST_STRINGS = {"", "unknown", "nan", "none", "(empty)", "*"}
INVALID_DEST_SET = set(INVALID_DEST_STRINGS)
AUTO_UNIQUE_ID_COL = "::auto_unique_id::"
FILTER_CACHE_VERSION = "ratio-precision-3dp-v3-mac-dest-day-table"
# ui/pages/shadow_sharings.py
import hashlib
import re
from datetime import timedelta
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd
import plotly.express as px
import streamlit as st
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode

try:
    from .shadow_sharings_backend import (
        _add_domain_to_whitelist,
        get_available_dates,
        load_shadow_sharing_bundle,
        build_shadow_sharing_incidents,
        refresh_shadow_sharing_runtime_state,
        shadow_sharing_logs_signature,
    )
except ImportError:
    from shadow_sharings_backend import (  # type: ignore
        _add_domain_to_whitelist,
        get_available_dates,
        load_shadow_sharing_bundle,
        build_shadow_sharing_incidents,
        refresh_shadow_sharing_runtime_state,
        shadow_sharing_logs_signature,
    )

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#f59e0b",
    "LOW": "#22c55e",
}

CONFIDENCE_COLORS = {
    "HIGH": "#ef4444",
    "PROBABLE": "#f59e0b",
    "WEAK": "#38bdf8",
}


def _shadow_sharing_policy_stamp() -> tuple:
    project_root = Path(__file__).resolve().parents[2]
    out: List[int] = []
    for policy_name in ("whitelist_domains.yaml", "shadow_sharing_signatures.yaml"):
        policy_path = project_root / policy_name
        try:
            out.append(int(policy_path.stat().st_mtime_ns))
        except Exception:
            out.append(0)
    return tuple(out)


def _grid_data_signature(df: pd.DataFrame) -> tuple:
    if not isinstance(df, pd.DataFrame):
        return ("invalid",)

    n_rows = int(len(df))
    cols = tuple(str(c) for c in df.columns)
    if n_rows <= 0:
        return (n_rows, cols, "empty")

    sig_cols = [
        c
        for c in [
            "event_id",
            "incident_id",
            "uid",
            "ts",
            "destination",
            "domain",
            "mac",
            "id.orig_h",
            "bytes",
            "Allowed",
            "allowed",
            "Allowed_Domain",
            "Status",
            "allow_basis",
        ]
        if c in df.columns
    ]
    if not sig_cols:
        sig_cols = list(df.columns[: min(4, len(df.columns))])

    sample = pd.concat([df.head(3), df.tail(3)], ignore_index=True)[sig_cols].copy()
    for c in sig_cols:
        sample[c] = sample[c].astype(str)
    sample_blob = sample.to_csv(index=False)
    digest = hashlib.sha1(sample_blob.encode("utf-8")).hexdigest()
    return (n_rows, cols, digest)


def _shadow_sharing_data_stamp(df: pd.DataFrame) -> tuple:
    if df is None or df.empty:
        return (0, "", "")
    ts_raw = df.get("ts", pd.Series([], dtype="datetime64[ns]"))
    ts = ts_raw if pd.api.types.is_datetime64_any_dtype(ts_raw) else pd.to_datetime(ts_raw, errors="coerce")
    tmax = ts.max()
    tmin = ts.min()
    return (
        int(len(df)),
        str(tmax) if pd.notna(tmax) else "",
        str(tmin) if pd.notna(tmin) else "",
    )


def _shadow_sharing_filter_cache_key(
    selected_scope_key: str,
    selected_sources: List[str],
    selected_risk_levels: List[str],
    search_q: str,
    data_stamp: tuple,
) -> tuple:
    return (
        FILTER_CACHE_VERSION,
        str(selected_scope_key),
        tuple(sorted([str(x) for x in (selected_sources or [])])),
        tuple(sorted([str(x) for x in (selected_risk_levels or [])])),
        str(search_q or "").strip().lower(),
        data_stamp,
    )


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


def _severity_cellstyle() -> JsCode:
    return JsCode(
        """
        function(params) {
            const v = (params.value || '').toString().toUpperCase();
            if (v === 'CRITICAL') return { 'color': '#ef4444', 'fontWeight': '900' };
            if (v === 'HIGH') return { 'color': '#f97316', 'fontWeight': '900' };
            if (v === 'MEDIUM') return { 'color': '#f59e0b', 'fontWeight': '800' };
            if (v === 'LOW') return { 'color': '#22c55e', 'fontWeight': '700' };
            return {};
        }
        """
    )


def _allowed_cellstyle() -> JsCode:
    return JsCode(
        """
        function(params) {
            const v = params.value;
            const yes = (v === true) || (String(v).toLowerCase() === 'true');
            if (yes) return { 'color': '#22c55e', 'fontWeight': '700' };
            return { 'color': '#ef4444', 'fontWeight': '800' };
        }
        """
    )


def _status_cellstyle() -> JsCode:
    return JsCode(
        """
        function(params) {
            const v = (params.value || '').toString().toLowerCase();
            if (v === 'authorized') return { 'color': '#22c55e', 'fontWeight': '700' };
            if (v === 'unauthorized') return { 'color': '#ef4444', 'fontWeight': '800' };
            return {};
        }
        """
    )


def _confidence_cellstyle() -> JsCode:
    return JsCode(
        """
        function(params) {
            const v = (params.value || '').toString().toUpperCase();
            if (v === 'HIGH') return { 'color': '#ef4444', 'fontWeight': '900' };
            if (v === 'PROBABLE') return { 'color': '#f59e0b', 'fontWeight': '800' };
            if (v === 'WEAK') return { 'color': '#38bdf8', 'fontWeight': '700' };
            return {};
        }
        """
    )


def _fixed_3dp_formatter() -> JsCode:
    return JsCode(
        """
        function(params) {
            const v = Number(params.value);
            if (!isFinite(v)) return '0.000';
            return v.toFixed(3);
        }
        """
    )


def render_shadow_aggrid(
    df: pd.DataFrame,
    gb: GridOptionsBuilder,
    *,
    key: str,
    height: int = 430,
    update_mode=GridUpdateMode.SELECTION_CHANGED,
    wrap_shell: bool = True,
    force_scrollbars: bool = False,
    hide_scrollbar_buttons: bool = False,
):
    grid_df = df.copy() if isinstance(df, pd.DataFrame) else pd.DataFrame()
    if AUTO_UNIQUE_ID_COL in grid_df.columns:
        grid_df = grid_df.drop(columns=[AUTO_UNIQUE_ID_COL], errors="ignore")

    grid_options = gb.build()
    row_count = int(len(grid_df))
    default_col_def = dict(grid_options.get("defaultColDef") or {})
    # Keep sorting available via column menu (three-dot menu).
    default_col_def["sortable"] = True
    default_col_def["filter"] = "agSetColumnFilter"
    default_col_def["floatingFilter"] = False
    default_col_def.setdefault("minWidth", 96)
    default_col_def.setdefault("cellStyle", {"textAlign": "left"})
    default_col_def["menuTabs"] = ["filterMenuTab", "generalMenuTab"]
    filter_params = dict(default_col_def.get("filterParams") or {})
    filter_params.setdefault("excelMode", "windows")
    filter_params.setdefault("buttons", ["apply", "clear", "cancel"])
    filter_params.setdefault("closeOnApply", True)
    filter_params.setdefault("suppressMiniFilter", False)
    default_col_def["filterParams"] = filter_params
    grid_options["defaultColDef"] = default_col_def
    grid_options["suppressMenuHide"] = False
    grid_options["enableCellTextSelection"] = True
    grid_options["ensureDomOrder"] = True
    grid_options["enableRtl"] = False
    # Large grids render much faster with column virtualization enabled.
    grid_options["suppressColumnVirtualisation"] = bool(row_count <= 2000)
    if force_scrollbars:
        grid_options["domLayout"] = "normal"
        grid_options["alwaysShowVerticalScroll"] = True
        grid_options["suppressHorizontalScroll"] = False
        grid_options["alwaysShowHorizontalScroll"] = True

    autofit_js = JsCode(
        """
        function(params) {
            setTimeout(function() {
                if (!params) return;
                if (params.columnApi) {
                    const cols = params.columnApi.getAllColumns ? params.columnApi.getAllColumns() : [];
                    const colIds = cols.map(function(c) { return c.getColId ? c.getColId() : c.colId; }).filter(Boolean);
                    if (colIds.length) {
                        try { params.columnApi.autoSizeColumns(colIds, false); } catch (e) {}
                    }
                }
            }, 0);
        }
        """
    )
    # Auto-size is expensive on large tables; keep it only for smaller grids.
    if row_count <= 2000:
        grid_options["onFirstDataRendered"] = autofit_js
        grid_options["onGridSizeChanged"] = autofit_js
    else:
        grid_options.pop("onFirstDataRendered", None)
        grid_options.pop("onGridSizeChanged", None)

    ag_theme, ag_css = get_aggrid_theme_and_css()
    table_css = dict(ag_css)
    table_css.update(
        {
            ".ag-root-wrapper": {"background-color": "#061120", "color": "#EAF2FF", "border": "1px solid #2A466E"},
            ".ag-header": {"background-color": "#10213E", "color": "#EAF2FF", "border-bottom": "1px solid #3A5A8E", "direction": "ltr !important"},
            ".ag-header-cell, .ag-header-group-cell": {
                "background-color": "#10213E",
                "color": "#EAF2FF",
                "border-right": "1px solid #2A466E",
                "direction": "ltr !important",
            },
            ".ag-header-cell-label": {
                "white-space": "nowrap",
                "justify-content": "flex-start !important",
                "text-align": "left !important",
            },
            ".ag-header-cell-label .ag-header-cell-text": {
                "white-space": "nowrap",
                "overflow": "hidden",
                "text-overflow": "ellipsis",
                "text-align": "left !important",
            },
            ".ag-cell": {
                "background-color": "#061120",
                "color": "#EAF2FF",
                "border-color": "#13233D",
                "text-align": "left !important",
            },
            ".ag-cell-value": {"text-align": "left !important"},
            ".ag-row-odd": {"background-color": "#07162A"},
            ".ag-row-even": {"background-color": "#0A1C33"},
            ".ag-row-hover": {"background-color": "#13305A"},
            ".ag-row-selected": {"background-color": "#1B3F75"},
        }
    )
    if hide_scrollbar_buttons:
        table_css[".ag-root-wrapper ::-webkit-scrollbar-button"] = {
            "display": "none !important",
            "width": "0 !important",
            "height": "0 !important",
        }

    if wrap_shell:
        st.markdown("<div class='shadow-table-shell'>", unsafe_allow_html=True)
    data_sig = _grid_data_signature(grid_df)
    sig_key = f"_shadow_sharing_grid_sig::{key}"
    reload_data = st.session_state.get(sig_key) != data_sig
    st.session_state[sig_key] = data_sig
    grid_response = AgGrid(
        grid_df,
        gridOptions=grid_options,
        update_mode=update_mode,
        data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
        height=height,
        theme=ag_theme,
        custom_css=table_css,
        allow_unsafe_jscode=True,
        enable_enterprise_modules=True,
        fit_columns_on_grid_load=False,
        reload_data=reload_data,
        key=key,
    )
    if wrap_shell:
        st.markdown("</div>", unsafe_allow_html=True)
    return grid_response


def inject_shadow_sharing_css():
    st.markdown(
        """
        <style>
        :root {
            --panel-border: rgba(255,255,255,0.12);
            --panel-bg: rgba(255,255,255,0.03);
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
            margin-bottom: 0.45rem;
        }

        .shadow-filter-hint {
            font-size: 0.76rem;
            color: #9fb1c8;
            margin-top: 0.2rem;
            margin-bottom: 0.3rem;
        }

        .shadow-scope-hint {
            font-size: 0.9rem;
            color: #c8d7ea;
            margin-top: 0.35rem;
            margin-bottom: 1rem;
            padding: 0.36rem 0.62rem;
            border: 1px solid rgba(148, 163, 184, 0.2);
            background: linear-gradient(135deg, rgba(15,23,42,0.52), rgba(2,6,23,0.46));
            border-radius: 10px;
        }

        .shadow-scope-hint strong {
            font-size: 1.05rem;
            color: #e5eefc;
        }

        .shadow-filter-shell [data-testid="stWidgetLabel"] p {
            font-size: 0.76rem;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            color: #bfd1ea;
            font-weight: 700;
        }

        .shadow-filter-shell [data-testid="stTextInput"] input,
        .shadow-filter-shell [data-testid="stTextArea"] textarea,
        .shadow-filter-shell [data-testid="stNumberInput"] input {
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

        .shadow-table-shell {
            border: 1px solid rgba(148, 163, 184, 0.24);
            background: linear-gradient(180deg, rgba(2,6,23,0.5), rgba(2,6,23,0.35));
            border-radius: 12px;
            padding: 0.56rem 0.62rem 0.46rem 0.62rem;
            margin-bottom: 0.75rem;
        }

        [data-testid="stMetric"] {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 12px;
            padding: 0.55rem 0.75rem;
            min-height: 115px;
            height: 115px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }

        [data-testid="stMetricLabel"] p {
            font-size: 0.75rem;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            font-weight: 600;
            min-height: 2.15em;
        }

        [data-testid="stMetricValue"] {
            line-height: 1.1;
            min-height: 2.5rem;
            display: flex;
            align-items: center;
        }

        [data-testid="stMetricDelta"] {
            min-height: 1.5rem;
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

# -----------------------------------------------------------------------------
# UI
# -----------------------------------------------------------------------------


def _close_shadow_sharing_dialog() -> None:
    st.session_state["shadow_sharing_dialog_open"] = False
    st.session_state["shadow_sharing_dialog_mac"] = None
    st.session_state["shadow_sharing_last_selected_mac"] = None
    st.session_state.pop("shadow_sharing_dialog_origin", None)
    st.session_state.pop("shadow_sharing_dialog_base_df", None)
    st.session_state.pop("shadow_sharing_dialog_base_key", None)
    st.session_state.pop("shadow_sharing_dialog_incidents_df", None)
    st.session_state["shadow_sharing_grid_nonce"] = int(st.session_state.get("shadow_sharing_grid_nonce", 0)) + 1


def _invalidate_shadow_sharing_frontend_cache() -> None:
    for key in [
        "_shadow_sharing_scope_cache_key_v1",
        "_shadow_sharing_scope_df_v1",
        "_shadow_sharing_scope_incidents_v1",
        "_shadow_sharing_filtered_cache_v1",
        "_shadow_sharing_source_masks_cache_v1",
        "shadow_sharing_dialog_base_df",
        "shadow_sharing_dialog_base_key",
        "shadow_sharing_dialog_incidents_df",
    ]:
        st.session_state.pop(key, None)
    st.session_state["shadow_sharing_grid_nonce"] = int(st.session_state.get("shadow_sharing_grid_nonce", 0)) + 1


def _close_shadow_sharing_allow_dialog(*, reset_grid: bool = True) -> None:
    st.session_state["shadow_sharing_allow_dialog_open"] = False
    st.session_state.pop("shadow_sharing_allow_candidate", None)
    if reset_grid:
        st.session_state["shadow_sharing_grid_nonce"] = int(st.session_state.get("shadow_sharing_grid_nonce", 0)) + 1


def _open_shadow_sharing_allow_dialog(candidate: dict) -> None:
    st.session_state["shadow_sharing_allow_candidate"] = candidate
    st.session_state["shadow_sharing_allow_dialog_open"] = True
    st.session_state["shadow_sharing_dialog_origin"] = "dialog"


def _extract_selected_mac(selected_rows) -> Optional[str]:
    selected_mac = None
    if isinstance(selected_rows, pd.DataFrame):
        if not selected_rows.empty and "mac" in selected_rows.columns:
            selected_mac = selected_rows.iloc[0]["mac"]
    elif isinstance(selected_rows, list):
        if len(selected_rows) > 0 and isinstance(selected_rows[0], dict):
            selected_mac = selected_rows[0].get("mac")

    if selected_mac is None:
        return None

    selected_mac = str(selected_mac).strip().lower()
    if not selected_mac:
        return None
    return selected_mac


def _coerce_bool_value(v) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    return str(v).strip().lower() in {"1", "true", "t", "yes", "y"}


def _clean_reason_value(value: object) -> str:
    s = str(value or "").strip()
    if s.lower() in {"", "nan", "none", "-", "(empty)", "n/a", "na", "unknown"}:
        return ""
    return s


def _compose_incident_reason(base_reason: object, action: object, action_basis: object) -> str:
    parts: List[str] = []
    base = _clean_reason_value(base_reason)
    if base:
        parts.append(base)

    action_txt = _clean_reason_value(action)
    action_basis_txt = _clean_reason_value(action_basis)

    # Do not surface Share Link action/basis text in the Reasons column.
    action_l = action_txt.lower()
    basis_l = action_basis_txt.lower()
    is_share_link_action = (
        action_l in {"share link", "shared link"}
        or ("share/link" in basis_l)
        or ("share link" in basis_l)
        or ("shared link" in basis_l)
    )

    if action_txt and action_l not in {"access", "baseline access"} and not is_share_link_action:
        if action_basis_txt and basis_l != "baseline access":
            parts.append(f"action: {action_txt} ({action_basis_txt})")
        else:
            parts.append(f"action: {action_txt}")

    deduped: List[str] = []
    seen = set()
    for p in parts:
        k = p.strip().lower()
        if not k or k in seen:
            continue
        seen.add(k)
        deduped.append(p)
    return "; ".join(deduped)



def _filter_incidents_nonzero_outbound(incidents_df: pd.DataFrame) -> pd.DataFrame:
    if incidents_df is None or incidents_df.empty:
        return pd.DataFrame()
    out = incidents_df.copy()
    out_bytes = pd.to_numeric(out.get("bytes_out_total", 0), errors="coerce").fillna(0)
    out = out[out_bytes > 0].copy()
    if out.empty:
        return pd.DataFrame()
    if "incident_id" in out.columns:
        out = out.drop_duplicates(subset=["incident_id"], keep="last")
    else:
        out = out.drop_duplicates()
    return out


def _confidence_label_from_score(score: object) -> str:
    score_num = pd.to_numeric(pd.Series([score]), errors="coerce").fillna(0).iloc[0]
    s = int(score_num)
    if s >= 80:
        return "HIGH"
    if s >= 50:
        return "PROBABLE"
    return "WEAK"


def _clean_text_token(value: object, *, lower: bool = False) -> str:
    s = str(value or "").strip()
    if s.lower() in {"", "nan", "none", "-", "(empty)", "unknown"}:
        return ""
    return s.lower() if lower else s


def _last_non_empty_text(values: pd.Series) -> str:
    vals = list(values.astype(str).tolist())
    for raw in reversed(vals):
        cleaned = _clean_text_token(raw, lower=False)
        if cleaned:
            return cleaned
    return ""


def _union_source_types(values: pd.Series) -> str:
    """Merge comma-separated source tags in a stable, operator-friendly order."""
    desired = ["conn", "http", "ssl", "dns", "files"]
    seen = set()
    tokens: List[str] = []
    for raw in values.fillna("").astype(str).tolist():
        for chunk in raw.split(","):
            tok = _clean_text_token(chunk, lower=True)
            if not tok:
                continue
            tok = tok.strip()
            if not tok or tok in seen:
                continue
            seen.add(tok)
            tokens.append(tok)

    ordered: List[str] = [t for t in desired if t in seen]
    extras = sorted([t for t in seen if t not in set(desired)])
    out = ordered + extras
    return ", ".join(out) if out else "conn"


def _combine_reason_texts(values: pd.Series) -> str:
    seen = set()
    merged: List[str] = []
    for raw in values.fillna("").astype(str).tolist():
        for chunk in raw.split(";"):
            tok = _clean_text_token(chunk, lower=False)
            key = tok.lower()
            if not tok or key in seen:
                continue
            seen.add(key)
            merged.append(tok)
    return "; ".join(merged)


def _aggregate_incidents_for_daily_mac_destination_table(incidents_df: pd.DataFrame, selected_date: str) -> pd.DataFrame:
    """
    Table-only rollup:
    one row per unique MAC + destination within the selected 24h date scope.
    Falls back to `orig_ip` when MAC is missing so unrelated blank-MAC devices do not merge.
    """
    if incidents_df is None or incidents_df.empty:
        return pd.DataFrame()

    src = incidents_df.copy()
    defaults = [
        ("incident_id", ""),
        ("first_ts", pd.NaT),
        ("last_ts", pd.NaT),
        ("mac", ""),
        ("host_name", ""),
        ("orig_ip", ""),
        ("destination", ""),
        ("domain", ""),
        ("source_types", ""),
        ("sig_service", ""),
        ("allowed", False),
        ("allow_basis", ""),
        ("bytes_out_total", 0),
        ("bytes_in_total", 0),
        ("conn_count", 0),
        ("total_duration", 0),
        ("action", ""),
        ("action_basis", ""),
        ("confidence_score", 0),
        ("confidence_reasons", ""),
        ("is_shadow_sharing", False),
    ]
    for col_name, default_value in defaults:
        if col_name not in src.columns:
            src[col_name] = default_value

    src["first_ts"] = pd.to_datetime(src["first_ts"], errors="coerce")
    src["last_ts"] = pd.to_datetime(src["last_ts"], errors="coerce")
    src["mac"] = src["mac"].astype(str).str.strip().str.lower().replace({"nan": "", "none": "", "-": ""})
    src["orig_ip"] = src["orig_ip"].astype(str).str.strip().replace({"nan": "", "None": "", "none": "", "-": ""})
    src["destination"] = src["destination"].astype(str).str.strip().replace({"nan": "", "None": "", "none": "", "*": ""})
    src["domain"] = src["domain"].astype(str).str.strip().str.lower().replace({"nan": "", "None": "", "none": ""})
    src["source_types"] = src["source_types"].astype(str).fillna("")
    src["allow_basis"] = src["allow_basis"].astype(str).fillna("")
    src["confidence_reasons"] = src["confidence_reasons"].astype(str).fillna("")

    src["bytes_out_total"] = pd.to_numeric(src["bytes_out_total"], errors="coerce").fillna(0)
    src["bytes_in_total"] = pd.to_numeric(src["bytes_in_total"], errors="coerce").fillna(0)
    src["conn_count"] = pd.to_numeric(src["conn_count"], errors="coerce").fillna(0)
    src["total_duration"] = pd.to_numeric(src["total_duration"], errors="coerce").fillna(0)
    src["confidence_score"] = pd.to_numeric(src["confidence_score"], errors="coerce").fillna(0)
    src["_allowed_b"] = src["allowed"].apply(_coerce_bool_value)
    src["_shadow_b"] = src["is_shadow_sharing"].apply(_coerce_bool_value)

    src["__mac_key"] = src["mac"].astype(str).str.strip().str.lower()
    src["__ip_key"] = src["orig_ip"].astype(str).str.strip().str.lower()
    src["__device_key"] = src["__mac_key"].where(src["__mac_key"].ne(""), "ip:" + src["__ip_key"])
    src.loc[src["__device_key"].isin(["", "ip:"]), "__device_key"] = "device:unknown"

    src["__dest_key"] = src["destination"].astype(str).str.strip().str.lower()
    src["__dest_key"] = src["__dest_key"].where(src["__dest_key"].ne(""), src["domain"].astype(str).str.strip().str.lower())
    src.loc[src["__dest_key"] == "", "__dest_key"] = "(unknown)"

    day_fallback = pd.to_datetime(selected_date, errors="coerce")
    day_fallback_txt = day_fallback.strftime("%Y-%m-%d") if pd.notna(day_fallback) else ""
    day_from_first = src["first_ts"].dt.strftime("%Y-%m-%d")
    day_from_last = src["last_ts"].dt.strftime("%Y-%m-%d")
    src["__day_key"] = day_from_first.where(day_from_first.notna(), day_from_last)
    src["__day_key"] = src["__day_key"].fillna(day_fallback_txt).astype(str)
    if day_fallback_txt:
        src.loc[src["__day_key"].eq(""), "__day_key"] = day_fallback_txt

    src = src.sort_values(["last_ts", "first_ts"], ascending=[True, True], kind="stable")
    group_keys = ["__device_key", "__dest_key", "__day_key"]
    gb = src.groupby(group_keys, dropna=False, sort=False)

    agg = gb.agg(
        first_ts=("first_ts", "min"),
        last_ts=("last_ts", "max"),
        bytes_out_total=("bytes_out_total", "sum"),
        bytes_in_total=("bytes_in_total", "sum"),
        conn_count=("conn_count", "sum"),
        total_duration=("total_duration", "sum"),
        confidence_score=("confidence_score", "max"),
        allowed=("_allowed_b", "min"),
        is_shadow_sharing=("_shadow_b", "max"),
    ).reset_index()

    text_cols = [
        "mac",
        "host_name",
        "orig_ip",
        "destination",
        "domain",
        "sig_service",
        "action",
        "action_basis",
        "method",
        "uri",
        "user_agent",
        "file_names",
        "file_mime_types",
    ]
    text_cols = [c for c in text_cols if c in src.columns]
    if text_cols:
        latest_rows = (
            src[group_keys + text_cols]
            .groupby(group_keys, dropna=False, sort=False)
            .tail(1)
            .drop_duplicates(subset=group_keys, keep="last")
        )
        agg = agg.merge(latest_rows, on=group_keys, how="left")

    src_union = gb["source_types"].apply(_union_source_types).reset_index(name="source_types")
    reason_union = gb["confidence_reasons"].apply(_combine_reason_texts).reset_index(name="confidence_reasons")
    basis_last = gb["allow_basis"].apply(_last_non_empty_text).reset_index(name="allow_basis")
    agg = agg.merge(src_union, on=group_keys, how="left")
    agg = agg.merge(reason_union, on=group_keys, how="left")
    agg = agg.merge(basis_last, on=group_keys, how="left")

    agg["allowed"] = agg["allowed"].fillna(False).astype(bool)
    agg["is_shadow_sharing"] = agg["is_shadow_sharing"].fillna(False).astype(bool)
    agg["conn_count"] = pd.to_numeric(agg["conn_count"], errors="coerce").fillna(0).astype(int)
    agg["confidence_score"] = pd.to_numeric(agg["confidence_score"], errors="coerce").fillna(0).astype(int)
    agg["out_in_ratio_total"] = (
        agg["bytes_out_total"] / pd.to_numeric(agg["bytes_in_total"], errors="coerce").fillna(0).clip(lower=1)
    ).replace([float("inf"), float("-inf")], 0).fillna(0).round(3)
    agg["confidence"] = agg["confidence_score"].apply(_confidence_label_from_score)
    agg["incident_id"] = (
        "day_mac_dest|"
        + agg["__device_key"].astype(str)
        + "|"
        + agg["__dest_key"].astype(str)
        + "|"
        + agg["__day_key"].astype(str)
    )

    if "destination" in agg.columns and "domain" in agg.columns:
        fill_dest = agg["destination"].astype(str).str.strip().eq("")
        agg.loc[fill_dest, "destination"] = agg.loc[fill_dest, "domain"].astype(str)
        fill_domain = agg["domain"].astype(str).str.strip().eq("")
        agg.loc[fill_domain, "domain"] = agg.loc[fill_domain, "destination"].astype(str).str.lower()

    agg = agg.drop(columns=["__device_key", "__dest_key", "__day_key"], errors="ignore")
    agg = agg.sort_values(["confidence_score", "bytes_out_total", "conn_count", "last_ts"], ascending=[False, False, False, False])
    return agg.reset_index(drop=True)


def _strict_scope_by_selected_date(df: pd.DataFrame, selected_date: str, *, ts_col: str = "ts") -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame()
    if not selected_date or ts_col not in df.columns:
        return df.copy()
    target_day = pd.to_datetime(selected_date, errors="coerce")
    if pd.isna(target_day):
        return df.copy()
    out = df.copy()
    ts = pd.to_datetime(out[ts_col], errors="coerce")
    day_start = target_day.normalize()
    day_end = day_start + pd.Timedelta(days=1)
    mask = (ts >= day_start) & (ts < day_end)
    return out.loc[mask].copy()


def _format_duration_minutes_seconds(total_seconds: object) -> str:
    sec_val = pd.to_numeric(pd.Series([total_seconds]), errors="coerce").fillna(0).iloc[0]
    sec = float(max(0.0, float(sec_val)))
    mins = int(sec // 60)
    secs = int(round(sec - (mins * 60)))
    if secs >= 60:
        mins += 1
        secs = 0
    return f"{mins}m {secs:02d}s"


def _table_csv_bytes(df: pd.DataFrame) -> bytes:
    if df is None or df.empty:
        return b""
    out = df.copy()
    if AUTO_UNIQUE_ID_COL in out.columns:
        out = out.drop(columns=[AUTO_UNIQUE_ID_COL], errors="ignore")
    if "#" not in out.columns:
        out = out.reset_index(drop=True)
        out.insert(0, "#", range(1, len(out) + 1))
    return out.to_csv(index=False).encode("utf-8")


def _confidence_score_explainer_text() -> str:
    return (
        "Incidents are 5-minute rollups grouped by `device + domain + time window`, then scored from 0-100.\n"
        "- `+40` signature match (`Service`) when destination matches configured sharing signatures.\n"
        "- `+30` when destination is not allowlisted (`Allowed (Domain)=False`).\n"
        "- `+30` when upload volume is high (`>=10MB`) and out/in ratio is high (`>=5`).\n"
        "- `+15` for chunking behavior (`Conns >= 5` in the same window).\n"
        "- `+40` for share-link evidence (`http_share=True` derived from correlated `http_any_share`).\n"
        "- `+20` for repeat behavior (seen across `>=2` days while still unapproved).\n"
        "- Confidence labels: `HIGH >= 80`, `PROBABLE >= 50`, `WEAK < 50`.\n\n"
        
        "- `Conns` = unique Zeek connection IDs (`uid`) in that incident window.\n"
        "- `Duration` is the sum of Zeek `conn.duration` (seconds) for all connections in that incident window, shown as minutes and seconds.\n"
        "- Chunking in plain terms: one transfer is split into many smaller connections in the same 5-minute window.\n"
        "- Chunking example A: 6 connections x 2MB to the same domain in one window -> `Conns=6` and chunking points apply.\n"
        "- Chunking example B: 1 connection x 12MB in one window -> large upload, but no chunking bonus because `Conns=1`.\n"
        "- `Action` is inferred in priority order: `Share Link` -> `Upload` -> `File Transfer (Upload/Download)` -> `Upload (TLS)`/`Download` -> `Access`.\n"
        "- `Share Link`/`Upload` come from HTTP markers (`http_any_share`/`http_any_upload`). `File Transfer` requires `files.log` bytes (`>=1MB`) plus conn direction (`bytes_out` vs `bytes_in`).\n"
        "- TLS heuristics are fallback only: `Upload (TLS)` when `bytes_out>=10MB` and `out/in>=5`; `Download` when `bytes_in>=25MB` and inbound is at least 3x outbound.\n"
        "- `Domain` is derived from destination (`dest_domain`) with fallback to destination text.\n"
        "- `Allowed (Domain)` is a boundary-safe suffix match against `whitelist_domains.yaml` (`example.com` matches `a.b.example.com`, not `example.com.evil.tld`).\n"
        ""
    )


def _render_incident_table_insights(grid_rows: pd.DataFrame) -> None:
    if grid_rows is None or grid_rows.empty:
        return

    src = grid_rows.copy()
    src["Outbound_MB"] = pd.to_numeric(src.get("Outbound_MB", 0), errors="coerce").fillna(0)
    src["Confidence"] = src.get("Confidence", pd.Series("", index=src.index)).astype(str).str.upper()
    src["Confidence"] = src["Confidence"].where(src["Confidence"].isin(["HIGH", "PROBABLE", "WEAK"]), "WEAK")

    conf_order = ["HIGH", "PROBABLE", "WEAK"]
    conf_counts = (
        src.groupby("Confidence", dropna=False)
        .size()
        .reindex(conf_order, fill_value=0)
        .reset_index(name="Incidents")
    )
    conf_counts = conf_counts[conf_counts["Incidents"] > 0].copy()

    top_dest_col = "Domain" if "Domain" in src.columns else "Destination"
    src[top_dest_col] = src.get(top_dest_col, "").astype(str).str.strip()
    top_dest = (
        src[src[top_dest_col] != ""]
        .groupby(top_dest_col, dropna=False)["Outbound_MB"]
        .sum()
        .reset_index()
        .sort_values("Outbound_MB", ascending=False)
        .head(10)
    )

    ch1, ch2 = st.columns([1.0, 1.35])
    with ch1:
        if conf_counts.empty:
            st.info("No confidence chart data in this scope.")
        else:
            fig_conf = px.bar(
                conf_counts,
                x="Confidence",
                y="Incidents",
                color="Confidence",
                category_orders={"Confidence": conf_order},
                color_discrete_map=CONFIDENCE_COLORS,
                template=get_plotly_template(),
            )
            style_plotly_figure(fig_conf, height=300, show_legend=False)
            fig_conf.update_xaxes(title="")
            fig_conf.update_yaxes(title="Incident Count")
            st.plotly_chart(fig_conf, width="stretch")

    with ch2:
        if top_dest.empty:
            st.info("No destination chart data in this scope.")
        else:
            fig_dest = px.bar(
                top_dest,
                y=top_dest_col,
                x="Outbound_MB",
                orientation="h",
                template=get_plotly_template(),
            )
            style_plotly_figure(fig_dest, height=300, show_legend=False)
            fig_dest.update_xaxes(title="Outbound MB")
            fig_dest.update_yaxes(title="Destination/Domain", categoryorder="total ascending")
            st.plotly_chart(fig_dest, width="stretch")


def _build_incident_grid_frame(incidents_df: pd.DataFrame, *, include_hostname: bool = True) -> pd.DataFrame:
    if incidents_df is None or incidents_df.empty:
        return pd.DataFrame()

    inc_src = incidents_df.copy()
    for col_name, default_value in [
        ("incident_id", ""),
        ("first_ts", pd.NaT),
        ("last_ts", pd.NaT),
        ("mac", ""),
        ("host_name", ""),
        ("orig_ip", ""),
        ("destination", ""),
        ("domain", ""),
        ("source_types", ""),
        ("sig_service", ""),
        ("allowed", False),
        ("allow_basis", ""),
        ("bytes_out_total", 0),
        ("bytes_in_total", 0),
        ("out_in_ratio_total", 0),
        ("conn_count", 0),
        ("total_duration", 0),
        ("action", ""),
        ("action_basis", ""),
        ("confidence", ""),
        ("confidence_score", 0),
        ("confidence_reasons", ""),
    ]:
        if col_name not in inc_src.columns:
            inc_src[col_name] = default_value

    inc_src["first_ts"] = pd.to_datetime(inc_src["first_ts"], errors="coerce")
    inc_src["last_ts"] = pd.to_datetime(inc_src["last_ts"], errors="coerce")
    inc_src["mac"] = inc_src["mac"].astype(str).str.strip().str.lower().replace({"nan": "", "none": "", "-": ""})
    inc_src["Hostname"] = inc_src["host_name"].astype(str).str.strip().replace({"nan": "", "None": "", "none": "", "-": "", "(empty)": ""})
    inc_src.loc[inc_src["Hostname"] == "", "Hostname"] = "Unknown"
    inc_src["orig_ip"] = inc_src["orig_ip"].astype(str).str.strip().replace({"nan": "", "None": "", "none": "", "-": ""})
    inc_src["Destination"] = inc_src["destination"].astype(str).str.strip().replace({"nan": "", "None": "", "none": "", "*": ""})
    inc_src["Domain"] = inc_src["domain"].astype(str).str.strip().str.lower().replace({"nan": "", "None": "", "none": ""})
    inc_src.loc[inc_src["Domain"] == "", "Domain"] = inc_src.loc[inc_src["Domain"] == "", "Destination"].astype(str).str.lower()
    inc_src["Source"] = inc_src["source_types"].astype(str).str.strip().str.lower().replace({"nan": "", "None": "", "none": ""})
    inc_src.loc[inc_src["Source"] == "", "Source"] = "conn"
    inc_src["Source"] = inc_src["Source"].apply(lambda s: _union_source_types(pd.Series([s])))
    inc_src["Allowed_Domain"] = inc_src["allowed"].apply(_coerce_bool_value)
    inc_src["Status"] = inc_src["Allowed_Domain"].map(lambda v: "Authorized" if bool(v) else "Unauthorized")
    inc_src["Service"] = inc_src["sig_service"].astype(str).str.strip()
    inc_src.loc[inc_src["Service"].isin(["", "nan", "None", "none"]), "Service"] = "No signature match"
    action_txt = inc_src["action"].astype(str).str.strip().replace({"nan": "", "None": "", "none": ""})
    action_basis_txt = inc_src["action_basis"].astype(str).str.strip().replace({"nan": "", "None": "", "none": ""})
    inc_src["allow_basis"] = inc_src["allow_basis"].astype(str).str.strip().replace({"nan": "", "None": "", "none": ""})
    inc_src.loc[(inc_src["allow_basis"] == "") & (inc_src["Allowed_Domain"] == False), "allow_basis"] = "no match"  # noqa: E712
    inc_src["Confidence"] = inc_src["confidence"].astype(str).str.upper()
    inc_src["Confidence"] = inc_src["Confidence"].where(inc_src["Confidence"].isin(["HIGH", "PROBABLE", "WEAK"]), "WEAK")
    inc_src["Score"] = pd.to_numeric(inc_src["confidence_score"], errors="coerce").fillna(0).astype(int)
    out_mb = (pd.to_numeric(inc_src["bytes_out_total"], errors="coerce").fillna(0) / 1024 / 1024).round(3)
    in_mb = (pd.to_numeric(inc_src["bytes_in_total"], errors="coerce").fillna(0) / 1024 / 1024).round(3)
    inc_src["Outbound_MB"] = out_mb
    inc_src["Inbound_MB"] = in_mb
    # Keep displayed Ratio consistent with displayed MB values.
    inc_src["Ratio"] = (out_mb / in_mb.where(in_mb > 0, pd.NA)).fillna(0).round(3)
    inc_src["Conns"] = pd.to_numeric(inc_src["conn_count"], errors="coerce").fillna(0).astype(int)
    inc_src["Duration"] = pd.to_numeric(inc_src["total_duration"], errors="coerce").fillna(0).apply(_format_duration_minutes_seconds)
    base_reasons = inc_src["confidence_reasons"].astype(str).str.strip().replace({"nan": "", "None": "", "none": ""})
    inc_src["Reasons"] = [
        _compose_incident_reason(br, a, ab)
        for br, a, ab in zip(base_reasons.tolist(), action_txt.tolist(), action_basis_txt.tolist())
    ]

    if "incident_id" not in inc_src.columns:
        inc_src["incident_id"] = (
            inc_src["mac"].astype(str) + "|"
            + inc_src["Domain"].astype(str) + "|"
            + inc_src["first_ts"].astype(str)
        )

    inc_src = inc_src[inc_src["Outbound_MB"] > 0].copy()
    if inc_src.empty:
        return pd.DataFrame()

    if "incident_id" in inc_src.columns:
        inc_src = inc_src.drop_duplicates(subset=["incident_id"], keep="last")
    else:
        inc_src = inc_src.drop_duplicates()

    inc_src = inc_src.sort_values(["Score", "Outbound_MB", "Conns", "last_ts"], ascending=[False, False, False, False])
    dev_grid = inc_src.copy()
    dev_grid["First_Seen"] = dev_grid["first_ts"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("")
    dev_grid["Last_Seen"] = dev_grid["last_ts"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("")
    allow_key = dev_grid["incident_id"].astype(str).str.strip()
    fallback_key = (
        dev_grid["mac"].astype(str).str.strip().str.lower()
        + "|"
        + dev_grid["Domain"].astype(str).str.strip().str.lower()
        + "|"
        + dev_grid["First_Seen"].astype(str).str.strip()
    )
    dev_grid["_allow_key"] = allow_key.where(allow_key.ne(""), fallback_key)

    show_cols = [
        "#",
        "First_Seen",
        "Last_Seen",
        "mac",
        "Hostname",
        "orig_ip",
        "Destination",
        "Domain",
        "Allowed_Domain",
        "Status",
        "Source",
        "Service",
        "Outbound_MB",
        "Inbound_MB",
        "Ratio",
        "Conns",
        "Duration",
        "Confidence",
        "Score",
        "Reasons",
        "allow_basis",
        "incident_id",
        "_allow_key",
    ]
    if not include_hostname:
        show_cols = [c for c in show_cols if c != "Hostname"]
    show_cols = [c for c in show_cols if c in dev_grid.columns]
    dev_grid = dev_grid[show_cols].copy()
    if "incident_id" in dev_grid.columns:
        dev_grid = dev_grid.drop_duplicates(subset=["incident_id"], keep="last").reset_index(drop=True)
    else:
        dev_grid = dev_grid.drop_duplicates().reset_index(drop=True)
    if AUTO_UNIQUE_ID_COL in dev_grid.columns:
        dev_grid = dev_grid.drop(columns=[AUTO_UNIQUE_ID_COL], errors="ignore")
    dev_grid.insert(0, "#", range(1, len(dev_grid) + 1))
    return dev_grid


def _configure_incident_grid_columns(
    gb: GridOptionsBuilder,
    *,
    clickable_mac: bool,
    editable_allowed_domain: bool,
    include_hostname: bool,
) -> None:
    gb.configure_default_column(filter=True, sortable=True, resizable=True, flex=1)
    if clickable_mac:
        gb.configure_selection(selection_mode="single", use_checkbox=False)
        mac_only_click_js = JsCode(
            """
            function(params) {
                if (!params || !params.column || !params.node) return;
                const colId = params.column.getColId ? params.column.getColId() : '';
            if (colId === 'mac') {
                params.node.setSelected(true, true);
                return;
            }
            }
            """
        )
        gb.configure_grid_options(
            rowSelection="single",
            suppressRowClickSelection=True,
            rowMultiSelectWithClick=False,
            onCellClicked=mac_only_click_js,
        )
    gb.configure_column("#", header_name="#", width=62, pinned="left", suppressMovable=True, resizable=False)
    gb.configure_column(AUTO_UNIQUE_ID_COL, hide=True)

    if clickable_mac:
        clickable_mac_style = JsCode(
            """
            function(params) {
                const v = String(params.value || '').trim();
                if (!v) return { 'color': '#93A6BF' };
                return {
                    'color': '#8AB4F8',
                    'fontWeight': '700',
                    'cursor': 'pointer',
                    'textDecoration': 'underline'
                };
            }
            """
        )
        gb.configure_column("mac", header_name="MAC", minWidth=165, cellStyle=clickable_mac_style)
    else:
        gb.configure_column("mac", header_name="MAC", minWidth=165)
    if include_hostname:
        gb.configure_column("Hostname", minWidth=170)

    gb.configure_column("First_Seen", width=172)
    gb.configure_column("Last_Seen", width=172)
    gb.configure_column("orig_ip", header_name="Orig IP", minWidth=140)
    gb.configure_column("Destination", minWidth=220)
    gb.configure_column("Domain", minWidth=210)
    gb.configure_column("Source", width=125)
    gb.configure_column("Service", width=180)

    allowed_kwargs = {}
    if editable_allowed_domain:
        allowed_editable = JsCode(
            """
            function(params) {
                const row = params && params.data ? params.data : {};
                const allowed = row.Allowed_Domain;
                const isAllowed = (allowed === true) || (String(allowed).toLowerCase() === 'true');
                if (isAllowed) return false;
                return true;
            }
            """
        )
        allowed_kwargs = {
            "editable": allowed_editable,
            "cellRenderer": "agCheckboxCellRenderer",
            "cellEditor": "agCheckboxCellEditor",
            "singleClickEdit": True,
            "filter": False,
            "sortable": False,
        }
    gb.configure_column("Allowed_Domain", header_name="Allowed", width=96, cellStyle=_allowed_cellstyle(), **allowed_kwargs)
    gb.configure_column(
        "Status",
        header_name="Status",
        width=118,
        editable=False,
        filter=False,
        sortable=True,
        cellStyle=_status_cellstyle(),
    )
    num_fmt = _fixed_3dp_formatter()
    gb.configure_column("Outbound_MB", header_name="Out MB", width=110, valueFormatter=num_fmt)
    gb.configure_column("Inbound_MB", header_name="In MB", width=110, valueFormatter=num_fmt)
    gb.configure_column("Ratio", width=100, valueFormatter=num_fmt)
    gb.configure_column("Conns", width=86)
    gb.configure_column("Duration", header_name="Duration (m/s)", width=128)
    gb.configure_column("Confidence", width=110, cellStyle=_confidence_cellstyle())
    gb.configure_column("Score", width=82)
    gb.configure_column("Reasons", minWidth=420)
    gb.configure_column("allow_basis", hide=True)
    gb.configure_column("incident_id", hide=True)
    gb.configure_column("_allow_key", hide=True)


def _clean_whitelist_target_value(value: object) -> str:
    txt = str(value or "").strip()
    if not txt:
        return ""
    if txt.lower() in INVALID_DEST_SET:
        return ""
    return txt


def _resolve_whitelist_target(row: pd.Series, *, remove: bool) -> str:
    # For allow actions, always use the Domain column so one allow entry
    # can immediately apply to all rows that share the same domain.
    domain = _clean_whitelist_target_value(row.get("Domain", ""))
    if domain:
        return domain

    # For remove actions, keep compatibility with prior basis-driven removal.
    if remove:
        basis = _clean_whitelist_target_value(row.get("allow_basis", ""))
        if basis and basis.lower() not in {"no match", "n/a (unknown destination)"}:
            return basis
        destination = _clean_whitelist_target_value(row.get("Destination", ""))
        if destination:
            return destination
    return ""


def _apply_allowed_domain_checkbox_changes(grid_before: pd.DataFrame, grid_response) -> bool:
    if grid_before is None or grid_before.empty or grid_response is None:
        return False

    if st.session_state.get("shadow_sharing_allow_dialog_open"):
        return False

    getter = getattr(grid_response, "get", None)
    if not callable(getter):
        return False

    data_after = getter("data", None)
    if data_after is None:
        return False

    after_df = pd.DataFrame(data_after)
    if after_df.empty:
        return False
    if "Allowed_Domain" not in grid_before.columns or "Allowed_Domain" not in after_df.columns:
        return False

    before_work = grid_before.copy()
    after_work = after_df.copy()

    # Be tolerant if hidden key column is not returned by grid response.
    if "_allow_key" not in before_work.columns:
        if "incident_id" in before_work.columns:
            before_work["_allow_key"] = before_work["incident_id"].astype(str).str.strip()
        else:
            before_work["_allow_key"] = before_work.index.astype(str)
    if "_allow_key" not in after_work.columns:
        if "incident_id" in after_work.columns:
            after_work["_allow_key"] = after_work["incident_id"].astype(str).str.strip()
        else:
            after_work["_allow_key"] = after_work.index.astype(str)

    before_keys = before_work["_allow_key"].astype(str).str.strip()
    before_allowed = before_work["Allowed_Domain"].apply(_coerce_bool_value)
    original_allow_map = {
        str(k): bool(v)
        for k, v in zip(before_keys.tolist(), before_allowed.tolist())
        if str(k).strip()
    }

    edited = after_work.drop_duplicates(subset=["_allow_key"], keep="last").copy()
    edited["_allow_key"] = edited["_allow_key"].astype(str).str.strip()
    edited = edited[edited["_allow_key"].str.len() > 0].copy()
    if edited.empty:
        return False

    edited["Allowed_Domain"] = edited["Allowed_Domain"].apply(_coerce_bool_value)
    edited["_was_allowed"] = edited["_allow_key"].map(lambda k: bool(original_allow_map.get(str(k), False)))

    newly_allowed = edited[
        (edited["Allowed_Domain"])
        & (~edited["_was_allowed"])
    ]
    if not newly_allowed.empty:
        pick = newly_allowed.iloc[0]
        target = _resolve_whitelist_target(pick, remove=False)
        if not str(target).strip():
            target = str(pick.get("Domain", "") or "").strip()
        incident_id = str(pick.get("incident_id", "") or "").strip()
        destination = str(pick.get("Destination", pick.get("destination", "")) or "").strip()
        mac = str(pick.get("mac", pick.get("Mac", "")) or "").strip().lower()
        hostname = str(pick.get("Hostname", pick.get("host_name", "")) or "").strip()
        candidate = {
            "incident_id": incident_id,
            "domain": str(target).strip(),
            "destination": destination,
            "mac": mac,
            "hostname": hostname,
        }
        _open_shadow_sharing_allow_dialog(candidate)
        st.session_state["shadow_sharing_grid_nonce"] = int(st.session_state.get("shadow_sharing_grid_nonce", 0)) + 1
        st.rerun()
        return True

    changed_mask = edited["Allowed_Domain"] != edited["_was_allowed"]
    if bool(changed_mask.any()):
        # Revert unsupported toggle directions (e.g., unchecking) or invalid target clicks.
        st.session_state["shadow_sharing_grid_nonce"] = int(st.session_state.get("shadow_sharing_grid_nonce", 0)) + 1
        st.rerun()
        return True
    return False


@st.dialog("Allow Destination Domain", width="small", dismissible=False)
def show_shadow_sharing_allow_dialog():
    st.session_state["shadow_sharing_dialog_origin"] = "dialog"
    candidate = st.session_state.get("shadow_sharing_allow_candidate") or {}
    target_domain = _clean_whitelist_target_value(candidate.get("domain", ""))
    destination = str(candidate.get("destination") or "").strip()
    target_mac = str(candidate.get("mac") or "").strip().lower()
    target_host = str(candidate.get("hostname") or "").strip()
    incident_id = str(candidate.get("incident_id") or "").strip()
    invalid_target = not bool(target_domain)
    whitelist_path = Path(__file__).resolve().parents[2] / "whitelist_domains.yaml"
    try:
        whitelist_label = str(whitelist_path.resolve())
    except Exception:
        whitelist_label = str(whitelist_path)

    st.markdown(f"Confirm allowlisting for MAC `{target_mac or 'unknown'}`.")
    st.markdown(f"- Domain: `{target_domain or '-'}`")
    st.markdown(f"- Destination: `{destination or '-'}`")
    st.markdown(f"- Hostname: `{target_host or '-'}`")
    st.markdown(f"- Incident ID: `{incident_id or '-'}`")
    st.caption(
        f"This will update `{whitelist_label}` and refresh Shadow Sharing cache/policy columns."
    )

    if invalid_target:
        st.error("This row has no valid domain in the Domain column.")

    c1, c2 = st.columns(2)
    with c1:
        if st.button(
            "Allow Domain",
            type="primary",
            width="stretch",
            disabled=invalid_target,
            key="shadow_sharing_allow_confirm_btn",
        ):
            ok, message = _add_domain_to_whitelist(str(target_domain))
            if ok:
                try:
                    refresh_shadow_sharing_runtime_state()
                except Exception:
                    pass
                _invalidate_shadow_sharing_frontend_cache()
                _close_shadow_sharing_allow_dialog(reset_grid=False)
                st.session_state["shadow_sharing_whitelist_feedback"] = {"ok": [str(message)], "error": []}
                st.rerun()
            st.error(str(message))
    with c2:
        if st.button("Cancel", width="stretch", key="shadow_sharing_allow_cancel_btn"):
            _close_shadow_sharing_allow_dialog(reset_grid=True)
            st.rerun()


@st.dialog("Device Forensics Details", width="large")
def show_shadow_sharing_device_dialog(
    filtered: pd.DataFrame,
    filtered_incidents: pd.DataFrame,
    *,
    selected_scope_key: str,
    selected_scope_label: str,
):
    st.session_state["shadow_sharing_dialog_origin"] = "dialog"
    target_mac = str(st.session_state.get("shadow_sharing_dialog_mac") or "").strip().lower()
    if not target_mac:
        st.info("No MAC selected.")
        return

    device_label = target_mac
    mac_key = re.sub(r"[^0-9A-Za-z_]+", "_", device_label).strip("_") or "device"

    st.markdown(
        """
        <style>
        div[data-testid="stDialog"] > div[role="dialog"] {
            width: min(95vw, 1450px) !important;
            max-width: min(95vw, 1450px) !important;
            border: 1px solid rgba(148, 163, 184, 0.35);
            background: linear-gradient(180deg, rgba(3,10,23,0.96), rgba(2,8,20,0.97));
        }
        div[data-testid="stDialog"] div[role="dialog"] .stDialogContent {
            padding-left: 1.05rem !important;
            padding-right: 1.05rem !important;
            padding-bottom: 0.8rem !important;
        }
        div[data-testid="stDialog"] .shadow-dialog-hero {
            border: 1px solid rgba(148, 163, 184, 0.28);
            background: linear-gradient(135deg, rgba(15,23,42,0.66), rgba(2,6,23,0.62));
            border-radius: 12px;
            padding: 0.58rem 0.76rem;
            margin-bottom: 0.4rem;
        }
        div[data-testid="stDialog"] .shadow-dialog-title {
            color: #e7efff;
            font-weight: 800;
            letter-spacing: 0.02em;
            font-size: 1rem;
            line-height: 1.2;
        }
        div[data-testid="stDialog"] .shadow-dialog-subtitle {
            color: #b8cae6;
            font-size: 0.8rem;
            margin-top: 0.22rem;
        }
        div[data-testid="stDialog"] .shadow-dialog-subtitle code {
            border: 1px solid rgba(148, 163, 184, 0.3);
            background: rgba(8, 20, 40, 0.78);
            color: #dbeafe;
            border-radius: 999px;
            padding: 0.12rem 0.52rem;
        }
        div[data-testid="stDialog"] .shadow-dialog-chips {
            display: flex;
            flex-wrap: wrap;
            gap: 0.42rem;
            margin: 0.05rem 0 0.5rem 0;
        }
        div[data-testid="stDialog"] .shadow-dialog-chip {
            border: 1px solid rgba(148, 163, 184, 0.28);
            background: rgba(255,255,255,0.04);
            border-radius: 999px;
            padding: 0.21rem 0.58rem;
            font-size: 0.72rem;
            color: #c7d6eb;
            line-height: 1.1;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    if "mac" not in filtered_incidents.columns:
        st.warning("MAC column is not available in incident data.")
        return

    scoped_incidents = filtered_incidents.copy()
    mac_norm = scoped_incidents["mac"].astype(str).str.strip().str.lower()
    scoped_incidents = scoped_incidents.loc[mac_norm == target_mac].copy()
    if scoped_incidents.empty:
        st.warning("No incident rows found for this MAC with current filters.")
        return

    mac_hostname = ""
    if "host_name" in scoped_incidents.columns:
        h = scoped_incidents["host_name"].astype(str).str.strip()
        h = h[~h.str.lower().isin(["", "nan", "none", "unknown", "-", "(empty)"])]
        if not h.empty:
            mac_hostname = str(h.value_counts(dropna=True).index[0]).strip()
    if not mac_hostname and isinstance(filtered, pd.DataFrame) and "mac" in filtered.columns and "host_name" in filtered.columns:
        f = filtered.copy()
        mac_mask = f["mac"].astype(str).str.strip().str.lower().eq(target_mac)
        h2 = f.loc[mac_mask, "host_name"].astype(str).str.strip()
        h2 = h2[~h2.str.lower().isin(["", "nan", "none", "unknown", "-", "(empty)"])]
        if not h2.empty:
            mac_hostname = str(h2.value_counts(dropna=True).index[0]).strip()
    mac_hostname = mac_hostname or "Unknown"

    top = st.columns([1.0, 5.0])
    with top[0]:
        if st.button("Close", width="stretch", type="primary", key=f"shadow_sharing_dlg_close_{selected_scope_key}_{mac_key}"):
            _close_shadow_sharing_dialog()
            st.rerun()
    with top[1]:
        scope_label = (
            f"MAC <code>{target_mac}</code> | "
            f"Hostname <code>{mac_hostname}</code> | "
            f"Date <code>{selected_scope_label}</code>"
        )
        st.markdown(
            f"""
            <div class='shadow-dialog-hero'>
                <div class='shadow-dialog-title'>Device Forensics Drilldown</div>
                <div class='shadow-dialog-subtitle'>Scope locked to {scope_label}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    dialog_search = st.text_input(
        "Search (time, destination, domain, source, reason/basis)",
        placeholder="e.g., drive.google.com",
        key=f"shadow_sharing_dlg_search_{selected_scope_key}_{mac_key}",
    ).strip()

    if dialog_search:
        q = dialog_search.lower()
        search_cols = [
            "mac",
            "orig_ip",
            "destination",
            "domain",
            "source_types",
            "sig_service",
            "allow_basis",
            "action",
            "action_basis",
            "confidence",
            "confidence_reasons",
        ]
        search_mask = pd.Series(False, index=scoped_incidents.index)
        for col in search_cols:
            if col in scoped_incidents.columns:
                search_mask = search_mask | scoped_incidents[col].astype(str).str.lower().str.contains(q, na=False, regex=False)
        if "first_ts" in scoped_incidents.columns:
            first_txt = pd.to_datetime(scoped_incidents["first_ts"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S").fillna("")
            search_mask = search_mask | first_txt.str.lower().str.contains(q, na=False, regex=False)
        if "last_ts" in scoped_incidents.columns:
            last_txt = pd.to_datetime(scoped_incidents["last_ts"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S").fillna("")
            search_mask = search_mask | last_txt.str.lower().str.contains(q, na=False, regex=False)
        scoped_incidents = scoped_incidents[search_mask].copy()

    scoped_incidents = _filter_incidents_nonzero_outbound(scoped_incidents)
    if scoped_incidents.empty:
        st.info("No non-zero outbound incident rows match your dialog search.")
        return

    scoped_incidents_raw = scoped_incidents.copy()
    scoped_incidents_table = _aggregate_incidents_for_daily_mac_destination_table(
        scoped_incidents_raw,
        str(selected_scope_label),
    )

    grid_rows = _build_incident_grid_frame(scoped_incidents_table, include_hostname=False)
    raw_grid_rows = _build_incident_grid_frame(scoped_incidents_raw, include_hostname=False)
    if raw_grid_rows.empty and not grid_rows.empty:
        raw_grid_rows = grid_rows.copy()
    if grid_rows.empty and not raw_grid_rows.empty:
        grid_rows = raw_grid_rows.copy()
    if grid_rows.empty:
        st.info("No incident rows above 0 MB are available for this MAC.")
        return
    if AUTO_UNIQUE_ID_COL in grid_rows.columns:
        grid_rows = grid_rows.drop(columns=[AUTO_UNIQUE_ID_COL], errors="ignore")
    if "#" not in grid_rows.columns:
        grid_rows = grid_rows.reset_index(drop=True)
        grid_rows.insert(0, "#", range(1, len(grid_rows) + 1))

    first_seen = pd.to_datetime(scoped_incidents.get("first_ts", pd.Series([], dtype="datetime64[ns]")), errors="coerce").min()
    last_seen = pd.to_datetime(scoped_incidents.get("last_ts", pd.Series([], dtype="datetime64[ns]")), errors="coerce").max()
    unique_dest = int(raw_grid_rows["Destination"].replace({"": None, "Unknown": None, "unknown": None}).dropna().nunique())
    total_outbound_mb = float(pd.to_numeric(raw_grid_rows["Outbound_MB"], errors="coerce").fillna(0).sum())
    unapproved = int((raw_grid_rows["Allowed_Domain"] == False).sum())  # noqa: E712
    high_conf = int((raw_grid_rows["Confidence"] == "HIGH").sum())

    st.markdown(
        (
            f"<div class='shadow-filter-hint shadow-scope-hint'>"
            f"Table grouped to <strong>{len(grid_rows):,}</strong> unique MAC+Destination rows "
            f"(from {len(raw_grid_rows):,} incident rows) for this device."
            f"</div>"
        ),
        unsafe_allow_html=True,
    )

    first_seen_txt = first_seen.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(first_seen) else "-"
    last_seen_txt = last_seen.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(last_seen) else "-"
    st.markdown(
        f"""
        <div class='shadow-dialog-chips'>
            <span class='shadow-dialog-chip'>First Seen: <strong>{first_seen_txt}</strong></span>
            <span class='shadow-dialog-chip'>Last Seen: <strong>{last_seen_txt}</strong></span>
            <span class='shadow-dialog-chip'>Unique Destinations: <strong>{unique_dest:,}</strong></span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    dm1, dm2, dm3, dm4 = st.columns(4)
    dm1.metric("Scoped Incidents", f"{len(raw_grid_rows):,}")
    dm2.metric("Unapproved", unapproved, delta="Investigate" if unapproved > 0 else "Clear", delta_color="inverse")
    dm3.metric("Outbound Volume", f"{total_outbound_mb:.2f} MB")
    dm4.metric("High Confidence", f"{high_conf:,}")

    with st.container():
        st.markdown("#### Shadow Sharing Incidents (MAC Scope)")
        st.caption("Table rows are grouped by unique MAC + Destination for the selected 24-hour date scope.")
        _render_incident_table_insights(raw_grid_rows)
        gb_rows = GridOptionsBuilder.from_dataframe(grid_rows)
        _configure_incident_grid_columns(
            gb_rows,
            clickable_mac=False,
            editable_allowed_domain=True,
            include_hostname=False,
        )
        row_response = render_shadow_aggrid(
            grid_rows,
            gb_rows,
            key=(
                f"shadow_sharing_rows_grid_{selected_scope_key}_{mac_key}_"
                f"{int(st.session_state.get('shadow_sharing_grid_nonce', 0))}"
            ),
            height=450,
            update_mode=(GridUpdateMode.VALUE_CHANGED | GridUpdateMode.MODEL_CHANGED),
            wrap_shell=False,
            force_scrollbars=True,
            hide_scrollbar_buttons=True,
        )
        _apply_allowed_domain_checkbox_changes(grid_rows, row_response)
        export_rows = pd.DataFrame(row_response.get("data", [])) if isinstance(row_response, dict) else pd.DataFrame()
        if export_rows.empty:
            export_rows = grid_rows.copy()
        st.download_button(
            "Download CSV (MAC scope)",
            data=_table_csv_bytes(export_rows),
            file_name=f"shadow_sharing_mac_{mac_key}_{selected_scope_label}.csv",
            mime="text/csv",
            key=f"shadow_sharing_mac_csv_{selected_scope_key}_{mac_key}",
        )

    with st.expander("Confidence score computation", expanded=False):
        st.markdown(_confidence_score_explainer_text())


def render_shadow_sharing(parquet_root: Path):
    inject_shadow_sharing_css()

    parquet_root = Path(parquet_root)
    if not parquet_root.exists():
        st.error("Data directory not found.")
        return

    available_dates = get_available_dates(parquet_root)
    if not available_dates:
        st.warning("No logs found.")
        return

    st.session_state.setdefault("shadow_sharing_dialog_open", False)
    st.session_state.setdefault("shadow_sharing_dialog_mac", None)
    st.session_state.setdefault("shadow_sharing_last_selected_mac", None)
    st.session_state.setdefault("shadow_sharing_dialog_base_df", None)
    st.session_state.setdefault("shadow_sharing_dialog_base_key", None)
    st.session_state.setdefault("shadow_sharing_dialog_incidents_df", None)
    st.session_state.setdefault("shadow_sharing_grid_nonce", 0)
    st.session_state.setdefault("shadow_sharing_allow_dialog_open", False)
    st.session_state.setdefault("shadow_sharing_allow_candidate", None)
    st.session_state.setdefault("_shadow_sharing_scope_cache_key_v1", None)
    st.session_state.setdefault("_shadow_sharing_scope_df_v1", None)
    st.session_state.setdefault("_shadow_sharing_scope_incidents_v1", None)

    origin = st.session_state.pop("shadow_sharing_dialog_origin", None)
    if st.session_state.get("shadow_sharing_dialog_open") and origin not in ("grid", "dialog"):
        _close_shadow_sharing_dialog()
        origin = None

    def _on_scope_change():
        _close_shadow_sharing_dialog()
        _close_shadow_sharing_allow_dialog(reset_grid=False)

    selected_date = st.selectbox(
        "Dataset Scope",
        available_dates,
        index=0,
        key="shadow_sharing_date",
        on_change=_on_scope_change,
    )
    selected_scope_key = re.sub(r"[^A-Za-z0-9_]+", "_", str(selected_date))

    feedback = st.session_state.pop("shadow_sharing_whitelist_feedback", None)
    if isinstance(feedback, dict):
        ok_msgs = [str(x) for x in (feedback.get("ok") or []) if str(x).strip()]
        err_msgs = [str(x) for x in (feedback.get("error") or []) if str(x).strip()]
        if ok_msgs:
            ok_txt = "; ".join(ok_msgs[:2]) + (" ..." if len(ok_msgs) > 2 else "")
            st.success(f"Whitelist updated: {ok_txt}")
        if err_msgs:
            err_txt = "; ".join(err_msgs[:2]) + (" ..." if len(err_msgs) > 2 else "")
            st.warning(f"Whitelist update issues: {err_txt}")
    # Date scope
    # NOTE: Zeek can write logs into a "day folder" that contains spillover timestamps
    # from the previous/next day around midnight. To avoid missing events for the
    # selected date, we load the selected folder plus adjacent folders (if present),
    # then apply a strict timestamp filter to keep only the selected date.
    target_dates: List[str] = []
    if selected_date:
        target_dates = [str(selected_date)]
        try:
            sel_dt = pd.to_datetime(str(selected_date), errors="coerce")
            if pd.notna(sel_dt):
                prev_d = (sel_dt - timedelta(days=1)).strftime("%Y-%m-%d")
                next_d = (sel_dt + timedelta(days=1)).strftime("%Y-%m-%d")
                for d in [prev_d, next_d]:
                    if d in available_dates and d not in target_dates:
                        target_dates.append(d)
        except Exception:
            pass
    logs_sig = shadow_sharing_logs_signature(parquet_root, target_dates)
    scope_cache_key = (
        str(parquet_root.resolve()),
        tuple(target_dates),
        str(logs_sig),
    )

    cached_key = st.session_state.get("_shadow_sharing_scope_cache_key_v1")
    cached_df = st.session_state.get("_shadow_sharing_scope_df_v1")
    cached_incidents = st.session_state.get("_shadow_sharing_scope_incidents_v1")
    if cached_key == scope_cache_key and isinstance(cached_df, pd.DataFrame):
        df = cached_df
        incidents = cached_incidents if isinstance(cached_incidents, pd.DataFrame) else pd.DataFrame()
    else:
        with st.spinner("Optimizing logs for fast load..."):
            df, incidents = load_shadow_sharing_bundle(parquet_root, target_dates)
        st.session_state["_shadow_sharing_scope_cache_key_v1"] = scope_cache_key
        st.session_state["_shadow_sharing_scope_df_v1"] = df
        st.session_state["_shadow_sharing_scope_incidents_v1"] = incidents
        st.session_state.pop("_shadow_sharing_filtered_cache_v1", None)
        st.session_state.pop("_shadow_sharing_source_masks_cache_v1", None)

    # Keep date scope strict to selected day by event timestamp.
    # Some day folders can still contain spillover rows around midnight.
    df_union = df
    total_scope_rows = int(len(df_union))
    df = _strict_scope_by_selected_date(df_union, str(selected_date), ts_col="ts")

    trimmed_rows = max(0, total_scope_rows - int(len(df)))

    adjacent_dates = [str(d) for d in (target_dates or []) if str(d) != str(selected_date)]
    included_from_adjacent = 0
    if adjacent_dates and "_folder_date" in df.columns:
        try:
            included_from_adjacent = int(df["_folder_date"].astype(str).isin(set(adjacent_dates)).sum())
        except Exception:
            included_from_adjacent = 0

    if trimmed_rows > 0 or adjacent_dates:
        st.caption(
            f"Date scope note: excluded {trimmed_rows:,} rows because their timestamps were outside `{selected_date}`. "
            f"Included {included_from_adjacent:,} rows from adjacent day folders (yesterday/tomorrow)."
        )
    if isinstance(incidents, pd.DataFrame) and not incidents.empty:
        incidents = _strict_scope_by_selected_date(incidents, str(selected_date), ts_col="first_ts")
    elif not df.empty:
        # Fallback if incident cache is unavailable.
        incidents = build_shadow_sharing_incidents(df)
    else:
        incidents = pd.DataFrame()

    if df.empty:
        st.info("No data detected for the selected timeframe.")
        return

    # -------------------------------------------------------------------------
    # Incident Rollup (Algorithms #2/#4/#5/#6)
    # -------------------------------------------------------------------------
    incidents = _filter_incidents_nonzero_outbound(incidents)

    st.markdown("### Shadow Sharing Incidents")
    st.caption("Incidents roll up conn/ssl/http/files evidence into 5-minute windows and score confidence (HIGH/PROBABLE/WEAK).")
    if incidents.empty:
        st.info("No flow-based incidents were found in this scope.")
    else:
        st.markdown(
            f"<div class='shadow-filter-hint shadow-scope-hint'>Detected <strong>{len(incidents):,}</strong> incident windows in this dataset. Use filters below to refine the incident timeline and table.</div>",
            unsafe_allow_html=True,
        )

    st.divider()

    def _has_text(s: pd.Series) -> pd.Series:
        t = s.astype(str).str.strip().str.lower()
        return ~t.isin(["", "nan", "none", "-", "unknown"])

    def _to_bool(s: pd.Series) -> pd.Series:
        if pd.api.types.is_bool_dtype(s):
            return s.fillna(False)
        t = s.astype(str).str.strip().str.lower()
        return t.isin(["1", "true", "t", "yes", "y"])

    def _build_real_source_masks(src: pd.DataFrame) -> Dict[str, pd.Series]:
        idx = src.index
        log_src = src["log_source"].astype(str).str.strip().str.lower() if "log_source" in src.columns else pd.Series("", index=idx)
        dns_mask = log_src.eq("dns")
        conn_mask = ~dns_mask

        http_mask = pd.Series(False, index=idx)
        for col in ["method", "uri", "user_agent", "host", "content_type"]:
            if col in src.columns:
                http_mask = http_mask | _has_text(src[col])
        for col in ["request_body_len", "response_body_len", "status_code"]:
            if col in src.columns:
                v = pd.to_numeric(src[col], errors="coerce").fillna(0)
                http_mask = http_mask | (v > 0)
        for col in ["http_any_upload", "http_any_share"]:
            if col in src.columns:
                http_mask = http_mask | _to_bool(src[col])
        http_mask = http_mask & conn_mask

        ssl_mask = pd.Series(False, index=idx)
        for col in ["server_name", "ja3", "ja3s", "version", "cipher", "curve", "next_protocol"]:
            if col in src.columns:
                ssl_mask = ssl_mask | _has_text(src[col])
        ssl_mask = ssl_mask & conn_mask

        files_mask = pd.Series(False, index=idx)
        for col in ["file_total_bytes", "file_seen_bytes"]:
            if col in src.columns:
                v = pd.to_numeric(src[col], errors="coerce").fillna(0)
                files_mask = files_mask | (v > 0)
        for col in ["file_mime_types", "file_names", "file_sources"]:
            if col in src.columns:
                files_mask = files_mask | _has_text(src[col])
        files_mask = files_mask & conn_mask

        return {
            "conn": conn_mask,
            "http": http_mask,
            "ssl": ssl_mask,
            "dns": dns_mask,
            "files": files_mask,
        }

    source_data_stamp = _shadow_sharing_data_stamp(df)
    source_mask_key = (str(selected_scope_key), source_data_stamp)
    source_mask_cache = st.session_state.get("_shadow_sharing_source_masks_cache_v1", {})
    if isinstance(source_mask_cache, dict) and source_mask_cache.get("key") == source_mask_key:
        source_masks = source_mask_cache.get("masks", {})
        source_options = source_mask_cache.get("options", [])
    else:
        source_masks = _build_real_source_masks(df)
        ordered_sources = ["conn", "http", "ssl", "dns", "files"]
        source_options = [s for s in ordered_sources if bool(source_masks.get(s, pd.Series([], dtype=bool)).any())]
        if not source_options:
            source_options = ordered_sources
        st.session_state["_shadow_sharing_source_masks_cache_v1"] = {
            "key": source_mask_key,
            "masks": source_masks,
            "options": source_options,
        }

    search_q = st.text_input("Search (MAC, Host, IP, Destination, Basis)", placeholder="e.g., 192.168.1.14",)

    c1, c2 = st.columns([1.4, 2.2])
    with c1:
        selected_risk_levels = st.multiselect("Risk Level", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    with c2:
        selected_sources = st.multiselect("Source Logs", source_options, default=source_options)

    filter_cache_key = _shadow_sharing_filter_cache_key(
        selected_scope_key=selected_scope_key,
        selected_sources=selected_sources,
        selected_risk_levels=selected_risk_levels,
        search_q=search_q,
        data_stamp=source_data_stamp,
    )
    filter_cache_state = st.session_state.get("_shadow_sharing_filtered_cache_v1", {})
    if isinstance(filter_cache_state, dict) and filter_cache_state.get("key") == filter_cache_key:
        filtered = filter_cache_state.get("filtered", pd.DataFrame())
        filtered_incidents = filter_cache_state.get("filtered_incidents", pd.DataFrame())
        dev_grid_table_cached = filter_cache_state.get("dev_grid_table", filter_cache_state.get("dev_grid", pd.DataFrame()))
        dev_grid_raw_cached = filter_cache_state.get("dev_grid_raw", pd.DataFrame())
    else:
        # Apply filters
        filtered = df.copy()

        if selected_sources:
            source_keep = pd.Series(False, index=filtered.index)
            for src_name in selected_sources:
                mask = source_masks.get(str(src_name).strip().lower())
                if mask is not None:
                    source_keep = source_keep | mask
            filtered = filtered[source_keep]

        if selected_risk_levels:
            filtered = filtered[filtered["Severity"].isin(selected_risk_levels)]

        if search_q:
            q = search_q.lower().strip()
            if q:
                filtered = filtered[
                    filtered["mac"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                    | filtered["host_name"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                    | filtered["id.orig_h"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                    | filtered["destination"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                    | filtered["Risk_Basis"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                    | filtered["Action_Basis"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                    | filtered["Allow_Basis"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                ]

        # Hard filter: hide Unknown/placeholder destinations in tables and Top Dest computations
        if "destination" in filtered.columns:
            dest_norm = filtered["destination"].astype(str).str.strip().str.lower()
            filtered = filtered[~dest_norm.isin(INVALID_DEST_SET)].copy()
        filtered["bytes"] = pd.to_numeric(filtered["bytes"], errors="coerce").fillna(0)
        filtered = filtered[filtered["bytes"] > 0].copy()

        if "event_id" in filtered.columns:
            filtered = filtered.drop_duplicates(subset=["event_id"], keep="last")
        else:
            dedupe_cols = [c for c in ["ts", "id.orig_h", "destination", "bytes"] if c in filtered.columns]
            if dedupe_cols:
                filtered = filtered.drop_duplicates(subset=dedupe_cols, keep="last")
            else:
                filtered = filtered.drop_duplicates()

        filtered_incidents = build_shadow_sharing_incidents(filtered)
        filtered_incidents = _filter_incidents_nonzero_outbound(filtered_incidents)
        dev_grid_raw_cached = _build_incident_grid_frame(filtered_incidents)
        table_incidents = _aggregate_incidents_for_daily_mac_destination_table(filtered_incidents, str(selected_date))
        dev_grid_table_cached = _build_incident_grid_frame(table_incidents)
        if dev_grid_table_cached.empty and not dev_grid_raw_cached.empty:
            dev_grid_table_cached = dev_grid_raw_cached.copy()
        st.session_state["_shadow_sharing_filtered_cache_v1"] = {
            "key": filter_cache_key,
            "filtered": filtered,
            "filtered_incidents": filtered_incidents,
            "dev_grid_table": dev_grid_table_cached,
            "dev_grid_raw": dev_grid_raw_cached,
        }

    if filtered.empty:
        st.warning("No rows above 0 MB match your filters.")
        return

    # Metrics
    st.divider()
    m1, m2, m3, m4 = st.columns(4)

    total_b = float(filtered.loc[filtered["bytes"] > 0, "bytes"].sum())
    total_mb = total_b / 1024 / 1024
    unapproved = int((filtered["Allowed"] == False).sum())  # noqa: E712
    autom = int((filtered["Client_Type"] == "Automation / SDK").sum())

    threat_metric_base = filtered[filtered["Allowed"] == False].copy()  # noqa: E712

    top_offender = "Unknown"
    top_offender_type = "Unknown"
    top_offender_cnt = 0
    top_offender_hostname = ""
    if not threat_metric_base.empty:
        mac_norm = threat_metric_base["mac"].astype(str).str.strip().str.lower().replace({"nan": "", "none": "", "-": ""})
        ip_norm = threat_metric_base["id.orig_h"].astype(str).str.strip().replace({"nan": "", "None": "", "none": "", "-": ""})
        offender_id = mac_norm.where(mac_norm != "", ip_norm)
        offender_type = pd.Series("Unknown", index=threat_metric_base.index, dtype="object")
        offender_type.loc[mac_norm != ""] = "MAC"
        offender_type.loc[(mac_norm == "") & (ip_norm != "")] = "IP"
        offender_src = pd.DataFrame({"__offender_id": offender_id, "__offender_type": offender_type})
        offender_src = offender_src[offender_src["__offender_id"] != ""]
        if not offender_src.empty:
            top_off = (
                offender_src.groupby(["__offender_id", "__offender_type"], dropna=False)
                .size()
                .reset_index(name="events")
                .sort_values("events", ascending=False)
                .head(1)
            )
            top_offender = str(top_off.iloc[0]["__offender_id"]) if not top_off.empty else "Unknown"
            top_offender_type = str(top_off.iloc[0]["__offender_type"]) if not top_off.empty else "Unknown"
            top_offender_cnt = int(top_off.iloc[0]["events"]) if not top_off.empty else 0

            # Try to attach a hostname for operator context (best-effort).
            top_offender_hostname = ""
            try:
                if "host_name" in threat_metric_base.columns:
                    hn_series = pd.Series("", index=threat_metric_base.index, dtype="object")
                    if top_offender_type == "MAC":
                        hn_series = threat_metric_base.loc[mac_norm == top_offender, "host_name"]
                    elif top_offender_type == "IP":
                        hn_series = threat_metric_base.loc[ip_norm == top_offender, "host_name"]
                    hn = hn_series.astype(str).str.strip()
                    hn = hn[~hn.str.lower().isin(["", "unknown", "nan", "none", "-", "(empty)"])]
                    if not hn.empty:
                        top_offender_hostname = str(hn.value_counts().index[0])
            except Exception:
                top_offender_hostname = ""

    metric_mac = filtered["mac"].astype(str).str.strip().str.lower().replace({"nan": "", "none": "", "-": ""})
    metric_ip = filtered["id.orig_h"].astype(str).str.strip().replace({"nan": "", "None": "", "none": "", "-": ""})
    metric_device = metric_mac.where(metric_mac != "", "ip:" + metric_ip)
    metric_device = metric_device.where(metric_device != "ip:", None)
    uniq_dev = int(metric_device.dropna().nunique())

    m1.metric("Selected Events", f"{len(filtered):,}", delta=f"Unapproved: {unapproved:,}", delta_color="inverse")
    m2.metric("Total Volume", f"{total_mb:.2f} MB")
    m3.metric("Automation / SDK", f"{autom:,}")
    top_offender_delta = f"{top_offender_cnt:,} events"
    if top_offender_hostname:
        top_offender_delta = f"{top_offender_delta} · {top_offender_hostname}"
    m4.metric(
        f"Top Offender ({top_offender_type})",
        top_offender,
        delta=top_offender_delta,
        delta_color="inverse",
    )
    st.markdown(
        f"<div class='shadow-filter-hint shadow-scope-hint'>Unique devices in scope: <strong>{uniq_dev:,}</strong></div>",
        unsafe_allow_html=True,
    )

    # Main content
    tab_overview = st.container()

    # -------------------------------------------------------------------------
    # Overview
    # -------------------------------------------------------------------------
    with tab_overview:
        ov = filtered_incidents.copy()
        st.markdown("#### Timeline (Incident Confidence + Policy Signals)")

        if len(ov) >= 3500:
            bucket = "1h"
        elif len(ov) >= 1200:
            bucket = "30min"
        else:
            bucket = "15min"

        for col_name, default_value in [
            ("incident_id", ""),
            ("first_ts", pd.NaT),
            ("confidence", ""),
            ("confidence_score", 0),
            ("allowed", False),
            ("is_shadow_sharing", False),
        ]:
            if col_name not in ov.columns:
                ov[col_name] = default_value

        ov["first_ts"] = pd.to_datetime(ov["first_ts"], errors="coerce")
        ov["confidence_score"] = pd.to_numeric(ov["confidence_score"], errors="coerce").fillna(0)
        ov["allowed"] = ov["allowed"].fillna(False).astype(bool)
        ov["is_shadow_sharing"] = ov["is_shadow_sharing"].fillna(False).astype(bool)
        ov["confidence"] = ov["confidence"].astype(str).str.upper()
        ov["confidence"] = ov["confidence"].where(ov["confidence"].isin(["HIGH", "PROBABLE", "WEAK"]), "WEAK")

        trend_src = ov.dropna(subset=["first_ts"]).copy()
        if trend_src.empty:
            st.info("No timestamped incidents are available for trend charts.")
        else:
            trend_src["time_bucket"] = trend_src["first_ts"].dt.floor(bucket)
            risk_timeline = (
                trend_src.groupby(["time_bucket", "confidence"], dropna=False)
                .agg(incidents=("incident_id", "nunique"), avg_score=("confidence_score", "mean"))
                .reset_index()
                .sort_values("time_bucket")
            )
            risk_timeline["confidence"] = risk_timeline["confidence"].astype(str).str.upper()
            risk_timeline["confidence"] = risk_timeline["confidence"].where(
                risk_timeline["confidence"].isin(["HIGH", "PROBABLE", "WEAK"]),
                "WEAK",
            )
            risk_timeline["confidence"] = pd.Categorical(
                risk_timeline["confidence"],
                categories=["HIGH", "PROBABLE", "WEAK"],
                ordered=True,
            )

            tl_left, tl_right = st.columns([1.55, 1.0])
            with tl_left:
                fig_timeline = px.area(
                    risk_timeline,
                    x="time_bucket",
                    y="incidents",
                    color="confidence",
                    color_discrete_map=CONFIDENCE_COLORS,
                    category_orders={"confidence": ["HIGH", "PROBABLE", "WEAK"]},
                    template=get_plotly_template(),
                    hover_data={"incidents": True, "avg_score": ":.1f"},
                )
                style_plotly_figure(fig_timeline, height=395)
                fig_timeline.update_layout(legend_title_text="Confidence")
                fig_timeline.update_xaxes(title=f"Time ({bucket} buckets)")
                fig_timeline.update_yaxes(title="Incidents")
                st.plotly_chart(fig_timeline, width="stretch")

            with tl_right:
                signal_line = (
                    trend_src.groupby("time_bucket", dropna=False)
                    .agg(
                        shadow_hits=("is_shadow_sharing", lambda s: int(pd.Series(s).fillna(False).astype(bool).sum())),
                        high_confidence=("confidence", lambda s: int(pd.Series(s).astype(str).str.upper().eq("HIGH").sum())),
                        unapproved_incidents=("allowed", lambda s: int((~pd.Series(s).fillna(False).astype(bool)).sum())),
                    )
                    .reset_index()
                    .sort_values("time_bucket")
                    .rename(
                        columns={
                            "shadow_hits": "Shadow Sharing Hits",
                            "high_confidence": "High Confidence",
                            "unapproved_incidents": "Unapproved Incidents",
                        }
                    )
                )
                fig_signal = px.line(
                    signal_line,
                    x="time_bucket",
                    y=["Shadow Sharing Hits", "High Confidence", "Unapproved Incidents"],
                    template=get_plotly_template(),
                    markers=True,
                    color_discrete_sequence=["#ef4444", "#f59e0b", "#38bdf8"],
                )
                style_plotly_figure(fig_signal, height=395)
                fig_signal.update_traces(line=dict(width=2.4))
                fig_signal.update_layout(legend_title_text=None)
                fig_signal.update_xaxes(title="Time")
                fig_signal.update_yaxes(title="Incident Count")
                st.plotly_chart(fig_signal, width="stretch")

    # -------------------------------------------------------------------------
    # Device Forensics (incident rows under Overview)
    # -------------------------------------------------------------------------
    with tab_overview:
        st.markdown("#### Shadow Sharing Incidents")
        st.caption(
            "Table rows are grouped by unique MAC + Destination for the selected 24-hour date scope. "
            "Click any MAC to open all matching rows for that MAC."
        )

        if isinstance(dev_grid_table_cached, pd.DataFrame):
            dev_grid = dev_grid_table_cached.copy()
        else:
            table_incidents = _aggregate_incidents_for_daily_mac_destination_table(filtered_incidents, str(selected_date))
            dev_grid = _build_incident_grid_frame(table_incidents)
        if isinstance(dev_grid_raw_cached, pd.DataFrame):
            dev_grid_raw = dev_grid_raw_cached.copy()
        else:
            dev_grid_raw = _build_incident_grid_frame(filtered_incidents)
        if dev_grid_raw.empty and not dev_grid.empty:
            dev_grid_raw = dev_grid.copy()
        if dev_grid.empty:
            st.info("No incident rows are available with the current filters.")
            st.session_state["shadow_sharing_last_selected_mac"] = None
        else:
            if "Hostname" not in dev_grid.columns:
                table_incidents = _aggregate_incidents_for_daily_mac_destination_table(filtered_incidents, str(selected_date))
                dev_grid = _build_incident_grid_frame(table_incidents, include_hostname=True)
            if "Hostname" not in dev_grid_raw.columns:
                dev_grid_raw = _build_incident_grid_frame(filtered_incidents, include_hostname=True)
            if AUTO_UNIQUE_ID_COL in dev_grid.columns:
                dev_grid = dev_grid.drop(columns=[AUTO_UNIQUE_ID_COL], errors="ignore")
            if "#" not in dev_grid.columns:
                dev_grid = dev_grid.reset_index(drop=True)
                dev_grid.insert(0, "#", range(1, len(dev_grid) + 1))
            _render_incident_table_insights(dev_grid_raw)
            gb_dev = GridOptionsBuilder.from_dataframe(dev_grid)
            _configure_incident_grid_columns(
                gb_dev,
                clickable_mac=True,
                editable_allowed_domain=True,
                include_hostname=True,
            )

            dev_response = render_shadow_aggrid(
                dev_grid,
                gb_dev,
                key=f"shadow_sharing_device_grid_{selected_scope_key}_{int(st.session_state.get('shadow_sharing_grid_nonce', 0))}",
                height=430,
                update_mode=(
                    GridUpdateMode.SELECTION_CHANGED
                    | GridUpdateMode.VALUE_CHANGED
                    | GridUpdateMode.MODEL_CHANGED
                ),
                wrap_shell=False,
                force_scrollbars=True,
                hide_scrollbar_buttons=True,
            )

            if _apply_allowed_domain_checkbox_changes(dev_grid, dev_response):
                return

            selected_mac = _extract_selected_mac(dev_response.get("selected_rows", None))
            if selected_mac:
                prev = st.session_state.get("shadow_sharing_last_selected_mac")
                if selected_mac != prev:
                    st.session_state["shadow_sharing_last_selected_mac"] = selected_mac
                    st.session_state["shadow_sharing_dialog_mac"] = selected_mac
                    st.session_state["shadow_sharing_dialog_open"] = True
                    st.session_state["shadow_sharing_dialog_origin"] = "grid"
                    st.rerun()
            else:
                st.session_state["shadow_sharing_last_selected_mac"] = None
                st.session_state.pop("shadow_sharing_dialog_incidents_df", None)

            has_mac_rows = dev_grid["mac"].astype(str).str.strip().replace({"": None, "nan": None, "none": None}).dropna().nunique() > 0
            if not has_mac_rows:
                st.info("MAC values are not available in this scope, so MAC drilldown dialog is disabled.")

            export_dev = pd.DataFrame(dev_response.get("data", [])) if isinstance(dev_response, dict) else pd.DataFrame()
            if export_dev.empty:
                export_dev = dev_grid.copy()
            st.download_button(
                "Download CSV (current incident table)",
                data=_table_csv_bytes(export_dev),
                file_name=f"shadow_sharing_incidents_{selected_date}.csv",
                mime="text/csv",
                key=f"shadow_sharing_incidents_csv_{selected_scope_key}",
            )

    with st.expander("Confidence score computation", expanded=False):
        st.markdown(_confidence_score_explainer_text())

    if st.session_state.get("shadow_sharing_allow_dialog_open") and st.session_state.get("shadow_sharing_allow_candidate"):
        show_shadow_sharing_allow_dialog()
    elif st.session_state.get("shadow_sharing_dialog_open") and st.session_state.get("shadow_sharing_dialog_mac") and origin in ("grid", "dialog"):
        show_shadow_sharing_device_dialog(
            filtered,
            filtered_incidents,
            selected_scope_key=selected_scope_key,
            selected_scope_label=str(selected_date),
        )


# Backward compatibility if your app imports render_shadow_uploads
def render_shadow_uploads(parquet_root: Path):
    return render_shadow_sharing(parquet_root)
