

# ----------------------------------------------------------------------------
# Hard filters for destination display
# ----------------------------------------------------------------------------
INVALID_DEST_STRINGS = {"", "unknown", "nan", "none", "(empty)", "*"}
INVALID_DEST_SET = set(INVALID_DEST_STRINGS)
# ui/pages/shadow_sharings.py
import re
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd
import plotly.express as px
import streamlit as st
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode

try:
    from .shadow_sharings_backend import (
        _detect_exfil_signal_row,
        _add_domain_to_whitelist,
        _remove_domain_from_whitelist,
        get_available_dates,
        load_shadow_sharing_data,
        load_shadow_sharing_incidents_data,
        build_shadow_sharing_incidents,
        refresh_shadow_sharing_runtime_state,
    )
except ImportError:
    from shadow_sharings_backend import (  # type: ignore
        _detect_exfil_signal_row,
        _add_domain_to_whitelist,
        _remove_domain_from_whitelist,
        get_available_dates,
        load_shadow_sharing_data,
        load_shadow_sharing_incidents_data,
        build_shadow_sharing_incidents,
        refresh_shadow_sharing_runtime_state,
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
    grid_options = gb.build()
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
    grid_options["suppressColumnVirtualisation"] = True
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
    grid_options["onFirstDataRendered"] = autofit_js
    grid_options["onGridSizeChanged"] = autofit_js

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
    grid_response = AgGrid(
        df,
        gridOptions=grid_options,
        update_mode=update_mode,
        data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
        height=height,
        theme=ag_theme,
        custom_css=table_css,
        allow_unsafe_jscode=True,
        enable_enterprise_modules=True,
        fit_columns_on_grid_load=False,
        reload_data=True,
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
            min-height: 125px;
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
    st.session_state.pop("shadow_sharing_dialog_base_df", None)
    st.session_state.pop("shadow_sharing_dialog_base_key", None)
    st.session_state.pop("shadow_sharing_dialog_incidents_df", None)
    st.session_state["shadow_sharing_grid_nonce"] = int(st.session_state.get("shadow_sharing_grid_nonce", 0)) + 1


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


def _build_incident_grid_frame(incidents_df: pd.DataFrame) -> pd.DataFrame:
    if incidents_df is None or incidents_df.empty:
        return pd.DataFrame()

    inc_src = incidents_df.copy()
    for col_name, default_value in [
        ("incident_id", ""),
        ("first_ts", pd.NaT),
        ("last_ts", pd.NaT),
        ("mac", ""),
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
        ("category", ""),
        ("confidence", ""),
        ("confidence_score", 0),
        ("confidence_reasons", ""),
    ]:
        if col_name not in inc_src.columns:
            inc_src[col_name] = default_value

    inc_src["first_ts"] = pd.to_datetime(inc_src["first_ts"], errors="coerce")
    inc_src["last_ts"] = pd.to_datetime(inc_src["last_ts"], errors="coerce")
    inc_src["mac"] = inc_src["mac"].astype(str).str.strip().str.lower().replace({"nan": "", "none": "", "-": ""})
    inc_src["orig_ip"] = inc_src["orig_ip"].astype(str).str.strip().replace({"nan": "", "None": "", "none": "", "-": ""})
    inc_src["Destination"] = inc_src["destination"].astype(str).str.strip().replace({"nan": "", "None": "", "none": "", "*": ""})
    inc_src["Domain"] = inc_src["domain"].astype(str).str.strip().str.lower().replace({"nan": "", "None": "", "none": ""})
    inc_src.loc[inc_src["Domain"] == "", "Domain"] = inc_src.loc[inc_src["Domain"] == "", "Destination"].astype(str).str.lower()
    inc_src["Source"] = inc_src["source_types"].astype(str).str.strip().str.lower().replace({"nan": "", "None": "", "none": ""})
    inc_src.loc[inc_src["Source"] == "", "Source"] = "conn"
    inc_src["Allowed_Domain"] = inc_src["allowed"].apply(_coerce_bool_value)
    inc_src["Service"] = inc_src["sig_service"].astype(str).str.strip()
    inc_src.loc[inc_src["Service"].isin(["", "nan", "None", "none"]), "Service"] = "No signature match"
    inc_src["Action"] = inc_src["action"].astype(str).str.strip().replace({"nan": "", "None": "", "none": ""})
    inc_src["Action_Basis"] = inc_src["action_basis"].astype(str).str.strip().replace({"nan": "", "None": "", "none": ""})
    inc_src["Action_Desc"] = inc_src["Action"]
    has_action_basis = inc_src["Action_Basis"] != ""
    inc_src.loc[has_action_basis, "Action_Desc"] = inc_src.loc[has_action_basis, "Action"] + " (" + inc_src.loc[has_action_basis, "Action_Basis"] + ")"
    inc_src["Category"] = inc_src["category"].astype(str).str.strip().replace({"nan": "", "None": "", "none": ""})
    inc_src.loc[inc_src["Category"] == "", "Category"] = "file_sharing"
    inc_src["allow_basis"] = inc_src["allow_basis"].astype(str).str.strip().replace({"nan": "", "None": "", "none": ""})
    inc_src.loc[(inc_src["allow_basis"] == "") & (inc_src["Allowed_Domain"] == False), "allow_basis"] = "no match"  # noqa: E712
    inc_src["Confidence"] = inc_src["confidence"].astype(str).str.upper()
    inc_src["Confidence"] = inc_src["Confidence"].where(inc_src["Confidence"].isin(["HIGH", "PROBABLE", "WEAK"]), "WEAK")
    inc_src["Score"] = pd.to_numeric(inc_src["confidence_score"], errors="coerce").fillna(0).astype(int)
    inc_src["Outbound_MB"] = (pd.to_numeric(inc_src["bytes_out_total"], errors="coerce").fillna(0) / 1024 / 1024).round(2)
    inc_src["Inbound_MB"] = (pd.to_numeric(inc_src["bytes_in_total"], errors="coerce").fillna(0) / 1024 / 1024).round(2)
    inc_src["Ratio"] = pd.to_numeric(inc_src["out_in_ratio_total"], errors="coerce").fillna(0).round(2)
    inc_src["Conns"] = pd.to_numeric(inc_src["conn_count"], errors="coerce").fillna(0).astype(int)
    inc_src["Duration_sec"] = pd.to_numeric(inc_src["total_duration"], errors="coerce").fillna(0).round(1)
    inc_src["Reasons"] = inc_src["confidence_reasons"].astype(str)

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
    dev_grid["First_Seen"] = dev_grid["first_ts"].dt.strftime("%m-%d %H:%M").fillna("")
    dev_grid["Last_Seen"] = dev_grid["last_ts"].dt.strftime("%m-%d %H:%M").fillna("")

    show_cols = [
        "First_Seen",
        "Last_Seen",
        "mac",
        "orig_ip",
        "Destination",
        "Domain",
        "Source",
        "Service",
        "Allowed_Domain",
        "allow_basis",
        "Outbound_MB",
        "Inbound_MB",
        "Ratio",
        "Conns",
        "Duration_sec",
        "Category",
        "Action_Desc",
        "Confidence",
        "Score",
        "Reasons",
        "incident_id",
    ]
    show_cols = [c for c in show_cols if c in dev_grid.columns]
    dev_grid = dev_grid[show_cols].copy()
    if "incident_id" in dev_grid.columns:
        dev_grid = dev_grid.drop_duplicates(subset=["incident_id"], keep="last").reset_index(drop=True)
    else:
        dev_grid = dev_grid.drop_duplicates().reset_index(drop=True)
    dev_grid.insert(0, "#", range(1, len(dev_grid) + 1))
    return dev_grid


def _configure_incident_grid_columns(
    gb: GridOptionsBuilder,
    *,
    clickable_mac: bool,
    editable_allowed_domain: bool,
) -> None:
    gb.configure_default_column(filter=True, sortable=True, resizable=True, flex=1)
    if clickable_mac:
        gb.configure_selection(selection_mode="single", use_checkbox=False)
    gb.configure_column("#", header_name="#", width=62, pinned="left", suppressMovable=True, resizable=False)

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

    gb.configure_column("First_Seen", width=115)
    gb.configure_column("Last_Seen", width=115)
    gb.configure_column("orig_ip", header_name="Orig IP", minWidth=140)
    gb.configure_column("Destination", minWidth=220)
    gb.configure_column("Domain", minWidth=210)
    gb.configure_column("Source", width=125)
    gb.configure_column("Service", width=180)

    allowed_kwargs = {}
    if editable_allowed_domain:
        allowed_kwargs = {
            "editable": True,
            "cellEditor": "agCheckboxCellEditor",
            "cellRenderer": "agCheckboxCellRenderer",
            "singleClickEdit": True,
        }
    gb.configure_column(
        "Allowed_Domain",
        header_name="Allowed (Domain)",
        width=145,
        cellStyle=_allowed_cellstyle(),
        **allowed_kwargs,
    )

    gb.configure_column("allow_basis", header_name="Allow Basis", minWidth=190)
    gb.configure_column("Outbound_MB", header_name="Out MB", width=104)
    gb.configure_column("Inbound_MB", header_name="In MB", width=98)
    gb.configure_column("Ratio", width=90)
    gb.configure_column("Conns", width=86)
    gb.configure_column("Duration_sec", header_name="Duration(sec)", width=125)
    gb.configure_column("Category", width=140)
    gb.configure_column("Action_Desc", header_name="Action (Description/Reason)", minWidth=260)
    gb.configure_column("Confidence", width=110, cellStyle=_confidence_cellstyle())
    gb.configure_column("Score", width=82)
    gb.configure_column("Reasons", minWidth=320)
    gb.configure_column("incident_id", hide=True)


def _resolve_whitelist_target(row: pd.Series, *, remove: bool) -> str:
    if remove:
        basis = str(row.get("allow_basis", "") or "").strip()
        if basis and basis.lower() not in {"no match", "n/a (unknown destination)"}:
            return basis
    for col in ["Domain", "Destination"]:
        val = str(row.get(col, "") or "").strip()
        if val and val.lower() not in INVALID_DEST_SET:
            return val
    return ""


def _apply_allowed_domain_checkbox_changes(grid_before: pd.DataFrame, grid_response: dict) -> bool:
    if grid_before is None or grid_before.empty or not isinstance(grid_response, dict):
        return False

    data_after = grid_response.get("data", None)
    if data_after is None:
        return False

    after_df = pd.DataFrame(data_after)
    if after_df.empty:
        return False
    if "incident_id" not in grid_before.columns or "incident_id" not in after_df.columns:
        return False
    if "Allowed_Domain" not in grid_before.columns or "Allowed_Domain" not in after_df.columns:
        return False

    before = grid_before[["incident_id", "Allowed_Domain"]].drop_duplicates(subset=["incident_id"], keep="last").copy()
    before["Allowed_Domain"] = before["Allowed_Domain"].apply(_coerce_bool_value)
    after = after_df[["incident_id", "Allowed_Domain"]].drop_duplicates(subset=["incident_id"], keep="last").copy()
    after["Allowed_Domain"] = after["Allowed_Domain"].apply(_coerce_bool_value)

    merged = before.merge(after, on="incident_id", how="inner", suffixes=("_old", "_new"))
    changed = merged[merged["Allowed_Domain_old"] != merged["Allowed_Domain_new"]]
    if changed.empty:
        return False

    rows_after = after_df.drop_duplicates(subset=["incident_id"], keep="last").set_index("incident_id")
    success_msgs: List[str] = []
    error_msgs: List[str] = []
    seen_ops = set()

    for _, ch in changed.iterrows():
        incident_id = ch.get("incident_id")
        if incident_id not in rows_after.index:
            continue
        row = rows_after.loc[incident_id]
        if isinstance(row, pd.DataFrame):
            row = row.iloc[0]

        new_allowed = bool(ch.get("Allowed_Domain_new"))
        target = _resolve_whitelist_target(row, remove=not new_allowed)
        op_key = (new_allowed, str(target).strip().lower())
        if op_key in seen_ops:
            continue
        seen_ops.add(op_key)

        if not str(target).strip():
            error_msgs.append(f"{incident_id}: missing domain target")
            continue

        if new_allowed:
            ok, msg = _add_domain_to_whitelist(str(target))
        else:
            ok, msg = _remove_domain_from_whitelist(str(target))

        if ok:
            success_msgs.append(msg)
        else:
            error_msgs.append(msg)

    if not success_msgs and not error_msgs:
        return False

    st.session_state["shadow_sharing_whitelist_feedback"] = {
        "ok": success_msgs,
        "error": error_msgs,
    }

    if success_msgs:
        try:
            refresh_shadow_sharing_runtime_state()
        except Exception:
            pass

    st.session_state["shadow_sharing_grid_nonce"] = int(st.session_state.get("shadow_sharing_grid_nonce", 0)) + 1
    st.rerun()
    return True


@st.dialog("Device Forensics Details", width="large")
def show_shadow_sharing_device_dialog(
    filtered: pd.DataFrame,
    filtered_incidents: pd.DataFrame,
    *,
    selected_scope_key: str,
):
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

    top = st.columns([1.0, 5.0])
    with top[0]:
        if st.button("Close", use_container_width=True, type="primary", key=f"shadow_sharing_dlg_close_{selected_scope_key}_{mac_key}"):
            _close_shadow_sharing_dialog()
            st.rerun()
    with top[1]:
        scope_label = f"MAC <code>{target_mac}</code>"
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
        "Search (time, destination, domain, source, action, basis)",
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
            "category",
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

    if scoped_incidents.empty:
        st.info("No incident rows match your dialog search.")
        return

    grid_rows = _build_incident_grid_frame(scoped_incidents)
    if grid_rows.empty:
        st.info("No incident rows above 0 MB are available for this MAC.")
        return

    first_seen = pd.to_datetime(scoped_incidents.get("first_ts", pd.Series([], dtype="datetime64[ns]")), errors="coerce").min()
    last_seen = pd.to_datetime(scoped_incidents.get("last_ts", pd.Series([], dtype="datetime64[ns]")), errors="coerce").max()
    unique_dest = int(grid_rows["Destination"].replace({"": None, "Unknown": None, "unknown": None}).dropna().nunique())
    total_outbound_mb = float(pd.to_numeric(grid_rows["Outbound_MB"], errors="coerce").fillna(0).sum())
    unapproved = int((grid_rows["Allowed_Domain"] == False).sum())  # noqa: E712
    high_conf = int((grid_rows["Confidence"] == "HIGH").sum())

    st.markdown(
        f"<div class='shadow-filter-hint shadow-scope-hint'>Loaded <strong>{len(grid_rows):,}</strong> incident rows for this device.</div>",
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
    dm1.metric("Scoped Incidents", f"{len(grid_rows):,}")
    dm2.metric("Unapproved", unapproved, delta="Investigate" if unapproved > 0 else "Clear", delta_color="inverse")
    dm3.metric("Outbound Volume", f"{total_outbound_mb:.2f} MB")
    dm4.metric("High Confidence", f"{high_conf:,}")

    with st.container():
        st.markdown("#### Shadow Sharing Incidents (MAC Scope)")
        gb_rows = GridOptionsBuilder.from_dataframe(grid_rows)
        _configure_incident_grid_columns(
            gb_rows,
            clickable_mac=False,
            editable_allowed_domain=True,
        )
        row_response = render_shadow_aggrid(
            grid_rows,
            gb_rows,
            key=f"shadow_sharing_rows_grid_{selected_scope_key}_{mac_key}",
            height=450,
            update_mode=GridUpdateMode.VALUE_CHANGED,
            wrap_shell=False,
            force_scrollbars=True,
            hide_scrollbar_buttons=True,
        )
        _apply_allowed_domain_checkbox_changes(grid_rows, row_response)


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

    def _on_scope_change():
        _close_shadow_sharing_dialog()

    selected_date = st.selectbox(
        "Dataset Scope",
        available_dates,
        index=0,
        key="shadow_sharing_date",
        on_change=_on_scope_change,
    )
    selected_scope_key = re.sub(r"[^A-Za-z0-9_]+", "_", str(selected_date))
    st.session_state.setdefault("shadow_sharing_dialog_open", False)
    st.session_state.setdefault("shadow_sharing_dialog_mac", None)
    st.session_state.setdefault("shadow_sharing_last_selected_mac", None)
    st.session_state.setdefault("shadow_sharing_dialog_base_df", None)
    st.session_state.setdefault("shadow_sharing_dialog_base_key", None)
    st.session_state.setdefault("shadow_sharing_dialog_incidents_df", None)
    st.session_state.setdefault("shadow_sharing_grid_nonce", 0)

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
    target_dates = [selected_date] if selected_date else []
    df = load_shadow_sharing_data(parquet_root, target_dates)

    if df.empty:
        st.info("No data detected for the selected timeframe.")
        return

    # -------------------------------------------------------------------------
    # Incident Rollup (Algorithms #2/#4/#5/#6)
    # -------------------------------------------------------------------------
    incidents = load_shadow_sharing_incidents_data(parquet_root, target_dates)

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

    def _token_options(series: pd.Series) -> List[str]:
        vals = (
            series.astype(str)
            .str.strip()
            .replace({"": pd.NA, "nan": pd.NA, "None": pd.NA})
            .dropna()
            .unique()
            .tolist()
        )
        return sorted(str(v) for v in vals)

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

    action_options = _token_options(df["Action"]) if "Action" in df.columns else []
    category_options = _token_options(df["Category"]) if "Category" in df.columns else []
    source_masks = _build_real_source_masks(df)
    ordered_sources = ["conn", "http", "ssl", "dns", "files"]
    source_options = [s for s in ordered_sources if bool(source_masks[s].any())]
    if not source_options:
        source_options = ordered_sources

    search_q = st.text_input("Search (MAC, Host, IP, Destination, Basis)", placeholder="e.g., 192.168.1.14",)

    c1, c2, c3 = st.columns([1.8, 1.4, 1.2])
    with c1:
        action_filter = st.multiselect(
            "Action",
            action_options,
            default=[],
            placeholder="All actions",
        )
    with c2:
        category_filter = st.multiselect(
            "Category",
            category_options,
            default=[],
            placeholder="All categories",
        )
    with c3:
        min_bytes_mb = st.number_input("Min Bytes (MB)", min_value=0, value=0, step=10)

    c4, c5 = st.columns([1.55, 2.0])
    with c4:
        selected_risk_levels = st.multiselect("Risk Level", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with c5:
        selected_sources = st.multiselect("Source Logs", source_options, default=source_options)

    # Apply filters
    filtered = df.copy()

    if selected_sources:
        source_keep = pd.Series(False, index=filtered.index)
        filtered_masks = _build_real_source_masks(filtered)
        for src_name in selected_sources:
            mask = filtered_masks.get(str(src_name).strip().lower())
            if mask is not None:
                source_keep = source_keep | mask
        filtered = filtered[source_keep]

    if selected_risk_levels:
        filtered = filtered[filtered["Severity"].isin(selected_risk_levels)]

    if min_bytes_mb > 0:
        filtered = filtered[filtered["bytes"] >= float(min_bytes_mb) * 1024 * 1024]

    if action_filter:
        filtered = filtered[filtered["Action"].isin(action_filter)]

    if category_filter:
        filtered = filtered[filtered["Category"].isin(category_filter)]

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
        dedupe_cols = [c for c in ["ts", "id.orig_h", "destination", "bytes", "Action", "Category"] if c in filtered.columns]
        if dedupe_cols:
            filtered = filtered.drop_duplicates(subset=dedupe_cols, keep="last")
        else:
            filtered = filtered.drop_duplicates()

    if filtered.empty:
        st.warning("No rows above 0 MB match your filters.")
        return

    filtered_incidents = build_shadow_sharing_incidents(filtered)
    if not filtered_incidents.empty:
        if "incident_id" in filtered_incidents.columns:
            filtered_incidents = filtered_incidents.drop_duplicates(subset=["incident_id"], keep="last")
        else:
            filtered_incidents = filtered_incidents.drop_duplicates()
        out_mb = (pd.to_numeric(filtered_incidents.get("bytes_out_total", 0), errors="coerce").fillna(0) / 1024 / 1024)
        filtered_incidents = filtered_incidents[out_mb > 0].copy()

    # Metrics
    st.divider()
    m1, m2, m3, m4 = st.columns(4)

    total_b = float(filtered.loc[filtered["bytes"] > 0, "bytes"].sum())
    total_mb = total_b / 1024 / 1024
    unapproved = int((filtered["Allowed"] == False).sum())  # noqa: E712
    autom = int((filtered["Client_Type"] == "Automation / SDK").sum())

    threat_metric_base = filtered.copy()
    if "Exfil_Indicator" not in threat_metric_base.columns:
        ex = threat_metric_base.apply(_detect_exfil_signal_row, axis=1)
        threat_metric_base["Exfil_Indicator"] = ex.apply(lambda x: bool(x[0]))
    threat_metric_base = threat_metric_base[
        (threat_metric_base["Allowed"] == False) & (threat_metric_base["Exfil_Indicator"] == True)  # noqa: E712
    ].copy()

    top_offender = "Unknown"
    top_offender_type = "Unknown"
    top_offender_cnt = 0
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

    metric_mac = filtered["mac"].astype(str).str.strip().str.lower().replace({"nan": "", "none": "", "-": ""})
    metric_ip = filtered["id.orig_h"].astype(str).str.strip().replace({"nan": "", "None": "", "none": "", "-": ""})
    metric_device = metric_mac.where(metric_mac != "", "ip:" + metric_ip)
    metric_device = metric_device.where(metric_device != "ip:", None)
    uniq_dev = int(metric_device.dropna().nunique())

    m1.metric("Selected Events", f"{len(filtered):,}", delta=f"Unapproved: {unapproved:,}", delta_color="inverse")
    m2.metric("Total Volume", f"{total_mb:.2f} MB")
    m3.metric("Automation / SDK", f"{autom:,}")
    m4.metric(
        f"Top Offender ({top_offender_type})",
        top_offender,
        delta=f"{top_offender_cnt:,} events",
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
                st.plotly_chart(fig_timeline, use_container_width=True)

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
                st.plotly_chart(fig_signal, use_container_width=True)

    # -------------------------------------------------------------------------
    # Device Forensics (incident rows under Overview)
    # -------------------------------------------------------------------------
    with tab_overview:
        st.markdown("#### Shadow Sharing Incidents")
        st.caption("Rows mirror Shadow Sharing Incidents in this filtered scope. Click any MAC to open all matching rows for that MAC.")

        dev_grid = _build_incident_grid_frame(filtered_incidents)
        if dev_grid.empty:
            st.info("No incident rows are available with the current filters.")
            st.session_state["shadow_sharing_last_selected_mac"] = None
        else:
            gb_dev = GridOptionsBuilder.from_dataframe(dev_grid)
            _configure_incident_grid_columns(
                gb_dev,
                clickable_mac=True,
                editable_allowed_domain=True,
            )

            dev_response = render_shadow_aggrid(
                dev_grid,
                gb_dev,
                key=f"shadow_sharing_device_grid_{selected_scope_key}_{int(st.session_state.get('shadow_sharing_grid_nonce', 0))}",
                height=430,
                update_mode=(GridUpdateMode.SELECTION_CHANGED | GridUpdateMode.VALUE_CHANGED),
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
                    st.rerun()
            else:
                st.session_state["shadow_sharing_last_selected_mac"] = None
                st.session_state.pop("shadow_sharing_dialog_incidents_df", None)

            has_mac_rows = dev_grid["mac"].astype(str).str.strip().replace({"": None, "nan": None, "none": None}).dropna().nunique() > 0
            if not has_mac_rows:
                st.info("MAC values are not available in this scope, so MAC drilldown dialog is disabled.")

    with st.expander("Confidence score computation", expanded=False):
        st.markdown(
            "Incidents are 5-minute rollups grouped by `device + domain + time window`, then scored from 0-100.\n"
            "- `+40` signature match (`Service`) when destination matches configured sharing signatures.\n"
            "- `+30` when destination is not allowlisted (`Allowed (Domain)=False`).\n"
            "- `+30` when upload volume is high (`>=10MB`) and out/in ratio is high (`>=5`).\n"
            "- `+15` for chunking behavior (`Conns >= 5` in the same window).\n"
            "- `+40` for share-link evidence (`http_any_share=True`, typically URI contains share/shared-link patterns).\n"
            "- `+20` for repeat behavior (seen across `>=2` days while still unapproved).\n"
            "- Confidence labels: `HIGH >= 80`, `PROBABLE >= 50`, `WEAK < 50`.\n"
            "- `Conns` = unique Zeek connection IDs (`uid`) in that incident window.\n"
            "- `Domain` is derived from destination (`dest_domain`) with fallback to destination text.\n"
            "- `Allowed (Domain)` is a boundary-safe suffix match against `whitelist_domains.yaml` (`example.com` matches `a.b.example.com`, not `example.com.evil.tld`).\n"
            "- `Allow Basis = no match` means no allowlist domain matched; improve it by adding the correct root domain (or wildcard entry) to the allowlist.\n"
            "- Row-level `Exfil` is from `_detect_exfil_signal_row` and needs explicit suspicious evidence (upload indicators, large outbound with ratio, DNS exfil patterns, or unapproved risky transfer signals)."
        )

    if st.session_state.get("shadow_sharing_dialog_open") and st.session_state.get("shadow_sharing_dialog_mac"):
        show_shadow_sharing_device_dialog(filtered, filtered_incidents, selected_scope_key=selected_scope_key)


# Backward compatibility if your app imports render_shadow_uploads
def render_shadow_uploads(parquet_root: Path):
    return render_shadow_sharing(parquet_root)
