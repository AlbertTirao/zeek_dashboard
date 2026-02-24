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
        _is_ip_literal,
        _severity_label,
        get_available_dates,
        load_shadow_sharing_data,
    )
except ImportError:
    from shadow_sharings_backend import (  # type: ignore
        _detect_exfil_signal_row,
        _is_ip_literal,
        _severity_label,
        get_available_dates,
        load_shadow_sharing_data,
    )

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#f59e0b",
    "LOW": "#22c55e",
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


def _link_cell_renderer() -> JsCode:
    return JsCode(
        """
        function(params) {
            if (!params.value) return '';
            return `<a href="${params.value}" target="_blank" style="color:#8AB4F8;text-decoration:underline;">Open</a>`;
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
            ".ag-header-cell-label": {"white-space": "nowrap"},
            ".ag-header-cell-label .ag-header-cell-text": {
                "white-space": "nowrap",
                "overflow": "hidden",
                "text-overflow": "ellipsis",
            },
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


@st.dialog("Device Forensics Details", width="large")
def show_shadow_sharing_device_dialog(
    filtered: pd.DataFrame,
    *,
    selected_scope_key: str,
):
    target_mac = str(st.session_state.get("shadow_sharing_dialog_mac") or "").strip().lower()
    if not target_mac:
        st.info("No MAC selected.")
        return

    mac_key = re.sub(r"[^0-9A-Za-z_]+", "_", target_mac).strip("_") or "mac"

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

    if "mac" not in filtered.columns:
        st.warning("MAC column is not available in this dataset.")
        return

    dialog_base_key = f"{selected_scope_key}:{target_mac}:{len(filtered)}"
    cached_base = st.session_state.get("shadow_sharing_dialog_base_df")
    cached_base_key = st.session_state.get("shadow_sharing_dialog_base_key")

    if isinstance(cached_base, pd.DataFrame) and cached_base_key == dialog_base_key:
        scoped = cached_base.copy()
    else:
        mac_norm = filtered["mac"].astype(str).str.strip().str.lower()
        scoped = filtered.loc[mac_norm == target_mac].copy()
        scoped["mac"] = target_mac
        st.session_state["shadow_sharing_dialog_base_df"] = scoped.copy()
        st.session_state["shadow_sharing_dialog_base_key"] = dialog_base_key

    if scoped.empty:
        st.warning("No records found for this MAC with current page filters.")
        return

    scoped["mac"] = target_mac

    top = st.columns([1.0, 5.0])
    with top[0]:
        if st.button("Close", use_container_width=True, type="primary", key=f"shadow_sharing_dlg_close_{selected_scope_key}_{mac_key}"):
            _close_shadow_sharing_dialog()
            st.rerun()
    with top[1]:
        st.markdown(
            f"""
            <div class='shadow-dialog-hero'>
                <div class='shadow-dialog-title'>Device Forensics Drilldown</div>
                <div class='shadow-dialog-subtitle'>Scope locked to MAC <code>{target_mac}</code></div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    dialog_search = st.text_input(
        "Search (destination, IP, host, action, URI, risk basis)",
        placeholder="e.g., 192.168.1.14",
        key=f"shadow_sharing_dlg_search_{selected_scope_key}_{mac_key}",
    ).strip()

    scoped_all = scoped.copy()
    if dialog_search:
        q = dialog_search.lower()
        search_cols = [
            "host_name",
            "id.orig_h",
            "destination",
            "log_source",
            "Category",
            "Action",
            "Allow_Basis",
            "Action_Basis",
            "Risk_Basis",
            "method",
            "uri",
            "DNS_Exfil_Reason",
        ]
        mask = pd.Series(False, index=scoped_all.index)
        for col in search_cols:
            if col in scoped_all.columns:
                mask = mask | scoped_all[col].astype(str).str.lower().str.contains(q, na=False)
        scoped_all = scoped_all[mask].copy()

    if scoped_all.empty:
        st.info("No records match your dialog search.")
        return

    scoped_ts = pd.to_datetime(scoped_all["ts"], errors="coerce")
    first_seen = scoped_ts.min()
    last_seen = scoped_ts.max()
    total_mb = float(scoped_all["bytes"].sum()) / 1024 / 1024
    unapproved = int((scoped_all["Allowed"] == False).sum())  # noqa: E712
    unique_dest = int(scoped_all["destination"].replace({"": None, "Unknown": None}).dropna().nunique())

    scoped = scoped_all.sort_values("ts", ascending=False).copy()
    matched_events = int(len(scoped))
    st.markdown(
        f"<div class='shadow-filter-hint shadow-scope-hint'>Loaded <strong>{matched_events:,}</strong> matched events.</div>",
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

    dm1, dm2, dm3 = st.columns(3)
    dm1.metric("Scoped Events", f"{len(scoped):,}")
    dm2.metric("Unapproved", unapproved, delta="Investigate" if unapproved > 0 else "Clear", delta_color="inverse")
    dm3.metric("Total Volume", f"{total_mb:.2f} MB")

    with st.container():
        st.markdown("#### Destination Forensics")

        dest = scoped.groupby("destination", dropna=False).agg(
            Category=("Category", lambda x: x.value_counts().index[0] if len(x) else "Unknown"),
            Allow_Basis=("Allow_Basis", lambda x: next((v for v in x.astype(str) if v), "")),
            Last_Seen=("ts", "max"),
            Events=("ts", "count"),
            Unique_IPs=("id.orig_h", lambda x: x.astype(str).str.strip().replace({"": None, "nan": None, "None": None, "none": None, "-": None}).dropna().nunique()),
            Total_MB=("bytes", lambda x: float(x.sum()) / 1024 / 1024),
            Max_Risk=("Risk_Score", "max"),
            Top_Action=("Action", lambda x: x.value_counts().index[0] if len(x) else ""),
        ).reset_index().sort_values(["Max_Risk", "Total_MB", "Events"], ascending=False)

        dest_grid = dest.copy()
        dest_grid.insert(0, "#", range(1, len(dest_grid) + 1))
        dest_grid["Last_Seen"] = pd.to_datetime(dest_grid["Last_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M").fillna("")
        dest_grid["Total_MB"] = pd.to_numeric(dest_grid["Total_MB"], errors="coerce").fillna(0).round(2)
        dest_grid["Max_Risk"] = pd.to_numeric(dest_grid["Max_Risk"], errors="coerce").fillna(0).astype(int)
        dest_grid["Max_Risk_Level"] = dest_grid["Max_Risk"].apply(_severity_label)
        dest_grid = dest_grid.drop(columns=["Max_Risk"])

        gb_dest = GridOptionsBuilder.from_dataframe(dest_grid)
        gb_dest.configure_default_column(filter=True, sortable=True, resizable=True, flex=1)
        gb_dest.configure_column("#", header_name="#", width=62, pinned="left", suppressMovable=True, resizable=False)
        gb_dest.configure_column("destination", header_name="Destination", minWidth=200)
        gb_dest.configure_column("Category", width=130)
        gb_dest.configure_column("Allow_Basis", header_name="Allow Basis", minWidth=210)
        gb_dest.configure_column("Last_Seen", header_name="Last Seen", width=150)
        gb_dest.configure_column("Events", width=88)
        gb_dest.configure_column("Unique_IPs", header_name="IPs", width=90)
        gb_dest.configure_column("Total_MB", header_name="Total MB", width=116)
        gb_dest.configure_column("Max_Risk_Level", header_name="Risk Level", width=130, cellStyle=_severity_cellstyle())
        gb_dest.configure_column("Top_Action", header_name="Top Action", minWidth=145)

        render_shadow_aggrid(
            dest_grid,
            gb_dest,
            key=f"shadow_sharing_dest_grid_{selected_scope_key}_{mac_key}",
            height=430,
            update_mode=GridUpdateMode.NO_UPDATE,
            wrap_shell=False,
            force_scrollbars=True,
            hide_scrollbar_buttons=True,
        )


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
    st.session_state.setdefault("shadow_sharing_grid_nonce", 0)

    # Date scope
    target_dates = [selected_date] if selected_date else []
    df = load_shadow_sharing_data(parquet_root, target_dates)

    if df.empty:
        st.info("No data detected for the selected timeframe.")
        return

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

    if filtered.empty:
        st.warning("No data matches your filters.")
        return

    # Metrics
    st.divider()
    m1, m2, m3, m4 = st.columns(4)

    total_b = float(filtered["bytes"].sum())
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
        ov = filtered.copy()
        ov["bytes"] = pd.to_numeric(ov["bytes"], errors="coerce").fillna(0)
        ov["Risk_Score"] = pd.to_numeric(ov["Risk_Score"], errors="coerce").fillna(0)
        ov["destination"] = ov["destination"].astype(str).replace({"": "Unknown", "nan": "Unknown", "None": "Unknown"}).fillna("Unknown")
        ov["Action"] = ov["Action"].astype(str).replace({"": "Unknown", "nan": "Unknown", "None": "Unknown"}).fillna("Unknown")
        ov["log_source"] = ov["log_source"].astype(str).replace({"": "Unknown", "nan": "Unknown", "None": "Unknown"}).fillna("Unknown")
        if "Exfil_Indicator" not in ov.columns:
            ov["Exfil_Indicator"] = False
        ov["Exfil_Indicator"] = ov["Exfil_Indicator"].fillna(False).astype(bool)

        st.markdown("#### Timeline (Risk + Exfil Signals)")
        if len(ov) >= 8000:
            bucket = "1h"
        elif len(ov) >= 2500:
            bucket = "30min"
        else:
            bucket = "15min"

        trend_src = ov.dropna(subset=["ts"]).copy()
        if trend_src.empty:
            st.info("No timestamped events are available for trend charts.")
        else:
            trend_src["time_bucket"] = trend_src["ts"].dt.floor(bucket)
            risk_timeline = (
                trend_src.groupby(["time_bucket", "Severity"], dropna=False)
                .agg(events=("ts", "count"), avg_risk=("Risk_Score", "mean"))
                .reset_index()
                .sort_values("time_bucket")
            )
            risk_timeline["Severity"] = risk_timeline["Severity"].astype(str).str.upper()
            risk_timeline["Severity"] = risk_timeline["Severity"].where(
                risk_timeline["Severity"].isin(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
                "LOW",
            )
            risk_timeline["Severity"] = pd.Categorical(
                risk_timeline["Severity"],
                categories=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                ordered=True,
            )

            tl_left, tl_right = st.columns([1.55, 1.0])
            with tl_left:
                fig_timeline = px.area(
                    risk_timeline,
                    x="time_bucket",
                    y="events",
                    color="Severity",
                    color_discrete_map=SEVERITY_COLORS,
                    category_orders={"Severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                    template=get_plotly_template(),
                    hover_data={"events": True, "avg_risk": ":.1f"},
                )
                style_plotly_figure(fig_timeline, height=395)
                fig_timeline.update_layout(legend_title_text="Risk Level")
                fig_timeline.update_xaxes(title=f"Time ({bucket} buckets)")
                fig_timeline.update_yaxes(title="Events")
                st.plotly_chart(fig_timeline, use_container_width=True)

            with tl_right:
                signal_line = (
                    trend_src.groupby("time_bucket", dropna=False)
                    .agg(
                        exfil_signals=("Exfil_Indicator", lambda s: int(pd.Series(s).fillna(False).astype(bool).sum())),
                        unapproved_events=("Allowed", lambda s: int((s == False).sum())),  # noqa: E712
                        high_crit_events=("Severity", lambda s: int(s.astype(str).str.upper().isin(["CRITICAL", "HIGH"]).sum())),
                    )
                    .reset_index()
                    .sort_values("time_bucket")
                    .rename(
                        columns={
                            "exfil_signals": "Exfil Signals",
                            "unapproved_events": "Unapproved Events",
                            "high_crit_events": "Critical/High Events",
                        }
                    )
                )
                fig_signal = px.line(
                    signal_line,
                    x="time_bucket",
                    y=["Exfil Signals", "Unapproved Events", "Critical/High Events"],
                    template=get_plotly_template(),
                    markers=True,
                    color_discrete_sequence=["#fb7185", "#f59e0b", "#38bdf8"],
                )
                style_plotly_figure(fig_signal, height=395)
                fig_signal.update_traces(line=dict(width=2.4))
                fig_signal.update_layout(legend_title_text=None)
                fig_signal.update_xaxes(title="Time")
                fig_signal.update_yaxes(title="Event Count")
                st.plotly_chart(fig_signal, use_container_width=True)

    # -------------------------------------------------------------------------
    # Device Forensics (moved under Overview)
    # -------------------------------------------------------------------------
    with tab_overview:
        st.markdown("#### Top Devices & Activities")
        st.caption("Click on any MAC Address to show device forensics dialog.")

        def _first_valid_mac(vals: pd.Series) -> str:
            for raw in vals.astype(str):
                v = raw.strip().lower()
                if v and v not in {"nan", "none"} and v != "-":
                    return v
            return ""

        def _first_valid_ip(vals: pd.Series) -> str:
            for raw in vals.astype(str):
                v = raw.strip()
                if v and v.lower() not in {"nan", "none"} and v != "-":
                    return v
            return ""

        def _first_device_name(vals: pd.Series) -> str:
            for raw in vals.astype(str):
                v = raw.strip()
                if v and v.lower() not in {"nan", "none", "unknown"} and v != "-" and not _is_ip_literal(v):
                    return v
            return "Unknown"

        dev_src = filtered.copy()
        dev_src["__mac"] = dev_src["mac"].astype(str).str.strip().str.lower().replace({"nan": "", "none": "", "-": ""})
        dev_src["__ip"] = dev_src["id.orig_h"].astype(str).str.strip().replace({"nan": "", "None": "", "none": "", "-": ""})
        dev_src = dev_src[(dev_src["__mac"] != "") | (dev_src["__ip"] != "")].copy()

        if dev_src.empty:
            st.info("No identifiable MAC/IP rows are available in this scope.")
            st.session_state["shadow_sharing_last_selected_mac"] = None
        else:
            dev_src["bytes"] = pd.to_numeric(dev_src["bytes"], errors="coerce").fillna(0)
            dev_src["Risk_Score"] = pd.to_numeric(dev_src["Risk_Score"], errors="coerce").fillna(0)
            dev_src["__device_key"] = dev_src["__mac"].where(dev_src["__mac"] != "", "ip:" + dev_src["__ip"])

            top_dest = (
                dev_src.groupby(["__device_key", "destination"], dropna=False)
                .agg(
                    dest_events=("ts", "count"),
                    dest_bytes=("bytes", "sum"),
                    Top_Dest_Max_Risk=("Risk_Score", "max"),
                )
                .reset_index()
                .sort_values(
                    ["__device_key", "dest_events", "dest_bytes", "Top_Dest_Max_Risk", "destination"],
                    ascending=[True, False, False, False, True],
                )
                .drop_duplicates("__device_key", keep="first")
                .rename(columns={"destination": "Top_Dest"})
            )

            dev = dev_src.groupby("__device_key", dropna=False).agg(
                mac=("__mac", _first_valid_mac),
                IP=("__ip", _first_valid_ip),
                Hostname=("host_name", _first_device_name),
                Last_Seen=("ts", "max"),
                Events=("ts", "count"),
                Unapproved=("Allowed", lambda x: int((x == False).sum())),  # noqa: E712
                Total_MB=("bytes", lambda x: float(x.sum()) / 1024 / 1024),
                Top_Action=("Action", lambda x: x.value_counts().index[0] if len(x) else ""),
                Max_Risk=("Risk_Score", "max"),
            ).reset_index()

            dev = dev.merge(top_dest[["__device_key", "Top_Dest", "Top_Dest_Max_Risk"]], on="__device_key", how="left")
            dev["Top_Dest"] = dev["Top_Dest"].astype(str).replace({"nan": "Unknown", "None": "Unknown"}).fillna("Unknown")
            dev["Top_Dest_Max_Risk"] = pd.to_numeric(dev["Top_Dest_Max_Risk"], errors="coerce").fillna(0).astype(int)
            dev = dev.sort_values(["Max_Risk", "Total_MB", "Events"], ascending=False).drop(columns=["__device_key"])

            dev_grid = dev.copy()
            dev_grid.insert(0, "#", range(1, len(dev_grid) + 1))
            dev_grid["Last_Seen"] = pd.to_datetime(dev_grid["Last_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M").fillna("")
            dev_grid["Total_MB"] = pd.to_numeric(dev_grid["Total_MB"], errors="coerce").fillna(0).round(2)
            dev_grid["Max_Risk"] = pd.to_numeric(dev_grid["Max_Risk"], errors="coerce").fillna(0).astype(int)
            dev_grid["Top_Dest_Max_Risk"] = pd.to_numeric(dev_grid["Top_Dest_Max_Risk"], errors="coerce").fillna(0).astype(int)
            dev_grid["Max_Risk_Level"] = dev_grid["Max_Risk"].apply(_severity_label)
            dev_grid["Top_Dest_Risk_Level"] = dev_grid["Top_Dest_Max_Risk"].apply(_severity_label)
            dev_grid = dev_grid.drop(columns=["Max_Risk"])
            dev_grid = dev_grid.drop(columns=["Top_Dest_Max_Risk"])

            gb_dev = GridOptionsBuilder.from_dataframe(dev_grid)
            gb_dev.configure_default_column(filter=True, sortable=True, resizable=True, flex=1)
            gb_dev.configure_selection(selection_mode="single", use_checkbox=False)
            gb_dev.configure_column("#", header_name="#", width=62, pinned="left", suppressMovable=True, resizable=False)
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
            gb_dev.configure_column("mac", header_name="MAC (Click)", minWidth=160, cellStyle=clickable_mac_style)
            gb_dev.configure_column("IP", header_name="IP", minWidth=140)
            gb_dev.configure_column("Hostname", minWidth=170)
            gb_dev.configure_column("Last_Seen", header_name="Last Seen", width=150)
            gb_dev.configure_column("Events", width=90)
            gb_dev.configure_column("Unapproved", width=108)
            gb_dev.configure_column("Total_MB", header_name="Total MB", width=116)
            gb_dev.configure_column("Top_Action", header_name="Top Action", minWidth=145)
            gb_dev.configure_column("Top_Dest", header_name="Top Destination", minWidth=180)
            gb_dev.configure_column("Top_Dest_Risk_Level", header_name="Device Top Destination Risk Level", width=150, cellStyle=_severity_cellstyle())
            gb_dev.configure_column("Max_Risk_Level", header_name="Device Max Risk Level", width=170, cellStyle=_severity_cellstyle())

            dev_response = render_shadow_aggrid(
                dev_grid,
                gb_dev,
                key=f"shadow_sharing_device_grid_{selected_scope_key}_{int(st.session_state.get('shadow_sharing_grid_nonce', 0))}",
                height=430,
                wrap_shell=False,
                force_scrollbars=True,
                hide_scrollbar_buttons=True,
            )

            selected_mac = _extract_selected_mac(dev_response.get("selected_rows", None))
            if selected_mac:
                prev = st.session_state.get("shadow_sharing_last_selected_mac")
                if selected_mac != prev:
                    mac_norm = filtered["mac"].astype(str).str.strip().str.lower()
                    dialog_base = filtered.loc[mac_norm == selected_mac].copy()
                    dialog_base["mac"] = selected_mac
                    st.session_state["shadow_sharing_dialog_base_df"] = dialog_base
                    st.session_state["shadow_sharing_dialog_base_key"] = f"{selected_scope_key}:{selected_mac}:{len(filtered)}"
                    st.session_state["shadow_sharing_last_selected_mac"] = selected_mac
                    st.session_state["shadow_sharing_dialog_mac"] = selected_mac
                    st.session_state["shadow_sharing_dialog_open"] = True
                    st.rerun()
            else:
                st.session_state["shadow_sharing_last_selected_mac"] = None
                st.session_state.pop("shadow_sharing_dialog_base_df", None)
                st.session_state.pop("shadow_sharing_dialog_base_key", None)

            has_mac_rows = dev_grid["mac"].astype(str).str.strip().replace({"": None, "nan": None, "none": None}).dropna().nunique() > 0
            if not has_mac_rows:
                st.info("MAC values are not available in this scope, so MAC drilldown dialog is disabled.")

    with st.expander("Detection basis", expanded=False):
        st.markdown(
            "This page correlates Zeek telemetry and flags potential Shadow Sharing / Exfiltration.\n"
            "- Primary events are correlated `flow` rows (`conn` joined with `http`/`ssl`/`files` by `uid`), plus `dns` rows for tunneling checks.\n"
            "- Destination selection is prioritized as `http.host` -> `ssl.server_name` -> DNS answer mapping -> `conn.id.resp_h` fallback.\n"
            "- Dashboard transfer `bytes` is outbound-oriented (`bytes_out`/`orig_bytes` on flow rows).\n"
            "- `Allowed`/`Unapproved` uses boundary-safe suffix matching against `whitelist_domains.yaml`; matched evidence is shown in `Allow_Basis`.\n"
            "- `Action` + `Action_Basis` come from log source, HTTP method/URI/content-type, and automation user-agent hints.\n"
            "- DNS exfil heuristics (length/entropy/charset) add explainable evidence in `DNS_Exfil_Reason`.\n"
            "- `Risk_Score`/`Severity` are explainable via `Risk_Basis` (allowlist status, category/action, outbound volume/ratio, files/request-body signals).\n"
            "- `Exfil_Indicator` uses stronger explicit signals; `Exfil_Detection_Basis` explains why a row is treated as a potential exfil event."
        )

    if st.session_state.get("shadow_sharing_dialog_open") and st.session_state.get("shadow_sharing_dialog_mac"):
        show_shadow_sharing_device_dialog(filtered, selected_scope_key=selected_scope_key)


# Backward compatibility if your app imports render_shadow_uploads
def render_shadow_uploads(parquet_root: Path):
    return render_shadow_sharing(parquet_root)
