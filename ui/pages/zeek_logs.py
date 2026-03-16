import streamlit as st
from pathlib import Path
from datetime import datetime, timedelta, timezone
import duckdb
import pandas as pd
from .header_layout import (
    dashboard_loading_ui,
    inject_traffic_style_header_css,
    render_traffic_style_header,
)
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode


def render_rows_caption(*, total_rows: int, shown_rows: int) -> None:
    if int(total_rows) > int(shown_rows):
        st.caption(f"Showing {shown_rows:,} of {total_rows:,} rows. Narrow filters or increase row limit for more.")
    else:
        st.caption(f"Showing {shown_rows:,} rows.")


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
        ".ag-root, .ag-body, .ag-body-viewport, .ag-body-clipper, .ag-center-cols-clipper, .ag-center-cols-viewport, .ag-center-cols-container": {
            "background-color": "#050B16"
        },
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
        ".ag-standard-button, .ag-button, button.ag-standard-button, .ag-filter-apply-panel button": {
            "background-color": "#0A1730 !important",
            "color": "#EAF2FF !important",
            "border": "1px solid #2D456C !important",
        },
        ".ag-standard-button:hover, .ag-button:hover, .ag-filter-apply-panel button:hover": {
            "background-color": "#13305A !important",
            "color": "#FFFFFF !important",
            "border": "1px solid #3B5C8F !important",
        },
        ".ag-standard-button span, .ag-button span, .ag-filter-apply-panel button span": {
            "color": "#EAF2FF !important",
        },
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
    min_px: int = 240,
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

    default_col_def["sortable"] = True
    default_col_def["filter"] = "agSetColumnFilter"
    default_col_def["floatingFilter"] = False
    default_col_def.setdefault("minWidth", 96)
    default_col_def["menuTabs"] = ["filterMenuTab", "generalMenuTab"]
    default_col_def["suppressMenu"] = False

    filter_params = dict(default_col_def.get("filterParams") or {})
    filter_params.setdefault("excelMode", "windows")
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
    # Keep column widths stable in the log explorer so sparse tables stretch cleanly
    # instead of collapsing to content width and leaving a blank viewport area.
    opts.pop("autoSizeStrategy", None)
    opts.pop("onFirstDataRendered", None)
    opts.pop("onGridSizeChanged", None)
    return opts


def _stretch_sparse_grid_columns(grid_options: dict, df_grid: pd.DataFrame) -> dict:
    opts = dict(grid_options or {})
    data_columns = [str(col) for col in df_grid.columns if str(col) != "#"]
    if len(data_columns) > 6:
        return opts

    column_defs = [dict(col_def or {}) for col_def in (opts.get("columnDefs") or [])]
    if not column_defs:
        return opts

    stretchable_count = max(len(data_columns), 1)
    flex_value = 2 if stretchable_count <= 3 else 1
    min_width = 150 if stretchable_count <= 3 else 130

    for col_def in column_defs:
        field = str(col_def.get("field", "") or "")
        if field == "#":
            col_def["width"] = 70
            col_def["maxWidth"] = 82
            col_def["minWidth"] = 64
            col_def["pinned"] = "left"
            col_def["suppressSizeToFit"] = True
            col_def.pop("flex", None)
            continue

        col_def["flex"] = flex_value
        col_def["minWidth"] = max(int(col_def.get("minWidth", 0) or 0), min_width)
        col_def["suppressSizeToFit"] = False

    default_col_def = dict(opts.get("defaultColDef") or {})
    default_col_def["resizable"] = True
    if stretchable_count <= 6:
        default_col_def["minWidth"] = max(int(default_col_def.get("minWidth", 0) or 0), min_width)
    opts["defaultColDef"] = default_col_def
    opts["columnDefs"] = column_defs
    opts["suppressHorizontalScroll"] = True
    return opts




# -------------------------
# Shadow UI Styling
# -------------------------
def inject_zeek_logs_css():
    st.markdown(
        """
        <style>
        :root {
            --panel-border: rgba(255,255,255,0.12);
            --panel-bg: rgba(255,255,255,0.03);
            --panel-shadow: 0 14px 38px rgba(0,0,0,0.25);
            --accent-cyan: #00F7FF;
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

        .page-header {
            display:flex;
            align-items:flex-end;
            justify-content:space-between;
            gap: 20px;
            margin-top: 15px;
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


# -------------------------
# DuckDB Connection Helper
# -------------------------
@st.cache_resource
def get_duckdb_connection():
    """Return an in-memory DuckDB connection shared across the session."""
    return duckdb.connect(database=":memory:")


# -------------------------
# Helper: Get available dates from Parquet folders
# -------------------------
@st.cache_data(show_spinner=False)
def get_available_dates(parquet_root: Path):
    """Return a descending list of date folders (YYYY-MM-DD)."""
    if not parquet_root.exists():
        return []

    dates = []
    for p in parquet_root.iterdir():
        if p.is_dir():
            try:
                datetime.strptime(p.name, "%Y-%m-%d")
                dates.append(p.name)
            except ValueError:
                continue
    return sorted(dates, reverse=True)


# -------------------------
# Helper: Get available log types for a date
# -------------------------
@st.cache_data(show_spinner=False)
def get_log_types_for_date(parquet_root: Path, selected_date: str):
    date_path = parquet_root / selected_date
    if not date_path.exists():
        return []

    return [f.stem for f in sorted(date_path.glob("*.parquet"))]


# -------------------------
# Helper: Parse datetime search into a range
# -------------------------
def _parse_datetime_range(search_term: str):
    """
    If search_term looks like a datetime/date, return (start, end, precision),
    else return None.

    Supported:
      YYYY-MM-DD
      YYYY-MM-DD HH
      YYYY-MM-DD HH:MM
      YYYY-MM-DD HH:MM:SS
      YYYY-MM-DD HH:MM:SS.ffffff
    """
    if not search_term:
        return None

    s = search_term.strip()
    if not s:
        return None

    # Try most-specific first.
    patterns = [
        ("%Y-%m-%d %H:%M:%S.%f", "micro"),
        ("%Y-%m-%d %H:%M:%S", "second"),
        ("%Y-%m-%d %H:%M", "minute"),
        ("%Y-%m-%d %H", "hour"),
        ("%Y-%m-%d", "day"),
    ]

    for fmt, precision in patterns:
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            if precision == "micro":
                # Small tolerance helps with float rounding in epoch seconds.
                start = dt - timedelta(milliseconds=1)
                end = dt + timedelta(milliseconds=1)
            elif precision == "second":
                start = dt
                end = dt + timedelta(seconds=1)
            elif precision == "minute":
                start = dt
                end = dt + timedelta(minutes=1)
            elif precision == "hour":
                start = dt
                end = dt + timedelta(hours=1)
            else:  # day
                start = dt
                end = dt + timedelta(days=1)

            return start, end, precision
        except ValueError:
            continue

    return None


# -------------------------
# Search / Load Logs via DuckDB
# -------------------------
@st.cache_data(show_spinner=False, ttl=120)
def query_parquet_log(
    parquet_root: Path,
    selected_date: str,
    log_type: str,
    search_term: str = None,
    limit: int = None,
):
    path = parquet_root / selected_date / f"{log_type}.parquet"
    if not path.exists():
        return pd.DataFrame()

    con = get_duckdb_connection()

    # Use POSIX-like path for DuckDB (more robust on Windows).
    path_str = path.as_posix().replace("'", "''")

    # Read schema (also capture types).
    schema_df = con.execute(
        f"DESCRIBE SELECT * FROM read_parquet('{path_str}')"
    ).fetchdf()

    cols = schema_df["column_name"].tolist()
    col_types = dict(zip(schema_df["column_name"], schema_df["column_type"]))

    sql = f"SELECT * FROM read_parquet('{path_str}')"
    params = []

    if search_term and search_term.strip():
        like = f"%{search_term.strip()}%"

        quoted_cols = [f'"{c}"' for c in cols]
        conditions = []

        # General: search across all columns.
        for c in quoted_cols:
            conditions.append(f"CAST({c} AS VARCHAR) ILIKE ?")
            params.append(like)

        # Special: datetime range filter (makes date-time search work reliably).
        dt_range = _parse_datetime_range(search_term)
        if dt_range and "ts" in col_types:
            start_dt, end_dt, _precision = dt_range
            ts_type = str(col_types.get("ts", "")).upper()

            if "TIMESTAMP" in ts_type or "DATE" in ts_type:
                # ts stored as timestamp/date.
                conditions.append('("ts" >= ? AND "ts" < ?)')
                params.extend([start_dt.replace(tzinfo=None), end_dt.replace(tzinfo=None)])
            else:
                # ts stored as epoch seconds (int/float/etc.).
                start_epoch = start_dt.timestamp()
                end_epoch = end_dt.timestamp()
                conditions.append('(CAST("ts" AS DOUBLE) >= ? AND CAST("ts" AS DOUBLE) < ?)')
                params.extend([start_epoch, end_epoch])

        sql += " WHERE " + " OR ".join(conditions)

    if limit:
        sql += f" LIMIT {int(limit)}"

    try:
        df = con.execute(sql, params).df()
    except Exception as exc:
        st.error(f"Query failed: {exc}")
        return pd.DataFrame()

    # Add a human-readable datetime column when ts exists.
    if "ts" in df.columns:
        ts_type = str(col_types.get("ts", "")).upper()
        if "TIMESTAMP" in ts_type or "DATE" in ts_type:
            dt_series = pd.to_datetime(df["ts"], errors="coerce")
        else:
            ts_numeric = pd.to_numeric(df["ts"], errors="coerce")
            dt_series = pd.to_datetime(ts_numeric, unit="s", errors="coerce")

        df.insert(0, "date time", dt_series)

    return df


# -------------------------
# Main Render Function
# -------------------------
def render(parquet_root: Path):
    inject_zeek_logs_css()
    inject_traffic_style_header_css()

    updated_txt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    render_traffic_style_header(
        title="Raw Log Explorer",
        subtitle="Inspect raw Zeek parquet logs with full-column search and datetime-aware filtering",
        chip_label="Live monitoring",
        updated_txt=updated_txt,
    )
    with dashboard_loading_ui(
        title="Loading Zeek Logs",
        subtitle="Scanning parquet logs, discovering datasets, and preparing the raw log explorer.",
        steps=["Discover dates", "Read parquet", "Render explorer"],
        container=st.empty(),
    ):
        available_dates = get_available_dates(parquet_root)
        if not available_dates:
            st.warning(f"No parquet data found in `{parquet_root}`")
            st.info("Try running 'Force Refresh Data' in the sidebar.")
            return

        day_col, day_hint_col = st.columns([1.2, 2])
        with day_col:
            selected_date = st.selectbox("Dataset Day", available_dates, key="zeek_day_select")
        with day_hint_col:
            st.markdown(
                f"<div class='shadow-day-chip'>Active date: &nbsp; <strong>{selected_date}</strong></div>",
                unsafe_allow_html=True,
            )

        log_types = get_log_types_for_date(parquet_root, selected_date)
        if not log_types:
            st.info(f"No logs found for {selected_date}")
            return

    log_key = "zeek_log_type"
    search_key = "zeek_log_search"

    if st.session_state.get(log_key) not in log_types:
        st.session_state[log_key] = log_types[0]
    if search_key not in st.session_state:
        st.session_state[search_key] = ""

    st.markdown("<div class='shadow-filter-shell'>", unsafe_allow_html=True)
    filter_col1, filter_col2 = st.columns([1.0, 1.8])
    with filter_col1:
        st.selectbox("Log Type", log_types, key=log_key)
    with filter_col2:
        st.text_input(
            "Search (all columns)",
            placeholder="IP, domain, uid, ts, or any value...",
            key=search_key,
        )

    selected_log = str(st.session_state.get(log_key, log_types[0]) or log_types[0])
    search_term = str(st.session_state.get(search_key, "") or "")
    row_limit = None

    st.markdown(
        f"<div class='shadow-filter-hint'>Log: <strong>{selected_log}</strong> | Search: <strong>{'On' if search_term.strip() else 'Off'}</strong> | Datetime: <strong>YYYY-MM-DD[ HH[:MM[:SS[.ffffff]]]]</strong></div>",
        unsafe_allow_html=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)

    df_display = query_parquet_log(parquet_root, selected_date, selected_log, search_term, limit=row_limit)

    if df_display.empty:
        if search_term and search_term.strip():
            st.warning("No rows matched your filter.")
        else:
            st.warning("No data matched or file is empty.")
        return

    st.write(f"### {selected_log}.log")
    render_rows_caption(total_rows=len(df_display), shown_rows=len(df_display))
    df_display = df_display.reset_index(drop=True)
    df_display.index = df_display.index + 1

    st.markdown("<div class='shadow-table-shell'>", unsafe_allow_html=True)
    df_grid = df_display.copy()
    df_grid.insert(0, "#", range(1, len(df_grid) + 1))

    gb = GridOptionsBuilder.from_dataframe(df_grid)
    gb.configure_default_column(filter=True, sortable=True, resizable=True)
    gb.configure_column("#", header_name="#", width=70, pinned="left", suppressMovable=True, resizable=False)

    grid_options = _apply_shadow_grid_filter_sort(gb.build())
    grid_options = _stretch_sparse_grid_columns(grid_options, df_grid)
    grid_options["pagination"] = False
    grid_options["rowSelection"] = "single"
    grid_options["suppressRowClickSelection"] = True
    grid_options["rowMultiSelectWithClick"] = False
    grid_options["domLayout"] = "normal"
    grid_options["alwaysShowVerticalScroll"] = True
    grid_options.setdefault("suppressHorizontalScroll", False)
    grid_options["alwaysShowHorizontalScroll"] = not bool(grid_options.get("suppressHorizontalScroll"))
    grid_options["maintainColumnOrder"] = True
    grid_options["suppressMovableColumns"] = True

    ag_theme, ag_css = get_aggrid_theme_and_css()
    log_ag_css = dict(ag_css)
    log_ag_css.update(
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

    AgGrid(
        df_grid,
        gridOptions=grid_options,
        update_mode=GridUpdateMode.MODEL_CHANGED,
        data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
        height=_table_height_for_rows(len(df_grid), min_px=240, max_px=520),
        theme=ag_theme,
        custom_css=log_ag_css,
        allow_unsafe_jscode=True,
        enable_enterprise_modules=True,
        fit_columns_on_grid_load=False,
        reload_data=False,
        key=f"zeek_log_grid_{selected_date}_{selected_log}",
    )
    st.markdown("</div>", unsafe_allow_html=True)

