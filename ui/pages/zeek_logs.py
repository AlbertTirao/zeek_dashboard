import streamlit as st
from pathlib import Path
from datetime import datetime, timedelta, timezone
import duckdb
import pandas as pd
from .header_layout import inject_traffic_style_header_css, render_traffic_style_header


def render_rows_caption(*, total_rows: int, shown_rows: int) -> None:
    if int(total_rows) > int(shown_rows):
        st.caption(f"Showing {shown_rows:,} of {total_rows:,} rows. Narrow filters or increase row limit for more.")
    else:
        st.caption(f"Showing {shown_rows:,} rows.")


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

    log_applied_key = "zeek_log_type_applied"
    search_applied_key = "zeek_log_search_applied"
    row_limit_applied_key = "zeek_row_limit_applied"
    log_draft_key = "zeek_log_type_draft"
    search_draft_key = "zeek_log_search_draft"
    row_limit_draft_key = "zeek_row_limit_draft"
    row_limit_options = [200, 500, 1000, 2000, 5000, 10000]

    if st.session_state.get(log_applied_key) not in log_types:
        st.session_state[log_applied_key] = log_types[0]
    if row_limit_applied_key not in st.session_state:
        st.session_state[row_limit_applied_key] = 1000
    if int(st.session_state.get(row_limit_applied_key, 1000)) not in row_limit_options:
        st.session_state[row_limit_applied_key] = 1000

    if st.session_state.get(log_draft_key) not in log_types:
        st.session_state[log_draft_key] = st.session_state[log_applied_key]
    if search_draft_key not in st.session_state:
        st.session_state[search_draft_key] = str(st.session_state.get(search_applied_key, "") or "")
    if int(st.session_state.get(row_limit_draft_key, st.session_state[row_limit_applied_key])) not in row_limit_options:
        st.session_state[row_limit_draft_key] = int(st.session_state[row_limit_applied_key])

    st.markdown("<div class='shadow-filter-shell'>", unsafe_allow_html=True)
    with st.form("zeek_logs_filters_form", clear_on_submit=False):
        filter_col1, filter_col2, filter_col3 = st.columns([1.0, 1.45, 0.8])
        with filter_col1:
            st.selectbox("Log Type", log_types, key=log_draft_key)
        with filter_col2:
            st.text_input(
                "Search (all columns)",
                placeholder="IP, domain, uid, ts, or any value...",
                key=search_draft_key,
            )
        with filter_col3:
            st.selectbox(
                "Rows",
                options=row_limit_options,
                key=row_limit_draft_key,
            )
        form_btn_col1, form_btn_col2, _ = st.columns([0.75, 0.75, 2.5])
        with form_btn_col1:
            apply_filters = st.form_submit_button("Apply Filters", use_container_width=True)
        with form_btn_col2:
            reset_filters = st.form_submit_button("Reset", use_container_width=True)

    if reset_filters:
        st.session_state[log_applied_key] = log_types[0]
        st.session_state[search_applied_key] = ""
        st.session_state[row_limit_applied_key] = 1000
        st.session_state[log_draft_key] = log_types[0]
        st.session_state[search_draft_key] = ""
        st.session_state[row_limit_draft_key] = 1000
        st.rerun()

    if apply_filters:
        chosen_log = st.session_state.get(log_draft_key, log_types[0])
        st.session_state[log_applied_key] = chosen_log if chosen_log in log_types else log_types[0]
        st.session_state[search_applied_key] = str(st.session_state.get(search_draft_key, "") or "").strip()
        chosen_limit = int(st.session_state.get(row_limit_draft_key, 1000) or 1000)
        st.session_state[row_limit_applied_key] = chosen_limit if chosen_limit in row_limit_options else 1000

    selected_log = str(st.session_state.get(log_applied_key, log_types[0]) or log_types[0])
    search_term = str(st.session_state.get(search_applied_key, "") or "")
    row_limit = int(st.session_state.get(row_limit_applied_key, 1000) or 1000)

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
    if len(df_display) >= row_limit:
        st.caption(f"Query is capped at {row_limit:,} rows for responsiveness.")

    df_display = df_display.reset_index(drop=True)
    df_display.index = df_display.index + 1

    st.markdown("<div class='shadow-table-shell'>", unsafe_allow_html=True)
    st.dataframe(df_display, width="stretch", height=600)
    st.markdown("</div>", unsafe_allow_html=True)

