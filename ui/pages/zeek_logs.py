# zeek_logs_duckdb.py
import streamlit as st
from pathlib import Path
from datetime import datetime, timedelta, timezone
import duckdb
import pandas as pd

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

    # Try most-specific first
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
                # small tolerance helps with float rounding in epoch seconds
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

    # Use POSIX-like path for DuckDB (more robust on Windows)
    path_str = path.as_posix().replace("'", "''")

    # 1️⃣ Read schema (also capture types)
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

        # General: search across all columns
        for c in quoted_cols:
            conditions.append(f"CAST({c} AS VARCHAR) ILIKE ?")
            params.append(like)

        # Special: datetime range filter (makes "date time" search work reliably)
        dt_range = _parse_datetime_range(search_term)
        if dt_range and "ts" in col_types:
            start_dt, end_dt, _precision = dt_range
            ts_type = str(col_types.get("ts", "")).upper()

            if "TIMESTAMP" in ts_type or "DATE" in ts_type:
                # ts stored as timestamp/date
                conditions.append(f'("ts" >= ? AND "ts" < ?)')
                params.extend([start_dt.replace(tzinfo=None), end_dt.replace(tzinfo=None)])
            else:
                # ts stored as epoch seconds (int/float/etc.)
                start_epoch = start_dt.timestamp()
                end_epoch = end_dt.timestamp()
                conditions.append(f'(CAST("ts" AS DOUBLE) >= ? AND CAST("ts" AS DOUBLE) < ?)')
                params.extend([start_epoch, end_epoch])

        sql += " WHERE " + " OR ".join(conditions)

    if limit:
        sql += f" LIMIT {int(limit)}"

    try:
        df = con.execute(sql, params).df()
    except Exception as e:
        st.error(f"Query failed: {e}")
        return pd.DataFrame()

    # 4️⃣ Human-readable datetime column
    if "ts" in df.columns:
        ts_type = str(col_types.get("ts", "")).upper()
        if "TIMESTAMP" in ts_type or "DATE" in ts_type:
            dt_series = pd.to_datetime(df["ts"], errors="coerce")
        else:
            dt_series = pd.to_datetime(df["ts"], unit="s", errors="coerce")

        df.insert(0, "date time", dt_series)

    return df

# -------------------------
# Main Render Function
# -------------------------
def render(parquet_root: Path):
    st.markdown("## Raw Log Explorer")

    # 1️⃣ Dates dropdown
    available_dates = get_available_dates(parquet_root)
    if not available_dates:
        st.warning(f"No parquet data found in `{parquet_root}`")
        st.info("Try running 'Update Data from Drive' in the sidebar.")
        return

    col1, col2 = st.columns(2)
    with col1:
        selected_date = st.selectbox("Select Date", available_dates)

    # 2️⃣ Log types dropdown
    log_types = get_log_types_for_date(parquet_root, selected_date)
    if not log_types:
        st.info(f"No logs found for {selected_date}")
        return

    with col2:
        selected_log = st.selectbox("Select Log Type", log_types)

    # 3️⃣ Search box
    search_term = st.text_input("Filter records (search all columns)", "")

    # 5️⃣ Query via DuckDB
    df_display = query_parquet_log(parquet_root, selected_date, selected_log, search_term)

    if df_display.empty:
        if search_term and search_term.strip():
            st.warning("No rows matched your filter.")
            st.caption("Datetime search supports: YYYY-MM-DD, YYYY-MM-DD HH:MM, YYYY-MM-DD HH:MM:SS, YYYY-MM-DD HH:MM:SS.ffffff")
        else:
            st.warning("No data matched or file is empty.")
        return

    st.write(f"### {selected_log}.log ({len(df_display)} rows)")

    df_display = df_display.reset_index(drop=True)
    df_display.index = df_display.index + 1

    # 6️⃣ Display table
    st.dataframe(df_display, use_container_width=True, height=600)
