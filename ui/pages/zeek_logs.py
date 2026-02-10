# zeek_logs_duckdb.py
import streamlit as st
from pathlib import Path
from datetime import datetime
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
# Search / Load Logs via DuckDB
# -------------------------
def query_parquet_log(parquet_root: Path, selected_date: str, log_type: str, search_term: str = None, limit: int = None):
    """
    Load or filter a Zeek log from Parquet using DuckDB.
    - search_term: string to search across all columns (case-insensitive)
    """
    path = parquet_root / selected_date / f"{log_type}.parquet"
    if not path.exists():
        return pd.DataFrame()

    con = get_duckdb_connection()

    # 1️⃣ Read column names from the parquet schema
    try:
        cols = con.execute(f"DESCRIBE SELECT * FROM read_parquet('{path}')").fetchdf()["column_name"].tolist()
    except Exception as e:
        st.error(f"Failed to read schema: {e}")
        return pd.DataFrame()

    # 2️⃣ Build SQL
    sql = f"SELECT * FROM read_parquet('{path}')"

    if search_term:
        # Quote column names properly
        quoted_cols = [f'"{c}"' for c in cols]  # <-- double quotes fix
        conditions = " OR ".join([f"CAST({c} AS VARCHAR) ILIKE '%{search_term}%'" for c in quoted_cols])
        sql += f" WHERE {conditions}"

    if limit:
        sql += f" LIMIT {limit}"

    # 3️⃣ Execute query
    try:
        df = con.execute(sql).df()
    except Exception as e:
        st.error(f"Failed to execute query: {e}")
        return pd.DataFrame()

    # 4️⃣ Convert 'ts' column to readable datetime if exists
    if "ts" in df.columns:
        ts_numeric = pd.to_numeric(df["ts"], errors="coerce")
        df.insert(0, "time", pd.to_datetime(ts_numeric, unit="s", errors="coerce"))

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
        st.warning("No data matched or file is empty.")
        return

    st.write(f"### {selected_log}.log ({len(df_display)} rows)")

    df_display = df_display.reset_index(drop=True)
    df_display.index = df_display.index + 1
    # 6️⃣ Display table
    st.dataframe(df_display, use_container_width=True, height=600)
