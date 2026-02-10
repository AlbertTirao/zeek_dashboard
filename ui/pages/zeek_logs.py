import streamlit as st
import pandas as pd
from pathlib import Path
from datetime import datetime
import duckdb

def search_log_with_duckdb(parquet_root, selected_date, log_type, term):
    path = parquet_root / selected_date / f"{log_type}.parquet"
    if not path.exists():
        return pd.DataFrame()

    # Build SQL dynamically
    con = duckdb.connect(database=":memory:")
    
    # Read schema first
    cols = con.execute(
        f"DESCRIBE SELECT * FROM read_parquet('{path}')"
    ).fetchdf()["column_name"].tolist()

    # Build OR-based search
    conditions = " OR ".join(
        [f"CAST({c} AS VARCHAR) ILIKE '%{term}%'" for c in cols]
    )

    query = f"""
        SELECT *
        FROM read_parquet('{path}')
        WHERE {conditions}
    """

    return con.execute(query).df()

# -------------------------
# Helper: Get available dates from Parquet folders
# -------------------------
@st.cache_data(show_spinner=False)
def get_available_dates(parquet_root: Path):
    """
    Scans the parquet_root for date directories (YYYY-MM-DD).
    Returns a sorted list of date strings (descending).
    """
    if not parquet_root.exists():
        return []
        
    dates = []
    for p in parquet_root.iterdir():
        if p.is_dir():
            # Basic validation: try to parse the folder name as date
            try:
                datetime.strptime(p.name, "%Y-%m-%d")
                dates.append(p.name)
            except ValueError:
                continue
                
    return sorted(dates, reverse=True)

# -------------------------
# Helper: Get available log types for a specific date
# -------------------------
@st.cache_data(show_spinner=False)
def get_log_types_for_date(parquet_root: Path, selected_date: str):
    """
    Returns a list of log types (e.g., 'conn', 'http') found in the date folder.
    """
    date_path = parquet_root / selected_date
    if not date_path.exists():
        return []
        
    # Find all .parquet files
    files = sorted(date_path.glob("*.parquet"))
    return [f.stem for f in files]

# -------------------------
# Helper: Load specific log file
# -------------------------
@st.cache_data(show_spinner=False)
def load_parquet_log(parquet_root: Path, selected_date: str, log_type: str):
    """
    Loads a specific parquet file into a DataFrame.
    """
    file_path = parquet_root / selected_date / f"{log_type}.parquet"
    if not file_path.exists():
        return pd.DataFrame()
        
    try:
        df = pd.read_parquet(file_path)
        
        # Human readable timestamp if 'ts' exists
        if "ts" in df.columns:
            # Convert to numeric, coerce errors
            ts_numeric = pd.to_numeric(df["ts"], errors="coerce")
            # Create a readable datetime column
            df.insert(0, "time", pd.to_datetime(ts_numeric, unit="s", errors="coerce"))
            
        return df
    except Exception as e:
        st.error(f"Error loading {file_path.name}: {e}")
        return pd.DataFrame()

# -------------------------
# Main Render Function
# -------------------------
def render(parquet_root: Path):
    st.title("Raw Log Explorer (Parquet)")

    # 1. Get Dates
    available_dates = get_available_dates(parquet_root)
    
    if not available_dates:
        st.warning(f"No parquet data found in `{parquet_root}`")
        st.info("Try running 'Update Data from Drive' in the sidebar.")
        return

    # 2. Sidebar Filters (or Top Bar)
    col1, col2 = st.columns(2)
    
    with col1:
        selected_date = st.selectbox("Select Date", available_dates)
        
    # 3. Get Log Types for that date
    log_types = get_log_types_for_date(parquet_root, selected_date)
    
    if not log_types:
        st.info(f"No logs found for {selected_date}")
        return

    with col2:
        selected_log = st.selectbox("Select Log Type", log_types)

    # 4. Load Data
    df = load_parquet_log(parquet_root, selected_date, selected_log)
    
    if df.empty:
        st.warning("File is empty or could not be loaded.")
        return

    st.write(f"### {selected_log}.log ({len(df)} rows)")
    
    # 5. Search / Filter
    search_term = st.text_input(" Filter records (search all columns)", "")
    
    if search_term:
        df_display = search_log_with_duckdb(
            parquet_root, selected_date, selected_log, search_term
        )
    else:
        df_display = df

    # 6. Display Table
    st.dataframe(
        df_display,
        use_container_width=True,
        height=600  # Give it plenty of height
    )