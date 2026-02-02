import streamlit as st
import pandas as pd
from pathlib import Path
from datetime import datetime

# -------------------------
# Cached helpers
# -------------------------
@st.cache_data(show_spinner=False)
def get_log_folders(logs_dir: Path):
    """Return immediate subfolders under logs_dir"""
    return sorted([p for p in logs_dir.iterdir() if p.is_dir()])

@st.cache_data(show_spinner=False)
def get_log_files(logs_dir: Path, selected_folders: tuple):
    """Return log files under selected folders"""
    files = []
    for folder in selected_folders:
        folder_path = logs_dir / folder
        if folder_path.exists():
            files.extend([f for f in folder_path.rglob("*") if f.is_file()])
    return sorted(files)

@st.cache_data(show_spinner=False)
def parse_log_file(file_path: Path, logs_dir: Path, authorized: set):
    rows = []
    cols = None

    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Zeek header
            if line.startswith("#fields"):
                cols = line.split("\t")[1:]
                continue

            # Skip other comments
            if line.startswith("#"):
                continue

            # No header yet → can't parse
            if not cols:
                continue

            parts = line.split("\t")
            row = {cols[i]: parts[i] if i < len(parts) else "" for i in range(len(cols))}

            # Convert ts → date
            if "ts" in row:
                try:
                    row["date"] = datetime.utcfromtimestamp(float(row["ts"])).date()
                except Exception:
                    row["date"] = None

            row["log_file"] = str(file_path.relative_to(logs_dir))

            if "mac" in row and row["mac"].lower() in authorized:
                row["status"] = "Authorized"
            else:
                row["status"] = row.get("status", "Unknown")

            rows.append(row)

    return pd.DataFrame(rows) if rows else pd.DataFrame()

# -------------------------
# Main page render
# -------------------------
def render(filtered, logs_dir: Path, authorized: set):
    st.title("Raw Log Explorer")

    # -------------------------
    # Refresh
    # -------------------------
    if st.button("🔄 Refresh Logs"):
        get_log_folders.clear()
        get_log_files.clear()
        parse_log_file.clear()
        st.rerun()

    # -------------------------
    # Folder selection
    # -------------------------
    folders = get_log_folders(logs_dir)
    folder_names = [f.name for f in folders]

    selected_folders = st.multiselect(
        "Select Log Folder(s)",
        options=folder_names
    )

    if not selected_folders:
        st.info("Please select one or more log folders.")
        return

    # -------------------------
    # File selection
    # -------------------------
    files = get_log_files(logs_dir, tuple(selected_folders))

    if not files:
        st.warning("No log files found in selected folders.")
        return

    # Map display name → full path
    file_map = {f.name: f for f in files}

    selected_file_name = st.selectbox(
        "Select Log File",
        options=sorted(file_map.keys())
    )

    selected_file_path = file_map[selected_file_name]

    # -------------------------
    # Date filter (from selected file only)
    # -------------------------
    df_preview = parse_log_file(selected_file_path, logs_dir, authorized)

    if df_preview.empty or "date" not in df_preview:
        st.warning("No parsable data found in selected log file.")
        return

    available_dates = (
        df_preview["date"]
        .dropna()
        .sort_values()
        .unique()
        .tolist()
    )

    selected_dates = st.multiselect(
        "Select Date(s)",
        options=available_dates
    )

    if not selected_dates:
        st.info("Please select one or more dates.")
        return

    # -------------------------
    # Load & display
    # -------------------------
    df_final = df_preview[df_preview["date"].isin(selected_dates)]

    if df_final.empty:
        st.warning("No logs found for selected date(s).")
        return

    st.dataframe(
        df_final.drop(columns=["date"], errors="ignore"),
        use_container_width=True
    )
