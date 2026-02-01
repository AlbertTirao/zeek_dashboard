import streamlit as st
import pandas as pd
from pathlib import Path

def render(logs_dir: Path, authorized: set):
    st.title("Raw Log Explorer")

    # -------------------------
    # Step 1: List all folders
    # -------------------------
    # folders = sorted([f for f in logs_dir.iterdir() if f.is_dir()])
    folders = sorted([
        f for f in logs_dir.iterdir() 
        if f.is_dir() and not f.name.endswith("-CSV")
    ])

    folder_names = [f.name for f in folders]

    selected_folder_name = st.selectbox("Select Folder", ["-- Select Folder --"] + folder_names)

    if selected_folder_name == "-- Select Folder --":
        st.info("Select a folder to see log files")
        return

    selected_folder = logs_dir / selected_folder_name

    # -------------------------
    # Step 2: List log files in folder
    # -------------------------
    log_files = sorted([f.name for f in selected_folder.glob("*.log")])
    selected_file_name = st.selectbox("Select Log File", ["-- Select File --"] + log_files)

    if selected_file_name == "-- Select File --":
        st.info("Select a log file to preview")
        return

    selected_file_path = selected_folder / selected_file_name

    # -------------------------
    # Step 3: Load the selected log file
    # -------------------------
    data_rows = []
    with open(selected_file_path, "r", errors="ignore") as f:
        fields = None
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                if line.startswith("#fields"):
                    fields = line.split()[1:]  # capture columns
                continue
            if not fields:
                continue
            parts = line.split("\t")
            row = {fields[i]: parts[i] if i < len(parts) else "" for i in range(len(fields))}
            row["log_file"] = selected_file_name
            # mark authorized if MAC exists
            if "mac" in row and row["mac"].lower() in authorized:
                row["status"] = "Authorized"
            else:
                row["status"] = row.get("status", "Unknown")
            data_rows.append(row)

    if not data_rows:
        st.warning("No data found in this log file.")
        return

    df = pd.DataFrame(data_rows)

    st.dataframe(df, use_container_width=True)
