import streamlit as st
import pandas as pd
from pathlib import Path

def render(filtered, logs_dir: Path, authorized: set):
    st.title(" Raw Log Explorer")

    def list_all_logs(log_dir: Path):
        files = []
        for f in sorted(log_dir.rglob("*")):
            if f.is_file():
                files.append(str(f.relative_to(log_dir)))
        return files

    all_log_files = list_all_logs(logs_dir)

    c1, c2 = st.columns([3, 1])
    with c1:
        selected_file = st.selectbox("Select Log File", ["-- All Logs --"] + all_log_files)

    logs_to_show = pd.DataFrame()

    if selected_file == "-- All Logs --":
        all_rows = []
        for f_path in logs_dir.rglob("*"):
            if not f_path.is_file(): 
                continue
            with open(f_path, "r", errors="ignore") as f:
                lines = f.readlines()
                header_line = next((l.strip() for l in lines if l.strip() and not l.startswith("#")), None)
                if not header_line:
                    continue
                cols = header_line.split("\t")
                for line in lines:
                    if not line.strip() or line.startswith("#"): 
                        continue
                    parts = line.strip().split("\t")
                    row = {cols[i]: parts[i] if i < len(parts) else "" for i in range(len(cols))}
                    row["log_file"] = str(f_path.relative_to(logs_dir))
                    # Optional: mark authorized
                    if "mac" in row and row["mac"].lower() in authorized:
                        row["status"] = "Authorized"
                    else:
                        row["status"] = row.get("status", "Unknown")
                    all_rows.append(row)
        if all_rows:
            logs_to_show = pd.DataFrame(all_rows)
    else:
        file_path = logs_dir / selected_file
        if file_path.exists():
            with open(file_path, "r", errors="ignore") as f:
                lines = f.readlines()
                header_line = next((l.strip() for l in lines if l.strip() and not l.startswith("#")), None)
                if header_line:
                    cols = header_line.split("\t")
                    rows = []
                    for line in lines:
                        if not line.strip() or line.startswith("#"): 
                            continue
                        parts = line.strip().split("\t")
                        row = {cols[i]: parts[i] if i < len(parts) else "" for i in range(len(cols))}
                        if "mac" in row and row["mac"].lower() in authorized:
                            row["status"] = "Authorized"
                        else:
                            row["status"] = row.get("status", "Unknown")
                        rows.append(row)
                    logs_to_show = pd.DataFrame(rows)

    if not logs_to_show.empty:
        st.dataframe(logs_to_show, use_container_width=True)
    else:
        st.warning("No data found in selected log.")
