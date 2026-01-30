import streamlit as st
import pandas as pd
from pathlib import Path
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from datetime import datetime, date
import json
import time
import os
import requests
import plotly.express as px

# =====================================================
# CONFIG
# =====================================================
st.set_page_config(
    page_title="Zeek Device Dashboard",
    layout="wide"
)

# =====================================================
# DIRECTORIES
# =====================================================
DATA_DIR = Path("data")
LOGS_DIR = Path("logs")
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

FOLDER_ID = "1k6tVW7ZmcpaTVu7xkVOS6Nx0xU1bQ8km"

# =====================================================
# GOOGLE DRIVE AUTH
# =====================================================
@st.cache_resource
def authenticate_drive():
    gauth = GoogleAuth()
    gauth.LoadClientConfigFile(
        "client_secret_262013512528-s1lbcqmro9623l0j5akshcoq8o1dso09.apps.googleusercontent.com.json"
    )
    gauth.LocalWebserverAuth()
    return GoogleDrive(gauth)

# =====================================================
# DOWNLOAD UPDATED FILES ONLY
# =====================================================
def download_logs(drive):
    def walk(folder_id, local_path):
        local_path.mkdir(exist_ok=True)
        files = drive.ListFile({
            "q": f"'{folder_id}' in parents and trashed=false"
        }).GetList()

        for f in files:
            if f["mimeType"].endswith("folder"):
                walk(f["id"], local_path / f["title"])
                continue

            dest = local_path / f["title"]
            remote_ts = datetime.fromisoformat(
                f["modifiedDate"].replace("Z", "+00:00")
            ).timestamp()
            
            if dest.exists() and dest.stat().st_mtime >= remote_ts:
                continue

            f.GetContentFile(str(dest))
            os.utime(dest, (time.time(), remote_ts))

    walk(FOLDER_ID, LOGS_DIR)

# =====================================================
# LOAD AUTHORIZED MACS FROM known_hosts.log
# =====================================================
def load_known_hosts():
    known_hosts_file = LOGS_DIR / "known_hosts.log"
    if not known_hosts_file.exists():
        return set()

    macs = set()
    with open(known_hosts_file, "r", errors="ignore") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split("\t")
            if len(parts) > 1:
                mac = parts[1].lower()
                macs.add(mac)
    return macs

# =====================================================
# PARSE DHCP LOG
# =====================================================
def parse_dhcp(file_path):
    rows = []
    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            if not line or line.startswith("#"):
                continue
            try:
                parts = line.strip().split("\t")
                ts = float(parts[0])
                mac = parts[6].lower()
                host = parts[7] if len(parts) > 7 else "unknown"
                rows.append({
                    "timestamp": datetime.fromtimestamp(ts),
                    "mac": mac,
                    "hostname": host,
                    "log_file": str(file_path.relative_to(LOGS_DIR))
                })
            except:
                continue
    return pd.DataFrame(rows)

# =====================================================
# LOAD LOGS
# =====================================================
@st.cache_data
def load_logs():
    drive = authenticate_drive()
    download_logs(drive)
    df = pd.DataFrame()
    for f in LOGS_DIR.rglob("dhcp.log"):
        df = pd.concat([df, parse_dhcp(f)], ignore_index=True)
    return df

# =====================================================
# MAC VENDOR LOOKUP
# =====================================================
@st.cache_data
def get_mac_vendor(mac):
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text if r.status_code == 200 else "Unknown"
    except:
        return "Unknown"

# =====================================================
# SESSION INIT
# =====================================================
if "data" not in st.session_state:
    st.session_state.data = load_logs()

df = st.session_state.data
authorized = load_known_hosts()
df["status"] = df["mac"].apply(
    lambda m: "Authorized" if m.lower() in authorized else "Unauthorized"
)

# =====================================================
# SIDEBAR
# =====================================================
st.sidebar.title("Zeek SOC Dashboard")
page = st.sidebar.radio(
    "Navigation",
    ["Overview", "Devices", "Analytics", "Zeek Logs", "Alerts", "Authorization"]
)

# Date range picker
start_date = st.sidebar.date_input("Start Date", value=date.today() - pd.Timedelta(days=7))
end_date = st.sidebar.date_input("End Date", value=date.today())
filtered = df[
    (df["timestamp"].dt.date >= start_date) &
    (df["timestamp"].dt.date <= end_date)
]

# Auto-refresh and force reload
if st.sidebar.checkbox("Auto-refresh every 5 min"):
    st.experimental_rerun()
if st.sidebar.button("Force Reload"):
    st.cache_data.clear()
    st.experimental_rerun()

# =====================================================
# ANALYTICS
# =====================================================
if page == "Analytics":
    st.title("Network Analytics")

    # Total devices
    total_devices = filtered["mac"].nunique()
    total_auth = filtered[filtered["status"]=="Authorized"]["mac"].nunique()
    total_unauth = filtered[filtered["status"]=="Unauthorized"]["mac"].nunique()

    st.subheader("Device Summary")
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Devices", total_devices)
    c2.metric("Authorized Devices", total_auth)
    c3.metric("Unauthorized Devices", total_unauth)

    # Vendor distribution
    st.subheader("Device Vendor Distribution")
    filtered["vendor"] = filtered["mac"].apply(get_mac_vendor)
    vendor_counts = filtered.groupby("vendor")["mac"].nunique().sort_values(ascending=False).head(10)
    fig_vendor = px.bar(
        vendor_counts,
        x=vendor_counts.index,
        y=vendor_counts.values,
        labels={"x":"Vendor", "y":"Device Count"},
        title="Top 10 Vendors"
    )
    st.plotly_chart(fig_vendor, use_container_width=True)

    # Risk levels
    st.subheader("Device Risk Levels")
    devices = (
        filtered.groupby("mac")
        .agg(
            hostname=("hostname", "last"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            events=("timestamp", "count"),
            status=("status", "last")
        )
        .reset_index()
    )
    devices["risk_score"] = devices.apply(
        lambda r: r["events"] * (2 if r["status"]=="Unauthorized" else 1),
        axis=1
    )
    devices["risk_level"] = pd.cut(
        devices["risk_score"],
        bins=[0,5,15,1000],
        labels=["Low","Medium","High"]
    )
    risk_counts = devices["risk_level"].value_counts()
    fig_risk = px.pie(
        names=risk_counts.index,
        values=risk_counts.values,
        title="Risk Level Distribution"
    )
    st.plotly_chart(fig_risk, use_container_width=True)

    # Unauthorized device trends
    st.subheader("Unauthorized Device Trend (Last 7 Days)")
    unauth = filtered[filtered["status"]=="Unauthorized"]
    if not unauth.empty:
        trend = unauth.set_index("timestamp").resample("1D").mac.nunique()
        fig_trend = px.line(
            trend,
            x=trend.index,
            y=trend.values,
            labels={"y":"Unauthorized Devices", "x":"Date"}
        )
        st.plotly_chart(fig_trend, use_container_width=True)
    else:
        st.info("No unauthorized devices detected in the selected period")

    # Top active devices
    st.subheader("Top 10 Most Active Devices")
    top_active = filtered.groupby("mac")["timestamp"].count().sort_values(ascending=False).head(10)
    fig_active = px.bar(
        top_active,
        x=top_active.index,
        y=top_active.values,
        labels={"x":"MAC", "y":"Event Count"},
        title="Top 10 Active Devices"
    )
    st.plotly_chart(fig_active, use_container_width=True)

# =====================================================
# ZEKE LOG FILE NAVIGATION
# =====================================================
def list_all_logs(log_dir: Path):
    files = []
    for f in sorted(log_dir.rglob("*.*")):
        if f.is_file():
            files.append(str(f.relative_to(log_dir)))
    return files

# =====================================================
# OVERVIEW
# =====================================================
if page == "Overview":
    st.title("Network Overview")
    c1, c2, c3, c4 = st.columns(4)
    total = filtered["mac"].nunique()
    auth = filtered[filtered["status"]=="Authorized"]["mac"].nunique()
    unauth = filtered[filtered["status"]=="Unauthorized"]["mac"].nunique()
    percent_unauth = round((unauth / total * 100), 2) if total > 0 else 0
    c1.metric("Total Devices", total)
    c2.metric("Authorized", auth)
    c3.metric("Unauthorized", unauth)
    c4.metric("% Unauthorized", f"{percent_unauth}%")

    # Timeline with status
    hourly = (
        filtered
        .set_index("timestamp")
        .groupby("status")
        .resample("1H")
        .size()
        .reset_index(name="events")
    )
    if not hourly.empty:
        fig = px.line(hourly, x="timestamp", y="events", color="status", title="Hourly Device Events")
        st.plotly_chart(fig, use_container_width=True)

# =====================================================
# DEVICES
# =====================================================
elif page == "Devices":
    st.title("Devices")
    devices = (
        filtered.groupby("mac")
        .agg(
            hostname=("hostname", "last"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            events=("timestamp", "count"),
            status=("status", "last")
        )
        .reset_index()
    )
    devices["risk_score"] = devices.apply(
        lambda r: r["events"] * (2 if r["status"]=="Unauthorized" else 1),
        axis=1
    )
    devices["risk_level"] = pd.cut(
        devices["risk_score"],
        bins=[0,5,15,1000],
        labels=["Low","Medium","High"]
    )
    devices["vendor"] = devices["mac"].apply(get_mac_vendor)

    st.subheader("Devices by Risk")
    st.dataframe(devices.sort_values("risk_score", ascending=False), use_container_width=True)

    st.subheader("Top Devices by Event Count")
    top_devices = filtered.groupby("mac")["timestamp"].count().sort_values(ascending=False).head(10)
    st.bar_chart(top_devices)

# =====================================================
# ZEKE LOGS
# =====================================================
elif page == "Zeek Logs":
    st.title("Zeek Logs Explorer")
    all_log_files = list_all_logs(LOGS_DIR)
    selected_file = st.selectbox(
        "Select a log file to view",
        ["-- All Logs --"] + all_log_files
    )

    logs_to_show = pd.DataFrame()

    if selected_file == "-- All Logs --":
        all_rows = []
        for f_path in LOGS_DIR.rglob("*.*"):
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
                    row["log_file"] = str(f_path.relative_to(LOGS_DIR))
                    all_rows.append(row)
        if all_rows:
            logs_to_show = pd.DataFrame(all_rows)
    else:
        file_path = LOGS_DIR / selected_file
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
                    rows.append(row)
                logs_to_show = pd.DataFrame(rows)

    if "mac" in logs_to_show.columns:
        logs_to_show["status"] = logs_to_show["mac"].apply(
            lambda m: "Authorized" if m.lower() in authorized else "Unauthorized"
        )

    if logs_to_show.empty:
        st.warning("No logs found.")
    else:
        st.dataframe(logs_to_show, use_container_width=True)
        st.download_button(
            "Export CSV",
            logs_to_show.to_csv(index=False),
            f"{selected_file.replace('/','_') if selected_file != '-- All Logs --' else 'all_logs'}.csv"
        )

# =====================================================
# ALERTS
# =====================================================
elif page == "Alerts":
    st.title("Alerts")
    unauth = filtered[filtered["status"]=="Unauthorized"]

    if unauth.empty:
        st.success("No unauthorized activity detected")
    else:
        st.error(f"{unauth['mac'].nunique()} unauthorized devices detected")

    # New devices in last 24h
    new_devices = unauth.groupby("mac")["timestamp"].min()
    recent_new = new_devices[new_devices >= datetime.now() - pd.Timedelta(days=1)]
    st.write(f"New unauthorized devices in last 24h: {len(recent_new)}")
    st.dataframe(unauth.sort_values("timestamp", ascending=False), use_container_width=True)

# =====================================================
# AUTHORIZATION
# =====================================================
elif page == "Authorization":
    st.title("Authorized MACs")
    text = st.text_area(
        "Authorized MAC addresses",
        "\n".join(sorted(authorized)),
        height=300
    )
    if st.button("Save"):
        macs = {m.strip().lower() for m in text.splitlines() if m.strip()}
        with open(LOGS_DIR / "known_hosts.log", "w") as f:
            f.write("\n".join(sorted(macs)))
        st.success("Updated successfully")
        st.experimental_rerun()
