import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path

# =====================================================
# Helper: get latest folder by date in name
# =====================================================
def get_latest_folder(root: Path, suffix="-CSV"):
    folders = [f for f in root.iterdir() if f.is_dir() and f.name.endswith(suffix)]
    if not folders:
        return None
    # Try parsing date from folder name
    def folder_date(f):
        try:
            return pd.to_datetime(f.name.replace(suffix, ""), errors="coerce")
        except:
            return pd.Timestamp.min
    folders.sort(key=folder_date, reverse=True)
    return folders[0]

# ======================================================
# Load latest known_hosts.csv and DHCP CSV
# =====================================================
logs_root = Path("logs")
latest_folder = get_latest_folder(logs_root)

known_hosts_file = None
dhcp_file = None

if latest_folder:
    # Pick the most recently modified CSVs inside the folder
    known_hosts_candidates = list(latest_folder.glob("known_hosts*.csv"))
    dhcp_candidates = list(latest_folder.glob("dhcp*.csv"))

    if known_hosts_candidates:
        known_hosts_file = max(known_hosts_candidates, key=lambda f: f.stat().st_mtime)
    if dhcp_candidates:
        dhcp_file = max(dhcp_candidates, key=lambda f: f.stat().st_mtime)
else:
    st.warning("No daily CSV folders found")

# =====================================================
# Load known_hosts
# =====================================================
known_hosts = pd.DataFrame()
if known_hosts_file and known_hosts_file.exists():
    known_hosts = pd.read_csv(known_hosts_file)
    if not {"ts", "host", "mac"}.issubset(known_hosts.columns):
        st.warning(f"known_hosts.csv missing expected columns: {known_hosts.columns}")
        known_hosts = pd.DataFrame()
else:
    st.warning("No known_hosts.csv found")

# =====================================================
# Load DHCP CSV
# =====================================================
dhcp = pd.DataFrame()
if dhcp_file and dhcp_file.exists():
    dhcp = pd.read_csv(dhcp_file)
    if not {"client_addr", "host_name", "domain"}.issubset(dhcp.columns):
        st.warning(f"DHCP CSV missing expected columns: {dhcp.columns}")
        dhcp = pd.DataFrame()
else:
    st.warning("No DHCP CSV found")

# =====================================================
# Load authorized MACs
# =====================================================
authorized_mac_file = Path("authorized_macs.txt")
authorized_macs = set()
if authorized_mac_file.exists():
    with open(authorized_mac_file, "r") as f:
        authorized_macs = set(line.strip().lower() for line in f if line.strip())
else:
    st.warning("authorized_macs.txt not found, all devices will show as Unauthorized")

# =====================================================
# Render Overview
# =====================================================
def render(_):
    st.title("Network Overview")

    if known_hosts.empty:
        st.info("No device data available")
        return

    # Merge known_hosts with DHCP
    if not dhcp.empty:
        merged = pd.merge(
            known_hosts,
            dhcp[["client_addr", "host_name", "domain"]],
            how="left",
            left_on="host",
            right_on="client_addr"
        )
    else:
        merged = known_hosts.copy()
        merged["host_name"] = "-"
        merged["domain"] = None

    merged["host_name"] = merged["host_name"].fillna("-")
    merged["mac"] = merged["mac"].str.lower().str.strip()
    merged["ts"] = pd.to_datetime(merged["ts"], errors="coerce")

    # Set status
    merged["status"] = merged["mac"].apply(
        lambda m: "Authorized" if m in authorized_macs else "Unauthorized"
    )

    # Count metrics
    total = merged["mac"].nunique()
    auth = merged[merged["status"] == "Authorized"]["mac"].nunique()
    unauth = merged[merged["status"] == "Unauthorized"]["mac"].nunique()
    percent_unauth = round((unauth / total * 100), 2) if total > 0 else 0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Active Devices", total)
    col2.metric("Authorized", auth)
    col3.metric("Unauthorized", unauth, delta_color="inverse")
    col4.metric("Risk Ratio", f"{percent_unauth}%", delta_color="inverse")

    # Timeline chart
    st.markdown("### Activity Timeline")
    hourly = (
        merged.set_index("ts")
        .groupby("status")
        .resample("1H")
        .size()
        .reset_index(name="events")
    )
    if not hourly.empty:
        fig = px.line(
            hourly,
            x="ts",
            y="events",
            color="status",
            color_discrete_map={"Authorized": "#10B981", "Unauthorized": "#f43f5e"},
            template="plotly_dark"
        )
        fig.update_layout(xaxis_title=None, yaxis_title="Events")
        st.plotly_chart(fig, use_container_width=True)
