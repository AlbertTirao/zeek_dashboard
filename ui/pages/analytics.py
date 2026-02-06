# ui/pages/analytics.py
import streamlit as st
import pandas as pd
from pathlib import Path
from .shadow_apps import render_shadow_apps
from .shadow_uploads import render_shadow_uploads
from .shadow_ai import render_shadow_ai

# ---------------------------------------------------------
# Helper: Reconstruct 'filtered' device list from Parquet
# ---------------------------------------------------------
@st.cache_data(show_spinner=False)
def load_device_data(parquet_root: Path):
    """
    Loads known_hosts and dhcp from Parquet to create the device list
    needed by Shadow Uploads/AI tabs.
    """
    if not parquet_root.exists():
        return pd.DataFrame()

    # Load all known_hosts and dhcp files
    kh_dfs = []
    dhcp_dfs = []
    
    for date_dir in parquet_root.iterdir():
        if not date_dir.is_dir(): continue
        
        kh = date_dir / "known_hosts.parquet"
        dh = date_dir / "dhcp.parquet"
        
        if kh.exists(): kh_dfs.append(pd.read_parquet(kh))
        if dh.exists(): dhcp_dfs.append(pd.read_parquet(dh))

    # Merge logic (simplified)
    known_hosts = pd.concat(kh_dfs, ignore_index=True) if kh_dfs else pd.DataFrame()
    dhcp = pd.concat(dhcp_dfs, ignore_index=True) if dhcp_dfs else pd.DataFrame()
    
    if known_hosts.empty:
        return pd.DataFrame()

    # If we have DHCP, merge it in to get hostnames
    if not dhcp.empty and "client_addr" in dhcp.columns:
        # Deduplicate DHCP to latest hostname per IP
        dhcp_clean = dhcp.drop_duplicates(subset=["client_addr"], keep="last")
        # Ensure join keys match type
        if "host" in known_hosts.columns:
             merged = pd.merge(known_hosts, dhcp_clean, left_on="host", right_on="client_addr", how="left")
             return merged
    
    return known_hosts

# ---------------------------------------------------------
# Main Render
# ---------------------------------------------------------
def render(parquet_root: Path):
    st.set_page_config(page_title="Network Analytics", layout="wide")
    st.title("Network Analytics")

    if st.button("Refresh Analytics"):
        st.rerun()

    # 1. Load Device Data (for Uploads/AI tabs)
    filtered = load_device_data(parquet_root)

    # 2. Tabs
    tab = st.radio("Select Section", ["Shadow Apps", "Shadow Uploads", "Shadow AI"], horizontal=True)

    if tab == "Shadow Apps":
        # Pass the ROOT PATH, not the dataframes
        render_shadow_apps(parquet_root)
        
    elif tab == "Shadow Uploads":
        if filtered.empty:
            st.info("No device data available for Uploads analysis.")
        else:
            render_shadow_uploads(filtered)
            
    elif tab == "Shadow AI":
        if filtered.empty:
            st.info("No device data available for AI analysis.")
        else:
            render_shadow_ai(parquet_root)