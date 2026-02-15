# ui/pages/analytics.py
from datetime import datetime

import streamlit as st
import pandas as pd
from pathlib import Path
from .shadow_apps import render_shadow_apps
from .shadow_sharings import render_shadow_uploads
from .shadow_ai import render_shadow_ai


def inject_traffic_header_css():
    st.markdown(
        """
        <style>
        :root {
            --panel-border: rgba(255,255,255,0.12);
            --panel-bg: rgba(255,255,255,0.03);
            --panel-shadow: 0 14px 38px rgba(0,0,0,0.25);
            --accent-cyan: #00F7FF;
            --accent-red: #F63049;
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

        .tm-page-header {
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

        .tm-page-title {
            font-size: 46px;
            font-weight: 900;
            line-height: 1.0;
            letter-spacing: -0.5px;
        }

        .tm-page-sub {
            opacity: 0.74;
            font-size: 13px;
            margin-top: 6px;
        }

        .tm-header-chip {
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

        .tm-header-dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: var(--accent-cyan);
            box-shadow: 0 0 10px rgba(0,247,255,0.8);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

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
    # REMOVED st.set_page_config() - This must be at the very top of app.py, not here
    inject_traffic_header_css()
    updated_txt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.markdown(
        f"""
        <div class="tm-page-header">
          <div>
            <div class="tm-page-title">Traffic Monitoring</div>
            <div class="tm-page-sub">Shadow Apps, Shadow Sharings, and Shadow AI telemetry | Updated: <b>{updated_txt}</b></div>
          </div>
          <div class="tm-header-chip"><span class="tm-header-dot"></span>Network Monitoring</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("Refresh Analytics"):
        st.rerun()

    # 1. Load Device Data (Optional usage)
    filtered = load_device_data(parquet_root)

    # 2. Tabs
    tab = st.radio("Select Section", ["Shadow Apps", "Shadow Sharings", "Shadow AI"], horizontal=True)

    if tab == "Shadow Apps":
        # Correct: Passes Path
        render_shadow_apps(parquet_root)
        
    elif tab == "Shadow Sharings":
        # --- FIXED HERE ---
        # Was passing 'filtered' (DataFrame), now passing 'parquet_root' (Path)
        render_shadow_uploads(parquet_root)
            
    elif tab == "Shadow AI":
        # Correct: Passes Path
        render_shadow_ai(parquet_root)
