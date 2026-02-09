# ui/pages/shadow_uploads.py
import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path

# --- Constants ---
APPROVED_DOMAINS = ["google.com", "microsoft.com", "github.com", "slack.com", "amazon.com", "azure.com"]
try:
    from .constants import MAX_ROWS_DISPLAY
except ImportError:
    MAX_ROWS_DISPLAY = 1000

# --- Helper: Load IP -> MAC -> HOSTNAME Mapping ---
@st.cache_data(show_spinner=False)
def load_device_mapping(parquet_root: Path, selected_date: str) -> pd.DataFrame:
    mapping_logs = []
    
    if selected_date and selected_date != "All Available Dates":
        target_dirs = [parquet_root / selected_date]
    else:
        target_dirs = [d for d in parquet_root.iterdir() if d.is_dir()]

    for date_dir in target_dirs:
        # 1. Check DHCP (Best for Hostnames)
        dhcp_path = date_dir / "dhcp.parquet"
        if dhcp_path.exists():
            try:
                # Load hostname if available
                cols = ["id.orig_h", "mac"]
                df_temp = pd.read_parquet(dhcp_path)
                
                # Check if host_name exists in this file
                if "host_name" in df_temp.columns:
                    cols.append("host_name")
                
                df = df_temp[cols].copy()
                df = df.rename(columns={"id.orig_h": "ip"}).dropna(subset=["ip"])
                
                # Normalize types to string to ensure merge works
                df["ip"] = df["ip"].astype(str)
                mapping_logs.append(df)
            except: pass
            
        # 2. Check Conn (Fallback for MACs)
        conn_path = date_dir / "conn.parquet"
        if conn_path.exists():
            try:
                df = pd.read_parquet(conn_path, columns=["id.orig_h", "orig_l2_addr"])
                df = df.rename(columns={"id.orig_h": "ip", "orig_l2_addr": "mac"}).dropna()
                df["ip"] = df["ip"].astype(str)
                mapping_logs.append(df)
            except: pass

    if not mapping_logs:
        return pd.DataFrame(columns=["ip", "mac", "host_name"])

    full_map = pd.concat(mapping_logs, ignore_index=True)
    
    # Clean duplicates, keeping the most complete info (last seen)
    if "host_name" not in full_map.columns:
        full_map["host_name"] = "Unknown"
        
    return full_map.drop_duplicates(subset=["ip"], keep="last")

# --- Helper: Load Traffic Data ---
@st.cache_data(show_spinner=False)
def load_shadow_data(parquet_root: Path, selected_date: str) -> pd.DataFrame:
    if not parquet_root.exists():
        return pd.DataFrame()

    all_logs = []
    log_types = ["http", "ssl", "dns"]
    
    if selected_date and selected_date != "All Available Dates":
        target_dirs = [parquet_root / selected_date]
    else:
        target_dirs = [d for d in parquet_root.iterdir() if d.is_dir()]

    for date_dir in target_dirs:
        if not date_dir.exists(): continue
        for lt in log_types:
            p_file = date_dir / f"{lt}.parquet"
            if p_file.exists():
                try:
                    df = pd.read_parquet(p_file)
                    df["log_source"] = lt 
                    all_logs.append(df)
                except: continue 

    if not all_logs:
        return pd.DataFrame()

    full_df = pd.concat(all_logs, ignore_index=True)
    
    # Clean Timestamp
    if "ts" in full_df.columns:
        full_df["ts"] = pd.to_numeric(full_df["ts"], errors='coerce')
        full_df["ts"] = pd.to_datetime(full_df["ts"], unit="s", errors="coerce")
        full_df = full_df.dropna(subset=["ts"])
    
    # Ensure Destination Exists
    for col in ["host", "server_name", "query"]:
        if col not in full_df.columns:
            full_df[col] = None

    full_df["destination"] = full_df["host"].fillna(
        full_df["server_name"].fillna(full_df["query"])
    ).fillna("Unknown")
    
    full_df["destination"] = full_df["destination"].replace("", "Unknown")
    
    # Ensure IP is string for merging
    if "id.orig_h" in full_df.columns:
        full_df["id.orig_h"] = full_df["id.orig_h"].astype(str)

    return full_df

# --- Main Render Function ---
def render_shadow_uploads(parquet_root: Path):
    st.markdown("#### Shadow IT & Data Exfiltration Monitor")
    
    if not parquet_root.exists():
        st.error("Data directory not found.")
        return

    available_dates = sorted([d.name for d in parquet_root.iterdir() if d.is_dir()], reverse=True)
    if not available_dates:
        st.warning("No logs found.")
        return

    # --- CONTROLS ---
    r1_c1, r1_c2 = st.columns([5, 1])
    with r1_c1:
        date_options = ["All Available Dates"] + available_dates
        selected_date = st.selectbox("Timeframe", date_options, index=1 if len(available_dates)>0 else 0)
    with r1_c2:
        st.write("") 
        st.write("") 
        if st.button("Refresh"):
            st.cache_data.clear()
            st.rerun()
            
    r2_c1, r2_c2 = st.columns([4, 2])
    with r2_c1:
        selected_sources = st.multiselect("Protocols", ["http", "ssl", "dns"], default=["http", "ssl", "dns"])
    with r2_c2:
        st.write("") 
        st.write("")
        exclude_whitelisted = st.checkbox("Hide Approved Domains", value=False)
        
    st.divider()

    # --- LOADING ---
    with st.spinner("Analyzing network traffic..."):
        raw_df = load_shadow_data(parquet_root, selected_date)
        device_map_df = load_device_mapping(parquet_root, selected_date)

    if raw_df.empty:
        st.info(f"No traffic logs found for {selected_date}.")
        return

    # --- CALCULATIONS ---
    if "request_body_len" in raw_df.columns:
        bytes_http = pd.to_numeric(raw_df["request_body_len"], errors='coerce').fillna(0)
    else:
        bytes_http = 0

    if "orig_bytes" in raw_df.columns:
        bytes_conn = pd.to_numeric(raw_df["orig_bytes"], errors='coerce').fillna(0)
    else:
        bytes_conn = 0
        
    raw_df["bytes"] = bytes_http + bytes_conn

    # --- FILTERING ---
    shadow_df = raw_df[raw_df["log_source"].isin(selected_sources)].copy()
    
    if exclude_whitelisted:
        def is_shadow(dest):
            dest = str(dest).lower()
            if dest in ["unknown", "nan", ""]: return False
            return not any(approved in dest for approved in APPROVED_DOMAINS)
        shadow_df = shadow_df[shadow_df["destination"].apply(is_shadow)]

    # --- MERGING HOSTNAMES & MACS ---
    if not device_map_df.empty and "id.orig_h" in shadow_df.columns:
        shadow_df = shadow_df.merge(device_map_df, left_on="id.orig_h", right_on="ip", how="left")
        shadow_df["mac"] = shadow_df["mac"].fillna("Unknown Device")
        # Fallback: If host_name is missing, try to use MAC, else "Unknown"
        shadow_df["host_name"] = shadow_df.get("host_name", "Unknown").fillna("Unknown")
    else:
        shadow_df["mac"] = "No MAC Data"
        shadow_df["host_name"] = "Unknown"

    if shadow_df.empty:
        st.warning("No data matches your filters.")
        return

    # --- ALERTS ---
    high_risk = shadow_df[shadow_df["bytes"] > 100 * 1024 * 1024]
    if not high_risk.empty:
        count = len(high_risk)
        target = high_risk.iloc[0]['destination']
        st.error(f"High Risk Alert: {count} large file transfers detected. (Target: {target})")

    # --- TABS ---
    tab_overview, tab_device, tab_details = st.tabs(["Overview", "By Device", "Event Log"])

    with tab_overview:
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Events", len(shadow_df))
        m2.metric("Unique Devices", shadow_df["id.orig_h"].nunique())
        
        total_b = shadow_df['bytes'].sum()
        size_str = f"{total_b/1024**2:.2f} MB" if total_b > 1024**2 else f"{total_b/1024:.2f} KB"
        m3.metric("Total Volume", size_str)
        
        top_dest = shadow_df["destination"].mode()
        m4.metric("Top Target", top_dest[0] if not top_dest.empty else "-")

        c_left, c_right = st.columns(2)
        with c_left:
            st.markdown("#### Destination Breakdown")
            if not shadow_df.empty:
                fig_tree = px.treemap(
                    shadow_df, 
                    path=["log_source", "destination"], 
                    values="bytes",
                    color="log_source",
                    color_discrete_sequence=px.colors.qualitative.Pastel
                )
                st.plotly_chart(fig_tree, use_container_width=True)
        
        with c_right:
            st.markdown("#### Protocol Usage")
            if not shadow_df.empty:
                fig_donut = px.pie(
                    shadow_df, 
                    names="log_source", 
                    values="bytes", 
                    hole=0.4,
                    color_discrete_sequence=px.colors.qualitative.Bold
                )
                st.plotly_chart(fig_donut, use_container_width=True)

        st.markdown("#### Traffic Timeline")
        if not shadow_df.empty:
            fig_scatter = px.scatter(
                shadow_df,
                x="ts",
                y="bytes",
                color="log_source",
                size="bytes",
                hover_data=["destination", "id.orig_h", "host_name"],
                template="plotly_dark"
            )
            st.plotly_chart(fig_scatter, use_container_width=True)

    with tab_device:
        st.markdown("#### Device Forensics")
        
        # Group by MAC and Hostname
        mac_stats = shadow_df.groupby(["mac", "host_name"]).agg({
            "bytes": "sum",
            "destination": "nunique",
            "id.orig_h": "first"
        }).reset_index().sort_values("bytes", ascending=False)
        
        fig_mac = px.bar(
            mac_stats,
            x="mac",
            y="bytes",
            color="bytes",
            text="host_name", # Show hostname on bars
            title="Total Data Transfer by Device",
            labels={"mac": "Physical Address", "bytes": "Total Bytes", "host_name": "Device Name"},
            template="plotly_dark",
            color_continuous_scale="Reds"
        )
        st.plotly_chart(fig_mac, use_container_width=True)

        st.dataframe(
            mac_stats,
            column_config={
                "mac": "MAC Address",
                "host_name": "Device Name",
                "bytes": st.column_config.ProgressColumn("Volume", format="%d", min_value=0, max_value=int(mac_stats["bytes"].max())),
                "destination": "Apps Accessed",
                "id.orig_h": "IP Address"
            },
            use_container_width=True
        )

    with tab_details:
        c_head, c_btn = st.columns([4, 1])
        with c_head:
            st.markdown("#### Detailed Event Log")
        
        # ADDED 'mac' here specifically
        target_cols = ["ts", "host_name", "mac", "id.orig_h", "destination", "bytes", "log_source"]
        
        # Double check columns exist before selecting
        final_cols = [c for c in target_cols if c in shadow_df.columns]
        
        export_df = shadow_df[final_cols].sort_values("bytes", ascending=False)

        def get_risk_badge(b):
            if b > 50 * 1024 * 1024: return "CRITICAL"
            if b > 10 * 1024 * 1024: return "WARNING"
            return "OK"
        
        export_df["Risk"] = export_df["bytes"].apply(get_risk_badge)
        
        # --- FIX: CREATE A REAL URL COLUMN ---
        # We replace the text in 'destination' with the URL, 
        # but we use LinkColumn(display_text) to make it look clean.
        export_df["scan_url"] = "https://www.virustotal.com/gui/domain/" + export_df["destination"].astype(str)

        with c_btn:
             csv_data = export_df.to_csv(index=False).encode('utf-8')
             st.download_button("Export CSV", csv_data, "security_log.csv", "text/csv")

        st.dataframe(
            export_df.head(MAX_ROWS_DISPLAY),
            column_config={
                "ts": st.column_config.DatetimeColumn("Timestamp", format="MM-DD HH:mm:ss"),
                "host_name": "Device Name",
                "mac": "MAC Address", # ADDED MAC ADDRESS
                "id.orig_h": "Source IP",
                "scan_url": st.column_config.LinkColumn(
                    "Destination", 
                    display_text="https://www.virustotal.com/gui/domain/(.*)", # Regex to hide the long URL and show just domain
                    help="Click to scan this domain on VirusTotal"
                ),
                "bytes": st.column_config.NumberColumn("Size (B)", format="%d"),
                "Risk": st.column_config.TextColumn("Risk Level"),
            },
            # Hide the raw 'destination' text column since we have the link now
            column_order=["ts", "host_name", "mac", "id.orig_h", "scan_url", "bytes", "Risk", "log_source"],
            use_container_width=True,
            hide_index=True
        )