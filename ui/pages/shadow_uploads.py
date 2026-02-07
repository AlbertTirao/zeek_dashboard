# ui/pages/shadow_uploads.py
import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
from .constants import MAX_ROWS_DISPLAY

# Approved/whitelisted domains - Keep this updated!
APPROVED_DOMAINS = ["google.com", "microsoft.com", "github.com", "slack.com", "internal-repo.local", "amazon.com", "azure.com"]

@st.cache_data(show_spinner=False)
def load_shadow_data(parquet_root: Path) -> pd.DataFrame:
    """
    Loads and combines multiple Zeek logs (HTTP, SSL, DNS) to identify 
    potential Shadow IT activity.
    """
    if not parquet_root.exists():
        return pd.DataFrame()

    all_logs = []
    # Targeted log types for Shadow IT
    log_types = ["http", "ssl", "dns", "files"]

    for date_dir in parquet_root.iterdir():
        if not date_dir.is_dir():
            continue
        
        for lt in log_types:
            p_file = date_dir / f"{lt}.parquet"
            if p_file.exists():
                df = pd.read_parquet(p_file)
                df["log_source"] = lt  # Tag the source
                all_logs.append(df)

    if not all_logs:
        return pd.DataFrame()

    full_df = pd.concat(all_logs, ignore_index=True)
    
    # Standardize columns across different log types
    if "ts" in full_df.columns:
        # Force conversion to datetime; turn errors (like '#types') into NaT
        full_df["ts"] = pd.to_datetime(full_df["ts"], errors='coerce')
        # Remove the rows that failed to parse (the header rows)
        full_df = full_df.dropna(subset=["ts"])
    
    # Create a unified 'destination' column
    # HTTP uses 'host', SSL uses 'server_name', DNS uses 'query'
    full_df["destination"] = full_df["host"].fillna(
        full_df.get("server_name", full_df.get("query", "unknown"))
    )
    
    return full_df

def render_shadow_uploads(parquet_root: Path):
    st.header("🕵️ Shadow IT & Unauthorized Uploads")
    st.markdown("Monitoring for unsanctioned cloud services and large data transfers.")

    raw_df = load_shadow_data(parquet_root)

    if raw_df.empty:
        st.warning("No network logs found for analysis.")
        return

    # --- Sidebar Filters ---
    st.sidebar.subheader("Shadow IT Filters")
    min_bytes = st.sidebar.slider("Min Upload Size (KB)", 0, 10000, 500)
    selected_sources = st.sidebar.multiselect("Log Sources", ["http", "ssl", "dns"], default=["http", "ssl", "dns"])

    # --- Shadow Detection Logic ---
    def is_shadow(dest):
        dest = str(dest).lower()
        if dest == "unknown" or dest == "nan": return False
        return not any(approved in dest for approved in APPROVED_DOMAINS)

    # Filter by whitelist and user selection
    shadow_df = raw_df[raw_df["destination"].apply(is_shadow)].copy()
    shadow_df = shadow_df[shadow_df["log_source"].isin(selected_sources)]
    
    # Calculate bytes for risk assessment (if available)
    shadow_df["bytes"] = shadow_df.get("request_body_len", 0).fillna(0) + shadow_df.get("orig_bytes", 0).fillna(0)

    if shadow_df.empty:
        st.success("No shadow activity detected for the current filters.")
        return

    # --- Key Metrics ---
    total_events = len(shadow_df)
    heavy_uploads = len(shadow_df[shadow_df["bytes"] > (min_bytes * 1024)])
    unique_apps = shadow_df["destination"].nunique()
    
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Shadow Hits", total_events)
    m2.metric("Unsanctioned Apps", unique_apps)
    m3.metric("Large Uploads (>{}KB)".format(min_bytes), heavy_uploads)
    m4.metric("Risk Level", "CRITICAL" if heavy_uploads > 5 else "STABLE")

    st.divider()

    # --- Visualizations ---
    c1, c2 = st.columns(2)

    with c1:
        # Treemap of Shadow Apps
        fig_tree = px.treemap(
            shadow_df, 
            path=["log_source", "destination"], 
            title="Shadow Traffic Distribution",
            template="plotly_dark",
            color_discrete_sequence=px.colors.qualitative.Pastel
        )
        st.plotly_chart(fig_tree, use_container_width=True)

    with c2:
        # Bytes over time
        if "ts" in shadow_df.columns:
            daily_bytes = shadow_df.set_index("ts").resample("1H")["bytes"].sum().reset_index()
            fig_area = px.area(
                daily_bytes, x="ts", y="bytes", 
                title="Data Transfer Volume (Shadow)",
                template="plotly_dark",
                color_discrete_sequence=["#EF553B"]
            )
            st.plotly_chart(fig_area, use_container_width=True)

    # --- Detailed Investigation Table ---
    st.subheader("Shadow Investigation Log")
    
    # Clean up table for display
    display_df = shadow_df[[
        "ts", "id.orig_h", "log_source", "destination", "bytes", "method"
    ]].fillna("-")
    
    # Add a Risk Badge based on size
    def assign_risk(b):
        if b > 1024*1024: return "CRITICAL (MB+)"
        if b > 100*1024: return "WARNING"
        return "MONITOR"

    display_df["Risk_Level"] = display_df["bytes"].apply(assign_risk)

    st.dataframe(
        display_df.sort_values("bytes", ascending=False).head(MAX_ROWS_DISPLAY),
        column_config={
            "ts": st.column_config.DatetimeColumn("Time"),
            "id.orig_h": "Source IP",
            "destination": "Target Domain",
            "bytes": st.column_config.NumberColumn("Transfer Size", format="%d bytes"),
            "Risk_Level": st.column_config.TextColumn("Security Risk"),
            "method": "Action"
        },
        use_container_width=True,
        hide_index=True
    )