import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import requests

# =====================================================
# Load Visual Metrics from Parquet
# =====================================================
@st.cache_data(show_spinner=False)
def load_visual_metrics_from_parquet(parquet_root: Path):
    """
    Load ONLY the data needed by Visual metrics
    from Parquet instead of raw Zeek logs.
    """
    known_hosts_all = []
    dhcp_all = []

    if not parquet_root.exists():
        return pd.DataFrame(), pd.DataFrame()

    # Expect structure: data/parquet/YYYY-MM-DD/*.parquet
    for day_dir in sorted(p for p in parquet_root.iterdir() if p.is_dir()):
        kh = day_dir / "known_hosts.parquet"
        dh = day_dir / "dhcp.parquet"

        if kh.exists():
            known_hosts_all.append(pd.read_parquet(kh))

        if dh.exists():
            dhcp_all.append(pd.read_parquet(dh))

    known_hosts = (
        pd.concat(known_hosts_all, ignore_index=True)
        if known_hosts_all else pd.DataFrame()
    )

    dhcp = (
        pd.concat(dhcp_all, ignore_index=True)
        if dhcp_all else pd.DataFrame()
    )

    return known_hosts, dhcp

# =====================================================
# Drill-Down Log Loader
# =====================================================
@st.cache_data(show_spinner=False)
def get_device_activity(parquet_root: Path, target_mac: str, target_ip: str, selected_date_str: str):
    """
    Searches DNS, HTTP, and SSL logs for a specific MAC or IP.
    """
    activity_log = []
    
    # Format: (filename_prefix, service_name, detail_column)
    log_types = [
        ("dns", "DNS", "query"),
        ("http", "HTTP", "host"),
        ("ssl", "SSL", "server_name")
    ]

    # Filter for specific date if selected
    if selected_date_str and selected_date_str != "All Dates":
        day_dirs = [parquet_root / selected_date_str]
    else:
        # Scan all date folders
        day_dirs = sorted(p for p in parquet_root.iterdir() if p.is_dir())

    for day_dir in day_dirs:
        if not day_dir.exists(): continue
        
        for file_prefix, service, detail_col in log_types:
            pq_file = day_dir / f"{file_prefix}.parquet"
            if not pq_file.exists(): continue
            
            try:
                # Optimized load
                df = pd.read_parquet(pq_file)
                
                # Filter by MAC (priority) or IP
                filtered = pd.DataFrame()
                if "mac" in df.columns:
                    filtered = df[df["mac"].str.lower() == target_mac.lower()]
                elif "id.orig_h" in df.columns:
                    filtered = df[df["id.orig_h"] == target_ip]
                
                if filtered.empty: continue

                # Normalize columns
                if detail_col not in filtered.columns: filtered[detail_col] = "-"
                
                norm = pd.DataFrame()
                norm["ts"] = filtered["ts"]
                norm["Service"] = service
                norm["Destination"] = filtered[detail_col]
                
                # Add context details
                if service == "HTTP" and "uri" in filtered.columns:
                    norm["Details"] = filtered["uri"]
                elif service == "DNS" and "qtype_name" in filtered.columns:
                    norm["Details"] = filtered["qtype_name"]
                elif service == "SSL" and "version" in filtered.columns:
                    norm["Details"] = filtered["version"]
                else:
                    norm["Details"] = "-"

                activity_log.append(norm)

            except Exception:
                continue

    if not activity_log:
        return pd.DataFrame()

    final_df = pd.concat(activity_log, ignore_index=True)
    final_df["ts"] = pd.to_numeric(final_df["ts"], errors='coerce')
    final_df["ts"] = pd.to_datetime(final_df["ts"], unit="s")
    
    return final_df.sort_values("ts", ascending=False)

# =====================================================
# MAC vendor lookup
# =====================================================
@st.cache_data(show_spinner=False)
def get_mac_vendor(mac: str) -> str:
    if not mac or mac == "unknown":
        return "Unknown"
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text if r.status_code == 200 else "Unknown"
    except Exception:
        return "Unknown"

# =====================================================
# Load authorized MACs
# =====================================================
def load_authorized_macs(file_path: Path) -> set:
    if not file_path.exists():
        st.warning("authorized_macs.txt not found — all devices Unauthorized")
        return set()
    with open(file_path, "r") as f:
        return {line.strip().lower() for line in f if line.strip()}

# =====================================================
# Main Render Function
# =====================================================
def render(logs_root: Path, authorized_mac_file: Path):
    st.set_page_config(page_title="Network Overview", layout="wide")
    st.title("Device Overview")

    PARQUET_ROOT = Path("data/parquet")

    known_hosts, dhcp = load_visual_metrics_from_parquet(PARQUET_ROOT)
    authorized_macs = load_authorized_macs(authorized_mac_file)
    
    if known_hosts.empty:
        st.info("No device data available")
        return

    # Merge DHCP Data
    if not dhcp.empty:
        dhcp_cols = [c for c in ["client_addr","host_name","domain"] if c in dhcp.columns]
        dhcp_norm = dhcp[dhcp_cols].drop_duplicates(subset=["client_addr"])
        merged = pd.merge(known_hosts, dhcp_norm, how="left", left_on="host", right_on="client_addr")
    else:
        merged = known_hosts.copy()
        merged["host_name"], merged["domain"] = "-", None

    merged["host_name"] = merged.get("host_name","-").fillna("-")
    merged["mac"] = merged["mac"].str.lower().str.strip()
    merged["status"] = merged["mac"].apply(lambda m: "Authorized" if m in authorized_macs else "Unauthorized")

    # ---------------------------------------------------------
    # Force 'ts' to datetime
    # ---------------------------------------------------------
    if "ts" in merged.columns and not merged.empty:
        merged["ts"] = pd.to_numeric(merged["ts"], errors='coerce')
        merged["ts"] = pd.to_datetime(merged["ts"], unit="s", errors='coerce')
        merged = merged.dropna(subset=["ts"])
        merged["date"] = merged["ts"].dt.date

    # Metrics
    total_unique = merged["mac"].nunique()
    auth_unique = merged[merged["status"]=="Authorized"]["mac"].nunique()
    unauth_unique = merged[merged["status"]=="Unauthorized"]["mac"].nunique()
    risk_ratio = round((unauth_unique/total_unique*100),2) if total_unique else 0

    # ---------- Metrics Cards ----------
    m1, m2, m3, m4 = st.columns(4)
    m1.markdown(f"<div><h4 style='margin:2px'>Active Devices</h4><h3 style='margin:2px'>{total_unique}</h3></div>", unsafe_allow_html=True)
    m2.markdown(f"<div><h4 style='margin:2px'>Authorized</h4><h3 style='margin:2px'>{auth_unique}</h3></div>", unsafe_allow_html=True)
    m3.markdown(f"<div><h4 style='margin:2px'>Unauthorized</h4><h3 style='margin:2px'>{unauth_unique}</h3></div>", unsafe_allow_html=True)
    m4.markdown(f"<div><h4 style='margin:2px'>Risk Ratio</h4><h3 style='margin:2px'>{risk_ratio}%</h3></div>", unsafe_allow_html=True)

    st.markdown("---")

    # ---------- Activity Overview ----------
    st.subheader("Activity Overview")
    
    hourly = pd.DataFrame()
    if not merged.empty and "ts" in merged.columns:
        try:
            hourly = merged.set_index("ts").groupby("status").resample("1H").size().reset_index(name="events")
        except TypeError as e:
            st.error(f"Error resampling data (Check timestamp format): {e}")

    if not hourly.empty:
        line_fig = px.line(
            hourly, x="ts", y="events", color="status",
            color_discrete_map={"Authorized":"#00F7FF","Unauthorized":"#F63049"},
            template="plotly_dark"
        )
        line_fig.update_layout(
            xaxis_title=None, yaxis_title="Events", legend_title=None,
            margin=dict(l=20, r=20, t=40, b=20), height=480,
            xaxis={"tickfont":{"size":14}}, yaxis={"tickfont":{"size":14}}, legend={"font":{"size":14}}     
        )
        st.plotly_chart(line_fig, use_container_width=True)

    # ---------- Unauthorized Device Ratio Gauge ----------
    st.markdown("<h2 style='color:white; text-align:left;'>Unauthorized Device Ratio</h2>", unsafe_allow_html=True)
    
    warning_text, warning_color, warning_icon = "STATUS: SAFE", "#6CA651", "✅"
    if risk_ratio > 20: warning_text, warning_color, warning_icon = "STATUS: WARNING", "#F3AE4B", "⚠️"
    if risk_ratio > 50: warning_text, warning_color, warning_icon = "STATUS: HIGH RISK", "#D63447", "🛑"

    gauge_fig = go.Figure()
    gauge_fig.add_trace(go.Indicator(
        mode="gauge+number", value=risk_ratio, number={"suffix":"%", "font":{"size":48}}, 
        gauge={
            "axis":{"range":[0,100], "tickfont":{"size":16}}, "bar":{"color":"#30C1F6"},
            "steps":[{"range":[0,20],"color":"#6CA651"},{"range":[20,50],"color":"#F3AE4B"},{"range":[50,100],"color":"#D63447"}],
            "threshold":{"line":{"color":"white","width":2},"thickness":0.75,"value":50}
        }
    ))
    for label, color in [('Current Level','#30C1F6'), ('Safe (0-20%)','#6CA651'), ('Warning (20-50%)','#F3AE4B'), ('High Risk (50%+)','#D63447')]:
        gauge_fig.add_trace(go.Scatter(x=[None], y=[None], mode='markers', marker=dict(size=10, color=color), name=label))

    gauge_fig.add_annotation(x=0.5, y=0.15, text=f"<b>{warning_icon} {warning_text}</b>", showarrow=False, font=dict(size=20, color=warning_color))
    gauge_fig.update_layout(
        template="plotly_dark", height=450, margin=dict(l=50, r=50, t=80, b=50),
        legend=dict(orientation="v", yanchor="top", y=1.0, xanchor="right", x=1.0, font=dict(size=12)),
        xaxis={'visible': False}, yaxis={'visible': False}
    )
    st.plotly_chart(gauge_fig, use_container_width=True)

    # ---------- Device Count Bar Chart ----------
    st.markdown("<h2 style='color:white; text-align:left;'>Device Count</h2>", unsafe_allow_html=True)
    
    if "ts" in merged.columns and not merged.empty:
        daily_count = merged.drop_duplicates(subset=["mac","date"]).groupby(["date","status"]).size().reset_index(name="devices")
        bar_fig = px.bar(
            daily_count, x="date", y="devices", color="status", barmode="stack",
            color_discrete_map={"Authorized":"#00F7FF","Unauthorized":"#F63049"},
            template="plotly_dark", labels={"devices":"Devices","date":"Date"}
        )
        bar_fig.update_layout(height=500, margin=dict(l=20, r=20, t=50, b=100), xaxis={"tickfont":{"size":14}}, yaxis={"tickfont":{"size":14}}, legend={"font":{"size":14}})
        st.plotly_chart(bar_fig, use_container_width=True)

    # =====================================================
    # DEVICE INVENTORY TABLE
    # =====================================================
    st.markdown("---")
    st.title("Device Inventory")

    # 1. Prepare Date Options (Used for both inventory and drill-down)
    available_dates = []
    if "date" in merged.columns:
        available_dates = sorted([d for d in merged["date"].unique() if pd.notnull(d)], reverse=True)
    date_options = ["All Dates"] + [str(d) for d in available_dates]

    # 2. Main Filter Row
    master_col1, master_col2, master_col3 = st.columns([1, 1.5, 2.5], gap="medium", vertical_alignment="bottom")

    with master_col1:
        selected_date_str = st.selectbox("Select Date", options=date_options, index=0)
    
    with master_col2:
        status_filter = st.radio(
            "Show Access:",
            ["Authorized", "Unauthorized"],
            horizontal=True,
            index=0
        )

    # 3. Apply Date Filter to INVENTORY
    if selected_date_str == "All Dates":
        table_df = merged.copy()
    else:
        table_df = merged[merged["date"].astype(str) == selected_date_str]

    with master_col3:
        with st.form(key="search_form", border=False):
            s_input_col, s_btn_col = st.columns([4, 1], gap="small", vertical_alignment="bottom")
            with s_input_col:
                search_term = st.text_input("Search", placeholder="🔍 Search MAC / IP / Host...", label_visibility="visible")
            with s_btn_col:
                submit_button = st.form_submit_button("Search", use_container_width=True)

    # 5. Table Display
    if not table_df.empty:
        inventory = (
            table_df.groupby("mac")
            .agg(
                ip=("host", "last"),
                host_name=("host_name", "last"),
                domain=("domain", "last"),
                first_seen=("ts", "min"),
                last_seen=("ts", "max"),
                status=("status", "first")
            )
            .reset_index()
        )
        
        inventory["vendor"] = inventory["mac"].apply(get_mac_vendor)

        if status_filter == "Authorized":
            inventory = inventory[inventory["status"] == "Authorized"]
        else:
            inventory = inventory[inventory["status"] == "Unauthorized"]

        if search_term:
            inventory = inventory[
                inventory.astype(str)
                .apply(lambda c: c.str.contains(search_term, case=False, na=False))
                .any(axis=1)
            ]

        def color_status(val):
            if val == "Authorized":
                return 'color: #81c995; font-weight: bold'
            elif val == "Unauthorized":
                return 'color: #ff6666; font-weight: bold'
            return ''

        styled_inventory = inventory.style.map(color_status, subset=['status'])

        st.dataframe(
            styled_inventory,
            column_config={
                "mac": "MAC Address",
                "ip": "IP Address",
                "host_name": "Host Name",
                "domain": "Domain",
                "vendor": "Vendor",
                "first_seen": st.column_config.DatetimeColumn("First Seen", format="YYYY-MM-DD HH:mm:ss"),
                "last_seen": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD HH:mm:ss"),
                "status": "Access Status",
            },
            use_container_width=True,
            hide_index=True
        )

        # =====================================================
        # NEW FEATURE: DRILL DOWN (Below the table)
        # =====================================================
        st.markdown("---")
        st.subheader("Device Forensics")
        
        # 1. Selection Dropdown (MACs)
        inventory["display_label"] = inventory["mac"]
        selected_device_mac = st.selectbox(
            "1. Select a device to investigate:",
            options=inventory["display_label"].tolist(),
            index=None,
            placeholder="Select a MAC address..."
        )

        if selected_device_mac:
            target_mac = selected_device_mac
            target_ip = ""
            try:
                target_ip = inventory[inventory["mac"] == target_mac]["ip"].values[0]
            except IndexError:
                pass 

            # Layout: Date Selection & Service Filter
            c_date, c_filter = st.columns([1, 2], gap="large")
            with c_date:
                drill_down_date = st.selectbox(
                    "2. Select Activity Date:",
                    options=date_options,
                    index=0 
                )
            
            with c_filter:
                service_view = st.radio(
                    "3. Filter View by Service:",
                    ["All Services", "DNS", "HTTP", "SSL"],
                    horizontal=True,
                    index=0
                )

            with st.spinner(f"Fetching logs for {target_mac} on {drill_down_date}..."):
                activity_df = get_device_activity(PARQUET_ROOT, target_mac, target_ip, drill_down_date)

            if not activity_df.empty:
                # --- FILTERING LOGIC ---
                filtered_activity = activity_df.copy()
                
                if service_view != "All Services":
                    filtered_activity = filtered_activity[filtered_activity["Service"] == service_view]

                # --- TOP DESTINATIONS TABLE (Full Width) ---
                top_sites = filtered_activity["Destination"].value_counts().head(5)
                
                st.markdown(f"#### Top Destinations ({service_view})")
                if not top_sites.empty:
                    st.dataframe(top_sites, use_container_width=True)
                else:
                    st.info("No activity for this service.")
                
                # --- DYNAMIC CHART (Full Width, Below Table) ---
                st.markdown("#### Traffic Activity Graph")
                # Define colors to match your theme
                color_map = {"DNS": "#F63049", "HTTP": "#00F7FF", "SSL": "#F3AE4B"}
                
                if service_view == "All Services":
                    # Resample data for a multi-line graph (Event count over time)
                    # We use a 10-minute frequency to avoid overflowing and keep lines distinct
                    line_data = (
                        filtered_activity.set_index("ts")
                        .groupby("Service")
                        .resample("10min")
                        .size()
                        .reset_index(name="Events")
                    )
                    
                    fig = px.line(
                        line_data, x="ts", y="Events", color="Service",
                        color_discrete_map=color_map,
                        title=f"Activity Timeline (All Services): {target_mac}",
                        template="plotly_dark"
                    )
                    # Add area fill to match your "on fire" look
                    fig.update_traces(mode="lines", fill='tozeroy') 
                else:
                    # SPECIFIC SERVICE: Volume Area/Line Chart for just one color
                    volume_df = (
                        filtered_activity.set_index("ts")
                        .resample("10min")
                        .size()
                        .reset_index(name="Events")
                    )
                    
                    fig = px.area(
                        volume_df, x="ts", y="Events",
                        title=f"{service_view} Traffic Volume (Events / 10min)",
                        template="plotly_dark"
                    )
                    fig.update_traces(line_color=color_map.get(service_view, "#ffffff"))

                # Increased Font Sizes and Layout adjustments to prevent overflow
                fig.update_layout(
                    template="plotly_dark", 
                    height=450, 
                    font=dict(size=16), 
                    legend=dict(
                        orientation="h",    # Horizontal legend to prevent side overflow
                        yanchor="bottom",
                        y=1.02,
                        xanchor="right",
                        x=1,
                        font=dict(size=14)
                    ),
                    margin=dict(l=50, r=50, t=80, b=50), # Add padding
                    xaxis=dict(
                        tickfont=dict(size=14), 
                        title="Timestamp",
                        showgrid=True,
                        gridcolor='rgba(255,255,255,0.1)'
                    ),
                    yaxis=dict(
                        tickfont=dict(size=14), 
                        title="Events Count",
                        showgrid=True,
                        gridcolor='rgba(255,255,255,0.1)'
                    )
                )
                st.plotly_chart(fig, use_container_width=True)