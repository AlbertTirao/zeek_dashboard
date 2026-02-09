#ui/pages/devices
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import requests
import yaml 

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
# Load authorized MACs (FIXED FOR DICTIONARY STRUCTURE)
# =====================================================
def load_authorized_macs(file_path: Path) -> set:
    """
    Loads authorized MACs from YAML.
    Handles:
    1. Simple Lists: ["mac1", "mac2"]
    2. Dict with List: {"filename": ["mac1", ...]}
    3. List of Dicts (NEW STRUCTURE): [{"mac": "...", "ip": "..."}, ...]
    """
    # Auto-fix extension: If .txt is passed but .yaml exists, switch to .yaml
    if file_path.suffix == ".txt":
        yaml_path = file_path.with_suffix(".yaml")
        if yaml_path.exists():
            file_path = yaml_path

    if not file_path.exists():
        # Fallback: Create empty if missing
        try:
            file_path.parent.mkdir(exist_ok=True, parents=True)
            with open(file_path, "w") as f:
                yaml.safe_dump([], f)
        except: pass
        st.warning(f"Authorized file not found ({file_path.name}) — all devices Unauthorized")
        return set()

    try:
        with open(file_path, "r") as f:
            data = yaml.safe_load(f)

        if data is None: 
            return set()

        raw_list = []

        # Case A: Data is a List (Could be list of strings OR list of dicts)
        if isinstance(data, list):
            raw_list = data

        # Case B: Data is a Dict (Look for the list inside)
        elif isinstance(data, dict):
            # Try to find list by filename key
            if file_path.stem in data and isinstance(data[file_path.stem], list):
                raw_list = data[file_path.stem]
            else:
                # Fallback: Scan values for any list
                for val in data.values():
                    if isinstance(val, list):
                        raw_list = val
                        break
        
        # Process the raw list to extract just the MAC strings
        final_macs = set()
        for item in raw_list:
            if isinstance(item, str):
                # Old format: just a string
                if item.strip():
                    final_macs.add(item.strip().lower())
            elif isinstance(item, dict):
                # New format: Dict with 'mac' key
                mac_val = item.get("mac")
                if mac_val and isinstance(mac_val, str) and mac_val.strip():
                    final_macs.add(mac_val.strip().lower())

        return final_macs

    except Exception as e:
        st.error(f"Error reading YAML: {e}")
        return set()

# =====================================================
# Main Render Function
# =====================================================
def render(logs_root: Path, authorized_mac_file: Path):
    st.set_page_config(page_title="Network Overview", layout="wide")
    
    # ---------------------------------------------------------
    # CSS: Force Metric Value and Delta to be on the same row
    # ---------------------------------------------------------
    st.markdown("""
    <style>
    /* Target the container for the metric value and delta */
    [data-testid="stMetric"] > div {
        width: fit-content;
        margin-right: auto;
    }

    /* Force the value and delta into a single row using a grid */
    [data-testid="stMetricValue"] {
        display: grid !important;
        grid-template-columns: auto auto; /* Number first, then Delta */
        align-items: baseline;
        column-gap: 15px; /* Adjust spacing between number and delta */
        width: max-content;
    }

    /* Adjust delta text size and ensure it doesn't wrap */
    [data-testid="stMetricDelta"] {
        white-space: nowrap !important;
        font-size: 16px !important;
    }
    </style>
    """, unsafe_allow_html=True)

    st.title("Device Overview")

    PARQUET_ROOT = Path("data/parquet")

    known_hosts, dhcp = load_visual_metrics_from_parquet(PARQUET_ROOT)
    
    # Load from YAML now
    authorized_macs = load_authorized_macs(authorized_mac_file)
    
    if known_hosts.empty:
        st.info("No device data available")
        return

    # ---------------------------------------------------------
    # 1. Normalize MACs in known_hosts first
    # ---------------------------------------------------------
    if "mac" in known_hosts.columns:
        known_hosts["mac"] = known_hosts["mac"].str.lower().str.strip()

    # ---------------------------------------------------------
    # 2. Merge DHCP Data
    # ---------------------------------------------------------
    if not dhcp.empty:
        if "mac" in dhcp.columns:
            dhcp["mac"] = dhcp["mac"].str.lower().str.strip()
            dhcp_cols = [c for c in ["mac", "host_name", "domain"] if c in dhcp.columns]
            dhcp_norm = dhcp[dhcp_cols].drop_duplicates(subset=["mac"])
            merged = pd.merge(known_hosts, dhcp_norm, how="left", on="mac")
        else:
            dhcp_cols = [c for c in ["client_addr","host_name","domain"] if c in dhcp.columns]
            dhcp_norm = dhcp[dhcp_cols].drop_duplicates(subset=["client_addr"])
            merged = pd.merge(known_hosts, dhcp_norm, how="left", left_on="host", right_on="client_addr")
    else:
        merged = known_hosts.copy()
        merged["host_name"], merged["domain"] = "-", None

    merged["host_name"] = merged.get("host_name","-").fillna("-")
    
    # Updated Status Check (Using YAML set)
    merged["status"] = merged["mac"].apply(lambda m: "Authorized" if m in authorized_macs else "Unauthorized")

    # ---------------------------------------------------------
    # Force 'ts' to datetime
    # ---------------------------------------------------------
    if "ts" in merged.columns and not merged.empty:
        merged["ts"] = pd.to_numeric(merged["ts"], errors='coerce')
        merged["ts"] = pd.to_datetime(merged["ts"], unit="s", errors='coerce')
        merged = merged.dropna(subset=["ts"])
        merged["date"] = merged["ts"].dt.date

    # ---------------------------------------------------------
    # METRICS & TRENDS
    # ---------------------------------------------------------
    total_unique = merged["mac"].nunique()
    auth_unique = merged[merged["status"]=="Authorized"]["mac"].nunique()
    unauth_unique = merged[merged["status"]=="Unauthorized"]["mac"].nunique()
    risk_ratio = round((unauth_unique/total_unique*100),2) if total_unique else 0

    # Initialize State if missing
    if 'metrics_history' not in st.session_state:
        st.session_state.metrics_history = {
            'total': total_unique, 'auth': auth_unique, 'unauth': unauth_unique, 'risk': risk_ratio
        }

    if 'risk' not in st.session_state.metrics_history:
        st.session_state.metrics_history['risk'] = risk_ratio

    # Calculate Deltas
    d_total = total_unique - st.session_state.metrics_history['total']
    d_auth = auth_unique - st.session_state.metrics_history['auth']
    d_unauth = unauth_unique - st.session_state.metrics_history['unauth']
    d_risk = round(risk_ratio - st.session_state.metrics_history['risk'], 2)

    # Helper function to format delta text with increase/decrease and + sign
    def format_delta(val, is_percent=False):
        if val == 0:
            return None
        suffix = "%" if is_percent else ""
        
        # Add Logic for + sign and Label
        if val > 0:
            label = "(Increase)"
            prefix = "+"
        else:
            label = "(Decrease)"
            prefix = "" # Negative numbers already have '-'
            
        return f"{prefix}{val}{suffix} {label}"

    # Display Metrics
    m1, m2, m3, m4 = st.columns(4)
    
    m1.metric(
        "Active Devices", 
        total_unique, 
        delta=format_delta(d_total),
        delta_color="normal"
    )
    
    m2.metric(
        "Authorized", 
        auth_unique, 
        delta=format_delta(d_auth),
        delta_color="normal"
    )
    
    m3.metric(
        "Unauthorized", 
        unauth_unique, 
        delta=format_delta(d_unauth),
        delta_color="inverse"
    )
    
    m4.metric(
        "Risk Ratio", 
        f"{risk_ratio}%", 
        delta=format_delta(d_risk, is_percent=True),
        delta_color="off"
    )

    st.markdown("---")

    # ---------- Activity Overview ----------
    st.subheader("Activity Overview")
    
    hourly = pd.DataFrame()
    if not merged.empty and "ts" in merged.columns:
        try:
            hourly = merged.set_index("ts").groupby("status").resample("1H").size().reset_index(name="events")
        except TypeError as e:
            st.error(f"Error resampling data: {e}")

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
    st.markdown("<h2 style='font-size:25px; color:white; text-align:left;'>Unauthorized Device Ratio</h2>", unsafe_allow_html=True)
    
    warning_text, warning_color, warning_icon = "STATUS: SAFE", "#6CA651", "✅"
    if risk_ratio >= 50: warning_text, warning_color, warning_icon = "STATUS: WARNING", "#F3AE4B", "⚠️"
    if risk_ratio >= 80: warning_text, warning_color, warning_icon = "STATUS: HIGH RISK", "#D63447", "🛑"

    gauge_fig = go.Figure()
    gauge_fig.add_trace(go.Indicator(
        mode="gauge+number", value=risk_ratio, number={"suffix":"%", "font":{"size":48}}, 
        gauge={
            "axis":{"range":[0,100], "tickfont":{"size":16}}, "bar":{"color":"#30C1F6"},
            "steps":[
                {"range":[0,50],"color":"#6CA651"},
                {"range":[50,80],"color":"#F3AE4B"},
                {"range":[80,100],"color":"#D63447"}
            ],
            "threshold":{"line":{"color":"white","width":2},"thickness":0.75,"value":50}
        }
    ))
    for label, color in [('Current Level','#30C1F6'), ('Safe (0-50%)','#6CA651'), ('Warning (50-80%)','#F3AE4B'), ('High Risk (80-100%+)','#D63447')]:
        gauge_fig.add_trace(go.Scatter(x=[None], y=[None], mode='markers', marker=dict(size=10, color=color), name=label))

    gauge_fig.add_annotation(x=0.5, y=0.15, text=f"<b>{warning_icon} {warning_text}</b>", showarrow=False, font=dict(size=20, color=warning_color))
    gauge_fig.update_layout(
        template="plotly_dark", height=450, margin=dict(l=50, r=50, t=80, b=50),
        legend=dict(orientation="v", yanchor="top", y=1.0, xanchor="right", x=1.0, font=dict(size=12)),
        xaxis={'visible': False}, yaxis={'visible': False}
    )
    st.plotly_chart(gauge_fig, use_container_width=True)

    # ---------- Device Count Bar Chart ----------
    st.markdown("<h2 style='font-size:25px; color:white; text-align:left;'>Device Count</h2>", unsafe_allow_html=True)
    
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
    st.subheader("Device Inventory")

    # 1. Prepare Date Options
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

    # 3. Apply Date Filter
    if selected_date_str == "All Dates":
        table_df = merged.copy()
    else:
        table_df = merged[merged["date"].astype(str) == selected_date_str]

    with master_col3:
        with st.form(key="search_form", border=False):
            s_input_col, s_btn_col = st.columns([4, 1], gap="small", vertical_alignment="bottom")
            with s_input_col:
                search_term = st.text_input("Search", placeholder="Search MAC / IP / Host...", label_visibility="visible")
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
                top_sites = filtered_activity["Destination"].value_counts().head(5).reset_index()
                top_sites.columns = ["Destination", "Count"] # Rename columns
                
                st.markdown(f"#### Top 5 Destinations ({service_view})")
                
                if not top_sites.empty:
                    # Style: Big Fonts
                    large_font_style = top_sites.style.set_properties(**{
                        'font-size': '20px', 
                        'height': '50px'
                    }).set_table_styles([
                        {'selector': 'th', 'props': [('font-size', '20px'), ('font-weight', 'bold')]},
                        {'selector': 'td', 'props': [('font-size', '20px')]}
                    ])

                    st.dataframe(
                        large_font_style, 
                        use_container_width=True, 
                        hide_index=True,
                        height=300
                    )
                else:
                    st.info("No activity for this service.")
                
                # --- DYNAMIC CHART (Full Width, Below Table) ---
                st.markdown("#### Traffic Activity Graph")
                color_map = {"DNS": "#F63049", "HTTP": "#00F7FF", "SSL": "#F3AE4B"}
                
                if service_view == "All Services":
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
                    fig.update_traces(mode="lines", fill='tozeroy') 
                else:
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

                # Chart Layout
                fig.update_layout(
                    template="plotly_dark", 
                    height=450, 
                    font=dict(size=16), 
                    legend=dict(
                        orientation="h",
                        yanchor="bottom",
                        y=1.02,
                        xanchor="right",
                        x=1,
                        font=dict(size=14)
                    ),
                    margin=dict(l=50, r=50, t=80, b=50),
                    xaxis=dict(tickfont=dict(size=14), title="Timestamp", showgrid=True, gridcolor='rgba(255,255,255,0.1)'),
                    yaxis=dict(tickfont=dict(size=14), title="Events Count", showgrid=True, gridcolor='rgba(255,255,255,0.1)')
                )
                st.plotly_chart(fig, use_container_width=True)

                # Detailed Log Table
                with st.expander("View Full Log Details (Unique Events)"):
                    if not filtered_activity.empty:
                        unique_logs = (
                            filtered_activity.groupby(["Service", "Destination", "Details"])
                            .agg(
                                Last_Seen=("ts", "max"),
                                Count=("ts", "count")
                            )
                            .reset_index()
                            .sort_values("Last_Seen", ascending=False)
                        )

                        st.dataframe(
                            unique_logs,
                            column_config={
                                "Last_Seen": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD HH:mm:ss"),
                                "Destination": "Query / Host / Server",
                                "Count": st.column_config.NumberColumn("Events", help="Number of times this event occurred"),
                            },
                            use_container_width=True,
                            hide_index=True
                        )
                    else:
                        st.info("No logs found for this filter.")
            else:
                st.info(f"No detailed activity found for {target_mac} on {drill_down_date}.")

    else:
        st.info("No logs found for this selection.")