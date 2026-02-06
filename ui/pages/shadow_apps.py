import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
from urllib.parse import urlparse

# -----------------------------
# Config
# -----------------------------
ALLOWLIST_FILE = Path(__file__).resolve().parents[2] / "allowlist.txt"

# -----------------------------
# License registry (example)
# -----------------------------
LICENSE_REGISTRY = {
    "office.com": 10,
    "microsoft.com": 10,
    "github.com": 50,
}

# -----------------------------
# Load Parquet Helper
# -----------------------------
@st.cache_data(show_spinner=False)
def load_shadow_logs(parquet_root: Path, log_type: str, selected_date: str):
    """Load parquet file for a specific log type and specific date."""
    date_dir = parquet_root / selected_date
    
    if not date_dir.exists():
        return pd.DataFrame()
        
    file_path = date_dir / f"{log_type}.parquet"
    if file_path.exists():
        return pd.read_parquet(file_path)
                
    return pd.DataFrame()

# -----------------------------
# Load DHCP MAC
# -----------------------------
def get_dhcp_mapping(parquet_root: Path, selected_date: str):
    """Creates a dictionary mapping IP addresses to MAC addresses from DHCP logs."""
    dhcp_path = parquet_root / selected_date / "dhcp.parquet"
    if not dhcp_path.exists():
        return {}
    
    try:
        df_dhcp = pd.read_parquet(dhcp_path)
        
        ip_candidates = ['assigned_addr', 'client_addr', 'lease_addr', 'yiaddr', 'ip']
        ip_col = next((col for col in ip_candidates if col in df_dhcp.columns), None)
        
        mac_candidates = ['chaddr', 'client_chaddr', 'mac', 'hardware_address', 'src_mac']
        mac_col = next((col for col in mac_candidates if col in df_dhcp.columns), None)

        if ip_col and mac_col:
            clean_df = df_dhcp.dropna(subset=[ip_col, mac_col]).copy()
            clean_df[ip_col] = clean_df[ip_col].astype(str).str.strip()
            clean_df[mac_col] = clean_df[mac_col].astype(str).str.strip().str.lower()
            mapping = clean_df.set_index(ip_col)[mac_col].to_dict()
            return mapping
            
    except Exception as e:
        pass
        
    return {}

# -----------------------------
# Load allowlist
# -----------------------------
def load_allowlist():
    if not ALLOWLIST_FILE.exists():
        return []

    approved = set()
    try:
        with open(ALLOWLIST_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if not line or line.startswith("#"):
                    continue
                domain = extract_domain(line)
                if domain:
                    approved.add(domain)
    except Exception:
        pass
    return list(approved)

# -----------------------------
# Extract domain
# -----------------------------
def extract_domain(url: str):
    if not url: return ""
    url = str(url).strip().lower()
    if "://" in url:
        parsed = urlparse(url)
        url = parsed.hostname or ""
    if url.startswith("www."):
        url = url[4:]
    url = url.rstrip(".")
    if ":" in url:
        url = url.split(":")[0]
    return url

# -----------------------------
# Check if domain is allowed
# -----------------------------
def is_allowed(domain: str, approved: list):
    domain = domain.lower().strip().rstrip(".")
    return any(domain == a or domain.endswith("." + a) for a in approved)

# -----------------------------
# Helper: Normalize Columns (UPDATED for BYTES)
# -----------------------------
def normalize_log_df(df, log_type, domain_col):
    """Standardize column names and extract context + BYTES info."""
    if df.empty or domain_col not in df.columns:
        return pd.DataFrame()
    
    # 1. Define possible mappings
    cols = {domain_col: "app_identifier", "ts": "ts"}
    
    # Mapping IP
    ip_options = ["id.orig_h", "orig_h", "src_ip", "ip", "c_ip"]
    for opt in ip_options:
        if opt in df.columns:
            cols[opt] = "ip"
            break

    # Mapping MAC
    mac_options = ["mac", "orig_mac", "id.orig_mac", "src_mac", "endpoint_mac", "ethernet_source"]
    for opt in mac_options:
        if opt in df.columns:
            cols[opt] = "mac"
            break
            
    # --- Capture Context Columns ---
    context_col = "Info"
    
    if log_type == "notice":
        if "msg" in df.columns: df[context_col] = df["msg"]
        elif "note" in df.columns: df[context_col] = df["note"]
    elif log_type == "weird":
        if "addl" in df.columns: df[context_col] = df["addl"]
        else: df[context_col] = df["name"]
    elif "method" in df.columns:
        df[context_col] = df["method"] + " " + df.get("uri", "")
    elif "proto" in df.columns and "id.resp_p" in df.columns:
         df[context_col] = df["proto"] + "/" + df["id.resp_p"].astype(str)
    elif "mime_type" in df.columns:
        df[context_col] = df["mime_type"]
    elif "version.major" in df.columns:
         df[context_col] = df["unparsed_version"]
    else:
        df[context_col] = "-"

    # Keep destination port
    if "id.resp_p" in df.columns: cols["id.resp_p"] = "dst_port"
    elif "dst_port" in df.columns: cols["dst_port"] = "dst_port"
    
    # --- NEW: CAPTURE BYTES FOR EXFILTRATION ANALYSIS ---
    # orig_bytes = Upload, resp_bytes = Download
    if "orig_bytes" in df.columns: cols["orig_bytes"] = "bytes_sent"
    if "resp_bytes" in df.columns: cols["resp_bytes"] = "bytes_received"
    if "id.orig_bytes" in df.columns: cols["id.orig_bytes"] = "bytes_sent"
    if "id.resp_bytes" in df.columns: cols["id.resp_bytes"] = "bytes_received"

    df = df.rename(columns=cols)
    
    # 2. Ensure columns exist
    if "ip" not in df.columns: df["ip"] = "Unknown"
    else: df["ip"] = df["ip"].astype(str).fillna("Unknown")

    if "mac" not in df.columns: df["mac"] = "Unknown"
    else: 
        df["mac"] = df["mac"].fillna("Unknown").replace("", "Unknown").astype(str).str.lower()
        df.loc[df["mac"].isin(["none", "nan"]), "mac"] = "Unknown"
        
    if "dst_port" not in df.columns: df["dst_port"] = 0
    else: df["dst_port"] = pd.to_numeric(df["dst_port"], errors='coerce').fillna(0).astype(int)
    
    # Ensure Bytes are Numeric
    if "bytes_sent" not in df.columns: df["bytes_sent"] = 0
    df["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors='coerce').fillna(0).astype(int)
    
    if "bytes_received" not in df.columns: df["bytes_received"] = 0
    df["bytes_received"] = pd.to_numeric(df["bytes_received"], errors='coerce').fillna(0).astype(int)

    df["source_log"] = log_type.upper()
    
    # Return specific columns (ADDED BYTES)
    return df[["ts", "app_identifier", "ip", "mac", "source_log", "Info", "dst_port", "bytes_sent", "bytes_received"]]

# -----------------------------
# Calculate Risk Level
# -----------------------------
def calculate_risk(row):
    """Assigns a simple risk level based on Port and Log Type."""
    port = row.get("dst_port", 0)
    log = row.get("source_log", "")
    status = row.get("App Status", "")
    
    # 1. Critical Logs (Anomalies)
    if log == "WEIRD" or log == "NOTICE":
        return "Critical"
    
    # 2. Remote Access Ports (SSH, Telnet, RDP, VNC)
    if port in [22, 23, 3389, 5900]:
        return "High"
        
    # 3. Database Ports
    if port in [1433, 3306, 5432]:
        return "Medium"
        
    # 4. Unauthorized Application
    if status == "Unauthorized":
        return "Low"
        
    return "Safe"

# -----------------------------
# NEW: Categorize Threat Behavior (Exfiltration Logic)
# -----------------------------
def categorize_threat(row):
    sent = row.get("bytes_sent", 0)
    recv = row.get("bytes_received", 0)
    
    if sent > 10_000_000: # > 10MB Upload
        return "Potential Exfiltration"
    if recv > 100_000_000: # > 100MB Download
        return "Heavy Download"
    if row["source_log"] == "WEIRD":
        return "Protocol Anomaly"
    return "Unauthorized Usage"

# -----------------------------
# Styling Function (Colors)
# -----------------------------
def color_risk(val):
    """Returns CSS styles for the Risk Level column."""
    color_map = {
        "Critical": "color: #FF0000; font-weight: bold;",   # Red
        "High": "color: #FF4500; font-weight: bold;",       # OrangeRed
        "Medium": "color: #FFA500;",                        # Orange
        "Low": "color: #FFD700;",                           # Gold
        "Safe": "color: #00FF00;"                           # Green
    }
    return color_map.get(val, "")

# -----------------------------
# Render Main Page
# -----------------------------
def render_shadow_apps(parquet_root: Path):
    st.subheader("Shadow Apps Overview")
    
    # 1. Date Selection
    if parquet_root.exists():
        available_dates = sorted([d.name for d in parquet_root.iterdir() if d.is_dir()], reverse=True)
        if not available_dates:
            st.warning("No log directories found.")
            return
        selected_date = st.selectbox("Select Date to View Logs", available_dates)
    else:
        st.error("Log root directory not found.")
        return

    # 2. Load DHCP Mapping
    with st.spinner("Loading DHCP Mapping..."):
        ip_to_mac = get_dhcp_mapping(parquet_root, selected_date)
    
    approved = load_allowlist()

    # 3. Load logs
    logs = [
        ("http", "host"),
        ("ssl", "server_name"),
        ("dns", "query"),
        ("files", "filename"),
        ("conn", "service"),
        ("software", "unparsed_version"),
        ("weird", "name"),
        ("notice", "note")
    ]
    
    combined_frames = []
    with st.spinner("Processing logs..."):
        for log_type, domain_col in logs:
            raw_df = load_shadow_logs(parquet_root, log_type, selected_date)
            norm_df = normalize_log_df(raw_df, log_type, domain_col)
            if not norm_df.empty:
                combined_frames.append(norm_df)

    if not combined_frames:
        st.info(f"No Shadow App logs available for {selected_date}.")
        return

    # 5. Create DF
    df = pd.concat(combined_frames, ignore_index=True)
    
    # 6. Enrich Data
    df["ip"] = df["ip"].astype(str)
    mask_unknown = (df["mac"] == "Unknown") | (df["mac"].isna())
    mapped_macs = df.loc[mask_unknown, "ip"].map(ip_to_mac)
    df.loc[mask_unknown, "mac"] = mapped_macs.fillna("Unknown")
    df["mac"] = df["mac"].fillna("Unknown")

    # 7. Process UI Data
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    df["datetime"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")
    df = df.dropna(subset=["datetime"])
    
    # Domain cleanup
    df["domain_clean"] = df["app_identifier"].apply(extract_domain)
    special_logs = ["CONN", "FILES", "SOFTWARE", "WEIRD", "NOTICE"] 
    mask = (df["source_log"].isin(special_logs)) & (df["domain_clean"] == "")
    df.loc[mask, "domain_clean"] = df["app_identifier"]
    df.loc[df["domain_clean"] == "", "domain_clean"] = "unidentified_activity"

    # Status Check
    df["App Status"] = df["domain_clean"].apply(lambda x: "Authorized" if is_allowed(x, approved) else "Unauthorized")
    
    # Calculate Risk GLOBALLY
    df["Risk Level"] = df.apply(calculate_risk, axis=1)
    
    # Calculate Threat Type (Exfiltration)
    df["Behavior"] = df.apply(categorize_threat, axis=1)

    # Metrics
    total = len(df)
    unauth_df = df[df["App Status"] == "Unauthorized"]
    critical_df = df[df["Risk Level"].isin(["Critical", "High"])]
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", total)
    col2.metric("Authorized Events", len(df[df["App Status"] == "Authorized"]))
    col3.metric("Unauthorized Events", len(unauth_df), delta_color="inverse")
    col4.metric("Critical / High Risk", len(critical_df), delta_color="inverse")
    
    st.divider()

    # Charts
    c1, c2 = st.columns([2, 1])
    with c1:
        st.markdown("### Activity Over Time")
        if not df.empty:
            df_line = df.groupby([pd.Grouper(key="datetime", freq="H"), "App Status"]).size().reset_index(name="count")
            fig = px.line(df_line, x="datetime", y="count", color="App Status", 
                          color_discrete_map={"Authorized": "#00FF00", "Unauthorized": "#FF0000"},
                          template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)
            
    with c2:
        st.markdown("### Source Distribution")
        df_pie = df.groupby("source_log").size().reset_index(name="Log Count")
        fig_pie = px.pie(
            df_pie, values="Log Count", names="source_log", template="plotly_dark", hole=0.4
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    # --------------------------------------------------------
    # TABS: The distinct UI Experience
    # --------------------------------------------------------
    t1, t2 = st.tabs(["Authorized Applications", "Unauthorized Applications"])
    
    # --- AUTHORIZED TAB (Standard View) ---
    with t1:
        tab_col1, tab_col2, tab_col3 = st.columns([2, 2, 1])
        with tab_col1: st.markdown("### Authorized Apps")
        with tab_col2: 
            search_query_auth = st.text_input("Search MAC/IP", placeholder="Enter MAC or IP...", key="auth_search").strip().lower()
        with tab_col3:
            raw_sources = sorted(df["source_log"].unique().tolist()) if not df.empty else []
            selected_source_auth = st.selectbox("Select Source", options=["All"] + raw_sources, key="auth_source_filter")
        
        # Filter Authorized
        auth_df = df[df["App Status"] == "Authorized"]
        
        if not auth_df.empty:
            if selected_source_auth != "All": auth_df = auth_df[auth_df["source_log"] == selected_source_auth]
            if search_query_auth:
                auth_df = auth_df[
                    (auth_df["mac"].str.contains(search_query_auth, case=False, na=False)) | 
                    (auth_df["ip"].str.contains(search_query_auth, case=False, na=False))
                ]

            if not auth_df.empty:
                allowed_summary = (
                    auth_df.sort_values("datetime")
                    .groupby(["domain_clean", "mac", "ip", "source_log", "App Status"])
                    .agg(First_Seen=("datetime", "min"), Last_Seen=("datetime", "max"), Count=("datetime", "count"))
                    .reset_index()
                )
                
                # --- FIX: Limit to 1000 rows to prevent crash ---
                allowed_summary = allowed_summary.head(1000)
                
                def color_status_green(val): return 'color: #6CA651; font-weight: bold;'
                styled_df = allowed_summary.style.applymap(color_status_green, subset=['App Status'])
                st.dataframe(styled_df, use_container_width=True, hide_index=True)
            else:
                st.info("No matching Authorized logs found.")
        else:
            st.info("No Authorized applications detected.")

        # -----------------------------
        # Shadow App Forensics Section (INSIDE TAB 1)
        # -----------------------------
        st.divider()
        st.header("Shadow App Forensics")

        search_query = st.text_input("Global Forensic Search", placeholder="Enter specific MAC or IP to start deep dive...", key="global_forensic_search").strip().lower()

        if search_query:
            st.info(f"Showing deep forensics for: **{search_query}**")
            
            f_col1, f_col2 = st.columns(2)
            with f_col1:
                view_type = st.radio(
                    "Forensic View", 
                    ["App Run (Connectivity)", "App Usage (Interaction)", "App Install (Files)", "Suspicious Behavior"],
                    horizontal=True
                )
            with f_col2:
                f_raw_sources = sorted(df["source_log"].unique().tolist()) if not df.empty else []
                selected_f_source = st.selectbox("Filter Forensic Source", options=["All"] + f_raw_sources, key="forensic_source_single")

            # Base Filter
            forensic_df = df[
                (df["mac"].str.contains(search_query, case=False, na=False)) | 
                (df["ip"].str.contains(search_query, case=False, na=False))
            ].copy()

            if selected_f_source != "All":
                forensic_df = forensic_df[forensic_df["source_log"] == selected_f_source]

            if not forensic_df.empty:
                
                # --- DISTINCT LOGIC IMPLEMENTATION ---
                if "App Run" in view_type:
                    display_df = forensic_df[forensic_df["source_log"].isin(["CONN", "DNS"])]
                    color_graph = ["#00CCFF"] 
                elif "App Usage" in view_type:
                    display_df = forensic_df[forensic_df["source_log"].isin(["HTTP", "SSL"])]
                    color_graph = ["#00FF99"] 
                elif "App Install" in view_type:
                    display_df = forensic_df[forensic_df["source_log"].isin(["FILES", "SOFTWARE"])]
                    color_graph = ["#FFFF00"] 
                elif "Suspicious" in view_type:
                    display_df = forensic_df[
                        (forensic_df["App Status"] == "Unauthorized") | 
                        (forensic_df["Risk Level"].isin(["Critical", "High", "Medium"]))
                    ]
                    color_graph = ["#FF0000"] 
                else:
                    display_df = forensic_df
                    color_graph = ["#888888"]

                # --- Activity Graph ---
                st.markdown("### Traffic Activity Graph")
                if not display_df.empty:
                    f_line = display_df.groupby([pd.Grouper(key="datetime", freq="10min")]).size().reset_index(name="hits")
                    fig_f = px.area(f_line, x="datetime", y="hits", template="plotly_dark", 
                                    color_discrete_sequence=color_graph, title=f"Activity: {view_type}")
                    st.plotly_chart(fig_f, use_container_width=True)
                else:
                    st.warning(f"No events found for {view_type} category.")

                # --- Top Destinations & Table ---
                low_col1, low_col2 = st.columns([1, 2])
                
                with low_col1:
                    st.markdown("### Top Destinations")
                    if not display_df.empty:
                        top_dest = display_df["domain_clean"].value_counts().head(10).reset_index()
                        top_dest.columns = ["Destination", "Count"]
                        st.table(top_dest)
                    else:
                        st.write("No data.")

                with low_col2:
                    title_col, opt_col, status_col = st.columns([1.5, 1.2, 1])
                    with title_col: st.markdown(f"### {view_type}")
                    with opt_col:
                        table_mode = st.selectbox(
                            "View Mode",
                            options=["Detailed Logs", "Unique Rows", "Group by App", "Group by Source"],
                            label_visibility="collapsed" 
                        )
                    with status_col:
                        allow_status = st.radio(
                            " ", ["Authorized", "Unauthorized", "All"],
                            horizontal=True, key="allow_filter", label_visibility="collapsed"
                        )
                    
                    if allow_status == "Authorized":
                        display_df = display_df[display_df["App Status"] == "Authorized"]
                    elif allow_status == "Unauthorized":
                        display_df = display_df[display_df["App Status"] == "Unauthorized"]
                    
                    if table_mode == "Unique Rows":
                        final_df = display_df.drop_duplicates(subset=["domain_clean", "ip", "mac", "source_log", "Info"]).sort_values("datetime", ascending=False)
                    elif table_mode == "Group by App":
                        final_df = display_df.groupby(["domain_clean", "App Status"]).size().reset_index(name='Count').sort_values(by="Count", ascending=False)
                    elif table_mode == "Group by Source":
                        final_df = display_df.groupby(["source_log", "App Status"]).size().reset_index(name='Count').sort_values(by="Count", ascending=False)
                    else:
                        final_df = display_df.sort_values("datetime", ascending=False)

                    # --- FIX: Limit to 1000 rows to prevent crash ---
                    final_df = final_df.head(1000)

                    if "Risk Level" in final_df.columns:
                        styled_final_df = final_df.style.applymap(color_risk, subset=["Risk Level"])
                    else:
                        styled_final_df = final_df

                    st.dataframe(
                        styled_final_df,
                        column_config={
                            "datetime": st.column_config.DatetimeColumn("Timestamp", format="HH:mm:ss"),
                            "Info": "Context Info",
                            "domain_clean": "Destination",
                            "dst_port": "Port",
                            "Risk Level": "Risk"
                        },
                        use_container_width=True,
                        hide_index=True
                    )
                    
                    if not final_df.empty:
                        st.download_button(
                            label="Download Evidence (CSV)",
                            data=final_df.to_csv(index=False).encode('utf-8'),
                            file_name=f"forensics_{search_query}_{view_type}.csv",
                            mime='text/csv'
                        )
                
                # -------------------------------------------
                # Device Analytics
                # -------------------------------------------
                st.divider()
                st.subheader("Device Analytics")
                
                g_col1, g_col2, g_col3, g_col4 = st.columns(4)
                
                with g_col1:
                    st.markdown("#### Total Activity")
                    if not forensic_df.empty:
                        forensic_df["hour"] = forensic_df["datetime"].dt.hour
                        hourly_counts = forensic_df.groupby("hour").size().reset_index(name="count")
                        fig1 = px.bar(hourly_counts, x="hour", y="count", template="plotly_dark", color_discrete_sequence=["#3366CC"])
                        st.plotly_chart(fig1, use_container_width=True)

                with g_col2:
                    st.markdown("#### Auth vs Unauth")
                    if not forensic_df.empty:
                        status_counts = forensic_df["App Status"].value_counts().reset_index()
                        status_counts.columns = ["App Status", "count"]
                        fig2 = px.pie(
                            status_counts, names="App Status", values="count", color="App Status",
                            color_discrete_map={"Authorized": "#00FF00", "Unauthorized": "#FF0000"},
                            template="plotly_dark", hole=0.5
                        )
                        st.plotly_chart(fig2, use_container_width=True)

                with g_col3:
                    st.markdown("#### Source Dist.")
                    if not forensic_df.empty:
                        source_counts = forensic_df["source_log"].value_counts().reset_index()
                        source_counts.columns = ["Source", "count"]
                        fig3 = px.bar(source_counts, x="Source", y="count", template="plotly_dark", color="Source")
                        st.plotly_chart(fig3, use_container_width=True)

                with g_col4:
                    st.markdown("#### Top Ports")
                    if not forensic_df.empty:
                        port_df = forensic_df[forensic_df["dst_port"] > 0]
                        if not port_df.empty:
                            port_counts = port_df["dst_port"].value_counts().head(5).reset_index()
                            port_counts.columns = ["Port", "count"]
                            port_counts["Port"] = port_counts["Port"].astype(str)
                            fig4 = px.bar(port_counts, x="Port", y="count", template="plotly_dark", color_discrete_sequence=["#FF9900"])
                            st.plotly_chart(fig4, use_container_width=True)
                        else:
                            st.write("No port data.")
                    else:
                        st.write("No data.")
        else:
            st.write("Please enter a MAC or IP address in the search bar above to begin forensics.")

    # --- UNAUTHORIZED TAB (Advanced Threat Dashboard) ---
    with t2:
        st.markdown("## Unauthorized Threat Dashboard")
        
        if not unauth_df.empty:
            # 1. Threat Metrics
            u_metrics1, u_metrics2, u_metrics3 = st.columns(3)
            with u_metrics1:
                st.metric("Active Unauthorized Apps", unauth_df["domain_clean"].nunique())
            with u_metrics2:
                top_offender = unauth_df["mac"].value_counts().idxmax()
                offender_count = unauth_df["mac"].value_counts().max()
                st.metric("Top Offender (MAC)", top_offender, delta=f"{offender_count} Events", delta_color="inverse")
            with u_metrics3:
                crit_count = len(unauth_df[unauth_df["Risk Level"].isin(["Critical", "High"])])
                st.metric("Critical Risks Detected", crit_count, delta="Requires Attention", delta_color="inverse")
            
            st.divider()
            
            # --- NEW: DATA EXFILTRATION MONITOR ---
            with st.expander("Data Exfiltration Monitor (High Volume Traffic)", expanded=True):
                exfil_c1, exfil_c2 = st.columns(2)
                
                # Calculate Totals
                total_sent_gb = unauth_df["bytes_sent"].sum() / 1_000_000_000
                total_recv_gb = unauth_df["bytes_received"].sum() / 1_000_000_000
                
                with exfil_c1:
                    st.metric("Total Unauthorized Upload", f"{total_sent_gb:.2f} GB", delta="Potential Leak", delta_color="inverse")
                    st.metric("Total Unauthorized Download", f"{total_recv_gb:.2f} GB")
                    
                with exfil_c2:
                    # Scatter Plot: Bytes Sent vs Port
                    fig_exfil = px.scatter(
                        unauth_df[unauth_df["bytes_sent"] > 0], 
                        x="dst_port", y="bytes_sent", 
                        size="bytes_sent", color="Behavior",
                        hover_data=["domain_clean", "mac"],
                        title="Outbound Data Volume by Port",
                        template="plotly_dark"
                    )
                    st.plotly_chart(fig_exfil, use_container_width=True)

            st.divider()

            # 2. Risk Distribution Chart
            u_chart1, u_chart2 = st.columns([2, 1])
            with u_chart1:
                st.markdown("#### Top Unauthorized Domains")
                top_unauth_domains = unauth_df["domain_clean"].value_counts().head(10).reset_index()
                top_unauth_domains.columns = ["Domain", "Hits"]
                fig_u1 = px.bar(top_unauth_domains, x="Hits", y="Domain", orientation='h', template="plotly_dark", color_discrete_sequence=["#FF4500"])
                fig_u1.update_layout(yaxis={'categoryorder':'total ascending'})
                st.plotly_chart(fig_u1, use_container_width=True)
            
            with u_chart2:
                st.markdown("#### Risk Distribution")
                risk_counts = unauth_df["Risk Level"].value_counts().reset_index()
                risk_counts.columns = ["Risk", "Count"]
                
                risk_colors = {
                    "Critical": "#FF0000", "High": "#FF4500", 
                    "Medium": "#FFA500", "Low": "#FFD700", "Safe": "#00FF00"
                }
                
                fig_u2 = px.pie(risk_counts, values="Count", names="Risk", 
                                color="Risk", color_discrete_map=risk_colors,
                                template="plotly_dark", hole=0.6)
                st.plotly_chart(fig_u2, use_container_width=True)

            st.divider()
            
            # 3. Advanced Filtering & Table
            st.markdown("### Threat Details")
            
            af_1, af_2, af_3 = st.columns([1, 1, 2])
            with af_1:
                filter_risk = st.multiselect("Filter by Risk", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
            with af_2:
                filter_source = st.multiselect("Filter by Log Source", unauth_df["source_log"].unique(), default=unauth_df["source_log"].unique())
            with af_3:
                search_query_unauth = st.text_input("Search (IP, MAC, Domain)", placeholder="Search threat details...", key="unauth_search")

            filtered_unauth = unauth_df.copy()
            if filter_risk: filtered_unauth = filtered_unauth[filtered_unauth["Risk Level"].isin(filter_risk)]
            if filter_source: filtered_unauth = filtered_unauth[filtered_unauth["source_log"].isin(filter_source)]
            if search_query_unauth:
                q = search_query_unauth.lower()
                filtered_unauth = filtered_unauth[
                    (filtered_unauth["mac"].str.contains(q, case=False, na=False)) | 
                    (filtered_unauth["ip"].str.contains(q, case=False, na=False)) |
                    (filtered_unauth["domain_clean"].str.contains(q, case=False, na=False))
                ]

            detail_table = (
                filtered_unauth[["datetime", "mac", "ip", "domain_clean", "source_log", "Info", "dst_port", "bytes_sent", "Behavior", "Risk Level"]]
                .sort_values("datetime", ascending=False)
            )
            
            # --- FIX: Limit to 1000 rows to prevent crash ---
            detail_table = detail_table.head(1000)
            
            styled_unauth = detail_table.style.applymap(color_risk, subset=["Risk Level"])

            st.dataframe(
                styled_unauth,
                column_config={
                    "datetime": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
                    "mac": "MAC Address",
                    "ip": "IP Address",
                    "domain_clean": "Unauthorized Domain",
                    "source_log": "Source",
                    "Info": "Context",
                    "dst_port": "Port",
                    "bytes_sent": "Upload (Bytes)",
                    "Behavior": "Behavior Tag",
                    "Risk Level": "Threat Risk"
                },
                use_container_width=True,
                hide_index=True
            )
        else:
            st.success("No Unauthorized applications detected. System is clean.")