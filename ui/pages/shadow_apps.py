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
    # selected_date should match the directory name (e.g., "2023-10-27")
    date_dir = parquet_root / selected_date
    
    if not date_dir.exists():
        return pd.DataFrame()
        
    file_path = date_dir / f"{log_type}.parquet"
    if file_path.exists():
        return pd.read_parquet(file_path)
                
    return pd.DataFrame()

# -----------------------------
# Load DHCP MAC to identify the user
# -----------------------------
def get_dhcp_mapping(parquet_root: Path, selected_date: str):
    """Creates a dictionary mapping IP addresses to MAC addresses from DHCP logs."""
    dhcp_path = parquet_root / selected_date / "dhcp.parquet"
    if not dhcp_path.exists():
        return {}
    
    try:
        df_dhcp = pd.read_parquet(dhcp_path)
        # Zeek DHCP logs typically use 'assigned_addr' or 'client_addr' for the IP
        # and 'mac' or 'chaddr' for the hardware address.
        ip_col = 'assigned_addr' if 'assigned_addr' in df_dhcp.columns else 'client_addr'
        
        if ip_col in df_dhcp.columns and 'mac' in df_dhcp.columns:
            # We take the latest MAC assigned to an IP to handle renewals
            mapping = df_dhcp.dropna(subset=[ip_col, 'mac']).set_index(ip_col)['mac'].to_dict()
            return mapping
    except Exception:
        pass
    return {}

# -----------------------------
# Load allowlist
# -----------------------------
def load_allowlist():
    if not ALLOWLIST_FILE.exists():
        st.error(f"Allowlist not found: {ALLOWLIST_FILE}")
        return []

    approved = set()
    with open(ALLOWLIST_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            domain = extract_domain(line)
            if domain:
                approved.add(domain)
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
# Helper: Normalize Columns
# -----------------------------
def normalize_log_df(df, log_type, domain_col):
    """Standardize column names for merging."""
    if df.empty or domain_col not in df.columns:
        return pd.DataFrame()
    
    # 1. Define possible mappings
    cols = {domain_col: "app_identifier", "ts": "ts"}
    
    # Mapping IP
    ip_options = ["id.orig_h", "orig_h", "ip"]
    for opt in ip_options:
        if opt in df.columns:
            cols[opt] = "ip"
            break

    # Mapping MAC - Added more potential Zeek/Parquet column names
    mac_options = ["mac", "orig_mac", "id.orig_mac", "src_mac", "endpoint_mac"]
    for opt in mac_options:
        if opt in df.columns:
            cols[opt] = "mac"
            break
    
    df = df.rename(columns=cols)
    
    # 2. Ensure columns exist and handle "None" values
    if "ip" not in df.columns: 
        df["ip"] = "Unknown"
    if "mac" not in df.columns: 
        df["mac"] = "Unknown"
    else:
        # Fill actual NaNs or empty strings with "Unknown"
        df["mac"] = df["mac"].fillna("Unknown").replace("", "Unknown")
    
    df["source_log"] = log_type.upper()
    
    # Return only the needed columns
    return df[["ts", "app_identifier", "ip", "mac", "source_log"]]

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

    # 2. Load DHCP Mapping (Look-up table for MAC addresses)
    ip_to_mac = get_dhcp_mapping(parquet_root, selected_date)
    approved = load_allowlist()

    # 3. Load and Normalize Logs
    logs = [
        ("http", "host"),
        ("ssl", "server_name"),
        ("dns", "query"),
        ("files", "filename"),
        ("conn", "service"),
        ("software", "unparsed_version")
    ]
    
    combined_frames = []
    for log_type, domain_col in logs:
        raw_df = load_shadow_logs(parquet_root, log_type, selected_date)
        norm_df = normalize_log_df(raw_df, log_type, domain_col)
        if not norm_df.empty:
            combined_frames.append(norm_df)

    # 4. Check if we actually found any data
    if not combined_frames:
        st.info(f"No Shadow App logs available for {selected_date}.")
        return

    # 5. Create the 'df' variable
    df = pd.concat(combined_frames, ignore_index=True)
    
    # 6. ENRICH DATA: Match IP to MAC using DHCP mapping
    # Only try to map if the MAC is currently "Unknown"
    df.loc[df["mac"] == "Unknown", "mac"] = df["ip"].map(ip_to_mac)
    df["mac"] = df["mac"].fillna("Unknown")

    # 7. Process Data for UI
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    df["datetime"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")
    df = df.dropna(subset=["datetime"])
    
    # Attempt to extract domain
    df["domain_clean"] = df["app_identifier"].apply(extract_domain)
    
    # --- FIX: Prevent CONN, FILES, and SOFTWARE from being filtered out ---
    # If it's one of these types and domain_clean is empty, use the raw identifier
    special_logs = ["CONN", "FILES", "SOFTWARE"]
    mask = (df["source_log"].isin(special_logs)) & (df["domain_clean"] == "")
    df.loc[mask, "domain_clean"] = df["app_identifier"]
    
    # Final Fallback: If it's still empty (e.g., CONN with no service), label it
    df.loc[df["domain_clean"] == "", "domain_clean"] = "unidentified_activity"
    # ----------------------------------------------------------------------

    df["Status"] = df["domain_clean"].apply(lambda x: "Allowed" if is_allowed(x, approved) else "Not Allowed")
    

    # Metrics
    total = len(df)
    unauth_df = df[df["Status"] == "Not Allowed"]
    auth_df = df[df["Status"] == "Allowed"]
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Events", total)
    col2.metric("Authorized Events", len(auth_df))
    col3.metric("Unauthorized Events", len(unauth_df), delta_color="inverse")
    
    st.divider()

    # Charts (Unified)
    c1, c2 = st.columns([2, 1])
    
    with c1:
        st.markdown("### Activity Over Time")
        if not df.empty:
            df_line = df.groupby([pd.Grouper(key="datetime", freq="H"), "Status"]).size().reset_index(name="count")
            fig = px.line(df_line, x="datetime", y="count", color="Status", 
                          color_discrete_map={"Allowed": "#00FF00", "Not Allowed": "#FF0000"},
                          template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)
            
    with c2:
        st.markdown("### Source Distribution")
        # Group by source to ensure Plotly has the counts ready for the hover label
        df_pie = df.groupby("source_log").size().reset_index(name="Log Count")
        
        fig_pie = px.pie(
            df_pie, 
            values="Log Count", 
            names="source_log", 
            template="plotly_dark", 
            hole=0.4,
            # This ensures the count is shown on hover
            hover_data=["Log Count"]
        )
        
        # Update traces to show both label, percentage, and the actual value
        fig_pie.update_traces(
            hovertemplate="<b>%{label}</b><br>Logs: %{value}<br>Percentage: %{percent}"
        )
        
        st.plotly_chart(fig_pie, use_container_width=True)

    # Tables
    t1, t2 = st.tabs(["Allowed Applications", "Unauthorized Applications"])
    
    with t1:
        # 1. Create three columns: Title, Search, and Source Filter
        tab_col1, tab_col2, tab_col3 = st.columns([2, 2, 1])
        
        with tab_col1:
            st.markdown("### Authorized Apps")
            
        with tab_col2:
            # Added Search Bar for MAC or IP
            search_query = st.text_input(
                "Search MAC/IP", 
                placeholder="Enter MAC or IP...", 
                key="auth_search"
            ).strip().lower()
            
        with tab_col3:
            raw_sources = sorted(df["source_log"].unique().tolist()) if not df.empty else []
            all_options = ["All"] + raw_sources
            selected_source = st.selectbox(
                "Select Source", 
                options=all_options, 
                key="auth_source_filter_all"
            )
        
        if not auth_df.empty:
            # 2. Apply Filters (Source + Search)
            filtered_auth = auth_df.copy()
            
            # Filter by Source
            if selected_source != "All":
                filtered_auth = filtered_auth[filtered_auth["source_log"] == selected_source]
            
            # Filter by Search Query (Checking both MAC and IP columns)
            if search_query:
                filtered_auth = filtered_auth[
                    (filtered_auth["mac"].str.contains(search_query, case=False, na=False)) | 
                    (filtered_auth["ip"].str.contains(search_query, case=False, na=False))
                ]

            if not filtered_auth.empty:
                # 3. Aggregation and Styling
                allowed_summary = (
                    filtered_auth.sort_values("datetime")
                    .groupby(["domain_clean", "mac", "ip", "source_log", "Status"])
                    .agg(
                        First_Seen=("datetime", "min"),
                        Last_Seen=("datetime", "max"),
                        Count=("datetime", "count")
                    )
                    .reset_index()
                )

                # Apply green text color styling
                def color_status_green(val):
                    return 'color: #6CA651; font-weight: bold;' # Bright green for dark theme

                styled_df = allowed_summary.style.applymap(color_status_green, subset=['Status'])

                st.dataframe(
                    styled_df,
                    column_config={
                        "domain_clean": "Application/Domain",
                        "Status": "Status",
                        "First_Seen": st.column_config.DatetimeColumn("First Seen", format="HH:mm:ss"),
                        "Last_Seen": st.column_config.DatetimeColumn("Last Seen", format="HH:mm:ss"),
                        "mac": "MAC Address",
                        "ip": "IP Address",
                        "source_log": "Source",
                        "Count": "Total Hits"
                    },
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("No matching authorized logs found.")
        else:
            st.info("No authorized applications detected.")

    with t2:
        st.markdown("### Unauthorized Apps Summary")
        if not unauth_df.empty:
            # Summary Table (Already grouped, so no duplicates here)
            unauth_summary = unauth_df.groupby(["domain_clean", "source_log"]).size().reset_index(name="Count")
            st.dataframe(unauth_summary, use_container_width=True)
            
            st.divider()
            
            # DETAILED TABLE (The one that usually looks "spammy")
            st.markdown("### Unauthorized Details (Unique Device Access)")
            st.write("Unique list of devices (IP/MAC) per application today.")
            
            # REMOVE DUPLICATES: 
            # We drop duplicates so we only see ONE entry per MAC/IP per App.
            # We keep the 'last' occurrence to show the most recent time.
            detail_table = (
                unauth_df[["datetime", "mac", "ip", "domain_clean", "source_log"]]
                .sort_values("datetime", ascending=True)
                .drop_duplicates(subset=["mac", "ip", "domain_clean"], keep="last")
                .sort_values("datetime", ascending=False)
            )
            
            st.dataframe(
                detail_table,
                column_config={
                    "datetime": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD HH:mm:ss"),
                    "mac": "MAC Address",
                    "ip": "IP Address",
                    "domain_clean": "Application / Domain",
                    "source_log": "Source"
                },
                use_container_width=True
            )
        else:
            st.success("No unauthorized applications detected.")

            # -----------------------------
    # Shadow App Forensics Section
    # -----------------------------
    st.divider()
    st.header("🔍 Shadow App Forensics")

    if search_query:
        st.info(f"Showing deep forensics for: **{search_query}**")
        
        f_col1, f_col2 = st.columns(2)
        with f_col1:
            view_type = st.radio(
                "Forensic View", 
                ["App Run", "App Install", "App Usage", "Suspicious Behavior"],
                horizontal=True
            )
        with f_col2:
            # Change: Single Selectbox instead of Multiselect
            f_raw_sources = sorted(df["source_log"].unique().tolist()) if not df.empty else []
            f_options = ["All"] + f_raw_sources
            
            selected_f_source = st.selectbox(
                "Filter Forensic Source", 
                options=f_options, 
                key="forensic_source_single"
            )

        # Filter data for the searched device
        forensic_df = df[
            (df["mac"].str.contains(search_query, case=False, na=False)) | 
            (df["ip"].str.contains(search_query, case=False, na=False))
        ].copy()

        # Apply the single source filter
        if selected_f_source != "All":
            forensic_df = forensic_df[forensic_df["source_log"] == selected_f_source]

        if not forensic_df.empty:
            # --- Traffic Activity Graph ---
            st.markdown("### Traffic Activity Graph")
            f_line = forensic_df.groupby([pd.Grouper(key="datetime", freq="10min")]).size().reset_index(name="hits")
            fig_f = px.area(f_line, x="datetime", y="hits", template="plotly_dark", 
                            color_discrete_sequence=["#00CCFF"], title=f"Activity for {view_type}")
            st.plotly_chart(fig_f, use_container_width=True)

            low_col1, low_col2 = st.columns([1, 2])
            
            with low_col1:
                st.markdown("### Top Destinations")
                top_dest = forensic_df["domain_clean"].value_counts().head(10).reset_index()
                top_dest.columns = ["Destination", "Count"]
                st.table(top_dest)

            with low_col2:
                st.markdown(f"### Full View Log Detail: {view_type}")
                
                # Logic to filter logs based on the Forensic View selected
                view_map = {
                    "App Run": ["CONN", "DNS", "SSL", "HTTP", "SOFTWARE"],
                    "App Install": ["HTTP", "FILES", "CONN", "SOFTWARE"],
                    "App Usage": ["CONN", "DNS", "SSL", "HTTP"],
                    "Suspicious Behavior": ["WEIRD", "NOTICE"] 
                }
                
                log_filter = view_map.get(view_type, [])
                
                # Further filter the already source-filtered dataframe by the View Type requirements
                display_df = forensic_df[forensic_df["source_log"].isin(log_filter)]
                
                st.dataframe(
                    display_df.sort_values("datetime", ascending=False),
                    use_container_width=True,
                    hide_index=True
                )
        else:
            st.warning(f"No forensic data found for {selected_f_source} under the current search.")
    else:
        st.write("Please enter a MAC or IP address in the search bar above to begin forensics.")