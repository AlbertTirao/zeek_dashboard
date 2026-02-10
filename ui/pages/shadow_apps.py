# #ui/pages/shadow_app.py
# import streamlit as st
# import pandas as pd
# import plotly.express as px
# from pathlib import Path
# from urllib.parse import urlparse
# import yaml

# # -----------------------------
# # Config
# # -----------------------------
# # Updated to point to the YAML file in the root directory
# WHITELIST_FILE = Path(__file__).resolve().parents[2] / "whitelist_domains.yaml"

# # -----------------------------
# # License registry (User Configured)
# # -----------------------------
# LICENSE_REGISTRY = {
#     "office.com": None,
#     "microsoft.com": None,
#     "github.com": None,
#     "zoom.us": None,        # Example
#     "slack.com": None       # Example
# }

# # -----------------------------
# # Load Parquet Helper
# # -----------------------------
# @st.cache_data(show_spinner=False)
# def load_shadow_logs(parquet_root: Path, log_type: str, selected_date: str):
#     """Load parquet file for a specific log type and specific date."""
#     date_dir = parquet_root / selected_date
    
#     if not date_dir.exists():
#         return pd.DataFrame()
        
#     file_path = date_dir / f"{log_type}.parquet"
#     if file_path.exists():
#         try:
#             return pd.read_parquet(file_path)
#         except Exception:
#             return pd.DataFrame()
                
#     return pd.DataFrame()

# # -----------------------------
# # Load DHCP MAC (Aggregated)
# # -----------------------------
# @st.cache_data(show_spinner=False)
# def get_dhcp_mapping(parquet_root: Path, target_dates: list):
#     """
#     Creates a dictionary mapping IP addresses to MAC addresses.
#     Iterates through all provided dates to build a comprehensive map.
#     """
#     full_mapping = {}
    
#     # Process oldest to newest so the latest IP assignment overwrites older ones
#     for date_str in sorted(target_dates):
#         dhcp_path = parquet_root / date_str / "dhcp.parquet"
#         if not dhcp_path.exists():
#             continue
    
#         try:
#             df_dhcp = pd.read_parquet(dhcp_path)
            
#             ip_candidates = ['assigned_addr', 'client_addr', 'lease_addr', 'yiaddr', 'ip']
#             ip_col = next((col for col in ip_candidates if col in df_dhcp.columns), None)
            
#             mac_candidates = ['chaddr', 'client_chaddr', 'mac', 'hardware_address', 'src_mac']
#             mac_col = next((col for col in mac_candidates if col in df_dhcp.columns), None)

#             if ip_col and mac_col:
#                 clean_df = df_dhcp.dropna(subset=[ip_col, mac_col]).copy()
#                 clean_df[ip_col] = clean_df[ip_col].astype(str).str.strip()
#                 clean_df[mac_col] = clean_df[mac_col].astype(str).str.strip().str.lower()
                
#                 # Update mapping (newest overwrite assumes we processed sorted dates)
#                 current_map = clean_df.set_index(ip_col)[mac_col].to_dict()
#                 full_mapping.update(current_map)
                
#         except Exception:
#             continue
            
#     return full_mapping

# # -----------------------------
# # Load allowlist (UPDATED FOR YAML)
# # -----------------------------
# def load_allowlist():
#     """Loads authorized domains from whitelist_domains.yaml"""
#     if not WHITELIST_FILE.exists():
#         return []

#     approved = set()
#     try:
#         with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
#             data = yaml.safe_load(f)
            
#             if data is None:
#                 return []
            
#             raw_list = []
            
#             # Case 1: Simple List
#             if isinstance(data, list):
#                 raw_list = data
            
#             # Case 2: Dictionary (e.g. whitelist_domains: [...])
#             elif isinstance(data, dict):
#                 # Try to find by filename key first
#                 target_key = WHITELIST_FILE.stem
#                 if target_key in data and isinstance(data[target_key], list):
#                     raw_list = data[target_key]
#                 else:
#                     # Fallback: grab the first list found
#                     for val in data.values():
#                         if isinstance(val, list):
#                             raw_list = val
#                             break
            
#             # Process the list using extract_domain
#             for item in raw_list:
#                 domain = extract_domain(str(item))
#                 if domain:
#                     approved.add(domain)
                    
#     except Exception:
#         pass
        
#     return list(approved)

# # -----------------------------
# # Extract domain
# # -----------------------------
# def extract_domain(url: str):
#     if not url: return ""
#     url = str(url).strip().lower()
#     # Handle 'nan' string or non-string
#     if url == 'nan' or url == 'none': return ""
    
#     if "://" in url:
#         parsed = urlparse(url)
#         url = parsed.hostname or ""
#     if url.startswith("www."):
#         url = url[4:]
#     url = url.rstrip(".")
#     if ":" in url:
#         url = url.split(":")[0]
#     return url

# # -----------------------------
# # Check if domain is allowed
# # -----------------------------
# def is_allowed(domain: str, approved: list):
#     domain = domain.lower().strip().rstrip(".")
#     if not domain: return False
#     return any(domain == a or domain.endswith("." + a) for a in approved)

# # -----------------------------
# # Helper: Normalize Columns (UPDATED for BYTES & ERRORS)
# # -----------------------------
# def normalize_log_df(df, log_type, domain_col):
#     """Standardize column names and extract context + BYTES info."""
#     if df.empty:
#         return pd.DataFrame()
    
#     # 1. Standardize Domain Column
#     if domain_col not in df.columns:
#         # If the expected domain column is missing, try to find a fallback or return empty
#         return pd.DataFrame()
    
#     cols = {domain_col: "app_identifier"}
    
#     # Mapping IP
#     ip_options = ["id.orig_h", "orig_h", "src_ip", "ip", "c_ip"]
#     for opt in ip_options:
#         if opt in df.columns:
#             cols[opt] = "ip"
#             break

#     # Mapping MAC
#     mac_options = ["mac", "orig_mac", "id.orig_mac", "src_mac", "endpoint_mac", "ethernet_source"]
#     for opt in mac_options:
#         if opt in df.columns:
#             cols[opt] = "mac"
#             break
            
#     # --- Capture Context Columns ---
#     context_col = "Info"
    
#     # Ensure columns used for context actually exist before combining
#     if log_type == "notice":
#         if "msg" in df.columns: df[context_col] = df["msg"]
#         elif "note" in df.columns: df[context_col] = df["note"]
#     elif log_type == "weird":
#         if "addl" in df.columns: df[context_col] = df["addl"]
#         elif "name" in df.columns: df[context_col] = df["name"]
#     elif "method" in df.columns:
#         uri = df["uri"] if "uri" in df.columns else ""
#         df[context_col] = df["method"].astype(str) + " " + uri.astype(str)
#     elif "proto" in df.columns and "id.resp_p" in df.columns:
#          df[context_col] = df["proto"].astype(str) + "/" + df["id.resp_p"].astype(str)
#     elif "mime_type" in df.columns:
#         df[context_col] = df["mime_type"]
#     elif "version.major" in df.columns:
#          df[context_col] = df["unparsed_version"]
#     else:
#         df[context_col] = "-"

#     # Keep destination port
#     if "id.resp_p" in df.columns: cols["id.resp_p"] = "dst_port"
#     elif "dst_port" in df.columns: cols["dst_port"] = "dst_port"
    
#     # --- NEW: CAPTURE BYTES FOR EXFILTRATION ANALYSIS ---
#     # orig_bytes = Upload, resp_bytes = Download
#     if "orig_bytes" in df.columns: cols["orig_bytes"] = "bytes_sent"
#     if "resp_bytes" in df.columns: cols["resp_bytes"] = "bytes_received"
#     if "id.orig_bytes" in df.columns: cols["id.orig_bytes"] = "bytes_sent"
#     if "id.resp_bytes" in df.columns: cols["id.resp_bytes"] = "bytes_received"

#     # Make sure 'ts' exists for the rename
#     if "ts" in df.columns:
#         cols["ts"] = "ts"

#     df = df.rename(columns=cols)
    
#     # 2. Ensure columns exist and fill missing
#     if "ts" not in df.columns: return pd.DataFrame() # Cannot proceed without timestamp
    
#     if "ip" not in df.columns: df["ip"] = "Unknown"
#     else: df["ip"] = df["ip"].astype(str).fillna("Unknown")

#     if "mac" not in df.columns: df["mac"] = "Unknown"
#     else: 
#         df["mac"] = df["mac"].fillna("Unknown").replace("", "Unknown").astype(str).str.lower()
#         df.loc[df["mac"].isin(["none", "nan"]), "mac"] = "Unknown"
        
#     if "dst_port" not in df.columns: df["dst_port"] = 0
#     else: df["dst_port"] = pd.to_numeric(df["dst_port"], errors='coerce').fillna(0).astype(int)
    
#     # Ensure Bytes are Numeric (Clean bad strings)
#     if "bytes_sent" not in df.columns: df["bytes_sent"] = 0
#     df["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors='coerce').fillna(0).astype(int)
    
#     if "bytes_received" not in df.columns: df["bytes_received"] = 0
#     df["bytes_received"] = pd.to_numeric(df["bytes_received"], errors='coerce').fillna(0).astype(int)

#     df["source_log"] = log_type.upper()
    
#     # Return specific columns (ADDED BYTES)
#     required_cols = ["ts", "app_identifier", "ip", "mac", "source_log", "Info", "dst_port", "bytes_sent", "bytes_received"]
#     # Only select columns that actually exist to prevent KeyErrors
#     final_cols = [c for c in required_cols if c in df.columns]
    
#     return df[final_cols]

# # -----------------------------
# # Calculate Risk Level
# # -----------------------------
# def calculate_risk(row):
#     """Assigns a simple risk level based on Port and Log Type."""
#     port = row.get("dst_port", 0)
#     log = row.get("source_log", "")
#     status = row.get("App Status", "")
    
#     # 1. Critical Logs (Anomalies)
#     if log == "WEIRD" or log == "NOTICE":
#         return "Critical"
    
#     # 2. Remote Access Ports (SSH, Telnet, RDP, VNC)
#     if port in [22, 23, 3389, 5900]:
#         return "High"
        
#     # 3. Database Ports
#     if port in [1433, 3306, 5432]:
#         return "Medium"
        
#     # 4. Unauthorized Application
#     if status == "Unauthorized":
#         return "Low"
        
#     return "Safe"

# # -----------------------------
# # NEW: Categorize Threat Behavior (Exfiltration Logic)
# # -----------------------------
# def categorize_threat(row):
#     sent = row.get("bytes_sent", 0)
#     recv = row.get("bytes_received", 0)
    
#     if sent > 10_000_000: # > 10MB Upload
#         return "Potential Exfiltration"
#     if recv > 100_000_000: # > 100MB Download
#         return "Heavy Download"
#     if row["source_log"] == "WEIRD":
#         return "Protocol Anomaly"
#     return "Unauthorized Usage"

# # -----------------------------
# # Styling Function (Colors)
# # -----------------------------
# def color_risk(val):
#     """Returns CSS styles for the Risk Level column."""
#     color_map = {
#         "Critical": "color: #FF0000; font-weight: bold;",   # Red
#         "High": "color: #FF4500; font-weight: bold;",       # OrangeRed
#         "Medium": "color: #FFA500;",                        # Orange
#         "Low": "color: #FFD700;",                           # Gold
#         "Safe": "color: #00FF00;"                           # Green
#     }
#     return color_map.get(val, "")

# # -----------------------------
# # Render Main Page
# # -----------------------------
# def render_shadow_apps(parquet_root: Path):
#     st.markdown("#### Shadow Apps Overview")
    
#     # 1. Date Selection with "All" option
#     if parquet_root.exists():
#         available_dates = sorted([d.name for d in parquet_root.iterdir() if d.is_dir()], reverse=True)
#         if not available_dates:
#             st.warning("No log directories found.")
#             return
            
#         # Add 'All Available Dates' to the options
#         date_options = ["All Available Dates"] + available_dates
#         selected_option = st.selectbox("Select Date Range", date_options, index=1 if len(date_options) > 1 else 0)
        
#         if selected_option == "All Available Dates":
#             target_dates = available_dates
#             st.toast(f"Loading data from all {len(target_dates)} days. This may take a moment...", icon="⏳")
#         else:
#             target_dates = [selected_option]
#     else:
#         st.error("Log root directory not found.")
#         return

#     # 2. Load DHCP Mapping (Iterates ALL dates to find historical leases)
#     # --- FIX: We pass 'available_dates' instead of 'target_dates' so we find ALL MAC addresses ---
#     with st.spinner("Loading Network Identity (DHCP)..."):
#         ip_to_mac = get_dhcp_mapping(parquet_root, available_dates)
    
#     approved = load_allowlist()

#     # 3. Load logs
#     logs_config = [
#         ("http", "host"),
#         ("ssl", "server_name"),
#         ("dns", "query"),
#         ("files", "filename"),
#         ("conn", "service"),
#         ("software", "unparsed_version"),
#         ("weird", "name"),
#         ("notice", "note")
#     ]
    
#     combined_frames = []
    
#     # Progress bar if loading many dates
#     progress_text = "Processing logs..."
#     my_bar = st.progress(0, text=progress_text)
#     total_steps = len(target_dates)
    
#     for i, date_str in enumerate(target_dates):
#         # Update progress
#         my_bar.progress((i + 1) / total_steps, text=f"Processing {date_str}...")
        
#         for log_type, domain_col in logs_config:
#             raw_df = load_shadow_logs(parquet_root, log_type, date_str)
#             norm_df = normalize_log_df(raw_df, log_type, domain_col)
#             if not norm_df.empty:
#                 combined_frames.append(norm_df)
                
#     my_bar.empty()

#     if not combined_frames:
#         st.info(f"No Shadow App logs available for selected range.")
#         return

#     # 5. Create Master DF
#     df = pd.concat(combined_frames, ignore_index=True)
    
#     # 6. FIX: Robust Type Conversion to prevent "Unknown datetime string" error
#     # This turns strings like "#types" or "#fields" into NaN, effectively filtering bad headers
#     df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    
#     # Create Datetime Object
#     df["datetime"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")
    
#     # Drop rows where datetime failed (this removes the corrupt header rows)
#     df = df.dropna(subset=["datetime"])
    
#     # 7. Enrich Data
#     df["ip"] = df["ip"].astype(str)
    
#     # --- FIX: MAC Address Enrichment ---
#     # Map unknown MACs using the global dictionary we built from ALL DHCP logs
#     mask_unknown = (df["mac"] == "Unknown") | (df["mac"].isna())
#     mapped_macs = df.loc[mask_unknown, "ip"].map(ip_to_mac)
#     df.loc[mask_unknown, "mac"] = mapped_macs.fillna("Unknown")
#     df["mac"] = df["mac"].fillna("Unknown")
#     # -----------------------------------

#     # Domain cleanup
#     df["domain_clean"] = df["app_identifier"].apply(extract_domain)
#     special_logs = ["CONN", "FILES", "SOFTWARE", "WEIRD", "NOTICE"] 
#     mask = (df["source_log"].isin(special_logs)) & (df["domain_clean"] == "")
#     df.loc[mask, "domain_clean"] = df["app_identifier"]
#     df.loc[df["domain_clean"] == "", "domain_clean"] = "unidentified_activity"

#     # Status Check
#     df["App Status"] = df["domain_clean"].apply(lambda x: "Authorized" if is_allowed(x, approved) else "Unauthorized")
    
#     # Calculate Risk GLOBALLY
#     df["Risk Level"] = df.apply(calculate_risk, axis=1)
    
#     # Calculate Threat Type (Exfiltration)
#     df["Behavior"] = df.apply(categorize_threat, axis=1)

#     # Metrics
#     total = len(df)
#     unauth_df = df[df["App Status"] == "Unauthorized"]
#     critical_df = df[df["Risk Level"].isin(["Critical", "High"])]
    
#     col1, col2, col3, col4 = st.columns(4)
#     col1.metric("Total Events", total)
#     # Calculate counts
#     authorized_count = len(df[df["App Status"] == "Authorized"])
#     unauthorized_count = len(unauth_df)
#     total_events = authorized_count + unauthorized_count

#     # Calculate percentage of unauthorized events
#     unauth_pct = (unauthorized_count / total_events * 100) if total_events > 0 else 0

#     # Display metrics in columns
#     col2.metric(
#         label="Authorized Events",
#         value=authorized_count,
#         delta=f"{100 - int(unauth_pct)}% of total",
#     )

#     col3.metric(
#         label="Unauthorized Events",
#         value=unauthorized_count,
#         delta=f"{int(unauth_pct)}% of total",
#         delta_color="inverse"
#     )
#     col4.metric("Critical / High Risk", len(critical_df), delta_color="inverse")
    
#     st.divider()

#     # Charts
#     c1, c2 = st.columns([2, 1])
#     with c1:
#         st.markdown("### Activity Over Time")
#         if not df.empty:
#             # Group by hour for clean graph
#             df_line = df.groupby([pd.Grouper(key="datetime", freq="H"), "App Status"]).size().reset_index(name="count")
#             fig = px.line(df_line, x="datetime", y="count", color="App Status", 
#                           color_discrete_map={"Authorized": "#00FF00", "Unauthorized": "#FF0000"},
#                           template="plotly_dark")
#             st.plotly_chart(fig, use_container_width=True)
            
#     with c2:
#         st.markdown("### Source Distribution")
#         df_pie = df.groupby("source_log").size().reset_index(name="Log Count")
#         fig_pie = px.pie(
#             df_pie, values="Log Count", names="source_log", template="plotly_dark", hole=0.4
#         )
#         st.plotly_chart(fig_pie, use_container_width=True)

#     # --------------------------------------------------------
#     # TABS: The distinct UI Experience
#     # --------------------------------------------------------
#     t1, t2 = st.tabs(["Authorized Applications & License Audit", "Unauthorized Applications"])
    
#     # --- AUTHORIZED & UNAUTHORIZED TAB ---
#     with t1:
#         # ==============================================================================
#         # 1. APPLICATION AUDIT LOG (ENHANCED WITH DE-DUPLICATION)
#         # ==============================================================================
        
#         st.markdown("### Application Audit Log")
        
#         # Row 1: Primary Search and Status Toggle
#         filter_col1, filter_col2 = st.columns([3, 2])
#         with filter_col1: 
#             search_query_audit = st.text_input("Search (MAC, IP, Domain)", placeholder="Search...", key="audit_search").strip().lower()
#         with filter_col2:
#             status_filter = st.radio(
#                 "Filter Status", 
#                 ["All", "Authorized", "Unauthorized"], 
#                 horizontal=True, 
#                 key="audit_status_filter"
#             )

#         # Row 2: Source Filter and De-duplication Toggle
#         filter_col3, filter_col4 = st.columns([3, 2])
#         with filter_col3:
#             raw_sources = sorted(df["source_log"].unique().tolist()) if not df.empty else []
#             selected_source_audit = st.selectbox("Source Log Type", ["All"] + raw_sources, key="audit_source_filter")
#         with filter_col4:
#             # --- NEW: DE-DUPLICATION SELECTION ---
#             dedup_enabled = st.toggle("Remove Duplications (Summary View)", value=True, help="Combine multiple hits from the same device into a single summary row.")

#         # --- Data Filtering Logic ---
#         audit_df = df.copy()

#         if status_filter != "All":
#             audit_df = audit_df[audit_df["App Status"] == status_filter]
            
#         if selected_source_audit != "All":
#             audit_df = audit_df[audit_df["source_log"] == selected_source_audit]

#         if search_query_audit:
#             q = search_query_audit
#             audit_df = audit_df[
#                 (audit_df["mac"].str.contains(q, case=False, na=False)) | 
#                 (audit_df["ip"].str.contains(q, case=False, na=False)) |
#                 (audit_df["domain_clean"].str.contains(q, case=False, na=False))
#             ]

#         if not audit_df.empty:
#             # --- RENDER LOGIC ---
#             if dedup_enabled:
#                 # Grouped Summary View
#                 display_df = (
#                     audit_df.sort_values("datetime")
#                     .groupby(["domain_clean", "mac", "ip", "source_log", "App Status"])
#                     .agg(
#                         First_Seen=("datetime", "min"), 
#                         Last_Seen=("datetime", "max"), 
#                         Hits=("datetime", "count")
#                     )
#                     .reset_index()
#                     .sort_values("Hits", ascending=False)
#                 )
#                 col_config = {
#                     "domain_clean": "Application",
#                     "mac": "MAC Address",
#                     "ip": "IP Address",
#                     "source_log": "Source",
#                     "First_Seen": st.column_config.DatetimeColumn("First Seen", format="MM-DD HH:mm"),
#                     "Last_Seen": st.column_config.DatetimeColumn("Last Seen", format="MM-DD HH:mm"),
#                     "Hits": st.column_config.NumberColumn("Total Hits"),
#                 }
#             else:
#                 # Detailed Raw View
#                 display_df = audit_df.sort_values("datetime", ascending=False)
#                 col_config = {
#                     "datetime": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
#                     "domain_clean": "Application",
#                     "mac": "MAC Address",
#                     "ip": "IP Address",
#                     "source_log": "Source",
#                 }

#             # Limit rows for performance
#             display_df = display_df.head(1000)
            
#             # Dynamic Coloring
#             def color_status(val):
#                 if val == "Authorized": return 'color: #6CA651; font-weight: bold;'
#                 if val == "Unauthorized": return 'color: #FF4B4B; font-weight: bold;'
#                 return ''

#             styled_audit = display_df.style.map(color_status, subset=['App Status'])
            
#             st.dataframe(
#                 styled_audit, 
#                 column_config=col_config,
#                 use_container_width=True, 
#                 hide_index=True
#             )
            
#             st.caption(f"Showing {len(display_df)} results. Use filters to narrow down data.")
#         else:
#             st.info(f"No {status_filter.lower()} logs found matching your criteria.")

#         st.divider()

#         # ==============================================================================
#         # 2. LICENSE COMPLIANCE AUDIT (Usage-Only Mode)
#         # ==============================================================================
#         st.markdown("### License Compliance Audit")
#         st.caption("Detected active devices for each monitored software. Paid license count unknown.")

#         usage_data = []

#         # -----------------------------
#         # Usage Detection Logic
#         # -----------------------------
#         for software in LICENSE_REGISTRY.keys():
#             software_usage = df[
#                 df["domain_clean"].astype(str).str.contains(software, case=False, na=False)
#             ]

#             # Unique MAC addresses
#             mac_list = software_usage["mac"].dropna().unique().tolist()
#             unique_users = len(mac_list)

#             # Status
#             status = "Usage Detected" if unique_users > 0 else "No Usage"

#             usage_data.append({
#                 "Software": software,
#                 "Active Devices Count": unique_users,
#                 "Active Device MACs": ", ".join(mac_list),
#                 "Status": status
#             })

#         # -----------------------------
#         # Table and Visualization
#         # -----------------------------
#         if usage_data:
#             usage_df = pd.DataFrame(usage_data)

#             table_col, chart_col = st.columns([1.7, 1])

#             with table_col:
#                 st.markdown("<div style='font-size:25px; font-weight:600;'>Detected Software Usage</div>",unsafe_allow_html=True)

#                 # Style the Status column
#                 def style_status(val):
#                     return "color: #FF4B4B; font-weight: 600;" if val == "Usage Detected" else "color: #00CC96; font-weight: 600;"

#                 st.dataframe(
#                     usage_df.style.applymap(style_status, subset=["Status"]),
#                     use_container_width=True,
#                     hide_index=True
#                 )

#             with chart_col:
#                 st.markdown("<div style='font-size:20px; font-weight:600;'>Active Devices per Software</div>",unsafe_allow_html=True)
#                 chart_df = usage_df[["Software", "Active Devices Count"]]

#                 fig = px.bar(
#                     chart_df,
#                     x="Software",
#                     y="Active Devices Count",
#                     text_auto=True,
#                     template="plotly_dark",
#                     color="Active Devices Count",
#                     color_continuous_scale="RdYlGn_r"
#                 )

#                 fig.update_layout(
#                     xaxis_title=None,
#                     yaxis_title="Active Devices",
#                     height=420,
#                     showlegend=False
#                 )

#                 st.plotly_chart(fig, use_container_width=True)

#         else:
#             st.info("No active usage detected for monitored software.")

#         st.divider()

#         # -----------------------------
#         # Shadow App Forensics Section (INSIDE TAB 1)
#         # -----------------------------
#         st.markdown("### Shadow App Forensics")

#         search_query = st.text_input("Global Forensic Search", placeholder="Enter specific MAC or IP to start deep dive...", key="global_forensic_search").strip().lower()

#         if search_query:
#             st.info(f"Showing deep forensics for: **{search_query}**")
            
#             f_col1, f_col2 = st.columns(2)
#             with f_col1:
#                 st.markdown(
#                     "<div style='font-size:10px; font-weight:600; margin-bottom:6px;'>Forensic View</div>",
#                     unsafe_allow_html=True
#                 )

#                 view_type = st.radio(
#                     label="",
#                     options=[
#                         "App Run (Connectivity)",
#                         "App Usage (Interaction)",
#                         "App Install (Files)",
#                         "Suspicious Behavior"
#                     ],
#                     horizontal=True
#                 )
#             with f_col2:
#                 f_raw_sources = sorted(df["source_log"].unique().tolist()) if not df.empty else []
#                 selected_f_source = st.selectbox("Filter Forensic Source", options=["All"] + f_raw_sources, key="forensic_source_single")

#             # Base Filter
#             forensic_df = df[
#                 (df["mac"].str.contains(search_query, case=False, na=False)) | 
#                 (df["ip"].str.contains(search_query, case=False, na=False))
#             ].copy()

#             if selected_f_source != "All":
#                 forensic_df = forensic_df[forensic_df["source_log"] == selected_f_source]

#             if not forensic_df.empty:
                
#                 # --- DISTINCT LOGIC IMPLEMENTATION ---
#                 if "App Run" in view_type:
#                     display_df = forensic_df[forensic_df["source_log"].isin(["CONN", "DNS"])]
#                     color_graph = ["#00CCFF"] 
#                 elif "App Usage" in view_type:
#                     display_df = forensic_df[forensic_df["source_log"].isin(["HTTP", "SSL"])]
#                     color_graph = ["#00FF99"] 
#                 elif "App Install" in view_type:
#                     display_df = forensic_df[forensic_df["source_log"].isin(["FILES", "SOFTWARE"])]
#                     color_graph = ["#FFFF00"] 
#                 elif "Suspicious" in view_type:
#                     display_df = forensic_df[
#                         (forensic_df["App Status"] == "Unauthorized") | 
#                         (forensic_df["Risk Level"].isin(["Critical", "High", "Medium"]))
#                     ]
#                     color_graph = ["#FF0000"] 
#                 else:
#                     display_df = forensic_df
#                     color_graph = ["#888888"]

#                 # --- Activity Graph ---
#                 st.markdown("#### Traffic Activity Graph")
#                 if not display_df.empty:
#                     f_line = display_df.groupby([pd.Grouper(key="datetime", freq="10min")]).size().reset_index(name="hits")
#                     fig_f = px.area(f_line, x="datetime", y="hits", template="plotly_dark", 
#                                     color_discrete_sequence=color_graph, title=f"Activity: {view_type}")
#                     st.plotly_chart(fig_f, use_container_width=True)
#                 else:
#                     st.warning(f"No events found for {view_type} category.")

#                 # --- Top Destinations & Table ---
#                 low_col1, low_col2 = st.columns([1, 2])
                
#                 with low_col1:
#                     st.markdown("#### Top Destinations")
#                     if not display_df.empty:
#                         top_dest = display_df["domain_clean"].value_counts().head(10).reset_index()
#                         top_dest.columns = ["Destination", "Count"]
#                         st.table(top_dest)
#                     else:
#                         st.write("No data.")

#                 with low_col2:
#                     title_col, opt_col, status_col = st.columns([1.5, 1.2, 1])
#                     with title_col: st.markdown(f"### {view_type}")
#                     with opt_col:
#                         table_mode = st.selectbox(
#                             "View Mode",
#                             options=["Detailed Logs", "Unique Rows", "Group by App", "Group by Source"],
#                             label_visibility="collapsed" 
#                         )
#                     with status_col:
#                         allow_status = st.radio(
#                             " ", ["Authorized", "Unauthorized", "All"],
#                             horizontal=True, key="allow_filter", label_visibility="collapsed"
#                         )
                    
#                     if allow_status == "Authorized":
#                         display_df = display_df[display_df["App Status"] == "Authorized"]
#                     elif allow_status == "Unauthorized":
#                         display_df = display_df[display_df["App Status"] == "Unauthorized"]
                    
#                     if table_mode == "Unique Rows":
#                         final_df = display_df.drop_duplicates(subset=["domain_clean", "ip", "mac", "source_log", "Info"]).sort_values("datetime", ascending=False)
#                     elif table_mode == "Group by App":
#                         final_df = display_df.groupby(["domain_clean", "App Status"]).size().reset_index(name='Count').sort_values(by="Count", ascending=False)
#                     elif table_mode == "Group by Source":
#                         final_df = display_df.groupby(["source_log", "App Status"]).size().reset_index(name='Count').sort_values(by="Count", ascending=False)
#                     else:
#                         final_df = display_df.sort_values("datetime", ascending=False)

#                     # Limit to 1000 rows to prevent crash
#                     final_df = final_df.head(1000)

#                     if "Risk Level" in final_df.columns:
#                         styled_final_df = final_df.style.applymap(color_risk, subset=["Risk Level"])
#                     else:
#                         styled_final_df = final_df

#                     st.dataframe(
#                         styled_final_df,
#                         column_config={
#                             "datetime": st.column_config.DatetimeColumn("Timestamp", format="HH:mm:ss"),
#                             "Info": "Context Info",
#                             "domain_clean": "Destination",
#                             "dst_port": "Port",
#                             "Risk Level": "Risk"
#                         },
#                         use_container_width=True,
#                         hide_index=True
#                     )
                    
#                     if not final_df.empty:
#                         st.download_button(
#                             label="Download Evidence (CSV)",
#                             data=final_df.to_csv(index=False).encode('utf-8'),
#                             file_name=f"forensics_{search_query}_{view_type}.csv",
#                             mime='text/csv'
#                         )
                
#                 # -------------------------------------------
#                 # Device Analytics
#                 # -------------------------------------------
#                 st.divider()
#                 st.subheader("Device Analytics")
                
#                 g_col1, g_col2, g_col3, g_col4 = st.columns(4)
                
#                 with g_col1:
#                     st.markdown("##### Total Activity")
#                     if not forensic_df.empty:
#                         forensic_df["hour"] = forensic_df["datetime"].dt.hour
#                         hourly_counts = forensic_df.groupby("hour").size().reset_index(name="count")
#                         fig1 = px.bar(hourly_counts, x="hour", y="count", template="plotly_dark", color_discrete_sequence=["#3366CC"])
#                         st.plotly_chart(fig1, use_container_width=True)

#                 with g_col2:
#                     st.markdown("##### Auth vs Unauth")
#                     if not forensic_df.empty:
#                         status_counts = forensic_df["App Status"].value_counts().reset_index()
#                         status_counts.columns = ["App Status", "count"]
#                         fig2 = px.pie(
#                             status_counts, names="App Status", values="count", color="App Status",
#                             color_discrete_map={"Authorized": "#00FF00", "Unauthorized": "#FF0000"},
#                             template="plotly_dark", hole=0.5
#                         )
#                         st.plotly_chart(fig2, use_container_width=True)

#                 with g_col3:
#                     st.markdown("##### Source Dist.")
#                     if not forensic_df.empty:
#                         source_counts = forensic_df["source_log"].value_counts().reset_index()
#                         source_counts.columns = ["Source", "count"]
#                         fig3 = px.bar(source_counts, x="Source", y="count", template="plotly_dark", color="Source")
#                         st.plotly_chart(fig3, use_container_width=True)

#                 with g_col4:
#                     st.markdown("##### Top Ports")
#                     if not forensic_df.empty:
#                         port_df = forensic_df[forensic_df["dst_port"] > 0]
#                         if not port_df.empty:
#                             port_counts = port_df["dst_port"].value_counts().head(5).reset_index()
#                             port_counts.columns = ["Port", "count"]
#                             port_counts["Port"] = port_counts["Port"].astype(str)
#                             fig4 = px.bar(port_counts, x="Port", y="count", template="plotly_dark", color_discrete_sequence=["#FF9900"])
#                             st.plotly_chart(fig4, use_container_width=True)
#                         else:
#                             st.write("No port data.")
#                     else:
#                         st.write("No data.")
#         else:
#             st.write("Please enter a MAC or IP address in the search bar above to begin forensics.")

#     # --- UNAUTHORIZED TAB (Advanced Threat Dashboard) ---
#     with t2:
#         st.markdown("## Unauthorized Threat Dashboard")
        
#         if not unauth_df.empty:
#             # 1. Threat Metrics
#             u_metrics1, u_metrics2, u_metrics3 = st.columns(3)
#             with u_metrics1:
#                 st.metric("Active Unauthorized Apps", unauth_df["domain_clean"].nunique())
#             with u_metrics2:
#                 top_offender = unauth_df["mac"].value_counts().idxmax()
#                 offender_count = unauth_df["mac"].value_counts().max()
#                 st.metric("Top Offender (MAC)", top_offender, delta=f"{offender_count} Events", delta_color="inverse")
#             with u_metrics3:
#                 crit_count = len(unauth_df[unauth_df["Risk Level"].isin(["Critical", "High"])])
#                 st.metric("Critical Risks Detected", crit_count, delta="Requires Attention", delta_color="inverse")
            
#             st.divider()
            
#             # --- NEW: DATA EXFILTRATION MONITOR ---
#             with st.expander("Data Exfiltration Monitor (High Volume Traffic)", expanded=True):
#                 exfil_c1, exfil_c2 = st.columns(2)
                
#                 # Calculate Totals
#                 total_sent_gb = unauth_df["bytes_sent"].sum() / 1_000_000_000
#                 total_recv_gb = unauth_df["bytes_received"].sum() / 1_000_000_000
                
#                 with exfil_c1:
#                     st.metric("Total Unauthorized Upload", f"{total_sent_gb:.2f} GB", delta="Potential Leak", delta_color="inverse")
#                     st.metric("Total Unauthorized Download", f"{total_recv_gb:.2f} GB")
                    
#                 with exfil_c2:
#                     # Scatter Plot: Bytes Sent vs Port
#                     if not unauth_df.empty and unauth_df["bytes_sent"].max() > 0:
#                         fig_exfil = px.scatter(
#                             unauth_df[unauth_df["bytes_sent"] > 0], 
#                             x="dst_port", y="bytes_sent", 
#                             size="bytes_sent", color="Behavior",
#                             hover_data=["domain_clean", "mac"],
#                             title="Outbound Data Volume by Port",
#                             template="plotly_dark"
#                         )
#                         st.plotly_chart(fig_exfil, use_container_width=True)
#                     else:
#                         st.info("No significant outbound traffic detected.")

#             st.divider()

#             # 2. Risk Distribution Chart
#             u_chart1, u_chart2 = st.columns([2, 1])
#             with u_chart1:
#                 st.markdown("#### Top Unauthorized Domains")
#                 top_unauth_domains = unauth_df["domain_clean"].value_counts().head(10).reset_index()
#                 top_unauth_domains.columns = ["Domain", "Hits"]
#                 fig_u1 = px.bar(top_unauth_domains, x="Hits", y="Domain", orientation='h', template="plotly_dark", color_discrete_sequence=["#FF4500"])
#                 fig_u1.update_layout(yaxis={'categoryorder':'total ascending'})
#                 st.plotly_chart(fig_u1, use_container_width=True)
            
#             with u_chart2:
#                 st.markdown("#### Risk Distribution")
#                 risk_counts = unauth_df["Risk Level"].value_counts().reset_index()
#                 risk_counts.columns = ["Risk", "Count"]
                
#                 risk_colors = {
#                     "Critical": "#FF0000", "High": "#FF4500", 
#                     "Medium": "#FFA500", "Low": "#FFD700", "Safe": "#00FF00"
#                 }
                
#                 fig_u2 = px.pie(risk_counts, values="Count", names="Risk", 
#                                 color="Risk", color_discrete_map=risk_colors,
#                                 template="plotly_dark", hole=0.6)
#                 st.plotly_chart(fig_u2, use_container_width=True)

#             st.divider()
            
#             # 3. Advanced Filtering & Table
#             st.markdown("### Threat Details")
            
#             af_1, af_2, af_3 = st.columns([1, 1, 2])
#             with af_1:
#                 filter_risk = st.multiselect("Filter by Risk", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
#             with af_2:
#                 filter_source = st.multiselect("Filter by Log Source", unauth_df["source_log"].unique(), default=unauth_df["source_log"].unique())
#             with af_3:
#                 search_query_unauth = st.text_input("Search (IP, MAC, Domain)", placeholder="Search threat details...", key="unauth_search")

#             filtered_unauth = unauth_df.copy()
#             if filter_risk: filtered_unauth = filtered_unauth[filtered_unauth["Risk Level"].isin(filter_risk)]
#             if filter_source: filtered_unauth = filtered_unauth[filtered_unauth["source_log"].isin(filter_source)]
#             if search_query_unauth:
#                 q = search_query_unauth.lower()
#                 filtered_unauth = filtered_unauth[
#                     (filtered_unauth["mac"].str.contains(q, case=False, na=False)) | 
#                     (filtered_unauth["ip"].str.contains(q, case=False, na=False)) |
#                     (filtered_unauth["domain_clean"].str.contains(q, case=False, na=False))
#                 ]

#             detail_table = (
#                 filtered_unauth[["datetime", "mac", "ip", "domain_clean", "source_log", "Info", "dst_port", "bytes_sent", "Behavior", "Risk Level"]]
#                 .sort_values("datetime", ascending=False)
#             )
            
#             # Limit to 1000 rows to prevent crash
#             detail_table = detail_table.head(1000)
            
#             styled_unauth = detail_table.style.applymap(color_risk, subset=["Risk Level"])

#             st.dataframe(
#                 styled_unauth,
#                 column_config={
#                     "datetime": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
#                     "mac": "MAC Address",
#                     "ip": "IP Address",
#                     "domain_clean": "Unauthorized Domain",
#                     "source_log": "Source",
#                     "Info": "Context",
#                     "dst_port": "Port",
#                     "bytes_sent": "Upload (Bytes)",
#                     "Behavior": "Behavior Tag",
#                     "Risk Level": "Threat Risk"
#                 },
#                 use_container_width=True,
#                 hide_index=True
#             )
#         else:
#             st.success("No Unauthorized applications detected. System is clean.")





# # ui/pages/shadow_app.py
# import streamlit as st
# import pandas as pd
# import plotly.express as px
# import pyarrow.parquet as pq  # Required for schema inspection
# from pathlib import Path
# from urllib.parse import urlparse
# import yaml

# # -----------------------------
# # Config
# # -----------------------------
# # Updated to point to the YAML file in the root directory
# WHITELIST_FILE = Path(__file__).resolve().parents[2] / "whitelist_domains.yaml"

# # -----------------------------
# # License registry (User Configured)
# # -----------------------------
# LICENSE_REGISTRY = {
#     "office.com": None,
#     "microsoft.com": None,
#     "github.com": None,
#     "zoom.us": None,        # Example
#     "slack.com": None       # Example
# }

# # -----------------------------
# # Optimized Parquet Loader (Columnar Projection)
# # -----------------------------
# @st.cache_data(show_spinner=False)
# def load_shadow_logs_optimized(parquet_root: Path, log_type: str, selected_date: str, requested_cols: list):
#     """
#     Lazy Loader:
#     1. Checks if file exists.
#     2. Reads Schema ONLY (instant).
#     3. Intersects requested columns with available columns.
#     4. Reads ONLY the intersection (Columnar Storage benefit).
#     """
#     date_dir = parquet_root / selected_date
#     if not date_dir.exists():
#         return pd.DataFrame()
        
#     file_path = date_dir / f"{log_type}.parquet"
#     if not file_path.exists():
#         return pd.DataFrame()

#     try:
#         # 1. Inspect Schema without reading data
#         parquet_file = pq.ParquetFile(file_path)
#         available_cols = set(parquet_file.schema.names)
        
#         # 2. Only load columns that actually exist
#         cols_to_load = [c for c in requested_cols if c in available_cols]
        
#         if not cols_to_load:
#             return pd.DataFrame()

#         # 3. Read specific columns
#         return pd.read_parquet(file_path, columns=cols_to_load)

#     except Exception:
#         return pd.DataFrame()

# # -----------------------------
# # Load DHCP MAC (Aggregated & Optimized)
# # -----------------------------
# @st.cache_data(show_spinner=False)
# def get_dhcp_mapping(parquet_root: Path, target_dates: list):
#     """
#     Creates a dictionary mapping IP addresses to MAC addresses.
#     OPTIMIZED: Only reads 'ip' and 'mac' columns to save memory.
#     """
#     full_mapping = {}
    
#     # Define possible column names for IP and MAC
#     ip_candidates = ['assigned_addr', 'client_addr', 'lease_addr', 'yiaddr', 'ip']
#     mac_candidates = ['chaddr', 'client_chaddr', 'mac', 'hardware_address', 'src_mac']
    
#     # We ask the loader to look for ALL candidates, then we filter in memory
#     # This is still much smaller than reading the whole file.
#     cols_to_request = ip_candidates + mac_candidates

#     # Process oldest to newest so the latest IP assignment overwrites older ones
#     for date_str in sorted(target_dates):
        
#         # Reuse the optimized loader
#         df_dhcp = load_shadow_logs_optimized(parquet_root, "dhcp", date_str, cols_to_request)
        
#         if df_dhcp.empty:
#             continue

#         try:
#             # Find the first valid column that exists in this dataframe
#             ip_col = next((col for col in ip_candidates if col in df_dhcp.columns), None)
#             mac_col = next((col for col in mac_candidates if col in df_dhcp.columns), None)

#             if ip_col and mac_col:
#                 clean_df = df_dhcp.dropna(subset=[ip_col, mac_col]).copy()
#                 clean_df[ip_col] = clean_df[ip_col].astype(str).str.strip()
#                 clean_df[mac_col] = clean_df[mac_col].astype(str).str.strip().str.lower()
                
#                 # Update mapping
#                 current_map = clean_df.set_index(ip_col)[mac_col].to_dict()
#                 full_mapping.update(current_map)
                
#         except Exception:
#             continue
            
#     return full_mapping

# # -----------------------------
# # Load allowlist (UPDATED FOR YAML)
# # -----------------------------
# def load_allowlist():
#     """Loads authorized domains from whitelist_domains.yaml"""
#     if not WHITELIST_FILE.exists():
#         return []

#     approved = set()
#     try:
#         with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
#             data = yaml.safe_load(f)
            
#             if data is None:
#                 return []
            
#             raw_list = []
            
#             # Case 1: Simple List
#             if isinstance(data, list):
#                 raw_list = data
            
#             # Case 2: Dictionary (e.g. whitelist_domains: [...])
#             elif isinstance(data, dict):
#                 # Try to find by filename key first
#                 target_key = WHITELIST_FILE.stem
#                 if target_key in data and isinstance(data[target_key], list):
#                     raw_list = data[target_key]
#                 else:
#                     # Fallback: grab the first list found
#                     for val in data.values():
#                         if isinstance(val, list):
#                             raw_list = val
#                             break
            
#             # Process the list using extract_domain
#             for item in raw_list:
#                 domain = extract_domain(str(item))
#                 if domain:
#                     approved.add(domain)
                    
#     except Exception:
#         pass
        
#     return list(approved)

# # -----------------------------
# # Extract domain
# # -----------------------------
# def extract_domain(url: str):
#     if not url: return ""
#     url = str(url).strip().lower()
#     # Handle 'nan' string or non-string
#     if url == 'nan' or url == 'none': return ""
    
#     if "://" in url:
#         parsed = urlparse(url)
#         url = parsed.hostname or ""
#     if url.startswith("www."):
#         url = url[4:]
#     url = url.rstrip(".")
#     if ":" in url:
#         url = url.split(":")[0]
#     return url

# # -----------------------------
# # Check if domain is allowed
# # -----------------------------
# def is_allowed(domain: str, approved: list):
#     domain = domain.lower().strip().rstrip(".")
#     if not domain: return False
#     return any(domain == a or domain.endswith("." + a) for a in approved)

# # -----------------------------
# # Helper: Normalize Columns (UPDATED for BYTES & ERRORS)
# # -----------------------------
# def normalize_log_df(df, log_type, domain_col):
#     """Standardize column names and extract context + BYTES info."""
#     if df.empty:
#         return pd.DataFrame()
    
#     # 1. Standardize Domain Column
#     if domain_col not in df.columns:
#         return pd.DataFrame()
    
#     cols = {domain_col: "app_identifier"}
    
#     # Mapping IP
#     ip_options = ["id.orig_h", "orig_h", "src_ip", "ip", "c_ip"]
#     for opt in ip_options:
#         if opt in df.columns:
#             cols[opt] = "ip"
#             break

#     # Mapping MAC
#     mac_options = ["mac", "orig_mac", "id.orig_mac", "src_mac", "endpoint_mac", "ethernet_source"]
#     for opt in mac_options:
#         if opt in df.columns:
#             cols[opt] = "mac"
#             break
            
#     # --- Capture Context Columns ---
#     context_col = "Info"
    
#     # Ensure columns used for context actually exist before combining
#     if log_type == "notice":
#         if "msg" in df.columns: df[context_col] = df["msg"]
#         elif "note" in df.columns: df[context_col] = df["note"]
#     elif log_type == "weird":
#         if "addl" in df.columns: df[context_col] = df["addl"]
#         elif "name" in df.columns: df[context_col] = df["name"]
#     elif "method" in df.columns:
#         uri = df["uri"] if "uri" in df.columns else ""
#         df[context_col] = df["method"].astype(str) + " " + uri.astype(str)
#     elif "proto" in df.columns and "id.resp_p" in df.columns:
#          df[context_col] = df["proto"].astype(str) + "/" + df["id.resp_p"].astype(str)
#     elif "mime_type" in df.columns:
#         df[context_col] = df["mime_type"]
#     elif "version.major" in df.columns:
#          df[context_col] = df["unparsed_version"]
#     else:
#         df[context_col] = "-"

#     # Keep destination port
#     if "id.resp_p" in df.columns: cols["id.resp_p"] = "dst_port"
#     elif "dst_port" in df.columns: cols["dst_port"] = "dst_port"
    
#     # --- NEW: CAPTURE BYTES FOR EXFILTRATION ANALYSIS ---
#     if "orig_bytes" in df.columns: cols["orig_bytes"] = "bytes_sent"
#     if "resp_bytes" in df.columns: cols["resp_bytes"] = "bytes_received"
#     if "id.orig_bytes" in df.columns: cols["id.orig_bytes"] = "bytes_sent"
#     if "id.resp_bytes" in df.columns: cols["id.resp_bytes"] = "bytes_received"

#     # Make sure 'ts' exists for the rename
#     if "ts" in df.columns:
#         cols["ts"] = "ts"

#     df = df.rename(columns=cols)
    
#     # 2. Ensure columns exist and fill missing
#     if "ts" not in df.columns: return pd.DataFrame() 
    
#     if "ip" not in df.columns: df["ip"] = "Unknown"
#     else: df["ip"] = df["ip"].astype(str).fillna("Unknown")

#     if "mac" not in df.columns: df["mac"] = "Unknown"
#     else: 
#         df["mac"] = df["mac"].fillna("Unknown").replace("", "Unknown").astype(str).str.lower()
#         df.loc[df["mac"].isin(["none", "nan"]), "mac"] = "Unknown"
        
#     if "dst_port" not in df.columns: df["dst_port"] = 0
#     else: df["dst_port"] = pd.to_numeric(df["dst_port"], errors='coerce').fillna(0).astype(int)
    
#     # Ensure Bytes are Numeric
#     if "bytes_sent" not in df.columns: df["bytes_sent"] = 0
#     df["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors='coerce').fillna(0).astype(int)
    
#     if "bytes_received" not in df.columns: df["bytes_received"] = 0
#     df["bytes_received"] = pd.to_numeric(df["bytes_received"], errors='coerce').fillna(0).astype(int)

#     df["source_log"] = log_type.upper()
    
#     # Return specific columns
#     required_cols = ["ts", "app_identifier", "ip", "mac", "source_log", "Info", "dst_port", "bytes_sent", "bytes_received"]
#     final_cols = [c for c in required_cols if c in df.columns]
    
#     return df[final_cols]

# # -----------------------------
# # Calculate Risk Level
# # -----------------------------
# def calculate_risk(row):
#     port = row.get("dst_port", 0)
#     log = row.get("source_log", "")
#     status = row.get("App Status", "")
    
#     if log == "WEIRD" or log == "NOTICE":
#         return "Critical"
#     if port in [22, 23, 3389, 5900]:
#         return "High"
#     if port in [1433, 3306, 5432]:
#         return "Medium"
#     if status == "Unauthorized":
#         return "Low"
#     return "Safe"

# # -----------------------------
# # NEW: Categorize Threat Behavior
# # -----------------------------
# def categorize_threat(row):
#     sent = row.get("bytes_sent", 0)
#     recv = row.get("bytes_received", 0)
    
#     if sent > 10_000_000: # > 10MB Upload
#         return "Potential Exfiltration"
#     if recv > 100_000_000: # > 100MB Download
#         return "Heavy Download"
#     if row["source_log"] == "WEIRD":
#         return "Protocol Anomaly"
#     return "Unauthorized Usage"

# # -----------------------------
# # Styling Function (Colors)
# # -----------------------------
# def color_risk(val):
#     color_map = {
#         "Critical": "color: #FF0000; font-weight: bold;",
#         "High": "color: #FF4500; font-weight: bold;",
#         "Medium": "color: #FFA500;",
#         "Low": "color: #FFD700;",
#         "Safe": "color: #00FF00;"
#     }
#     return color_map.get(val, "")

# # -----------------------------
# # Render Main Page
# # -----------------------------
# def render_shadow_apps(parquet_root: Path):
#     st.markdown("#### Shadow Apps Overview")
    
#     # 1. Date Selection
#     if parquet_root.exists():
#         available_dates = sorted([d.name for d in parquet_root.iterdir() if d.is_dir()], reverse=True)
#         if not available_dates:
#             st.warning("No log directories found.")
#             return
            
#         date_options = ["All Available Dates"] + available_dates
#         selected_option = st.selectbox("Select Date Range", date_options, index=1 if len(date_options) > 1 else 0)
        
#         if selected_option == "All Available Dates":
#             target_dates = available_dates
#             st.toast(f"Lazy loading data from all {len(target_dates)} days...", icon="⏳")
#         else:
#             target_dates = [selected_option]
#     else:
#         st.error("Log root directory not found.")
#         return

#     # 2. Load DHCP Mapping (Optimized - scans all dates but only reading minimal columns)
#     with st.spinner("Loading Network Identity (DHCP)..."):
#         ip_to_mac = get_dhcp_mapping(parquet_root, available_dates)
    
#     approved = load_allowlist()

#     # 3. Load logs (Defined with required context columns per log type)
#     # We explicitly list columns to read to enforce Columnar Projection
#     base_cols = ["ts", "id.orig_h", "id.resp_p", "orig_bytes", "resp_bytes", "id.orig_bytes", "id.resp_bytes"]
    
#     logs_config = [
#         # (LogType, DomainCol, [Extra Context Cols])
#         ("http", "host", ["method", "uri"]),
#         ("ssl", "server_name", []),
#         ("dns", "query", []),
#         ("files", "filename", ["mime_type"]),
#         ("conn", "service", ["proto"]),
#         ("software", "unparsed_version", ["version.major"]),
#         ("weird", "name", ["addl"]),
#         ("notice", "note", ["msg"])
#     ]
    
#     combined_frames = []
    
#     progress_text = "Projecting columns from Parquet..."
#     my_bar = st.progress(0, text=progress_text)
#     total_steps = len(target_dates)
    
#     for i, date_str in enumerate(target_dates):
#         my_bar.progress((i + 1) / total_steps, text=f"Scanning {date_str}...")
        
#         for log_type, domain_col, extra_cols in logs_config:
            
#             # Construct strict column list for this specific log type
#             # This is the "Lazy / Columnar" magic. We don't read the whole file.
#             needed_cols = base_cols + [domain_col] + extra_cols
            
#             # Add MAC candidates to the request list just in case they exist in source
#             needed_cols += ["mac", "id.orig_mac"]

#             raw_df = load_shadow_logs_optimized(parquet_root, log_type, date_str, needed_cols)
#             norm_df = normalize_log_df(raw_df, log_type, domain_col)
            
#             if not norm_df.empty:
#                 combined_frames.append(norm_df)
                
#     my_bar.empty()

#     if not combined_frames:
#         st.info(f"No Shadow App logs available for selected range.")
#         return

#     # 5. Create Master DF
#     df = pd.concat(combined_frames, ignore_index=True)
    
#     # 6. Type Conversion
#     df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
#     df["datetime"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")
#     df = df.dropna(subset=["datetime"])
    
#     # 7. Enrich Data (MAC Mapping)
#     df["ip"] = df["ip"].astype(str)
    
#     mask_unknown = (df["mac"] == "Unknown") | (df["mac"].isna())
#     mapped_macs = df.loc[mask_unknown, "ip"].map(ip_to_mac)
#     df.loc[mask_unknown, "mac"] = mapped_macs.fillna("Unknown")
#     df["mac"] = df["mac"].fillna("Unknown")

#     # Domain cleanup
#     df["domain_clean"] = df["app_identifier"].apply(extract_domain)
#     special_logs = ["CONN", "FILES", "SOFTWARE", "WEIRD", "NOTICE"] 
#     mask = (df["source_log"].isin(special_logs)) & (df["domain_clean"] == "")
#     df.loc[mask, "domain_clean"] = df["app_identifier"]
#     df.loc[df["domain_clean"] == "", "domain_clean"] = "unidentified_activity"

#     # Status Check
#     df["App Status"] = df["domain_clean"].apply(lambda x: "Authorized" if is_allowed(x, approved) else "Unauthorized")
    
#     # Calculate Risk & Behavior
#     df["Risk Level"] = df.apply(calculate_risk, axis=1)
#     df["Behavior"] = df.apply(categorize_threat, axis=1)

#     # Metrics
#     total = len(df)
#     unauth_df = df[df["App Status"] == "Unauthorized"]
#     critical_df = df[df["Risk Level"].isin(["Critical", "High"])]
    
#     col1, col2, col3, col4 = st.columns(4)
#     col1.metric("Total Events", total)
#     authorized_count = len(df[df["App Status"] == "Authorized"])
#     unauthorized_count = len(unauth_df)
#     total_events = authorized_count + unauthorized_count
#     unauth_pct = (unauthorized_count / total_events * 100) if total_events > 0 else 0

#     col2.metric("Authorized Events", authorized_count, f"{100 - int(unauth_pct)}% of total")
#     col3.metric("Unauthorized Events", unauthorized_count, f"{int(unauth_pct)}% of total", delta_color="inverse")
#     col4.metric("Critical / High Risk", len(critical_df), delta_color="inverse")
    
#     st.divider()

#     # Charts
#     c1, c2 = st.columns([2, 1])
#     with c1:
#         st.markdown("### Activity Over Time")
#         if not df.empty:
#             df_line = df.groupby([pd.Grouper(key="datetime", freq="H"), "App Status"]).size().reset_index(name="count")
#             fig = px.line(df_line, x="datetime", y="count", color="App Status", 
#                           color_discrete_map={"Authorized": "#00FF00", "Unauthorized": "#FF0000"},
#                           template="plotly_dark")
#             st.plotly_chart(fig, use_container_width=True)
            
#     with c2:
#         st.markdown("### Source Distribution")
#         df_pie = df.groupby("source_log").size().reset_index(name="Log Count")
#         fig_pie = px.pie(df_pie, values="Log Count", names="source_log", template="plotly_dark", hole=0.4)
#         st.plotly_chart(fig_pie, use_container_width=True)

#     # --------------------------------------------------------
#     # TABS
#     # --------------------------------------------------------
#     t1, t2 = st.tabs(["Authorized Applications & License Audit", "Unauthorized Applications"])
    
#     # --- TAB 1 ---
#     with t1:
#         st.markdown("### Application Audit Log")
        
#         filter_col1, filter_col2 = st.columns([3, 2])
#         with filter_col1: 
#             search_query_audit = st.text_input("Search (MAC, IP, Domain)", placeholder="Search...", key="audit_search").strip().lower()
#         with filter_col2:
#             status_filter = st.radio("Filter Status", ["All", "Authorized", "Unauthorized"], horizontal=True, key="audit_status_filter")

#         filter_col3, filter_col4 = st.columns([3, 2])
#         with filter_col3:
#             raw_sources = sorted(df["source_log"].unique().tolist()) if not df.empty else []
#             selected_source_audit = st.selectbox("Source Log Type", ["All"] + raw_sources, key="audit_source_filter")
#         with filter_col4:
#             dedup_enabled = st.toggle("Remove Duplications (Summary View)", value=True)

#         audit_df = df.copy()

#         if status_filter != "All":
#             audit_df = audit_df[audit_df["App Status"] == status_filter]
            
#         if selected_source_audit != "All":
#             audit_df = audit_df[audit_df["source_log"] == selected_source_audit]

#         if search_query_audit:
#             q = search_query_audit
#             audit_df = audit_df[
#                 (audit_df["mac"].str.contains(q, case=False, na=False)) | 
#                 (audit_df["ip"].str.contains(q, case=False, na=False)) |
#                 (audit_df["domain_clean"].str.contains(q, case=False, na=False))
#             ]

#         if not audit_df.empty:
#             if dedup_enabled:
#                 display_df = (
#                     audit_df.sort_values("datetime")
#                     .groupby(["domain_clean", "mac", "ip", "source_log", "App Status"])
#                     .agg(First_Seen=("datetime", "min"), Last_Seen=("datetime", "max"), Hits=("datetime", "count"))
#                     .reset_index()
#                     .sort_values("Hits", ascending=False)
#                 )
#                 col_config = {
#                     "domain_clean": "Application", "mac": "MAC Address", "ip": "IP Address",
#                     "source_log": "Source", "First_Seen": st.column_config.DatetimeColumn("First Seen", format="MM-DD HH:mm"),
#                     "Last_Seen": st.column_config.DatetimeColumn("Last Seen", format="MM-DD HH:mm"), "Hits": st.column_config.NumberColumn("Total Hits"),
#                 }
#             else:
#                 display_df = audit_df.sort_values("datetime", ascending=False)
#                 col_config = {
#                     "datetime": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
#                     "domain_clean": "Application", "mac": "MAC Address", "ip": "IP Address", "source_log": "Source",
#                 }

#             display_df = display_df.head(1000)
            
#             def color_status(val):
#                 if val == "Authorized": return 'color: #6CA651; font-weight: bold;'
#                 if val == "Unauthorized": return 'color: #FF4B4B; font-weight: bold;'
#                 return ''

#             styled_audit = display_df.style.map(color_status, subset=['App Status'])
            
#             st.dataframe(styled_audit, column_config=col_config, use_container_width=True, hide_index=True)
#             st.caption(f"Showing {len(display_df)} results. Use filters to narrow down data.")
#         else:
#             st.info(f"No {status_filter.lower()} logs found matching your criteria.")

#         st.divider()

#         # License Compliance
#         st.markdown("### License Compliance Audit")
#         usage_data = []

#         for software in LICENSE_REGISTRY.keys():
#             software_usage = df[df["domain_clean"].astype(str).str.contains(software, case=False, na=False)]
#             mac_list = software_usage["mac"].dropna().unique().tolist()
#             unique_users = len(mac_list)
#             status = "Usage Detected" if unique_users > 0 else "No Usage"

#             usage_data.append({
#                 "Software": software,
#                 "Active Devices Count": unique_users,
#                 "Status": status
#             })

#         if usage_data:
#             usage_df = pd.DataFrame(usage_data)
#             table_col, chart_col = st.columns([1.7, 1])

#             with table_col:
#                 st.markdown("<div style='font-size:25px; font-weight:600;'>Detected Software Usage</div>",unsafe_allow_html=True)
#                 def style_status(val):
#                     return "color: #FF4B4B; font-weight: 600;" if val == "Usage Detected" else "color: #00CC96; font-weight: 600;"
#                 st.dataframe(usage_df.style.applymap(style_status, subset=["Status"]), use_container_width=True, hide_index=True)

#             with chart_col:
#                 st.markdown("<div style='font-size:20px; font-weight:600;'>Active Devices per Software</div>",unsafe_allow_html=True)
#                 chart_df = usage_df[["Software", "Active Devices Count"]]
#                 fig = px.bar(chart_df, x="Software", y="Active Devices Count", text_auto=True, template="plotly_dark", color="Active Devices Count", color_continuous_scale="RdYlGn_r")
#                 fig.update_layout(xaxis_title=None, yaxis_title="Active Devices", height=420, showlegend=False)
#                 st.plotly_chart(fig, use_container_width=True)
#         else:
#             st.info("No active usage detected for monitored software.")

#         st.divider()

#         # Shadow App Forensics
#         st.markdown("### Shadow App Forensics")
#         search_query = st.text_input("Global Forensic Search", placeholder="Enter specific MAC or IP...", key="global_forensic_search").strip().lower()

#         if search_query:
#             st.info(f"Showing deep forensics for: **{search_query}**")
#             f_col1, f_col2 = st.columns(2)
#             with f_col1:
#                 view_type = st.radio("", ["App Run (Connectivity)", "App Usage (Interaction)", "App Install (Files)", "Suspicious Behavior"], horizontal=True)
#             with f_col2:
#                 f_raw_sources = sorted(df["source_log"].unique().tolist()) if not df.empty else []
#                 selected_f_source = st.selectbox("Filter Forensic Source", ["All"] + f_raw_sources, key="forensic_source_single")

#             forensic_df = df[(df["mac"].str.contains(search_query, case=False, na=False)) | (df["ip"].str.contains(search_query, case=False, na=False))].copy()

#             if selected_f_source != "All":
#                 forensic_df = forensic_df[forensic_df["source_log"] == selected_f_source]

#             if not forensic_df.empty:
#                 if "App Run" in view_type:
#                     display_df = forensic_df[forensic_df["source_log"].isin(["CONN", "DNS"])]
#                     color_graph = ["#00CCFF"] 
#                 elif "App Usage" in view_type:
#                     display_df = forensic_df[forensic_df["source_log"].isin(["HTTP", "SSL"])]
#                     color_graph = ["#00FF99"] 
#                 elif "App Install" in view_type:
#                     display_df = forensic_df[forensic_df["source_log"].isin(["FILES", "SOFTWARE"])]
#                     color_graph = ["#FFFF00"] 
#                 elif "Suspicious" in view_type:
#                     display_df = forensic_df[(forensic_df["App Status"] == "Unauthorized") | (forensic_df["Risk Level"].isin(["Critical", "High", "Medium"]))]
#                     color_graph = ["#FF0000"] 
#                 else:
#                     display_df = forensic_df
#                     color_graph = ["#888888"]

#                 st.markdown("#### Traffic Activity Graph")
#                 if not display_df.empty:
#                     f_line = display_df.groupby([pd.Grouper(key="datetime", freq="10min")]).size().reset_index(name="hits")
#                     fig_f = px.area(f_line, x="datetime", y="hits", template="plotly_dark", color_discrete_sequence=color_graph, title=f"Activity: {view_type}")
#                     st.plotly_chart(fig_f, use_container_width=True)
#                 else:
#                     st.warning(f"No events found for {view_type} category.")

#                 low_col1, low_col2 = st.columns([1, 2])
#                 with low_col1:
#                     st.markdown("#### Top Destinations")
#                     if not display_df.empty:
#                         top_dest = display_df["domain_clean"].value_counts().head(10).reset_index()
#                         top_dest.columns = ["Destination", "Count"]
#                         st.table(top_dest)
#                     else:
#                         st.write("No data.")

#                 with low_col2:
#                     title_col, opt_col, status_col = st.columns([1.5, 1.2, 1])
#                     with title_col: st.markdown(f"### {view_type}")
#                     with opt_col:
#                         table_mode = st.selectbox("View Mode", ["Detailed Logs", "Unique Rows", "Group by App", "Group by Source"], label_visibility="collapsed")
#                     with status_col:
#                         allow_status = st.radio(" ", ["Authorized", "Unauthorized", "All"], horizontal=True, key="allow_filter", label_visibility="collapsed")
                    
#                     if allow_status == "Authorized": display_df = display_df[display_df["App Status"] == "Authorized"]
#                     elif allow_status == "Unauthorized": display_df = display_df[display_df["App Status"] == "Unauthorized"]
                    
#                     if table_mode == "Unique Rows":
#                         final_df = display_df.drop_duplicates(subset=["domain_clean", "ip", "mac", "source_log", "Info"]).sort_values("datetime", ascending=False)
#                     elif table_mode == "Group by App":
#                         final_df = display_df.groupby(["domain_clean", "App Status"]).size().reset_index(name='Count').sort_values(by="Count", ascending=False)
#                     elif table_mode == "Group by Source":
#                         final_df = display_df.groupby(["source_log", "App Status"]).size().reset_index(name='Count').sort_values(by="Count", ascending=False)
#                     else:
#                         final_df = display_df.sort_values("datetime", ascending=False)

#                     final_df = final_df.head(1000)
#                     styled_final_df = final_df.style.applymap(color_risk, subset=["Risk Level"]) if "Risk Level" in final_df.columns else final_df

#                     st.dataframe(styled_final_df, column_config={"datetime": st.column_config.DatetimeColumn("Timestamp", format="HH:mm:ss"), "Info": "Context Info", "domain_clean": "Destination", "dst_port": "Port", "Risk Level": "Risk"}, use_container_width=True, hide_index=True)
                    
#                     if not final_df.empty:
#                         st.download_button("Download Evidence (CSV)", final_df.to_csv(index=False).encode('utf-8'), f"forensics_{search_query}_{view_type}.csv", 'text/csv')

#                 st.divider()
#                 st.subheader("Device Analytics")
#                 g_col1, g_col2, g_col3, g_col4 = st.columns(4)
                
#                 with g_col1:
#                     st.markdown("##### Total Activity")
#                     if not forensic_df.empty:
#                         forensic_df["hour"] = forensic_df["datetime"].dt.hour
#                         hourly_counts = forensic_df.groupby("hour").size().reset_index(name="count")
#                         fig1 = px.bar(hourly_counts, x="hour", y="count", template="plotly_dark", color_discrete_sequence=["#3366CC"])
#                         st.plotly_chart(fig1, use_container_width=True)

#                 with g_col2:
#                     st.markdown("##### Auth vs Unauth")
#                     if not forensic_df.empty:
#                         status_counts = forensic_df["App Status"].value_counts().reset_index()
#                         status_counts.columns = ["App Status", "count"]
#                         fig2 = px.pie(status_counts, names="App Status", values="count", color="App Status", color_discrete_map={"Authorized": "#00FF00", "Unauthorized": "#FF0000"}, template="plotly_dark", hole=0.5)
#                         st.plotly_chart(fig2, use_container_width=True)

#                 with g_col3:
#                     st.markdown("##### Source Dist.")
#                     if not forensic_df.empty:
#                         source_counts = forensic_df["source_log"].value_counts().reset_index()
#                         source_counts.columns = ["Source", "count"]
#                         fig3 = px.bar(source_counts, x="Source", y="count", template="plotly_dark", color="Source")
#                         st.plotly_chart(fig3, use_container_width=True)

#                 with g_col4:
#                     st.markdown("##### Top Ports")
#                     if not forensic_df.empty:
#                         port_df = forensic_df[forensic_df["dst_port"] > 0]
#                         if not port_df.empty:
#                             port_counts = port_df["dst_port"].value_counts().head(5).reset_index()
#                             port_counts.columns = ["Port", "count"]
#                             port_counts["Port"] = port_counts["Port"].astype(str)
#                             fig4 = px.bar(port_counts, x="Port", y="count", template="plotly_dark", color_discrete_sequence=["#FF9900"])
#                             st.plotly_chart(fig4, use_container_width=True)
#                         else:
#                             st.write("No port data.")
#             else:
#                 st.write("Please enter a MAC or IP address in the search bar above to begin forensics.")

#     # --- TAB 2 ---
#     with t2:
#         st.markdown("## Unauthorized Threat Dashboard")
        
#         if not unauth_df.empty:
#             u_metrics1, u_metrics2, u_metrics3 = st.columns(3)
#             with u_metrics1:
#                 st.metric("Active Unauthorized Apps", unauth_df["domain_clean"].nunique())
#             with u_metrics2:
#                 top_offender = unauth_df["mac"].value_counts().idxmax()
#                 offender_count = unauth_df["mac"].value_counts().max()
#                 st.metric("Top Offender (MAC)", top_offender, delta=f"{offender_count} Events", delta_color="inverse")
#             with u_metrics3:
#                 crit_count = len(unauth_df[unauth_df["Risk Level"].isin(["Critical", "High"])])
#                 st.metric("Critical Risks Detected", crit_count, delta="Requires Attention", delta_color="inverse")
            
#             st.divider()
            
#             with st.expander("Data Exfiltration Monitor (High Volume Traffic)", expanded=True):
#                 exfil_c1, exfil_c2 = st.columns(2)
#                 total_sent_gb = unauth_df["bytes_sent"].sum() / 1_000_000_000
#                 total_recv_gb = unauth_df["bytes_received"].sum() / 1_000_000_000
                
#                 with exfil_c1:
#                     st.metric("Total Unauthorized Upload", f"{total_sent_gb:.2f} GB", delta="Potential Leak", delta_color="inverse")
#                     st.metric("Total Unauthorized Download", f"{total_recv_gb:.2f} GB")
                    
#                 with exfil_c2:
#                     if not unauth_df.empty and unauth_df["bytes_sent"].max() > 0:
#                         fig_exfil = px.scatter(unauth_df[unauth_df["bytes_sent"] > 0], x="dst_port", y="bytes_sent", size="bytes_sent", color="Behavior", hover_data=["domain_clean", "mac"], title="Outbound Data Volume by Port", template="plotly_dark")
#                         st.plotly_chart(fig_exfil, use_container_width=True)
#                     else:
#                         st.info("No significant outbound traffic detected.")

#             st.divider()

#             u_chart1, u_chart2 = st.columns([2, 1])
#             with u_chart1:
#                 st.markdown("#### Top Unauthorized Domains")
#                 top_unauth_domains = unauth_df["domain_clean"].value_counts().head(10).reset_index()
#                 top_unauth_domains.columns = ["Domain", "Hits"]
#                 fig_u1 = px.bar(top_unauth_domains, x="Hits", y="Domain", orientation='h', template="plotly_dark", color_discrete_sequence=["#FF4500"])
#                 fig_u1.update_layout(yaxis={'categoryorder':'total ascending'})
#                 st.plotly_chart(fig_u1, use_container_width=True)
            
#             with u_chart2:
#                 st.markdown("#### Risk Distribution")
#                 risk_counts = unauth_df["Risk Level"].value_counts().reset_index()
#                 risk_counts.columns = ["Risk", "Count"]
#                 risk_colors = {"Critical": "#FF0000", "High": "#FF4500", "Medium": "#FFA500", "Low": "#FFD700", "Safe": "#00FF00"}
#                 fig_u2 = px.pie(risk_counts, values="Count", names="Risk", color="Risk", color_discrete_map=risk_colors, template="plotly_dark", hole=0.6)
#                 st.plotly_chart(fig_u2, use_container_width=True)

#             st.divider()
            
#             st.markdown("### Threat Details")
#             af_1, af_2, af_3 = st.columns([1, 1, 2])
#             with af_1: filter_risk = st.multiselect("Filter by Risk", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
#             with af_2: filter_source = st.multiselect("Filter by Log Source", unauth_df["source_log"].unique(), default=unauth_df["source_log"].unique())
#             with af_3: search_query_unauth = st.text_input("Search (IP, MAC, Domain)", placeholder="Search threat details...", key="unauth_search")

#             filtered_unauth = unauth_df.copy()
#             if filter_risk: filtered_unauth = filtered_unauth[filtered_unauth["Risk Level"].isin(filter_risk)]
#             if filter_source: filtered_unauth = filtered_unauth[filtered_unauth["source_log"].isin(filter_source)]
#             if search_query_unauth:
#                 q = search_query_unauth.lower()
#                 filtered_unauth = filtered_unauth[(filtered_unauth["mac"].str.contains(q, case=False, na=False)) | (filtered_unauth["ip"].str.contains(q, case=False, na=False)) | (filtered_unauth["domain_clean"].str.contains(q, case=False, na=False))]

#             detail_table = filtered_unauth[["datetime", "mac", "ip", "domain_clean", "source_log", "Info", "dst_port", "bytes_sent", "Behavior", "Risk Level"]].sort_values("datetime", ascending=False).head(1000)
#             styled_unauth = detail_table.style.applymap(color_risk, subset=["Risk Level"])

#             st.dataframe(styled_unauth, column_config={"datetime": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"), "mac": "MAC Address", "ip": "IP Address", "domain_clean": "Unauthorized Domain", "source_log": "Source", "Info": "Context", "dst_port": "Port", "bytes_sent": "Upload (Bytes)", "Behavior": "Behavior Tag", "Risk Level": "Threat Risk"}, use_container_width=True, hide_index=True)
#         else:
#             st.success("No Unauthorized applications detected. System is clean.")








# ui/pages/shadow_app.py
import streamlit as st
import pandas as pd
import plotly.express as px
import duckdb 
from pathlib import Path
from urllib.parse import urlparse
import yaml

# -----------------------------
# Config
# -----------------------------
# Updated to point to the YAML file in the root directory
WHITELIST_FILE = Path(__file__).resolve().parents[2] / "whitelist_domains.yaml"

# -----------------------------
# License registry (User Configured)
# -----------------------------
LICENSE_REGISTRY = {
    "office.com": None,
    "microsoft.com": None,
    "github.com": None,
    "zoom.us": None,        
    "slack.com": None       
}

# -----------------------------
# DUCKDB ENGINE (The Speed Layer)
# -----------------------------
@st.cache_resource
def get_db_connection():
    """
    Creates an in-memory DuckDB connection.
    This acts as our transient high-speed analytical engine.
    """
    conn = duckdb.connect(database=':memory:')
    # Set memory limit to prevent crashes on smaller VMs
    conn.execute("SET memory_limit='4GB'") 
    return conn

@st.cache_data(show_spinner=False)
def query_shadow_logs(_conn, parquet_root: Path, target_dates: list):
    """
    Uses DuckDB to read logs, normalize columns, join with DHCP, 
    and return a single clean DataFrame.
    """
    # 1. Gather File Paths
    dhcp_files = []
    log_files = []
    
    log_types = ["http", "ssl", "dns", "files", "conn", "software", "weird", "notice"]
    
    for d in target_dates:
        d_path = parquet_root / d
        if not d_path.exists(): continue
        
        # Check for DHCP
        dhcp_p = d_path / "dhcp.parquet"
        if dhcp_p.exists(): dhcp_files.append(str(dhcp_p))
        
        # Check for Audit Logs
        for l in log_types:
            l_path = d_path / f"{l}.parquet"
            if l_path.exists(): log_files.append(str(l_path))
            
    if not log_files:
        return pd.DataFrame()

    # 2. Create DHCP View (The Identity Map)
    if dhcp_files:
        try:
            # Create a temporary view so we can inspect columns safely
            _conn.execute(f"CREATE OR REPLACE VIEW raw_dhcp_files AS SELECT * FROM read_parquet({dhcp_files}, union_by_name=True)")
            dhcp_cols = [r[0] for r in _conn.execute("DESCRIBE raw_dhcp_files").fetchall()]
            
            # Dynamic Column Selection for DHCP
            # We pick the first matching column we find in the actual file
            dhcp_ip = next((c for c in ["client_addr", "assigned_addr", "requested_addr", "ip"] if c in dhcp_cols), "'0.0.0.0'")
            dhcp_mac = next((c for c in ["mac", "client_chaddr", "hardware_address"] if c in dhcp_cols), "'Unknown'")
            
            _conn.execute(f"""
                CREATE OR REPLACE VIEW v_dhcp AS 
                SELECT DISTINCT
                    {dhcp_ip} as ip_addr,
                    {dhcp_mac} as mac_addr
                FROM raw_dhcp_files
                WHERE {dhcp_ip} IS NOT NULL AND {dhcp_mac} IS NOT NULL
            """)
        except Exception:
            _conn.execute("CREATE OR REPLACE VIEW v_dhcp AS SELECT '0.0.0.0' as ip_addr, 'Unknown' as mac_addr")
    else:
        _conn.execute("CREATE OR REPLACE VIEW v_dhcp AS SELECT '0.0.0.0' as ip_addr, 'Unknown' as mac_addr")

    # 3. Main Query (Dynamic Construction)
    try:
        # A. Create a view of ALL logs to inspect the schema
        _conn.execute(f"CREATE OR REPLACE VIEW raw_logs AS SELECT * FROM read_parquet({log_files}, union_by_name=True, filename='source_file_path')")
        
        # B. Get the actual list of columns that exist in these files
        existing_cols = set([r[0] for r in _conn.execute("DESCRIBE raw_logs").fetchall()])
        
        # C. Helper to safely build COALESCE strings
        def get_coalesce(candidates, fallback="'Unknown'"):
            valid = [f'"{c}"' for c in candidates if c in existing_cols]
            if not valid: return fallback
            return f"COALESCE({', '.join(valid)}, {fallback})"

        # D. Build the Dynamic SQL
        # We only ask for columns that we KNOW exist in 'raw_logs'
        
        sql_ip = get_coalesce(["id.orig_h", "orig_h", "src_ip", "ip"], "'0.0.0.0'")
        sql_mac = get_coalesce(["mac", "orig_mac", "id.orig_mac", "src_mac"], "NULL") # NULL so we can coalesce with DHCP later
        
        # For integers/numbers, we need explicit casts if they exist
        def get_cast_coalesce(candidates, cast_type, fallback="0"):
            valid = [f'try_cast("{c}" as {cast_type})' for c in candidates if c in existing_cols]
            if not valid: return fallback
            return f"COALESCE({', '.join(valid)}, {fallback})"

        sql_port = get_cast_coalesce(["id.resp_p", "dst_port", "resp_p"], "INT")
        sql_sent = get_cast_coalesce(["orig_bytes", "id.orig_bytes"], "BIGINT")
        sql_recv = get_cast_coalesce(["resp_bytes", "id.resp_bytes"], "BIGINT")
        
        # For App ID, we want the first non-null match
        sql_app = get_coalesce([
            "host", "server_name", "query", "filename", 
            "service", "unparsed_version", "name", "note"
        ], "'-'")
        
        # E. Context Info Logic (Complex concatenation)
        # We build this manually based on what exists
        info_parts = []
        if "method" in existing_cols and "uri" in existing_cols:
            info_parts.append("concat(method, ' ', uri)")
        if "mime_type" in existing_cols: info_parts.append("mime_type")
        if "addl" in existing_cols: info_parts.append("addl")
        if "msg" in existing_cols: info_parts.append("msg")
        if "proto" in existing_cols and "id.resp_p" in existing_cols:
             info_parts.append("concat(proto, '/', \"id.resp_p\")")
        
        sql_info = f"COALESCE({', '.join(info_parts)}, '-')" if info_parts else "'-'"

        # F. Final Query Construction
        query = f"""
        SELECT 
            try_cast(ts as DOUBLE) as ts,
            {sql_ip} as ip,
            COALESCE({sql_mac}, d.mac_addr, 'Unknown') as mac,
            {sql_port} as dst_port,
            {sql_sent} as bytes_sent,
            {sql_recv} as bytes_received,
            {sql_app} as app_identifier,
            {sql_info} as Info,
            upper(regexp_extract(source_file_path, '([a-z]+)\.parquet', 1)) as source_log
        FROM raw_logs r
        LEFT JOIN v_dhcp d ON {sql_ip} = d.ip_addr
        """
        
        return _conn.execute(query).df()
        
    except Exception as e:
        # Safety net: return empty DF if something critical fails
        return pd.DataFrame()

# -----------------------------
# Load allowlist (User Config)
# -----------------------------
def load_allowlist():
    """Loads authorized domains from whitelist_domains.yaml"""
    if not WHITELIST_FILE.exists(): return []

    approved = set()
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if data is None: return []
            
            raw_list = []
            if isinstance(data, list): raw_list = data
            elif isinstance(data, dict):
                target_key = WHITELIST_FILE.stem
                if target_key in data and isinstance(data[target_key], list):
                    raw_list = data[target_key]
                else:
                    for val in data.values():
                        if isinstance(val, list):
                            raw_list = val
                            break
            
            for item in raw_list:
                domain = extract_domain(str(item))
                if domain: approved.add(domain)
    except Exception: pass
    return list(approved)

# -----------------------------
# Python Helpers (Logic)
# -----------------------------
def extract_domain(url: str):
    if not url: return ""
    url = str(url).strip().lower()
    if url in ['nan', 'none', '', 'unknown']: return ""
    
    if "://" in url:
        try: url = urlparse(url).hostname or ""
        except: pass
    
    if url.startswith("www."): url = url[4:]
    return url.split(":")[0].rstrip(".")

def is_allowed(domain: str, approved: list):
    domain = domain.lower().strip().rstrip(".")
    if not domain: return False
    return any(domain == a or domain.endswith("." + a) for a in approved)

def calculate_risk(row):
    port = row.get("dst_port", 0)
    log = row.get("source_log", "")
    status = row.get("App Status", "")
    
    if log in ["WEIRD", "NOTICE"]: return "Critical"
    if port in [22, 23, 3389, 5900]: return "High"
    if port in [1433, 3306, 5432]: return "Medium"
    if status == "Unauthorized": return "Low"
    return "Safe"

def categorize_threat(row):
    sent = row.get("bytes_sent", 0)
    recv = row.get("bytes_received", 0)
    if sent > 10_000_000: return "Potential Exfiltration"
    if recv > 100_000_000: return "Heavy Download"
    if row["source_log"] == "WEIRD": return "Protocol Anomaly"
    return "Unauthorized Usage"

def color_risk(val):
    color_map = {
        "Critical": "color: #FF0000; font-weight: bold;",
        "High": "color: #FF4500; font-weight: bold;",
        "Medium": "color: #FFA500;",
        "Low": "color: #FFD700;",
        "Safe": "color: #00FF00;"
    }
    return color_map.get(val, "")

# -----------------------------
# Render Main Page
# -----------------------------
def render_shadow_apps(parquet_root: Path):
    st.markdown("#### Shadow Apps Overview")
    
    # 1. Date Selection
    if parquet_root.exists():
        available_dates = sorted([d.name for d in parquet_root.iterdir() if d.is_dir()], reverse=True)
        if not available_dates:
            st.warning("No log directories found.")
            return
            
        date_options = ["All Available Dates"] + available_dates
        selected_option = st.selectbox("Select Date Range", date_options, index=1 if len(date_options) > 1 else 0)
        target_dates = available_dates if selected_option == "All Available Dates" else [selected_option]
    else:
        st.error("Log root directory not found.")
        return

    # 2. DUCKDB QUERY execution
    conn = get_db_connection()
    with st.spinner("🦆 DuckDB is analyzing logs..."):
        df = query_shadow_logs(conn, parquet_root, target_dates)

    if df.empty:
        st.info("No logs available for selected range.")
        return

    # 3. Post-Process (Fast Python Logic)
    # Convert TS to Datetime
    df["datetime"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")
    df = df.dropna(subset=["datetime"])
    
    # Cleanup IP/MAC
    df["ip"] = df["ip"].fillna("Unknown").astype(str)
    df["mac"] = df["mac"].fillna("Unknown").astype(str).str.lower()
    
    # Domain Cleanup
    df["domain_clean"] = df["app_identifier"].apply(extract_domain)
    # If domain extraction failed, fallback to raw identifier for weird logs
    mask_empty = df["domain_clean"] == ""
    df.loc[mask_empty, "domain_clean"] = df.loc[mask_empty, "app_identifier"]
    df["domain_clean"] = df["domain_clean"].fillna("unidentified_activity")

    # Status Check
    approved = load_allowlist()
    df["App Status"] = df["domain_clean"].apply(lambda x: "Authorized" if is_allowed(x, approved) else "Unauthorized")
    
    # Risk & Threat
    df["Risk Level"] = df.apply(calculate_risk, axis=1)
    df["Behavior"] = df.apply(categorize_threat, axis=1)

    # 4. Metrics
    unauth_df = df[df["App Status"] == "Unauthorized"]
    critical_df = df[df["Risk Level"].isin(["Critical", "High"])]
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", len(df))
    authorized_count = len(df) - len(unauth_df)
    unauthorized_count = len(unauth_df)
    total_events = len(df)
    unauth_pct = (unauthorized_count / total_events * 100) if total_events > 0 else 0

    col2.metric("Authorized Events", authorized_count, f"{100 - int(unauth_pct)}% of total")
    col3.metric("Unauthorized Events", unauthorized_count, f"{int(unauth_pct)}% of total", delta_color="inverse")
    col4.metric("Critical / High Risk", len(critical_df), delta_color="inverse")
    
    st.divider()

    # 5. Charts (Sampling for speed if data > 50k rows)
    chart_df = df if len(df) < 50000 else df.sample(50000)

    c1, c2 = st.columns([2, 1])
    with c1:
        st.markdown("### Activity Over Time")
        # Aggregating in Pandas first makes Plotly 10x faster
        df_line = chart_df.groupby([pd.Grouper(key="datetime", freq="H"), "App Status"]).size().reset_index(name="count")
        if not df_line.empty:
            fig = px.line(df_line, x="datetime", y="count", color="App Status", 
                          color_discrete_map={"Authorized": "#00FF00", "Unauthorized": "#FF0000"},
                          template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)
            
    with c2:
        st.markdown("### Source Distribution")
        df_pie = chart_df.groupby("source_log").size().reset_index(name="Log Count")
        fig_pie = px.pie(df_pie, values="Log Count", names="source_log", template="plotly_dark", hole=0.4)
        st.plotly_chart(fig_pie, use_container_width=True)

    # --------------------------------------------------------
    # TABS
    # --------------------------------------------------------
    t1, t2 = st.tabs(["Authorized Applications & License Audit", "Unauthorized Applications"])
    
    # --- TAB 1 ---
    with t1:
        st.markdown("### Application Audit Log")
        
        filter_col1, filter_col2 = st.columns([3, 2])
        with filter_col1: 
            search_query_audit = st.text_input("Search (MAC, IP, Domain)", placeholder="Search...", key="audit_search").strip().lower()
        with filter_col2:
            status_filter = st.radio("Filter Status", ["All", "Authorized", "Unauthorized"], horizontal=True, key="audit_status_filter")

        filter_col3, filter_col4 = st.columns([3, 2])
        with filter_col3:
            raw_sources = sorted(df["source_log"].unique().tolist()) if not df.empty else []
            selected_source_audit = st.selectbox("Source Log Type", ["All"] + raw_sources, key="audit_source_filter")
        with filter_col4:
            dedup_enabled = st.toggle("Remove Duplications (Summary View)", value=True)

        # Filtering in Memory (Fast for <1M rows)
        audit_df = df.copy()

        if status_filter != "All":
            audit_df = audit_df[audit_df["App Status"] == status_filter]
        if selected_source_audit != "All":
            audit_df = audit_df[audit_df["source_log"] == selected_source_audit]
        if search_query_audit:
            q = search_query_audit
            audit_df = audit_df[
                (audit_df["mac"].str.contains(q, case=False, na=False)) | 
                (audit_df["ip"].str.contains(q, case=False, na=False)) |
                (audit_df["domain_clean"].str.contains(q, case=False, na=False))
            ]

        if not audit_df.empty:
            if dedup_enabled:
                display_df = (
                    audit_df.sort_values("datetime")
                    .groupby(["domain_clean", "mac", "ip", "source_log", "App Status"])
                    .agg(First_Seen=("datetime", "min"), Last_Seen=("datetime", "max"), Hits=("datetime", "count"))
                    .reset_index()
                    .sort_values("Hits", ascending=False)
                )
                col_config = {
                    "domain_clean": "Application", "mac": "MAC Address", "ip": "IP Address",
                    "source_log": "Source", "First_Seen": st.column_config.DatetimeColumn("First Seen", format="MM-DD HH:mm"),
                    "Last_Seen": st.column_config.DatetimeColumn("Last Seen", format="MM-DD HH:mm"), "Hits": st.column_config.NumberColumn("Total Hits"),
                }
            else:
                display_df = audit_df.sort_values("datetime", ascending=False)
                col_config = {
                    "datetime": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
                    "domain_clean": "Application", "mac": "MAC Address", "ip": "IP Address", "source_log": "Source",
                }

            display_df = display_df.head(1000)
            styled_audit = display_df.style.map(lambda x: 'color: #FF4B4B; font-weight: bold;' if x == "Unauthorized" else 'color: #6CA651; font-weight: bold;' if x == "Authorized" else '', subset=['App Status'])
            
            st.dataframe(styled_audit, column_config=col_config, use_container_width=True, hide_index=True)
            st.caption(f"Showing {len(display_df)} results.")
        else:
            st.info(f"No matching logs found.")

        st.divider()

        # License Compliance
        st.markdown("### License Compliance Audit")
        usage_data = []

        for software in LICENSE_REGISTRY.keys():
            software_usage = df[df["domain_clean"].astype(str).str.contains(software, case=False, na=False)]
            mac_list = software_usage["mac"].dropna().unique().tolist()
            unique_users = len(mac_list)
            status = "Usage Detected" if unique_users > 0 else "No Usage"

            usage_data.append({
                "Software": software,
                "Active Devices Count": unique_users,
                "Status": status
            })

        if usage_data:
            usage_df = pd.DataFrame(usage_data)
            table_col, chart_col = st.columns([1.7, 1])
            with table_col:
                st.markdown("<div style='font-size:25px; font-weight:600;'>Detected Software Usage</div>",unsafe_allow_html=True)
                st.dataframe(usage_df.style.map(lambda x: "color: #FF4B4B; font-weight: 600;" if x == "Usage Detected" else "color: #00CC96; font-weight: 600;", subset=["Status"]), use_container_width=True, hide_index=True)
            with chart_col:
                st.markdown("<div style='font-size:20px; font-weight:600;'>Active Devices per Software</div>",unsafe_allow_html=True)
                fig = px.bar(usage_df, x="Software", y="Active Devices Count", text_auto=True, template="plotly_dark", color="Active Devices Count", color_continuous_scale="RdYlGn_r")
                fig.update_layout(xaxis_title=None, yaxis_title="Active Devices", height=420, showlegend=False)
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No active usage detected for monitored software.")

        st.divider()

        # Shadow App Forensics
        st.markdown("### Shadow App Forensics")
        search_query = st.text_input("Global Forensic Search", placeholder="Enter specific MAC or IP...", key="global_forensic_search").strip().lower()

        if search_query:
            st.info(f"Showing deep forensics for: **{search_query}**")
            f_col1, f_col2 = st.columns(2)
            with f_col1:
                view_type = st.radio("", ["App Run (Connectivity)", "App Usage (Interaction)", "App Install (Files)", "Suspicious Behavior"], horizontal=True)
            with f_col2:
                f_raw_sources = sorted(df["source_log"].unique().tolist()) if not df.empty else []
                selected_f_source = st.selectbox("Filter Forensic Source", ["All"] + f_raw_sources, key="forensic_source_single")

            forensic_df = df[(df["mac"].str.contains(search_query, case=False, na=False)) | (df["ip"].str.contains(search_query, case=False, na=False))].copy()

            if selected_f_source != "All":
                forensic_df = forensic_df[forensic_df["source_log"] == selected_f_source]

            if not forensic_df.empty:
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
                    display_df = forensic_df[(forensic_df["App Status"] == "Unauthorized") | (forensic_df["Risk Level"].isin(["Critical", "High", "Medium"]))]
                    color_graph = ["#FF0000"] 
                else:
                    display_df = forensic_df
                    color_graph = ["#888888"]

                st.markdown("#### Traffic Activity Graph")
                if not display_df.empty:
                    f_line = display_df.groupby([pd.Grouper(key="datetime", freq="10min")]).size().reset_index(name="hits")
                    fig_f = px.area(f_line, x="datetime", y="hits", template="plotly_dark", color_discrete_sequence=color_graph, title=f"Activity: {view_type}")
                    st.plotly_chart(fig_f, use_container_width=True)
                else:
                    st.warning(f"No events found for {view_type} category.")

                low_col1, low_col2 = st.columns([1, 2])
                with low_col1:
                    st.markdown("#### Top Destinations")
                    if not display_df.empty:
                        top_dest = display_df["domain_clean"].value_counts().head(10).reset_index()
                        top_dest.columns = ["Destination", "Count"]
                        st.table(top_dest)
                    else:
                        st.write("No data.")

                with low_col2:
                    # Create columns to place Title, Filter, and Mode side-by-side
                    header_col1, header_col2, header_col3 = st.columns([2, 1.5, 1.5])
                    
                    with header_col1:
                        st.markdown(f"### {view_type}")
                    
                    with header_col2:
                        # Risk Filter (collapsed label to save space)
                        forensic_risk_filter = st.multiselect(
                            "Filter Risk", 
                            options=["Critical", "High", "Medium", "Low", "Safe"],
                            default=[],
                            placeholder="Filter by Risk...",
                            label_visibility="collapsed",
                            key="forensic_risk_multiselect"
                        )
                    
                    with header_col3:
                        table_mode = st.selectbox(
                            "View Mode", 
                            ["Detailed Logs", "Unique Rows", "Group by App"], 
                            label_visibility="collapsed"
                        )
                    
                    # --- APPLY RISK FILTER ---
                    if forensic_risk_filter:
                        display_df = display_df[display_df["Risk Level"].isin(forensic_risk_filter)]

                    # Apply View Mode Logic
                    if table_mode == "Unique Rows":
                        final_df = display_df.drop_duplicates(subset=["domain_clean", "ip", "mac", "source_log", "Info"]).sort_values("datetime", ascending=False)
                    elif table_mode == "Group by App":
                        final_df = display_df.groupby(["domain_clean", "App Status"]).size().reset_index(name='Count').sort_values(by="Count", ascending=False)
                    else:
                        final_df = display_df.sort_values("datetime", ascending=False)

                    final_df = final_df.head(1000)
                    styled_final_df = final_df.style.map(color_risk, subset=["Risk Level"]) if "Risk Level" in final_df.columns else final_df

                    st.dataframe(styled_final_df, column_config={"datetime": st.column_config.DatetimeColumn("Timestamp", format="HH:mm:ss"), "Info": "Context Info", "domain_clean": "Destination", "dst_port": "Port", "Risk Level": "Risk"}, use_container_width=True, hide_index=True)
                    
                    if not final_df.empty:
                        st.download_button("Download Evidence (CSV)", final_df.to_csv(index=False).encode('utf-8'), f"forensics_{search_query}_{view_type}.csv", 'text/csv')
            else:
                st.write("Please enter a MAC or IP address in the search bar above to begin forensics.")

    # --- TAB 2 ---
    with t2:
        st.markdown("## Unauthorized Threat Dashboard")
        
        if not unauth_df.empty:
            u_metrics1, u_metrics2, u_metrics3 = st.columns(3)
            with u_metrics1:
                st.metric("Active Unauthorized Apps", unauth_df["domain_clean"].nunique())
            with u_metrics2:
                top_offender = unauth_df["mac"].value_counts().idxmax()
                st.metric("Top Offender (MAC)", top_offender, delta=f"{unauth_df['mac'].value_counts().max()} Events", delta_color="inverse")
            with u_metrics3:
                st.metric("Critical Risks", len(unauth_df[unauth_df["Risk Level"].isin(["Critical", "High"])]), delta="Requires Attention", delta_color="inverse")
            
            st.divider()
            
            with st.expander("Data Exfiltration Monitor (High Volume Traffic)", expanded=True):
                exfil_c1, exfil_c2 = st.columns(2)
                total_sent_gb = unauth_df["bytes_sent"].sum() / 1_000_000_000
                total_recv_gb = unauth_df["bytes_received"].sum() / 1_000_000_000
                
                with exfil_c1:
                    st.metric("Total Unauthorized Upload", f"{total_sent_gb:.2f} GB", delta="Potential Leak", delta_color="inverse")
                    st.metric("Total Unauthorized Download", f"{total_recv_gb:.2f} GB")
                
                with exfil_c2:
                    if not unauth_df.empty and unauth_df["bytes_sent"].max() > 0:
                        fig_exfil = px.scatter(unauth_df[unauth_df["bytes_sent"] > 0], x="dst_port", y="bytes_sent", size="bytes_sent", color="Behavior", hover_data=["domain_clean", "mac"], title="Outbound Data Volume by Port", template="plotly_dark")
                        st.plotly_chart(fig_exfil, use_container_width=True)
                    else:
                        st.info("No significant outbound traffic detected.")

            st.divider()

            u_chart1, u_chart2 = st.columns([2, 1])
            with u_chart1:
                st.markdown("#### Top Unauthorized Domains")
                top_unauth = unauth_df["domain_clean"].value_counts().head(10).reset_index()
                top_unauth.columns = ["Domain", "Hits"]
                fig_u1 = px.bar(top_unauth, x="Hits", y="Domain", orientation='h', template="plotly_dark", color_discrete_sequence=["#FF4500"])
                fig_u1.update_layout(yaxis={'categoryorder':'total ascending'})
                st.plotly_chart(fig_u1, use_container_width=True)
            
            with u_chart2:
                st.markdown("#### Risk Distribution")
                risk_counts = unauth_df["Risk Level"].value_counts().reset_index()
                risk_counts.columns = ["Risk", "Count"]
                risk_colors = {"Critical": "#FF0000", "High": "#FF4500", "Medium": "#FFA500", "Low": "#FFD700", "Safe": "#00FF00"}
                fig_u2 = px.pie(risk_counts, values="Count", names="Risk", color="Risk", color_discrete_map=risk_colors, template="plotly_dark", hole=0.6)
                st.plotly_chart(fig_u2, use_container_width=True)

            st.divider()
            
            st.markdown("### Threat Details")
            af_1, af_2, af_3 = st.columns([1, 1, 2])
            with af_1: filter_risk = st.multiselect("Filter by Risk", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
            with af_2: filter_source = st.multiselect("Filter by Log Source", unauth_df["source_log"].unique(), default=unauth_df["source_log"].unique())
            with af_3: search_query_unauth = st.text_input("Search (IP, MAC, Domain)", placeholder="Search threat details...", key="unauth_search")

            filtered_unauth = unauth_df.copy()
            if filter_risk: filtered_unauth = filtered_unauth[filtered_unauth["Risk Level"].isin(filter_risk)]
            if filter_source: filtered_unauth = filtered_unauth[filtered_unauth["source_log"].isin(filter_source)]
            if search_query_unauth:
                q = search_query_unauth.lower()
                filtered_unauth = filtered_unauth[(filtered_unauth["mac"].str.contains(q, case=False, na=False)) | (filtered_unauth["ip"].str.contains(q, case=False, na=False)) | (filtered_unauth["domain_clean"].str.contains(q, case=False, na=False))]

            detail_table = filtered_unauth[["datetime", "mac", "ip", "domain_clean", "source_log", "Info", "dst_port", "bytes_sent", "Behavior", "Risk Level"]].sort_values("datetime", ascending=False).head(1000)
            styled_unauth = detail_table.style.map(color_risk, subset=["Risk Level"])

            st.dataframe(styled_unauth, column_config={"datetime": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"), "mac": "MAC Address", "ip": "IP Address", "domain_clean": "Unauthorized Domain", "source_log": "Source", "Info": "Context", "dst_port": "Port", "bytes_sent": "Upload (Bytes)", "Behavior": "Behavior Tag", "Risk Level": "Threat Risk"}, use_container_width=True, hide_index=True)
        else:
            st.success("No Unauthorized applications detected. System is clean.")