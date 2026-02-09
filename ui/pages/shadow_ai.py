import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import re
import yaml
from datetime import datetime

# ==============================================================================
# 1. SECURITY CONFIGURATION & THREAT INTEL
# ==============================================================================

@st.cache_data(ttl=600)
def load_ai_signatures():
    signatures_path = Path("signatures.yaml")
    if not signatures_path.exists():
        # Fallback defaults if file is missing
        return ["Microsoft Copilot"], {}, {}
    
    with open(signatures_path, "r") as f:
        signatures = yaml.safe_load(f)
        
    return (
        signatures.get("authorized_providers", []),
        signatures.get("ai_signatures", {}),
        signatures.get("local_ai_ports", {})
    )

# Load the values globally
AUTHORIZED_PROVIDERS, AI_SIGNATURES, LOCAL_AI_PORTS = load_ai_signatures()

# ==============================================================================
# 2. SOC LOGIC: SCORING & CLASSIFICATION
# ==============================================================================

def fingerprint_client(ua: str) -> str:
    """Identify if the actor is a Browser, a Script (Python/Curl), or an App."""
    if pd.isna(ua) or ua in ["-", ""]: return "Unknown"
    ua = str(ua).lower()
    
    # Dev Tools / Automation SDKs
    if any(x in ua for x in ["python", "curl", "wget", "aiohttp", "requests", "httpx", "langchain", "openai-python"]):
        return "Automation / SDK"
    
    # Browsers
    if any(x in ua for x in ["mozilla", "chrome", "safari", "edge", "firefox"]):
        return "Web Browser"
    
    return "Mobile / App"

def calculate_severity(row):
    """
    SOC-Grade Scoring Logic (0-100).
    Factors: Data Volume, Method (POST), Client Type, Endpoint Sensitivity.
    """
    score = 10  # Base score (DNS lookup)
    
    # 1. Traffic Type Context
    if row["Detection_Source"] == "HTTP":
        score += 20
        if row.get("method") == "POST":
            score += 20  # Posting data is higher risk than reading
        
        # 2. Data Exfiltration Volume
        bytes_out = row.get("Upload_Bytes", 0)
        if bytes_out > 5 * 1024 * 1024: score += 40  # > 5MB upload
        elif bytes_out > 1 * 1024 * 1024: score += 20 # > 1MB upload
        elif bytes_out > 10 * 1024: score += 10       # > 10KB (Prompt Injection/Chat)

        # 3. Sensitive Endpoints
        uri = str(row.get("Detail", "")).lower()
        if any(x in uri for x in ["/upload", "/files", "/embeddings", "/fine-tune"]):
            score += 15

    # 4. Client Context (Non-Browser is suspicious for shadow IT)
    if row.get("Client_Type") == "Automation / SDK":
        score += 15

    # Cap at 100
    return min(100, score)

def normalize_severity_label(score):
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 30: return "MEDIUM"
    return "LOW"

# ==============================================================================
# 3. DATA LOADING & CORRELATION ENGINE
# ==============================================================================
@st.cache_data(show_spinner=False)
def load_shadow_ai_data(parquet_root: Path):
    ai_events = []
    
    # --- 1. DHCP Correlation Map ---
    dhcp_map = pd.DataFrame()
    dhcp_files = sorted(parquet_root.glob("**/dhcp.parquet"))
    if dhcp_files:
        try:
            raw_dhcp = pd.concat([pd.read_parquet(f) for f in dhcp_files], ignore_index=True)
            if "mac" in raw_dhcp.columns:
                raw_dhcp["mac"] = raw_dhcp["mac"].str.lower().str.strip()
                # Keep most recent hostname per MAC
                dhcp_map = raw_dhcp.sort_values("ts").drop_duplicates(subset=["mac"], keep="last")[["mac", "client_addr", "host_name"]]
        except: pass

    # --- 2. Log Scanning Loop ---
    if not parquet_root.exists():
        return pd.DataFrame()

    for day_dir in sorted(p for p in parquet_root.iterdir() if p.is_dir()):
        
        # [A] HTTP LOGS
        if (day_dir / "http.parquet").exists():
            try:
                df = pd.read_parquet(day_dir / "http.parquet")
                if "host" in df.columns:
                    target_col = "host"
                elif "id.resp_h" in df.columns:
                    target_col = "id.resp_h"
                else:
                    target_col = None

                if target_col:
                    for provider, regexes in AI_SIGNATURES.items():
                        pattern = "|".join(regexes)
                        mask = df[target_col].str.contains(pattern, case=False, na=False)
                        if "uri" in df.columns:
                             mask = mask | df["uri"].str.contains(pattern, case=False, na=False)

                        matches = df[mask].copy()
                        if not matches.empty:
                            matches["AI_Provider"] = provider
                            matches["Detection_Source"] = "HTTP"
                            matches["Client_Type"] = matches["user_agent"].apply(fingerprint_client) if "user_agent" in matches.columns else "Unknown"
                            matches["Upload_Bytes"] = pd.to_numeric(matches["request_body_len"], errors='coerce').fillna(0) if "request_body_len" in matches.columns else 0
                            method = matches["method"] if "method" in matches.columns else "-"
                            uri = matches["uri"] if "uri" in matches.columns else "-"
                            matches["Detail"] = method + " " + uri
                            matches["Destination"] = matches[target_col]
                            ai_events.append(matches)
            except: pass

        # [B] SSL LOGS
        if (day_dir / "ssl.parquet").exists():
            try:
                df = pd.read_parquet(day_dir / "ssl.parquet")
                target_col = "server_name" if "server_name" in df.columns else ("id.resp_h" if "id.resp_h" in df.columns else None)
                if target_col:
                    for provider, regexes in AI_SIGNATURES.items():
                        pattern = "|".join(regexes)
                        mask = df[target_col].str.contains(pattern, case=False, na=False)
                        matches = df[mask].copy()
                        if not matches.empty:
                            matches["AI_Provider"] = provider
                            matches["Detection_Source"] = "SSL"
                            matches["Client_Type"] = "Encrypted (TLS)"
                            matches["Upload_Bytes"] = 0
                            matches["Detail"] = "SNI: " + matches[target_col].astype(str)
                            matches["Destination"] = matches[target_col]
                            ai_events.append(matches)
            except: pass

        # [C] CONN LOGS
        if (day_dir / "conn.parquet").exists():
            try:
                df = pd.read_parquet(day_dir / "conn.parquet")
                if "id.resp_p" in df.columns:
                    for port, tool_name in LOCAL_AI_PORTS.items():
                        matches = df[df["id.resp_p"] == port].copy()
                        if not matches.empty:
                            matches["AI_Provider"] = f"{tool_name} (Local/Custom)"
                            matches["Detection_Source"] = "CONN (Port)"
                            matches["Client_Type"] = "Local Tool"
                            matches["Upload_Bytes"] = pd.to_numeric(matches["orig_ip_bytes"], errors='coerce').fillna(0) if "orig_ip_bytes" in matches.columns else 0
                            matches["Detail"] = f"Port {port} Traffic"
                            matches["Destination"] = matches["id.resp_h"] if "id.resp_h" in matches.columns else "Unknown"
                            ai_events.append(matches)
            except: pass
            
    if not ai_events: return pd.DataFrame()
    final_df = pd.concat(ai_events, ignore_index=True)

    # DHCP Enrichment
    if "mac" not in final_df.columns: final_df["mac"] = None
    if "id.orig_h" in final_df.columns and not dhcp_map.empty:
        final_df = pd.merge(final_df, dhcp_map, how="left", left_on="id.orig_h", right_on="client_addr")
        final_df["mac"] = final_df["mac_x"].fillna(final_df["mac_y"])
        final_df = final_df.drop(columns=["mac_x", "mac_y", "client_addr"])

    final_df["ts"] = pd.to_datetime(final_df["ts"], unit="s")
    final_df["host_name"] = final_df.get("host_name", "Unknown").fillna("Unknown")
    final_df["mac"] = final_df.get("mac", "Unknown").fillna("Unknown")
    final_df["Upload_Bytes"] = final_df.get("Upload_Bytes", 0).fillna(0)
    final_df["Risk_Score"] = final_df.apply(calculate_severity, axis=1)
    final_df["Severity"] = final_df["Risk_Score"].apply(normalize_severity_label)
    final_df["Policy_Verdict"] = final_df["AI_Provider"].apply(lambda x: "Allowed" if x in AUTHORIZED_PROVIDERS else "Shadow AI")
    final_df["Confidence"] = final_df["Detection_Source"].apply(lambda x: "High" if x in ["HTTP", "SSL"] else "Medium")

    return final_df.sort_values("ts", ascending=False)

# ==============================================================================
# 4. DASHBOARD RENDERER
# ==============================================================================
def render_shadow_ai(parquet_root: Path):
    st.markdown("#### Shadow AI & Data Leakage")
    with st.spinner("Correlating network telemetry..."):
        df = load_shadow_ai_data(parquet_root)

    # --- 0. HANDLING EMPTY STATE ---
    # If no data found, initialize an empty DataFrame with expected schema
    # This allows the UI to render (showing 0s) instead of crashing or hiding.
    if df.empty:
        st.info("ℹNo AI signatures detected in logs. Dashboard active in monitoring mode.")
        required_cols = [
            "ts", "AI_Provider", "Risk_Score", "Severity", "mac", "host_name", 
            "Detail", "Client_Type", "Policy_Verdict", "Upload_Bytes", 
            "Detection_Source", "user_agent", "id.orig_h"
        ]
        df = pd.DataFrame(columns=required_cols)
        df["ts"] = pd.to_datetime([])

    # --- FILTERS SECTION ---
    st.markdown("### Global Threat Filters")
    
    # Date filter logic (Handle empty TS for fallback)
    if not df.empty:
        min_date = df["ts"].min().date()
        max_date = df["ts"].max().date()
    else:
        min_date = datetime.now().date()
        max_date = datetime.now().date()
    
    with st.container(border=True):
        f1, f2, f3 = st.columns([2, 2, 2])
        with f1:
            date_range = st.date_input("Filter by Date Range", value=(min_date, max_date), min_value=min_date, max_value=max_date)
        with f2:
            selected_verdict = st.multiselect("Policy Verdict", ["Shadow AI", "Allowed"], default=["Shadow AI", "Allowed"])
        with f3:
            selected_severity = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
            
        f4, f5 = st.columns([3, 3])
        with f4:
            # Handle empty case for unique values
            if not df.empty:
                all_clients = sorted([str(x) for x in df["Client_Type"].unique()])
            else:
                all_clients = []
            client_filter = st.multiselect("Client Type", all_clients, placeholder="All Clients")
        with f5:
            search_q = st.text_input("Search Logs (Host, MAC, Provider, or Detail)", placeholder="Enter keywords...")

    # Apply Filter Logic
    filtered = df.copy()
    
    # 1. Date Range Filter
    if not filtered.empty and isinstance(date_range, tuple) and len(date_range) == 2:
        start_dt, end_dt = pd.to_datetime(date_range[0]), pd.to_datetime(date_range[1]) + pd.Timedelta(days=1)
        filtered = filtered[(filtered["ts"] >= start_dt) & (filtered["ts"] < end_dt)]
    
    # 2. Category Filters
    if not filtered.empty:
        if selected_verdict:
            filtered = filtered[filtered["Policy_Verdict"].isin(selected_verdict)]
        if selected_severity:
            filtered = filtered[filtered["Severity"].isin(selected_severity)]
        if client_filter:
            filtered = filtered[filtered["Client_Type"].isin(client_filter)]
            
    # 3. Global Search Filter
    if not filtered.empty and search_q:
        q = search_q.lower()
        search_mask = (
            filtered["host_name"].str.lower().str.contains(q, na=False) |
            filtered["mac"].str.lower().str.contains(q, na=False) |
            filtered["AI_Provider"].str.lower().str.contains(q, na=False) |
            filtered["Detail"].str.lower().str.contains(q, na=False) |
            filtered["id.orig_h"].astype(str).str.contains(q, na=False)
        )
        filtered = filtered[search_mask]

    # --- METRICS ROW ---
    st.markdown("---")
    m1, m2, m3, m4 = st.columns(4)
    
    # Safe calculation for empty filtered df
    total_leakage_mb = filtered["Upload_Bytes"].sum() / 1024 / 1024 if not filtered.empty else 0
    critical_events = len(filtered[filtered["Severity"] == "CRITICAL"]) if not filtered.empty else 0
    automations = len(filtered[filtered["Client_Type"] == "Automation / SDK"]) if not filtered.empty else 0
    
    m1.metric("Selected Events", len(filtered))
    m2.metric("Data Leakage", f"{total_leakage_mb:.2f} MB")
    m3.metric("Critical Incidents", critical_events, delta="Risk" if critical_events > 0 else "Clear", delta_color="inverse")
    m4.metric("Automation Count", automations)

    # --- VISUALIZATIONS ---
    st.markdown("### Posture Analysis")
    g1, g2 = st.columns([2, 1])
    with g1:
        # Plotly handles empty DFs by showing empty axes, which is what we want
        fig_scatter = px.scatter(
            filtered, x="ts", y="AI_Provider", 
            size="Risk_Score" if not filtered.empty else None, 
            color="Severity" if not filtered.empty else None,
            color_discrete_map={"LOW": "#00CC96", "MEDIUM": "#FFA15A", "HIGH": "#EF553B", "CRITICAL": "#B80000"},
            hover_data=["mac", "host_name", "Detail"] if not filtered.empty else None,
            title="Incident Timeline",
            template="plotly_dark"
        )
        st.plotly_chart(fig_scatter, use_container_width=True)
    with g2:
        if not filtered.empty:
            risk_vectors = filtered.groupby("Client_Type")["Risk_Score"].mean().reset_index()
        else:
            risk_vectors = pd.DataFrame(columns=["Risk_Score", "Client_Type"])
            
        fig_bar = px.bar(
            risk_vectors, x="Risk_Score", y="Client_Type", orientation='h',
            title="Avg Risk by Client", color="Risk_Score", color_continuous_scale="Reds", template="plotly_dark"
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    # --- FORENSICS TABLE ---
    st.markdown("---")
    st.subheader("Incident Forensics")
    
    tab_list = st.tabs(["Priority Alerts", "Client/MAC Mapping", "Full Traffic Log", "Top Data Exfiltrators"])

    with tab_list[0]: # Critical/High
        if filtered.empty:
            st.info("No data to display.")
        else:
            high_sev = filtered[filtered["Severity"].isin(["CRITICAL", "HIGH"])]
            if high_sev.empty:
                st.success("No High severity incidents in filtered view.")
            else:
                st.dataframe(
                    high_sev[["ts", "Severity", "mac", "host_name", "AI_Provider", "Detail", "Upload_Bytes"]],
                    use_container_width=True, hide_index=True,
                    column_config={"Upload_Bytes": st.column_config.NumberColumn("Upload Size", format="%d Bytes")}
                )

    with tab_list[1]: # Scripts/MACs
        if filtered.empty:
             st.info("No data to display.")
        else:
            scripts = filtered[filtered["Client_Type"] == "Automation / SDK"]
            st.dataframe(
                filtered[["ts", "mac", "host_name", "AI_Provider", "Client_Type", "user_agent"]].drop_duplicates(subset=["mac", "AI_Provider"]),
                use_container_width=True, hide_index=True
            )

    with tab_list[2]: # All
        def style_severity(v):
            colors = {"CRITICAL": "#B80000", "HIGH": "#EF553B", "MEDIUM": "#FFA15A", "LOW": "#00CC96"}
            return f"color: {colors.get(v, 'white')}; font-weight: bold"
        
        cols = ["ts", "mac", "host_name", "Severity", "AI_Provider", "Detail", "Policy_Verdict"]
        
        # Handle styling on empty DF
        if filtered.empty:
             st.dataframe(pd.DataFrame(columns=cols), use_container_width=True)
        else:
            st.dataframe(
                filtered[cols].style.map(style_severity, subset=["Severity"]),
                use_container_width=True, height=500,
                column_config={"ts": st.column_config.DatetimeColumn("Time", format="MM-DD HH:mm")}
            )

    with tab_list[3]: # Top Leakers
        if filtered.empty:
            st.info("No data to display.")
        else:
            leakers = filtered.groupby(["host_name", "mac", "AI_Provider"]).agg(
                Total_Upload_MB=("Upload_Bytes", lambda x: x.sum() / 1024 / 1024),
                Event_Count=("ts", "count")
            ).reset_index().sort_values("Total_Upload_MB", ascending=False)
            
            max_val = int(leakers["Total_Upload_MB"].max()) if not leakers.empty else 100
            st.dataframe(
                leakers, 
                use_container_width=True, hide_index=True,
                column_config={
                    "Total_Upload_MB": st.column_config.ProgressColumn(
                        "Data Exfiltrated (MB)", format="%.2f MB", min_value=0, max_value=max_val
                    )
                }
            )