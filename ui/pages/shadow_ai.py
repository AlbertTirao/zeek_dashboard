import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import re

# ==============================================================================
# 1. SECURITY CONFIGURATION & THREAT INTEL
# ==============================================================================

# Enterprise Policy: Define what is "Allowed" vs "Shadow"
AUTHORIZED_PROVIDERS = ["Microsoft Copilot"]  # Example: Only Copilot is sanctioned

# Extended Pattern Matching
AI_SIGNATURES = {
    "OpenAI / ChatGPT": [r"openai\.com", r"chatgpt\.com", r"api\.openai", r"chat\.openai", r"oaistatic\.com"],
    "Microsoft Copilot": [r"copilot\.microsoft\.com", r"githubcopilot\.com", r"bing\.com/chat", r"edgeservices\.bing\.com"],
    "Google Gemini/Bard": [r"bard\.google\.com", r"gemini\.google\.com", r"generativelanguage\.googleapis", r"alkalimakersuite"],
    "Anthropic Claude": [r"anthropic\.com", r"claude\.ai", r"cdn\.anthropic\.com"],
    "Hugging Face": [r"huggingface\.co", r"hf\.co", r"huggingface\.tech"],
    "Perplexity": [r"perplexity\.ai", r"pplx\.ai"],
    "Midjourney": [r"midjourney\.com", r"discord\.com/invite/midjourney"],
    "Ollama (Local/Cloud)": [r"ollama\.ai", r"localhost:11434", r"127\.0\.0\.1:11434"],
    "LM Studio": [r"lmstudio\.ai", r"localhost:1234"],
    "Generic AI API": [r"api\.[\w-]+\.ai", r"v1/chat/completions", r"v1/embeddings"] # Catch-all for emerging tools
}

# Local AI Port Signatures (for conn.log)
LOCAL_AI_PORTS = {
    11434: "Ollama",
    1234: "LM Studio",
    7860: "HuggingFace Gradio",
    5000: "Local Flask AI" # Generic
}

# ==============================================================================
# 2. SOC LOGIC: SCORING & CLASSIFICATION
# ==============================================================================

def fingerprint_client(ua: str) -> str:
    """Identify if the actor is a Browser, a Script (Python/Curl), or an App."""
    if pd.isna(ua) or ua in ["-", ""]: return "Unknown"
    ua = str(ua).lower()
    
    # Dev Tools / Automation SDKs
    if any(x in ua for x in ["python", "curl", "wget", "aiohttp", "requests", "httpx", "langchain", "openai-python"]):
        return "🤖 Automation / SDK"
    
    # Browsers
    if any(x in ua for x in ["mozilla", "chrome", "safari", "edge", "firefox"]):
        return "👤 Web Browser"
    
    return "📱 Mobile / App"

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
    # Robustly check for directories
    if not parquet_root.exists():
        return pd.DataFrame()

    for day_dir in sorted(p for p in parquet_root.iterdir() if p.is_dir()):
        
        # [A] HTTP LOGS (Rich Context: Size, UA, Method)
        if (day_dir / "http.parquet").exists():
            try:
                df = pd.read_parquet(day_dir / "http.parquet")
                
                # Column Safety Check
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
                        
                        # Also check URI if it exists
                        if "uri" in df.columns:
                             mask = mask | df["uri"].str.contains(pattern, case=False, na=False)

                        matches = df[mask].copy()
                        
                        if not matches.empty:
                            matches["AI_Provider"] = provider
                            matches["Detection_Source"] = "HTTP"
                            
                            if "user_agent" in matches.columns:
                                matches["Client_Type"] = matches["user_agent"].apply(fingerprint_client) 
                            else:
                                matches["Client_Type"] = "Unknown"
                            
                            # Safely get body length
                            if "request_body_len" in matches.columns:
                                matches["Upload_Bytes"] = pd.to_numeric(matches["request_body_len"], errors='coerce').fillna(0)
                            else:
                                matches["Upload_Bytes"] = 0

                            # Construct detail
                            method = matches["method"] if "method" in matches.columns else "-"
                            uri = matches["uri"] if "uri" in matches.columns else "-"
                            matches["Detail"] = method + " " + uri
                            matches["Destination"] = matches[target_col]
                            
                            ai_events.append(matches)
            except: pass

        # [B] SSL LOGS (Encrypted Traffic)
        if (day_dir / "ssl.parquet").exists():
            try:
                df = pd.read_parquet(day_dir / "ssl.parquet")
                
                # Column Safety
                if "server_name" in df.columns:
                    target_col = "server_name"
                elif "id.resp_h" in df.columns: # Fallback
                    target_col = "id.resp_h"
                else:
                    target_col = None

                if target_col:
                    for provider, regexes in AI_SIGNATURES.items():
                        pattern = "|".join(regexes)
                        mask = df[target_col].str.contains(pattern, case=False, na=False)
                        matches = df[mask].copy()
                        
                        if not matches.empty:
                            matches["AI_Provider"] = provider
                            matches["Detection_Source"] = "SSL"
                            matches["Client_Type"] = "Encrypted (TLS)"
                            matches["Upload_Bytes"] = 0 # Cannot see size easily
                            matches["Detail"] = "SNI: " + matches[target_col]
                            matches["Destination"] = matches[target_col]
                            ai_events.append(matches)
            except: pass

        # [C] CONN LOGS (Local AI Ports)
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
                            
                            if "orig_ip_bytes" in matches.columns:
                                matches["Upload_Bytes"] = pd.to_numeric(matches["orig_ip_bytes"], errors='coerce').fillna(0)
                            else:
                                matches["Upload_Bytes"] = 0
                                
                            matches["Detail"] = f"Port {port} Traffic"
                            matches["Destination"] = matches["id.resp_h"] if "id.resp_h" in matches.columns else "Unknown"
                            ai_events.append(matches)
            except: pass
            
    # --- 3. Normalization ---
    if not ai_events: return pd.DataFrame()
    final_df = pd.concat(ai_events, ignore_index=True)

    # DHCP Enrichment
    if "mac" not in final_df.columns: final_df["mac"] = None
    if "id.orig_h" in final_df.columns and not dhcp_map.empty:
        final_df = pd.merge(final_df, dhcp_map, how="left", left_on="id.orig_h", right_on="client_addr")
        final_df["mac"] = final_df["mac_x"].fillna(final_df["mac_y"])
        final_df = final_df.drop(columns=["mac_x", "mac_y", "client_addr"])

    # Final Cleanup
    final_df["ts"] = pd.to_datetime(final_df["ts"], unit="s")
    final_df["host_name"] = final_df.get("host_name", "Unknown").fillna("Unknown")
    final_df["mac"] = final_df.get("mac", "Unknown").fillna("Unknown")
    final_df["Upload_Bytes"] = final_df.get("Upload_Bytes", 0).fillna(0)

    # --- 4. SOC Scoring Execution ---
    final_df["Risk_Score"] = final_df.apply(calculate_severity, axis=1)
    final_df["Severity"] = final_df["Risk_Score"].apply(normalize_severity_label)
    final_df["Policy_Verdict"] = final_df["AI_Provider"].apply(lambda x: "Allowed" if x in AUTHORIZED_PROVIDERS else "Shadow AI")
    
    # Confidence (Binary for now, but scalable)
    final_df["Confidence"] = final_df["Detection_Source"].apply(lambda x: "High" if x in ["HTTP", "SSL"] else "Medium")

    return final_df.sort_values("ts", ascending=False)

# ==============================================================================
# 4. DASHBOARD RENDERER
# ==============================================================================
def render_shadow_ai(parquet_root: Path):
    st.title("Shadow AI & Data Leakage Dashboard")
    st.markdown("Advanced detection of unauthorized AI APIs, automation scripts, and data exfiltration.")

    with st.spinner("Correlating network telemetry..."):
        df = load_shadow_ai_data(parquet_root)

    if df.empty:
        st.success("Clean Network: No AI signatures detected.")
        return

    # --- FILTERS ---
    st.markdown("### Threat Hunting Filters")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1: 
        # Default: Select ALL verdicts so data appears by default
        selected_verdict = st.multiselect("Policy Verdict", ["Shadow AI", "Allowed"], default=["Shadow AI", "Allowed"])
    with col2:
        # Default: Select ALL severities
        selected_severity = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with col3:
        # Client filter
        all_clients = sorted([str(x) for x in df["Client_Type"].unique()])
        client_filter = st.multiselect("Client Type", all_clients, placeholder="Filter by Client")
    with col4:
        search_q = st.text_input("Search User/MAC/App")

    # Filter Logic
    filtered = df.copy()
    
    if selected_verdict:
        filtered = filtered[filtered["Policy_Verdict"].isin(selected_verdict)]
    if selected_severity:
        filtered = filtered[filtered["Severity"].isin(selected_severity)]
    if client_filter:
        filtered = filtered[filtered["Client_Type"].isin(client_filter)]
    if search_q:
        q = search_q.lower()
        filtered = filtered[filtered.astype(str).apply(lambda x: x.str.lower().str.contains(q, na=False)).any(axis=1)]

    if filtered.empty:
        st.info("No events match the current security filters.")
        return

    # --- METRICS ROW ---
    st.markdown("---")
    m1, m2, m3, m4 = st.columns(4)
    
    total_leakage_mb = filtered["Upload_Bytes"].sum() / 1024 / 1024
    critical_events = len(filtered[filtered["Severity"] == "CRITICAL"])
    automations = len(filtered[filtered["Client_Type"] == "🤖 Automation / SDK"])
    
    m1.metric("Shadow AI Events", len(filtered))
    m2.metric("Data Leakage Volume", f"{total_leakage_mb:.2f} MB", help="Total bytes sent to AI endpoints (HTTP POST/PUT)")
    m3.metric("Critical Incidents", critical_events, delta="Action Required" if critical_events > 0 else "Safe", delta_color="inverse")
    m4.metric("Unauthorized Scripts", automations, help="Python/Curl/SDKs detected accessing AI")

    # --- VISUALIZATIONS ---
    st.markdown("### Posture Analysis")
    
    g1, g2 = st.columns([2, 1])
    
    with g1:
        # Scatter Plot: Time vs Risk Score vs App
        fig_scatter = px.scatter(
            filtered, x="ts", y="AI_Provider", 
            size="Risk_Score", color="Severity",
            color_discrete_map={"LOW": "#00CC96", "MEDIUM": "#FFA15A", "HIGH": "#EF553B", "CRITICAL": "#B80000"},
            hover_data=["Client_Type", "host_name", "Detail"],
            title="AI Incidents Timeline (Size = Risk Score)",
            template="plotly_dark"
        )
        st.plotly_chart(fig_scatter, use_container_width=True)
        
    with g2:
        # Risk by Client Type
        risk_vectors = filtered.groupby("Client_Type")["Risk_Score"].mean().reset_index()
        fig_bar = px.bar(
            risk_vectors, x="Risk_Score", y="Client_Type", orientation='h',
            title="Avg Risk by Client Type",
            color="Risk_Score", color_continuous_scale="Reds",
            template="plotly_dark"
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    # --- FORENSICS TABLE ---
    st.markdown("---")
    st.subheader("Incident Forensics")
    
    tab_list = st.tabs(["Critical & High Risk", "Automation/SDKs", "All Events", "Top Data Leakers"])

    with tab_list[0]: # Critical/High
        high_sev = filtered[filtered["Severity"].isin(["CRITICAL", "HIGH"])]
        if high_sev.empty:
            st.success("No Critical or High severity incidents found.")
        else:
            st.dataframe(
                high_sev[["ts", "Severity", "host_name", "AI_Provider", "Detail", "Upload_Bytes"]],
                use_container_width=True, hide_index=True,
                column_config={"Upload_Bytes": st.column_config.NumberColumn("Upload Size", format="%d Bytes")}
            )

    with tab_list[1]: # Scripts
        scripts = filtered[filtered["Client_Type"] == "Automation / SDK"]
        if scripts.empty:
            st.info("No automation scripts detected.")
        else:
            st.dataframe(
                scripts[["ts", "mac", "host_name", "AI_Provider", "Detail", "user_agent"]],
                use_container_width=True, hide_index=True
            )

    with tab_list[2]: # All
        # Styling
        def style_severity(v):
            colors = {"CRITICAL": "#B80000", "HIGH": "#EF553B", "MEDIUM": "#FFA15A", "LOW": "#00CC96"}
            return f"color: {colors.get(v, 'white')}; font-weight: bold"
        
        cols = ["ts", "Policy_Verdict", "Severity", "host_name", "AI_Provider", "Client_Type", "Detail"]
        st.dataframe(
            filtered[cols].style.map(style_severity, subset=["Severity"]),
            use_container_width=True, height=500,
            column_config={
                "ts": st.column_config.DatetimeColumn("Time", format="MM-DD HH:mm"),
            }
        )

    with tab_list[3]: # Top Leakers
        leakers = filtered.groupby(["host_name", "mac", "AI_Provider"]).agg(
            Total_Upload_MB=("Upload_Bytes", lambda x: x.sum() / 1024 / 1024),
            Event_Count=("ts", "count")
        ).reset_index().sort_values("Total_Upload_MB", ascending=False)
        
        # Max value safely cast to int
        max_val = int(leakers["Total_Upload_MB"].max()) if not leakers.empty else 100
        
        st.dataframe(
            leakers, 
            use_container_width=True, hide_index=True,
            column_config={
                "Total_Upload_MB": st.column_config.ProgressColumn(
                    "Data Exfiltrated (MB)", 
                    format="%.2f MB", 
                    min_value=0, 
                    max_value=max_val
                )
            }
        )