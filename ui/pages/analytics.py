import streamlit as st
import pandas as pd
import plotly.express as px
import re
from datetime import datetime

# ---------------------------------------------------------
# CONFIGURATION & CONSTANTS
# ---------------------------------------------------------
APPROVED_DOMAINS = [
    "internal.example.com", "github.com", "jira.example.com", 
    "office.com", "company.cloud", "salesforce.com", 
    "slack.com", "google.com", "microsoft.com", "aws.amazon.com"
]

AI_KEYWORDS = ["openai", "chatgpt", "claude", "bard", "gemini", "midjourney", "huggingface"]
UPLOAD_KEYWORDS = ["upload", "drive", "dropbox", "box.com", "wetransfer", "mega.nz", "onedrive"]

STATUS_COLORS = {
    "Authorized": "#10B981",  # Emerald Green
    "Shadow": "#EF4444",      # Red
    "Unknown": "#6B7280"      # Gray
}

MAX_ROWS_DISPLAY = 500

# Pre-compile regex for speed (Critical for Real-Time performance)
APPROVED_PATTERN = "|".join([re.escape(d) for d in APPROVED_DOMAINS])

# ---------------------------------------------------------
# HELPER FUNCTIONS (OPTIMIZED)
# ---------------------------------------------------------

def classify_traffic_vectorized(df: pd.DataFrame, domain_col: str) -> pd.DataFrame:
    """
    High-performance classification using Vectorized Pandas operations.
    Much faster than .apply() for real-time loops.
    """
    if df is None or df.empty or domain_col not in df.columns:
        return df
    
    # 1. Convert to string and lowercase once
    df[domain_col] = df[domain_col].astype(str).str.lower()
    
    # 2. Vectorized check (Check all rows at once)
    is_authorized = df[domain_col].str.contains(APPROVED_PATTERN, case=False, na=False)
    
    # 3. Assign Status
    df["status"] = "Shadow"
    df.loc[is_authorized, "status"] = "Authorized"
    
    # Handle NaNs/Empty
    df.loc[df[domain_col] == "nan", "status"] = "Unknown"
    
    return df

def filter_by_keywords(df: pd.DataFrame, column: str, keywords: list) -> pd.DataFrame:
    """
    Filters a DataFrame for rows where the column contains any of the keywords.
    """
    if df is None or df.empty or column not in df.columns:
        return pd.DataFrame()
    
    pattern = '|'.join(keywords)
    return df[df[column].astype(str).str.contains(pattern, case=False, na=False)].copy()

def render_traffic_section(df: pd.DataFrame, source_name: str, domain_col: str):
    """
    Renders the metrics and charts for a specific traffic source.
    """
    if df is None or df.empty:
        st.info(f"Waiting for {source_name} traffic data...")
        return

    # 1. Prepare Data & Ensure Timestamp
    df_viz = df.copy()
    
    # Standardize Timestamp
    ts_col = "ts" if "ts" in df_viz.columns else "timestamp"
    if ts_col in df_viz.columns:
        df_viz["timestamp"] = pd.to_datetime(df_viz[ts_col], unit='s' if ts_col == 'ts' else None, errors='coerce')
        df_viz = df_viz.sort_values("timestamp") # Sort for correct line charts

    # 2. Classify Traffic (Fast)
    if domain_col in df_viz.columns:
        df_viz = classify_traffic_vectorized(df_viz, domain_col)
    else:
        st.warning(f"Column '{domain_col}' not found in {source_name} logs.")
        return

    # 3. Calculate Metrics
    total_reqs = len(df_viz)
    shadow_df = df_viz[df_viz["status"] == "Shadow"]
    shadow_count = len(shadow_df)
    risk_ratio = (shadow_count / total_reqs * 100) if total_reqs > 0 else 0

    # 4. Display Metrics
    st.markdown(f"#### {source_name} Analysis")
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Events", f"{total_reqs:,}")
    c2.metric("Shadow Events", f"{shadow_count:,}", delta="High Risk" if risk_ratio > 10 else "Normal", delta_color="inverse")
    c3.metric("Shadow Ratio", f"{risk_ratio:.1f}%", delta_color="inverse")

    # 5. Charts
    chart_col1, chart_col2 = st.columns([2, 1])

    with chart_col1:
        # Time Series
        if "timestamp" in df_viz.columns and not df_viz["timestamp"].isna().all():
            # Group by 1 minute intervals for cleaner real-time graphs
            df_time = df_viz.groupby([pd.Grouper(key="timestamp", freq="1min"), "status"]).size().reset_index(name="count")
            
            fig_line = px.line(
                df_time, x="timestamp", y="count", color="status",
                title=f"{source_name} Traffic Trend",
                color_discrete_map=STATUS_COLORS,
                template="plotly_dark",
                height=300
            )
            # Update layout to stop zooming reset on every refresh
            fig_line.update_layout(uirevision=source_name) 
            st.plotly_chart(fig_line, use_container_width=True, key=f"{source_name}_line")
        else:
            st.info("No timestamp data available for trend line.")

    with chart_col2:
        # Donut Chart
        status_counts = df_viz["status"].value_counts().reset_index()
        status_counts.columns = ["status", "count"]
        
        fig_pie = px.pie(
            status_counts, names="status", values="count",
            title="Compliance Split",
            color="status",
            color_discrete_map=STATUS_COLORS,
            hole=0.5,
            template="plotly_dark",
            height=300
        )
        fig_pie.update_layout(uirevision=source_name)
        st.plotly_chart(fig_pie, use_container_width=True, key=f"{source_name}_pie")

    # 6. Detail View
    with st.expander(f"🔴 View {source_name} Shadow Details"):
        cols_to_show = ["timestamp", "src_ip", "dest_ip", domain_col, "uri", "status"]
        st.dataframe(
            shadow_df[[c for c in shadow_df.columns if c in cols_to_show]].head(MAX_ROWS_DISPLAY),
            use_container_width=True
        )

# ---------------------------------------------------------
# MAIN RENDER ENTRY POINT
# ---------------------------------------------------------
def render(filtered_devices: pd.DataFrame, http_logs: pd.DataFrame = None, ssl_logs: pd.DataFrame = None, dns_logs: pd.DataFrame = None):
    """
    Called by app.py to render the Analytics page.
    """
    st.title(" Network Traffic Analytics")
    
    # Add a timestamp to show the user it is actually updating
    current_time = datetime.now().strftime("%H:%M:%S")
    st.caption(f"Live Analysis • Last Updated: {current_time}")

    tabs = st.tabs([" Shadow Apps", " Shadow Uploads", " Shadow AI"])

    # TAB 1: SHADOW APPS
    with tabs[0]:
        st.subheader("Unauthorized Application Usage")
        if http_logs is not None:
            render_traffic_section(http_logs, "HTTP", "host")
            st.divider()
        if ssl_logs is not None:
            render_traffic_section(ssl_logs, "SSL/TLS", "server_name")
            st.divider()
        if dns_logs is not None:
            render_traffic_section(dns_logs, "DNS", "query")

    # TAB 2: SHADOW UPLOADS
    with tabs[1]:
        st.subheader("Data Exfiltration Risks")
        upload_findings = []

        # Helper to process logs for uploads
        for name, df, col in [("HTTP", http_logs, "host"), ("SSL", ssl_logs, "server_name"), ("DNS", dns_logs, "query")]:
            if df is not None and col in df.columns:
                found = filter_by_keywords(df, col, UPLOAD_KEYWORDS)
                if not found.empty:
                    found["source"] = name
                    found["target"] = found[col]
                    upload_findings.append(found)

        if upload_findings:
            all_uploads = pd.concat(upload_findings, ignore_index=True)
            
            # Standardize timestamp for the combined view
            if "ts" in all_uploads.columns:
                all_uploads["timestamp"] = pd.to_datetime(all_uploads["ts"], unit='s', errors='coerce')

            st.metric("Potential Upload Activities", len(all_uploads), delta="Investigation Required", delta_color="inverse")
            
            bar_data = all_uploads["target"].value_counts().reset_index()
            bar_data.columns = ["Target Domain", "Count"]
            
            fig = px.bar(
                bar_data.head(10), x="Target Domain", y="Count",
                title="Top Storage/Transfer Targets",
                template="plotly_dark",
                color_discrete_sequence=["#F59E0B"]
            )
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(all_uploads[["timestamp", "source", "target", "id.orig_h"]].fillna("-"), use_container_width=True)
        else:
            st.success("No obvious data exfiltration signatures detected.")

    # TAB 3: SHADOW AI
    with tabs[2]:
        st.subheader("Generative AI Usage")
        ai_findings = []

        # Helper to process logs for AI
        for name, df, col in [("HTTP", http_logs, "host"), ("SSL", ssl_logs, "server_name"), ("DNS", dns_logs, "query")]:
            if df is not None and col in df.columns:
                found = filter_by_keywords(df, col, AI_KEYWORDS)
                if not found.empty:
                    found["detected_via"] = f"{name} ({col})"
                    found["target_service"] = found[col]
                    ai_findings.append(found)

        if ai_findings:
            df_ai = pd.concat(ai_findings, ignore_index=True)
            
            # Standardize timestamp
            if "ts" in df_ai.columns:
                df_ai["timestamp"] = pd.to_datetime(df_ai["ts"], unit='s', errors='coerce')

            c1, c2 = st.columns(2)
            c1.metric("AI Interactions", len(df_ai))
            c2.metric("Unique Devices", df_ai["id.orig_h"].nunique() if "id.orig_h" in df_ai.columns else "N/A")

            col_chart1, col_chart2 = st.columns(2)
            with col_chart1:
                top_services = df_ai["target_service"].value_counts().head(10)
                fig_ai = px.bar(
                    x=top_services.index, y=top_services.values,
                    title="Top AI Services",
                    labels={'x': 'Service', 'y': 'Count'},
                    template="plotly_dark",
                    color_discrete_sequence=["#8B5CF6"]
                )
                st.plotly_chart(fig_ai, use_container_width=True)

            with col_chart2:
                if "timestamp" in df_ai.columns:
                    df_ai_trend = df_ai.groupby(pd.Grouper(key="timestamp", freq="1min")).size().reset_index(name="count")
                    fig_trend = px.area(
                        df_ai_trend, x="timestamp", y="count",
                        title="AI Usage Trend",
                        template="plotly_dark",
                        color_discrete_sequence=["#8B5CF6"]
                    )
                    st.plotly_chart(fig_trend, use_container_width=True)
            
            st.dataframe(df_ai, use_container_width=True)
        else:
            st.success("No Generative AI traffic detected.")