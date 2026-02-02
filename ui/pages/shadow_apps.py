# ui/pages/shadow_apps.py
import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path

# -----------------------------
# Config
# -----------------------------
MAX_ROWS_DISPLAY = 100000000
ALLOWLIST_FILE = Path(__file__).parent.parent / "allowlist.txt"

# -----------------------------
# Load allowlist
# -----------------------------
def load_allowlist():
    if not ALLOWLIST_FILE.exists():
        return []
    with open(ALLOWLIST_FILE, "r", encoding="utf-8") as f:
        return [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]

# -----------------------------
# Render charts and table
# -----------------------------
def render_charts(df: pd.DataFrame, ts_col: str, domain_col: str, title_prefix: str, approved: list):
    if df.empty:
        st.info(f"No {title_prefix} detected.")
        return

    # Mark Allowed / Not Allowed
    df["Status"] = df[domain_col].apply(lambda x: "Allowed" if str(x).lower() in approved else "Not Allowed")

    # Convert timestamp to datetime
    if ts_col in df.columns:
        df["datetime"] = pd.to_datetime(df[ts_col], unit="s", errors="coerce")
        df = df.dropna(subset=["datetime"])
    else:
        df["datetime"] = pd.NaT

    # -----------------------------
    # Charts
    # -----------------------------
    col1, col2 = st.columns([3, 1])

    # Line chart
    with col1:
        if "datetime" in df.columns:
            df_line = df.groupby([pd.Grouper(key="datetime", freq="H"), "Status"]).size().reset_index(name="count")

            all_status = ["Allowed", "Not Allowed"]
            all_times = pd.date_range(df_line['datetime'].min(), df_line['datetime'].max(), freq='H')
            full_index = pd.MultiIndex.from_product([all_times, all_status], names=['datetime', 'Status'])
            df_line = df_line.set_index(['datetime', 'Status']).reindex(full_index, fill_value=0).reset_index()

            fig_line = px.line(
                df_line,
                x="datetime",
                y="count",
                color="Status",
                color_discrete_map={"Allowed": "green", "Not Allowed": "red"},
                markers=True,
                template="plotly_dark",
                title=f"{title_prefix} Over Time"
            )
            fig_line.update_layout(
                legend_title_text="Status",
                yaxis_title="Number of Requests",
                xaxis_title="Time"
            )
            st.plotly_chart(fig_line, use_container_width=True)

    # Pie chart
    with col2:
        status_counts = df["Status"].value_counts()

        for status in ["Allowed", "Not Allowed"]:
            if status not in status_counts:
                status_counts[status] = 0

        # Swap order so Allowed is first, Not Allowed second
        status_counts = status_counts.reindex(["Allowed", "Not Allowed"])

        fig_pie = px.pie(
            names=status_counts.index,
            values=status_counts.values,
            hole=0.4,
            template="plotly_dark",
            color=status_counts.index,
            color_discrete_map={"Allowed": "green", "Not Allowed": "red"},
            title="Status"
        )
        fig_pie.update_traces(
            textposition='inside',
            textinfo='label+percent',
            sort=False
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    # -----------------------------
    # Table (move outside the columns)
    # -----------------------------
    st.markdown("---")
    st.dataframe(df.head(MAX_ROWS_DISPLAY), use_container_width=True)
    st.markdown(f"Showing {min(MAX_ROWS_DISPLAY, len(df))} of {len(df)} rows")

# -----------------------------
# Main renderer
# -----------------------------
def render_shadow_apps(http_logs=None, ssl_logs=None, dns_logs=None):
    st.subheader("Shadow Apps Overview")
    approved = load_allowlist()

    # Determine available logs
    logs_options = []
    if http_logs is not None and "host" in http_logs.columns:
        logs_options.append("HTTP")
    if ssl_logs is not None and "server_name" in ssl_logs.columns:
        logs_options.append("SSL")
    if dns_logs is not None and "query" in dns_logs.columns:
        logs_options.append("DNS")

    if not logs_options:
        st.info("No Shadow App logs available to display.")
        return

    selected_log = st.selectbox("Select which analytics log to show", options=logs_options, index=0)

    # Map log to dataframe and column
    log_mapping = {
        "HTTP": (http_logs, "host", "HTTP Shadow Apps"),
        "SSL": (ssl_logs, "server_name", "SSL Shadow Apps"),
        "DNS": (dns_logs, "query", "DNS Shadow Apps"),
    }

    df, domain_col, title_prefix = log_mapping[selected_log]
    df = df.copy()
    df[f"{domain_col}_lower"] = df[domain_col].str.lower()
    render_charts(df, ts_col="ts", domain_col=f"{domain_col}_lower", title_prefix=title_prefix, approved=approved)
