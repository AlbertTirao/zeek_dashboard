import streamlit as st
import pandas as pd
import plotly.express as px

# Approved domains for Shadow App detection
APPROVED_DOMAINS = [
    "internal.example.com",
    "github.com",
    "jira.example.com",
    "office.com",
    "company.cloud"
]

MAX_ROWS_DISPLAY = 500  # Limit rows to avoid Streamlit message size error

def render(filtered: pd.DataFrame, http_logs: pd.DataFrame = None, ssl_logs: pd.DataFrame = None, dns_logs: pd.DataFrame = None):
    """
    Shadow IT aware Network Analytics dashboard
    Separate tables for HTTP, SSL, DNS logs for Shadow Apps
    """
    st.set_page_config(page_title="Network Analytics", layout="wide")
    st.title("Network Analytics")

    # -----------------------------
    # Top tabs
    # -----------------------------
    tab = st.radio("Select Section", ["Shadow Apps", "Shadow Uploads", "Shadow AI"], horizontal=True)

    if filtered.empty:
        st.info("No device data available for analytics.")
        return

    # -----------------------------
    # Shadow Apps detection
    # -----------------------------
    if tab == "Shadow Apps":
        st.subheader("Shadow Apps Overview")

        # -----------------------------
        # HTTP Logs
        # -----------------------------
        if http_logs is not None and "host" in http_logs.columns:
            df_http = http_logs.copy()
            df_http["host_lower"] = df_http["host"].str.lower()
            df_http["is_shadow"] = ~df_http["host_lower"].isin([d.lower() for d in APPROVED_DOMAINS])
            df_http_shadow = df_http[df_http["is_shadow"]].copy()
            df_http_shadow["status"] = "Shadow"

            if not df_http_shadow.empty:
                st.markdown("### HTTP Logs Shadow Apps")
                
                # Line chart
                if "timestamp" in df_http_shadow.columns:
                    df_http_shadow["timestamp"] = pd.to_datetime(df_http_shadow["timestamp"], errors="coerce")
                    df_line = df_http_shadow.dropna(subset=["timestamp"]).groupby(pd.Grouper(key="timestamp", freq="H")).size().reset_index(name="count")
                    fig_line = px.line(df_line, x="timestamp", y="count", title="HTTP Shadow Apps Over Time", template="plotly_dark")
                    st.plotly_chart(fig_line, use_container_width=True)
                
                # Bar chart
                count_by_host = df_http_shadow.groupby("host_lower").size().reset_index(name="count")
                fig_bar = px.bar(count_by_host.head(50), x="host_lower", y="count", title="Top HTTP Shadow Hosts", template="plotly_dark", color_discrete_sequence=["#6366f1"])
                st.plotly_chart(fig_bar, use_container_width=True)

                # Pie chart
                status_counts = df_http_shadow["status"].value_counts()
                fig_pie = px.pie(names=status_counts.index, values=status_counts.values, hole=0.4, template="plotly_dark", color_discrete_sequence=px.colors.sequential.RdBu)
                st.plotly_chart(fig_pie, use_container_width=True)

                # Table
                st.dataframe(df_http_shadow.head(MAX_ROWS_DISPLAY), use_container_width=True)
                st.markdown(f"Showing {min(MAX_ROWS_DISPLAY, len(df_http_shadow))} of {len(df_http_shadow)} HTTP Shadow App rows")
            else:
                st.info("No HTTP shadow apps detected.")

        # -----------------------------
        # SSL Logs
        # -----------------------------
        if ssl_logs is not None and "server_name" in ssl_logs.columns:
            df_ssl = ssl_logs.copy()
            df_ssl["server_name_lower"] = df_ssl["server_name"].str.lower()
            df_ssl["is_shadow"] = ~df_ssl["server_name_lower"].isin([d.lower() for d in APPROVED_DOMAINS])
            df_ssl_shadow = df_ssl[df_ssl["is_shadow"]].copy()
            df_ssl_shadow["status"] = "Shadow"

            if not df_ssl_shadow.empty:
                st.markdown("### SSL Logs Shadow Apps")

                # Line chart
                if "timestamp" in df_ssl_shadow.columns:
                    df_ssl_shadow["timestamp"] = pd.to_datetime(df_ssl_shadow["timestamp"], errors="coerce")
                    df_line = df_ssl_shadow.dropna(subset=["timestamp"]).groupby(pd.Grouper(key="timestamp", freq="H")).size().reset_index(name="count")
                    fig_line = px.line(df_line, x="timestamp", y="count", title="SSL Shadow Apps Over Time", template="plotly_dark")
                    st.plotly_chart(fig_line, use_container_width=True)

                # Bar chart
                count_by_host = df_ssl_shadow.groupby("server_name_lower").size().reset_index(name="count")
                fig_bar = px.bar(count_by_host.head(50), x="server_name_lower", y="count", title="Top SSL Shadow Hosts", template="plotly_dark", color_discrete_sequence=["#6366f1"])
                st.plotly_chart(fig_bar, use_container_width=True)

                # Pie chart
                status_counts = df_ssl_shadow["status"].value_counts()
                fig_pie = px.pie(names=status_counts.index, values=status_counts.values, hole=0.4, template="plotly_dark", color_discrete_sequence=px.colors.sequential.RdBu)
                st.plotly_chart(fig_pie, use_container_width=True)

                # Table
                st.dataframe(df_ssl_shadow.head(MAX_ROWS_DISPLAY), use_container_width=True)
                st.markdown(f"Showing {min(MAX_ROWS_DISPLAY, len(df_ssl_shadow))} of {len(df_ssl_shadow)} SSL Shadow App rows")
            else:
                st.info("No SSL shadow apps detected.")

        # -----------------------------
        # DNS Logs
        # -----------------------------
        if dns_logs is not None and "query" in dns_logs.columns:
            df_dns = dns_logs.copy()
            df_dns["query_lower"] = df_dns["query"].str.lower()
            df_dns["is_shadow"] = ~df_dns["query_lower"].str.contains("|".join([d.lower() for d in APPROVED_DOMAINS]), na=False)
            df_dns_shadow = df_dns[df_dns["is_shadow"]].copy()
            df_dns_shadow["status"] = "Shadow"

            if not df_dns_shadow.empty:
                st.markdown("### DNS Logs Shadow Apps")

                # Line chart
                if "timestamp" in df_dns_shadow.columns:
                    df_dns_shadow["timestamp"] = pd.to_datetime(df_dns_shadow["timestamp"], errors="coerce")
                    df_line = df_dns_shadow.dropna(subset=["timestamp"]).groupby(pd.Grouper(key="timestamp", freq="H")).size().reset_index(name="count")
                    fig_line = px.line(df_line, x="timestamp", y="count", title="DNS Shadow Apps Over Time", template="plotly_dark")
                    st.plotly_chart(fig_line, use_container_width=True)

                # Bar chart
                count_by_query = df_dns_shadow.groupby("query_lower").size().reset_index(name="count")
                fig_bar = px.bar(count_by_query.head(50), x="query_lower", y="count", title="Top DNS Shadow Queries", template="plotly_dark", color_discrete_sequence=["#6366f1"])
                st.plotly_chart(fig_bar, use_container_width=True)

                # Pie chart
                status_counts = df_dns_shadow["status"].value_counts()
                fig_pie = px.pie(names=status_counts.index, values=status_counts.values, hole=0.4, template="plotly_dark", color_discrete_sequence=px.colors.sequential.RdBu)
                st.plotly_chart(fig_pie, use_container_width=True)

                # Table
                st.dataframe(df_dns_shadow.head(MAX_ROWS_DISPLAY), use_container_width=True)
                st.markdown(f"Showing {min(MAX_ROWS_DISPLAY, len(df_dns_shadow))} of {len(df_dns_shadow)} DNS Shadow App rows")
            else:
                st.info("No DNS shadow apps detected.")

    # -----------------------------
    # Shadow Uploads
    # -----------------------------
    elif tab == "Shadow Uploads":
        st.subheader("Shadow Uploads Overview")
        if "application" in filtered.columns:
            df_tab = filtered[filtered["application"].str.contains("upload", case=False, na=False)]
            if not df_tab.empty:
                # Bar chart by MAC
                count_by_mac = df_tab.groupby("mac").size().reset_index(name="count")
                fig_bar = px.bar(count_by_mac.head(50), x="mac", y="count", title="Top Uploading Devices", template="plotly_dark", color_discrete_sequence=["#f59e0b"])
                st.plotly_chart(fig_bar, use_container_width=True)

                # Line chart by hour
                if "timestamp" in df_tab.columns:
                    df_tab["timestamp"] = pd.to_datetime(df_tab["timestamp"], errors="coerce")
                    df_line = df_tab.dropna(subset=["timestamp"]).groupby(pd.Grouper(key="timestamp", freq="H")).size().reset_index(name="count")
                    fig_line = px.line(df_line, x="timestamp", y="count", title="Uploads Over Time", template="plotly_dark")
                    st.plotly_chart(fig_line, use_container_width=True)

                # Pie chart
                status_counts = df_tab["status"].value_counts()
                fig_pie = px.pie(names=status_counts.index, values=status_counts.values, hole=0.4, template="plotly_dark", color_discrete_sequence=px.colors.sequential.RdBu)
                st.plotly_chart(fig_pie, use_container_width=True)

                # Table
                st.subheader("Device Details - Shadow Uploads")
                st.dataframe(df_tab.head(MAX_ROWS_DISPLAY), use_container_width=True)
                st.markdown(f"Showing {min(MAX_ROWS_DISPLAY, len(df_tab))} of {len(df_tab)} rows")
            else:
                st.info("No uploads detected.")
        else:
            st.info("No upload data available.")

    # -----------------------------
    # Shadow AI
    # -----------------------------
    else:
        st.subheader("Shadow AI Overview")
        if "application" in filtered.columns:
            df_tab = filtered[filtered["application"].str.contains("ai", case=False, na=False)]
            if not df_tab.empty:
                # Bar chart by MAC
                count_by_mac = df_tab.groupby("mac").size().reset_index(name="count")
                fig_bar = px.bar(count_by_mac.head(50), x="mac", y="count", title="Top AI App Devices", template="plotly_dark", color_discrete_sequence=["#10b981"])
                st.plotly_chart(fig_bar, use_container_width=True)

                # Line chart by hour
                if "timestamp" in df_tab.columns:
                    df_tab["timestamp"] = pd.to_datetime(df_tab["timestamp"], errors="coerce")
                    df_line = df_tab.dropna(subset=["timestamp"]).groupby(pd.Grouper(key="timestamp", freq="H")).size().reset_index(name="count")
                    fig_line = px.line(df_line, x="timestamp", y="count", title="AI App Events Over Time", template="plotly_dark")
                    st.plotly_chart(fig_line, use_container_width=True)

                # Pie chart
                status_counts = df_tab["status"].value_counts()
                fig_pie = px.pie(names=status_counts.index, values=status_counts.values, hole=0.4, template="plotly_dark", color_discrete_sequence=px.colors.sequential.RdBu)
                st.plotly_chart(fig_pie, use_container_width=True)

                # Table
                st.subheader("Device Details - Shadow AI")
                st.dataframe(df_tab.head(MAX_ROWS_DISPLAY), use_container_width=True)
                st.markdown(f"Showing {min(MAX_ROWS_DISPLAY, len(df_tab))} of {len(df_tab)} rows")
            else:
                st.info("No AI apps detected.")
        else:
            st.info("No AI data available.")
