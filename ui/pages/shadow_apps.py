# ui/pages/shadow_apps.py
import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
from urllib.parse import urlparse

# -----------------------------
# Config
# -----------------------------
MAX_ROWS_DISPLAY = 500
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
# Load allowlist
# -----------------------------
def load_allowlist():
    """Load and normalize domains from allowlist.txt."""
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
    st.caption(f"Loaded {len(approved)} allowlisted domains")
    return list(approved)

# -----------------------------
# Extract domain from URL or hostname
# -----------------------------
def extract_domain(url: str):
    if not url:
        return ""
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
# Helper: Device columns
# -----------------------------
def get_device_columns(df: pd.DataFrame):
    ip_col = "id.orig_h" if "id.orig_h" in df.columns else None
    mac_col = None
    for c in ["mac", "orig_mac", "id.orig_mac"]:
        if c in df.columns:
            mac_col = c
            break
    return ip_col, mac_col

# -----------------------------
# Session state: selected MAC
# -----------------------------
if "selected_mac" not in st.session_state:
    st.session_state.selected_mac = None

# -----------------------------
# Cross-filter UI by day
# -----------------------------
def render_filters(df, title_prefix):
    if "datetime" not in df.columns:
        return df

    st.markdown("### Global Filters")
    df["day"] = df["datetime"].dt.date

    col1, col2 = st.columns(2)

    with col1:
        selected_day = st.selectbox(
            "Filter by day",
            ["All"] + sorted(df["day"].dropna().unique().tolist()),
            key=f"day_filter_{title_prefix}"
        )

    if selected_day != "All":
        df = df[df["day"] == selected_day]

    return df

# -----------------------------
# Table MAC selector
# -----------------------------
def mac_selector_table(df, table_name="Table"):
    """Display table and allow MAC selection for cross-filtering."""
    st.markdown(f"### {table_name}")
    st.dataframe(df, use_container_width=True)

    if "mac" in df.columns:
        macs = df["mac"].dropna().unique()
        if len(macs) > 0:
            mac_choice = st.selectbox(
                f"Filter by MAC in {table_name}",
                ["All"] + sorted(macs),
                key=f"mac_filter_{table_name}"
            )
            if mac_choice != "All":
                st.session_state.selected_mac = mac_choice
                df = df[df["mac"] == mac_choice]

    return df

# -----------------------------
# Apply global MAC filter
# -----------------------------
def apply_global_mac_filter(df):
    if st.session_state.selected_mac:
        df = df[df["mac"] == st.session_state.selected_mac]
    return df

# -----------------------------
# Render charts, metrics, and tables
# -----------------------------
# -----------------------------
# Render charts, metrics, and tables
# -----------------------------
def render_charts(df: pd.DataFrame, ts_col: str, domain_col: str, title_prefix: str, approved: list):
    if df.empty:
        st.info(f"No {title_prefix} detected.")
        return

    # Normalize domains
    df["domain_clean"] = df[domain_col].apply(extract_domain)
    df["Status"] = df["domain_clean"].apply(lambda x: "Allowed" if is_allowed(x, approved) else "Not Allowed")

    # Convert timestamp robustly
    if ts_col in df.columns:
        # Try numeric (epoch seconds)
        df["datetime"] = pd.to_datetime(df[ts_col], unit='s', errors='coerce')
        # If all NaT, try parsing as string
        if df["datetime"].isna().all():
            df["datetime"] = pd.to_datetime(df[ts_col], errors='coerce')
        # Drop rows where datetime is NaT
        df = df.dropna(subset=["datetime"])
    else:
        df["datetime"] = pd.NaT

    # Device info
    ip_col, mac_col = get_device_columns(df)
    df["ip"] = df[ip_col] if ip_col else "Unknown"
    df["mac"] = df[mac_col] if mac_col else "Unknown"

    # Cross-filter by day
    df = render_filters(df, title_prefix=title_prefix)

    # -----------------------------
    # Separate tables: Allowed vs Not Allowed
    # -----------------------------
    allowed_df = df[df["Status"] == "Allowed"]
    blocked_df = df[df["Status"] == "Not Allowed"]

    allowed_table = allowed_df.groupby(["domain_clean", "mac", "ip", "Status"]) \
        .agg(
            executions=("domain_clean", "count"),
            first_seen=("datetime", "min"),
            last_seen=("datetime", "max")
        ).reset_index()

    blocked_table = blocked_df.groupby(["domain_clean", "mac", "ip", "Status"]) \
        .agg(
            executions=("domain_clean", "count"),
            first_seen=("datetime", "min"),
            last_seen=("datetime", "max")
        ).reset_index()

    # Apply global MAC filter for charts
    df_combined = pd.concat([allowed_table, blocked_table], ignore_index=True)
    df_combined = apply_global_mac_filter(df_combined)

    # -----------------------------
    # Metrics on top
    # -----------------------------
    total = len(df_combined)
    allowed_count = (df_combined["Status"] == "Allowed").sum()
    not_allowed_count = (df_combined["Status"] == "Not Allowed").sum()
    allowed_pct = round((allowed_count / total) * 100, 2) if total else 0
    not_allowed_pct = round((not_allowed_count / total) * 100, 2) if total else 0
    total_raw_logs = len(df)  # New metric for all raw logs

    col_metrics = st.columns(5)
    col_metrics[0].metric("Total Requests", total)
    col_metrics[1].metric("Allowed Requests", allowed_count, f"{allowed_pct}%")
    col_metrics[2].metric("Not Allowed Requests", not_allowed_count, f"{not_allowed_pct}%")
    col_metrics[3].metric("Allowed %", f"{allowed_pct}%")
    col_metrics[4].metric("Total Raw Logs", total_raw_logs)

    # -----------------------------
    # Charts below metrics
    # -----------------------------
    chart_col1, chart_col2 = st.columns([3, 1])

    # Line chart
    with chart_col1:
        if not df.empty and "datetime" in df.columns and not df["datetime"].isna().all():
            # Group by hour and status
            df_line = df.groupby([pd.Grouper(key="datetime", freq="H"), "Status"]).size().reset_index(name="count")

            # Ensure both statuses exist for all time points
            all_status = ["Allowed", "Not Allowed"]
            min_time = df_line['datetime'].min()
            max_time = df_line['datetime'].max()
            all_times = pd.date_range(min_time, max_time, freq='H')
            full_index = pd.MultiIndex.from_product([all_times, all_status], names=['datetime', 'Status'])
            df_line = df_line.set_index(['datetime', 'Status']).reindex(full_index, fill_value=0).reset_index()

            # Plot line chart
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
        else:
            st.info("No timestamped data available to plot line chart.")

    # Pie chart
    with chart_col2:
        status_counts = df_combined["Status"].value_counts()
        for status in ["Allowed", "Not Allowed"]:
            if status not in status_counts:
                status_counts[status] = 0
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
        fig_pie.update_traces(textposition='inside', textinfo='label+percent', sort=False)
        st.plotly_chart(fig_pie, use_container_width=True)

    # -----------------------------
    # Tables side by side below charts
    # -----------------------------
    table_col1, table_col2 = st.columns(2)
    with table_col1:
        st.markdown(f"### Allowed Applications")
        st.dataframe(allowed_table, use_container_width=True)

        # Line + Pie charts for Allowed Applications
        if not allowed_df.empty:
            chart_line_col, chart_pie_col = st.columns([3, 1])

            # Line chart: allowed mac addresses over time
            with chart_line_col:
                df_allowed_line = allowed_df.groupby([pd.Grouper(key="datetime", freq="H"), "mac"]).size().reset_index(name="count")
                if not df_allowed_line.empty:
                    all_macs = df_allowed_line['mac'].unique()
                    all_times = pd.date_range(df_allowed_line['datetime'].min(), df_allowed_line['datetime'].max(), freq='H')
                    full_index = pd.MultiIndex.from_product([all_times, all_macs], names=['datetime', 'mac'])
                    df_allowed_line = df_allowed_line.set_index(['datetime', 'mac']).reindex(full_index, fill_value=0).reset_index()

                    fig_allowed_line = px.line(
                        df_allowed_line,
                        x='datetime',
                        y='count',
                        color='mac',
                        markers=True,
                        template='plotly_dark',
                        title="Allowed: MAC Activity Over Time"
                    )
                    fig_allowed_line.update_layout(yaxis_title="Requests", xaxis_title="Time", legend_title="MAC")
                    st.plotly_chart(fig_allowed_line, use_container_width=True)

            # Pie chart: allowed MAC distribution
            with chart_pie_col:
                df_allowed_pie = allowed_df['mac'].value_counts().reset_index()
                df_allowed_pie.columns = ['mac', 'count']
                fig_allowed_pie = px.pie(
                    df_allowed_pie,
                    names='mac',
                    values='count',
                    hole=0.4,
                    template='plotly_dark',
                    title="Allowed: MAC Distribution"
                )
                fig_allowed_pie.update_traces(textposition='inside', textinfo='label+percent', sort=False)
                st.plotly_chart(fig_allowed_pie, use_container_width=True)

    with table_col2:
        st.markdown(f"### Unauthorized Applications")
        st.dataframe(blocked_table, use_container_width=True)

        # Line + Pie charts for Not Allowed Applications
        if not blocked_df.empty:
            chart_line_col, chart_pie_col = st.columns([3, 1])

            # Line chart: blocked mac addresses over time
            with chart_line_col:
                df_blocked_line = blocked_df.groupby([pd.Grouper(key="datetime", freq="H"), "mac"]).size().reset_index(name="count")
                if not df_blocked_line.empty:
                    all_macs = df_blocked_line['mac'].unique()
                    all_times = pd.date_range(df_blocked_line['datetime'].min(), df_blocked_line['datetime'].max(), freq='H')
                    full_index = pd.MultiIndex.from_product([all_times, all_macs], names=['datetime', 'mac'])
                    df_blocked_line = df_blocked_line.set_index(['datetime', 'mac']).reindex(full_index, fill_value=0).reset_index()

                    fig_blocked_line = px.line(
                        df_blocked_line,
                        x='datetime',
                        y='count',
                        color='mac',
                        markers=True,
                        template='plotly_dark',
                        title="Unauthorized: MAC Activity Over Time"
                    )
                    fig_blocked_line.update_layout(yaxis_title="Requests", xaxis_title="Time", legend_title="MAC")
                    st.plotly_chart(fig_blocked_line, use_container_width=True)

            # Pie chart: blocked MAC distribution
            with chart_pie_col:
                df_blocked_pie = blocked_df['mac'].value_counts().reset_index()
                df_blocked_pie.columns = ['mac', 'count']
                fig_blocked_pie = px.pie(
                    df_blocked_pie,
                    names='mac',
                    values='count',
                    hole=0.4,
                    template='plotly_dark',
                    title="Unauthorized: MAC Distribution"
                )
                fig_blocked_pie.update_traces(textposition='inside', textinfo='label+percent', sort=False)
                st.plotly_chart(fig_blocked_pie, use_container_width=True)

    # -----------------------------
    # License compliance below tables
    # -----------------------------
    st.markdown("## License Compliance")
    license_rows = []
    for app, licenses in LICENSE_REGISTRY.items():
        usage = allowed_df[allowed_df["domain_clean"].str.endswith(app)]["mac"].nunique()
        license_rows.append({
            "Software": app,
            "Licenses Purchased": licenses,
            "Unique Devices Detected": usage,
            "Overused By": max(0, usage - licenses),
            "Status": "EXCEPTION" if usage > licenses else "OK"
        })
    license_df = pd.DataFrame(license_rows)
    st.dataframe(license_df, use_container_width=True)

    # -----------------------------
    # Raw log table at the bottom
    # -----------------------------
    st.markdown("### Raw Logs")
    st.dataframe(df, use_container_width=True)

# -----------------------------
# Main renderer
# -----------------------------
def render_shadow_apps(http_logs=None, ssl_logs=None, dns_logs=None):
    st.subheader("Shadow Apps Overview")
    approved = load_allowlist()

    tabs = []
    data_mapping = {}

    if http_logs is not None and "host" in http_logs.columns:
        tabs.append("HTTP")
        data_mapping["HTTP"] = (http_logs, "host", "HTTP Shadow Apps")
    if ssl_logs is not None and "server_name" in ssl_logs.columns:
        tabs.append("SSL")
        data_mapping["SSL"] = (ssl_logs, "server_name", "SSL Shadow Apps")
    if dns_logs is not None and "query" in dns_logs.columns:
        tabs.append("DNS")
        data_mapping["DNS"] = (dns_logs, "query", "DNS Shadow Apps")

    if not tabs:
        st.info("No Shadow App logs available to display.")
        return

    selected_tab = st.tabs(tabs)
    for idx, tab_name in enumerate(tabs):
        with selected_tab[idx]:
            df, domain_col, title_prefix = data_mapping[tab_name]
            df = df.copy()
            df[f"{domain_col}_lower"] = df[domain_col].astype(str).str.strip().str.lower()
            render_charts(
                df,
                ts_col="ts",
                domain_col=f"{domain_col}_lower",
                title_prefix=title_prefix,
                approved=approved
            )
