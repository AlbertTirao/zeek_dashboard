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
#--------------------------
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
    """Normalize URL/hostname to domain for allowlist checking."""
    if not url:
        return ""
    url = str(url).strip().lower()
    # Remove protocol
    if "://" in url:
        parsed = urlparse(url)
        url = parsed.hostname or ""
    # Remove www prefix
    if url.startswith("www."):
        url = url[4:]
    # Remove trailing dot
    url = url.rstrip(".")
    # Remove port
    if ":" in url:
        url = url.split(":")[0]
    return url

def is_allowed(domain: str, approved: list):
    """Return True if domain matches any allowlist entry. Handles subdomains."""
    domain = domain.lower().strip().rstrip(".")
    for a in approved:
        a = a.lower().strip().rstrip(".")
        if domain == a or domain.endswith("." + a):
            return True
    return False

# -----------------------------
# Check if domain is allowed
# -----------------------------
def is_allowed(domain: str, approved: list):
    """
    Returns True if domain matches any allowlist entry.
    Handles subdomains correctly.
    """
    domain = domain.lower().strip()
    return any(domain == a or domain.endswith("." + a) for a in approved)

# -----------------------------
# Render charts, metrics, and table
# -----------------------------
def render_charts(df: pd.DataFrame, ts_col: str, domain_col: str, title_prefix: str, approved: list):
    if df.empty:
        st.info(f"No {title_prefix} detected.")
        return

    # Normalize domains
    df["domain_clean"] = df[domain_col].apply(extract_domain)

    # Mark Allowed / Not Allowed
    df["Status"] = df["domain_clean"].apply(lambda x: "Allowed" if is_allowed(x, approved) else "Not Allowed")

    # Convert timestamp to datetime
    if ts_col in df.columns:
        df["datetime"] = pd.to_datetime(df[ts_col], unit="s", errors="coerce")
        df = df.dropna(subset=["datetime"])
    else:
        df["datetime"] = pd.NaT

    # -----------------------------
    # Metrics
    # -----------------------------
    total = len(df)
    allowed = (df["Status"] == "Allowed").sum()
    not_allowed = (df["Status"] == "Not Allowed").sum()
    allowed_pct = round((allowed / total) * 100, 2) if total else 0
    not_allowed_pct = round((not_allowed / total) * 100, 2) if total else 0

    col_metrics = st.columns(4)
    col_metrics[0].metric("Total Requests", total)
    col_metrics[1].metric("Allowed Requests", allowed, f"{allowed_pct}%")
    col_metrics[2].metric("Not Allowed Requests", not_allowed, f"{not_allowed_pct}%")
    col_metrics[3].metric("Allowed %", f"{allowed_pct}%")

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
    # Table
    # -----------------------------
    st.markdown("---")
    st.dataframe(df.head(MAX_ROWS_DISPLAY), use_container_width=True)
    st.markdown(f"Showing {min(MAX_ROWS_DISPLAY, len(df))} of {len(df)} rows")

# -----------------------------
# Main renderer with tabs
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
