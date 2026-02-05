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
def load_shadow_logs(parquet_root: Path, log_type: str):
    """Load all parquet files of a specific log type."""
    if not parquet_root.exists():
        return pd.DataFrame()
        
    dfs = []
    for date_dir in sorted(parquet_root.iterdir()):
        if date_dir.is_dir():
            file_path = date_dir / f"{log_type}.parquet"
            if file_path.exists():
                dfs.append(pd.read_parquet(file_path))
                
    if not dfs:
        return pd.DataFrame()
        
    return pd.concat(dfs, ignore_index=True)

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
    
    # Select relevant cols
    cols = {domain_col: "app_identifier", "ts": "ts"}
    
    # Map IP/MAC columns if they exist
    if "id.orig_h" in df.columns: cols["id.orig_h"] = "ip"
    elif "orig_h" in df.columns: cols["orig_h"] = "ip"
    
    if "mac" in df.columns: cols["mac"] = "mac"
    elif "orig_mac" in df.columns: cols["orig_mac"] = "mac"
    elif "id.orig_mac" in df.columns: cols["id.orig_mac"] = "mac"
    
    df = df.rename(columns=cols)
    
    # Ensure required columns exist
    if "ip" not in df.columns: df["ip"] = "Unknown"
    if "mac" not in df.columns: df["mac"] = "Unknown"
    
    df["source_log"] = log_type.upper()
    return df[["ts", "app_identifier", "ip", "mac", "source_log"]]

# -----------------------------
# Render Main Page
# -----------------------------
def render_shadow_apps(parquet_root: Path):
    st.subheader("Shadow Apps Overview (Unified)")
    approved = load_allowlist()

    # 1. Load ALL 5 Log Types
    logs = [
        ("http", "host"),
        ("ssl", "server_name"),
        ("dns", "query"),
        ("files", "filename"),  # Using filename as identifier
        ("conn", "service")     # Using service as identifier
    ]
    
    combined_frames = []
    
    for log_type, domain_col in logs:
        raw_df = load_shadow_logs(parquet_root, log_type)
        norm_df = normalize_log_df(raw_df, log_type, domain_col)
        if not norm_df.empty:
            combined_frames.append(norm_df)

    if not combined_frames:
        st.info("No Shadow App logs available (HTTP, SSL, DNS, Files, or Conn).")
        return

    # 2. Combine into One DataFrame
    df = pd.concat(combined_frames, ignore_index=True)
    
    # 3. Process Data
    # Convert TS
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    df["datetime"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")
    df = df.dropna(subset=["datetime"])
    
    # Extract Domains & Check Status
    df["domain_clean"] = df["app_identifier"].apply(extract_domain)
    # Filter out empty domains (often happens in conn/files logs)
    df = df[df["domain_clean"] != ""]
    
    df["Status"] = df["domain_clean"].apply(lambda x: "Allowed" if is_allowed(x, approved) else "Not Allowed")

    # 4. Metrics
    total = len(df)
    unauth_df = df[df["Status"] == "Not Allowed"]
    auth_df = df[df["Status"] == "Allowed"]
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Events", total)
    col2.metric("Authorized Events", len(auth_df))
    col3.metric("Unauthorized Events", len(unauth_df), delta_color="inverse")
    
    st.divider()

    # 5. Charts (Unified)
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
        fig_pie = px.pie(df, names="source_log", template="plotly_dark", hole=0.4)
        st.plotly_chart(fig_pie, use_container_width=True)

    # 6. Tables
    t1, t2 = st.tabs(["✅ Allowed Applications", "🚫 Unauthorized Applications"])
    
    with t1:
        st.markdown("### Authorized Apps")
        if not auth_df.empty:
            allowed_summary = auth_df.groupby(["domain_clean", "source_log"]).size().reset_index(name="Count")
            st.dataframe(allowed_summary, use_container_width=True)
        else:
            st.info("No authorized apps found.")

    with t2:
        st.markdown("### Unauthorized Apps Summary")
        if not unauth_df.empty:
            # Summary Table
            unauth_summary = unauth_df.groupby(["domain_clean", "source_log"]).size().reset_index(name="Count")
            st.dataframe(unauth_summary, use_container_width=True)
            
            st.divider()
            
            # DETAILED TABLE (Requested)
            st.markdown("### 🚨 Unauthorized Details (Who installed/ran it?)")
            st.write("List of devices (IP/MAC) that accessed unauthorized applications.")
            
            detail_table = unauth_df[["datetime", "mac", "ip", "domain_clean", "source_log"]].sort_values("datetime", ascending=False)
            
            st.dataframe(
                detail_table,
                column_config={
                    "datetime": st.column_config.DatetimeColumn("Time", format="YYYY-MM-DD HH:mm:ss"),
                    "mac": "MAC Address",
                    "ip": "IP Address",
                    "domain_clean": "Application / Domain",
                    "source_log": "Source"
                },
                use_container_width=True
            )
        else:
            st.success("No unauthorized applications detected.")