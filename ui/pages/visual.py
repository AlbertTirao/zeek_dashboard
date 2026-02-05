import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import requests

# =====================================================
# Load Visual Metrics from Parquet
# =====================================================
@st.cache_data(show_spinner=False)
def load_visual_metrics_from_parquet(parquet_root: Path):
    """
    Load ONLY the data needed by Visual metrics
    from Parquet instead of raw Zeek logs.
    """
    known_hosts_all = []
    dhcp_all = []

    if not parquet_root.exists():
        return pd.DataFrame(), pd.DataFrame()

    # Expect structure: data/parquet/YYYY-MM-DD/*.parquet
    for day_dir in sorted(p for p in parquet_root.iterdir() if p.is_dir()):
        kh = day_dir / "known_hosts.parquet"
        dh = day_dir / "dhcp.parquet"

        if kh.exists():
            known_hosts_all.append(pd.read_parquet(kh))

        if dh.exists():
            dhcp_all.append(pd.read_parquet(dh))

    known_hosts = (
        pd.concat(known_hosts_all, ignore_index=True)
        if known_hosts_all else pd.DataFrame()
    )

    dhcp = (
        pd.concat(dhcp_all, ignore_index=True)
        if dhcp_all else pd.DataFrame()
    )

    return known_hosts, dhcp

# =====================================================
# MAC vendor lookup
# =====================================================
@st.cache_data(show_spinner=False)
def get_mac_vendor(mac: str) -> str:
    if not mac or mac == "unknown":
        return "Unknown"
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text if r.status_code == 200 else "Unknown"
    except Exception:
        return "Unknown"

# =====================================================
# Zeek log loader
# =====================================================
# def load_zeek_log(path: Path) -> pd.DataFrame:
#     headers, rows = None, []
#     try:
#         with open(path, "r", encoding="utf-8") as f:
#             for line in f:
#                 line = line.strip()
#                 if not line:
#                     continue
#                 if line.startswith("#"):
#                     if line.startswith("#fields"):
#                         headers = line.split("\t")[1:]
#                     continue
#                 if headers:
#                     parts = line.split("\t")
#                     row = {col: parts[i] if i < len(parts) else None for i, col in enumerate(headers)}
#                     rows.append(row)
#         if not headers or not rows:
#             return pd.DataFrame()
#         df = pd.DataFrame(rows)
#         if "ts" in df.columns:
#             df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
#             df["ts"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")
#         if "mac" in df.columns:
#             df["mac"] = df["mac"].astype(str).str.lower().str.strip()
#         if "host" in df.columns:
#             df["host"] = df["host"].astype(str).str.strip()
#         return df
#     except Exception as e:
#         st.warning(f"Failed to load {path.name}: {e}")
#         return pd.DataFrame()

# =====================================================
# Load authorized MACs
# =====================================================
def load_authorized_macs(file_path: Path) -> set:
    if not file_path.exists():
        st.warning("authorized_macs.txt not found — all devices Unauthorized")
        return set()
    with open(file_path, "r") as f:
        return {line.strip().lower() for line in f if line.strip()}

# =====================================================
# Main Render Function
# =====================================================
def render(logs_root: Path, authorized_mac_file: Path):
    st.set_page_config(page_title="Network Overview", layout="wide")
    st.title("Device Overview")

    PARQUET_ROOT = Path("data/parquet")

    known_hosts, dhcp = load_visual_metrics_from_parquet(PARQUET_ROOT)
    authorized_macs = load_authorized_macs(authorized_mac_file)
    
    if known_hosts.empty:
        st.info("No device data available")
        return

    # Merge DHCP Data
    if not dhcp.empty:
        dhcp_cols = [c for c in ["client_addr","host_name","domain"] if c in dhcp.columns]
        dhcp_norm = dhcp[dhcp_cols].drop_duplicates(subset=["client_addr"])
        merged = pd.merge(known_hosts, dhcp_norm, how="left", left_on="host", right_on="client_addr")
    else:
        merged = known_hosts.copy()
        merged["host_name"], merged["domain"] = "-", None

    merged["host_name"] = merged.get("host_name","-").fillna("-")
    merged["mac"] = merged["mac"].str.lower().str.strip()
    merged["status"] = merged["mac"].apply(lambda m: "Authorized" if m in authorized_macs else "Unauthorized")

    # ---------------------------------------------------------
    # ROBUST FIX: Force 'ts' to datetime
    # ---------------------------------------------------------
    if "ts" in merged.columns and not merged.empty:
        # 1. Force convert to numeric first (handles strings that look like numbers)
        #    'coerce' turns non-parseable data into NaN
        merged["ts"] = pd.to_numeric(merged["ts"], errors='coerce')
        
        # 2. Convert numeric to datetime (assuming Unix timestamp in seconds)
        merged["ts"] = pd.to_datetime(merged["ts"], unit="s", errors='coerce')

        # 3. Drop rows where timestamp conversion failed (NaN/NaT)
        merged = merged.dropna(subset=["ts"])

    # Metrics
    total_unique = merged["mac"].nunique()
    auth_unique = merged[merged["status"]=="Authorized"]["mac"].nunique()
    unauth_unique = merged[merged["status"]=="Unauthorized"]["mac"].nunique()
    risk_ratio = round((unauth_unique/total_unique*100),2) if total_unique else 0

    # ---------- Metrics Cards ----------
    m1, m2, m3, m4 = st.columns(4)
    m1.markdown(f"<div><h4 style='margin:2px'>Active Devices</h4><h3 style='margin:2px'>{total_unique}</h3></div>", unsafe_allow_html=True)
    m2.markdown(f"<div><h4 style='margin:2px'>Authorized</h4><h3 style='margin:2px'>{auth_unique}</h3></div>", unsafe_allow_html=True)
    m3.markdown(f"<div><h4 style='margin:2px'>Unauthorized</h4><h3 style='margin:2px'>{unauth_unique}</h3></div>", unsafe_allow_html=True)
    m4.markdown(f"<div><h4 style='margin:2px'>Risk Ratio</h4><h3 style='margin:2px'>{risk_ratio}%</h3></div>", unsafe_allow_html=True)

    st.markdown("---")

    # ---------- Activity Overview ----------
    st.subheader("Activity Overview")
    
    hourly = pd.DataFrame()
    # Now that 'ts' is guaranteed to be datetime, set_index will work for resampling
    if not merged.empty and "ts" in merged.columns:
        try:
            hourly = merged.set_index("ts").groupby("status").resample("1H").size().reset_index(name="events")
        except TypeError as e:
            st.error(f"Error resampling data (Check timestamp format): {e}")

    if not hourly.empty:
        line_fig = px.line(
            hourly, x="ts", y="events", color="status",
            color_discrete_map={"Authorized":"#00F7FF","Unauthorized":"#F63049"},
            template="plotly_dark"
        )
        line_fig.update_layout(
            xaxis_title=None, yaxis_title="Events", legend_title=None,
            margin=dict(l=20, r=20, t=40, b=20), height=480,
            xaxis={"tickfont":{"size":14}}, yaxis={"tickfont":{"size":14}}, legend={"font":{"size":14}}     
        )
        st.plotly_chart(line_fig, use_container_width=True)

    # ---------- Unauthorized Device Ratio Gauge ----------
    st.markdown("<h2 style='color:white; text-align:left;'>Unauthorized Device Ratio</h2>", unsafe_allow_html=True)
    
    warning_text, warning_color, warning_icon = "STATUS: SAFE", "#6CA651", "✅"
    if risk_ratio > 20: warning_text, warning_color, warning_icon = "STATUS: WARNING", "#F3AE4B", "⚠️"
    if risk_ratio > 50: warning_text, warning_color, warning_icon = "STATUS: HIGH RISK", "#D63447", "🛑"

    gauge_fig = go.Figure()
    gauge_fig.add_trace(go.Indicator(
        mode="gauge+number", value=risk_ratio, number={"suffix":"%", "font":{"size":48}}, 
        gauge={
            "axis":{"range":[0,100], "tickfont":{"size":16}}, "bar":{"color":"#30C1F6"},
            "steps":[{"range":[0,20],"color":"#6CA651"},{"range":[20,50],"color":"#F3AE4B"},{"range":[50,100],"color":"#D63447"}],
            "threshold":{"line":{"color":"white","width":2},"thickness":0.75,"value":50}
        }
    ))
    # Dummy traces for legend
    for label, color in [('Current Level','#30C1F6'), ('Safe (0-20%)','#6CA651'), ('Warning (20-50%)','#F3AE4B'), ('High Risk (50%+)','#D63447')]:
        gauge_fig.add_trace(go.Scatter(x=[None], y=[None], mode='markers', marker=dict(size=10, color=color), name=label))

    gauge_fig.add_annotation(x=0.5, y=0.15, text=f"<b>{warning_icon} {warning_text}</b>", showarrow=False, font=dict(size=20, color=warning_color))
    gauge_fig.update_layout(
        template="plotly_dark", height=450, margin=dict(l=50, r=50, t=80, b=50),
        legend=dict(orientation="v", yanchor="top", y=1.0, xanchor="right", x=1.0, font=dict(size=12)),
        xaxis={'visible': False}, yaxis={'visible': False}
    )
    st.plotly_chart(gauge_fig, use_container_width=True)

    # ---------- Device Count Bar Chart ----------
    st.markdown("<h2 style='color:white; text-align:left;'>Device Count</h2>", unsafe_allow_html=True)
    
    if "ts" in merged.columns and not merged.empty:
        merged["date"] = merged["ts"].dt.date
        daily_count = merged.drop_duplicates(subset=["mac","date"]).groupby(["date","status"]).size().reset_index(name="devices")
        bar_fig = px.bar(
            daily_count, x="date", y="devices", color="status", barmode="stack",
            color_discrete_map={"Authorized":"#00F7FF","Unauthorized":"#F63049"},
            template="plotly_dark", labels={"devices":"Devices","date":"Date"}
        )
        bar_fig.update_layout(height=500, margin=dict(l=20, r=20, t=50, b=100), xaxis={"tickfont":{"size":14}}, yaxis={"tickfont":{"size":14}}, legend={"font":{"size":14}})
        st.plotly_chart(bar_fig, use_container_width=True)

    # =====================================================
    # DEVICE INVENTORY TABLE (BOTTOM PART)
    # =====================================================
    st.markdown("---")
    st.title("Device Inventory")

    # 1. Prepare Date Options
    available_dates = []
    if "date" in merged.columns:
        available_dates = sorted([d for d in merged["date"].unique() if pd.notnull(d)], reverse=True)
    date_options = ["All Dates"] + [str(d) for d in available_dates]

    # 2. Main Filter Row
    master_col1, master_col2 = st.columns([1, 3], gap="medium", vertical_alignment="bottom")

    with master_col1:
        selected_date_str = st.selectbox(
            "Select Date", 
            options=date_options, 
            index=1 if len(date_options) > 1 else 0
        )

    # 3. Apply Date Filter
    if selected_date_str == "All Dates":
        table_df = merged.copy()
    else:
        table_df = merged[merged["date"].astype(str) == selected_date_str]

    with master_col2:
        # 4. Search Form
        with st.form(key="search_form", border=False):
            s_input_col, s_btn_col = st.columns([5, 1], gap="small", vertical_alignment="bottom")
            
            with s_input_col:
                search_term = st.text_input(
                    "Search", 
                    placeholder="🔍 Search MAC / IP / Host / Domain...", 
                    label_visibility="visible"
                )
            with s_btn_col:
                submit_button = st.form_submit_button("Search", use_container_width=True)

    # 5. Data Processing & Table Display
    if not table_df.empty:
        inventory = (
            table_df.groupby("mac")
            .agg(
                ip=("host", "last"),
                host_name=("host_name", "last"),
                domain=("domain", "last"),
                first_seen=("ts", "min"),
                last_seen=("ts", "max"),
                status=("status", "first")
            )
            .reset_index()
        )
        
        inventory["vendor"] = inventory["mac"].apply(get_mac_vendor)

        if search_term:
            inventory = inventory[
                inventory.astype(str)
                .apply(lambda c: c.str.contains(search_term, case=False, na=False))
                .any(axis=1)
            ]

        st.dataframe(
            inventory.sort_values("last_seen", ascending=False),
            column_config={
                "mac": "MAC Address",
                "ip": "IP Address",
                "host_name": "Host Name",
                "domain": "Domain",
                "vendor": "Vendor",
                "first_seen": st.column_config.DatetimeColumn("First Seen", format="YYYY-MM-DD HH:mm:ss"),
                "last_seen": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD HH:mm:ss"),
                "status": "Access Status",
            },
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No devices for the selected date")