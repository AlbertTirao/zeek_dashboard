import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path

# =====================================================
# Zeek log loader
# =====================================================
def load_zeek_log(path: Path) -> pd.DataFrame:
    headers, rows = None, []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    if line.startswith("#fields"):
                        headers = line.split("\t")[1:]
                    continue
                if headers:
                    parts = line.split("\t")
                    row = {col: parts[i] if i < len(parts) else None for i, col in enumerate(headers)}
                    rows.append(row)
        if not headers or not rows:
            return pd.DataFrame()
        df = pd.DataFrame(rows)
        if "ts" in df.columns:
            df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
            df["ts"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")
        if "mac" in df.columns:
            df["mac"] = df["mac"].astype(str).str.lower().str.strip()
        if "host" in df.columns:
            df["host"] = df["host"].astype(str).str.strip()
        return df
    except Exception as e:
        st.warning(f"Failed to load {path.name}: {e}")
        return pd.DataFrame()


# =====================================================
# Load all daily Zeek logs
# =====================================================
def load_all_daily_logs(logs_root: Path):
    daily_folders = sorted([f for f in logs_root.iterdir() if f.is_dir() and not f.name.endswith("-CSV")])
    all_known_hosts, all_dhcp = pd.DataFrame(), pd.DataFrame()
    for folder in daily_folders:
        kh_log, dhcp_log = folder / "known_hosts.log", folder / "dhcp.log"
        if kh_log.exists():
            df = load_zeek_log(kh_log)
            if not df.empty:
                all_known_hosts = pd.concat([all_known_hosts, df], ignore_index=True)
        if dhcp_log.exists():
            df = load_zeek_log(dhcp_log)
            if not df.empty:
                all_dhcp = pd.concat([all_dhcp, df], ignore_index=True)
    return all_known_hosts, all_dhcp


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
# Dashboard without card, compact text
# =====================================================
def render(logs_root: Path, authorized_mac_file: Path):
    st.set_page_config(page_title="Network Overview", layout="wide")
    st.title("VIsualization Device")

    known_hosts, dhcp = load_all_daily_logs(logs_root)
    authorized_macs = load_authorized_macs(authorized_mac_file)
    if known_hosts.empty:
        st.info("No device data available")
        return

    # Merge DHCP
    if not dhcp.empty:
        dhcp_cols = [c for c in ["client_addr","host_name","domain"] if c in dhcp.columns]
        dhcp_norm = dhcp[dhcp_cols]
        merged = pd.merge(known_hosts, dhcp_norm, how="left", left_on="host", right_on="client_addr")
    else:
        merged = known_hosts.copy()
        merged["host_name"], merged["domain"] = "-", None

    merged["host_name"] = merged.get("host_name","-").fillna("-")
    merged["mac"] = merged["mac"].str.lower().str.strip()
    merged["ts"] = pd.to_datetime(merged["ts"], errors="coerce")
    merged["status"] = merged["mac"].apply(lambda m: "Authorized" if m in authorized_macs else "Unauthorized")

    # Metrics
    total = merged["mac"].nunique()
    auth = merged[merged["status"]=="Authorized"]["mac"].nunique()
    unauth = merged[merged["status"]=="Unauthorized"]["mac"].nunique()
    risk_ratio = round((unauth/total*100),2) if total else 0

    # ---------- Metrics Cards ----------
    m1, m2, m3, m4 = st.columns(4)
    card_style = (
        "padding:10px; "
        "background-color:rgba(30,30,30,0.25); "
        "border-radius:8px; "
        "text-align:center; "
        "font-size:12px; "
        "box-shadow: 1px 1px 5px rgba(0,0,0,0.3);"
    )
    m1.markdown(f"<div style='{card_style}'><h4 style='margin:2px'>Active Devices</h4><h3 style='margin:2px'>{total}</h3></div>", unsafe_allow_html=True)
    m2.markdown(f"<div style='{card_style}'><h4 style='margin:2px'>Authorized</h4><h3 style='margin:2px'>{auth}</h3></div>", unsafe_allow_html=True)
    m3.markdown(f"<div style='{card_style}'><h4 style='margin:2px'>Unauthorized</h4><h3 style='margin:2px'>{unauth}</h3></div>", unsafe_allow_html=True)
    m4.markdown(f"<div style='{card_style}'><h4 style='margin:2px'>Risk Ratio</h4><h3 style='margin:2px'>{risk_ratio}%</h3></div>", unsafe_allow_html=True)

    st.markdown("---")

    # ---------- Activity Overview ----------
    st.subheader("Activity Overview")
    left_col, right_col = st.columns([3,1], gap="large")

    with left_col:
        hourly = merged.set_index("ts").groupby("status").resample("1H").size().reset_index(name="events")
        if not hourly.empty:
            line_fig = px.line(
                hourly, x="ts", y="events", color="status",
                color_discrete_map={"Authorized":"#00F7FF","Unauthorized":"#F63049"},
                template="plotly_dark"
            )
            line_fig.update_layout(
                xaxis_title=None, yaxis_title="Events", legend_title=None,
                margin=dict(l=10,r=10,t=10,b=10),
                height=480,
                xaxis={"tickfont":{"size":10}},
                yaxis={"tickfont":{"size":10}},
                legend={"font":{"size":10}}
            )
            st.plotly_chart(line_fig, use_container_width=True)

    with right_col:
        card_height = 480

        st.markdown("<h6 style='color:white; margin-bottom:3px;'>Unauthorized Device Ratio</h6>", unsafe_allow_html=True)

        gauge_fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk_ratio,
            number={"suffix":"%", "font":{"size":16}},
            gauge={
                "axis":{"range":[0,100], "tickfont":{"size":10}},
                "bar":{"color":"#30C1F6"},
                "steps":[
                    {"range":[0,20],"color":"#6CA651"},
                    {"range":[20,50],"color":"#F3AE4B"},
                    {"range":[50,100],"color":"#D63447"}
                ],
                "threshold":{"line":{"color":"white","width":2},"thickness":0.75,"value":50}
            }
        ))
        gauge_fig.update_layout(
            template="plotly_dark",
            height=int(card_height*0.35),
            margin=dict(l=10,r=10,t=5,b=5)
        )
        st.plotly_chart(gauge_fig, use_container_width=True)

        st.markdown("<h6 style='color:white; margin-top:5px; margin-bottom:3px;'>Device Count</h6>", unsafe_allow_html=True)

        merged["date"] = merged["ts"].dt.date
        daily_count = merged.drop_duplicates(subset=["mac","date"]).groupby(["date","status"]).size().reset_index(name="devices")
        bar_fig = px.bar(
            daily_count,
            x="date",
            y="devices",
            color="status",
            barmode="stack",
            color_discrete_map={"Authorized":"#00F7FF","Unauthorized":"#F63049"},
            template="plotly_dark",
            labels={"devices":"Devices","date":"Date"}
        )
        bar_fig.update_layout(
            height=int(card_height*0.65),
            margin=dict(l=10,r=10,t=5,b=5),
            xaxis={"tickfont":{"size":10}},
            yaxis={"tickfont":{"size":10}},
            legend={"font":{"size":10}}
        )
        st.plotly_chart(bar_fig, use_container_width=True)
