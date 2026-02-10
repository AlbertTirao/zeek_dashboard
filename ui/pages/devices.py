# ui/pages/device.py
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import requests
import yaml
from datetime import datetime, timedelta

# --- IMPORTS FOR CLICKABLE TABLE ---
try:
    from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, JsCode
except ImportError:
    st.error("This solution requires the 'streamlit-aggrid' library.")
    st.info("Please run: pip install streamlit-aggrid")
    st.stop()

# =====================================================
# 1. Load Visual Metrics from Parquet
# =====================================================
@st.cache_data(show_spinner=False)
def load_visual_metrics_from_parquet(parquet_root: Path):
    known_hosts_all = []
    dhcp_all = []
    if not parquet_root.exists():
        return pd.DataFrame(), pd.DataFrame()

    for day_dir in sorted(p for p in parquet_root.iterdir() if p.is_dir()):
        kh = day_dir / "known_hosts.parquet"
        dh = day_dir / "dhcp.parquet"
        if kh.exists():
            known_hosts_all.append(pd.read_parquet(kh))
        if dh.exists():
            dhcp_all.append(pd.read_parquet(dh))

    known_hosts = pd.concat(known_hosts_all, ignore_index=True) if known_hosts_all else pd.DataFrame()
    dhcp = pd.concat(dhcp_all, ignore_index=True) if dhcp_all else pd.DataFrame()
    return known_hosts, dhcp

# =====================================================
# 2. Drill-Down Log Loader
# =====================================================
@st.cache_data(show_spinner=False)
def get_device_activity(parquet_root: Path, target_mac: str, target_ip: str, selected_date_str: str):
    activity_log = []
    log_types = [("dns", "DNS", "query"), ("http", "HTTP", "host"), ("ssl", "SSL", "server_name")]

    if selected_date_str and selected_date_str != "All Dates":
        day_dirs = [parquet_root / selected_date_str]
    else:
        day_dirs = sorted(p for p in parquet_root.iterdir() if p.is_dir())

    for day_dir in day_dirs:
        if not day_dir.exists():
            continue
        for file_prefix, service, detail_col in log_types:
            pq_file = day_dir / f"{file_prefix}.parquet"
            if not pq_file.exists():
                continue
            try:
                df = pd.read_parquet(pq_file)
                filtered = pd.DataFrame()
                if "mac" in df.columns:
                    filtered = df[df["mac"].str.lower() == target_mac.lower()]
                elif "id.orig_h" in df.columns:
                    filtered = df[df["id.orig_h"] == target_ip]
                if filtered.empty:
                    continue
                if detail_col not in filtered.columns:
                    filtered[detail_col] = "-"

                norm = pd.DataFrame()
                norm["ts"] = filtered["ts"]
                norm["Service"] = service
                norm["Destination"] = filtered[detail_col]
                if service == "HTTP" and "uri" in filtered.columns:
                    norm["Details"] = filtered["uri"]
                elif service == "DNS" and "qtype_name" in filtered.columns:
                    norm["Details"] = filtered["qtype_name"]
                elif service == "SSL" and "version" in filtered.columns:
                    norm["Details"] = filtered["version"]
                else:
                    norm["Details"] = "-"
                activity_log.append(norm)
            except Exception:
                continue

    if not activity_log:
        return pd.DataFrame()
    final_df = pd.concat(activity_log, ignore_index=True)
    final_df["ts"] = pd.to_numeric(final_df["ts"], errors="coerce")
    final_df["ts"] = pd.to_datetime(final_df["ts"], unit="s")
    return final_df.sort_values("ts", ascending=False)

# =====================================================
# 3. Helpers
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
# Load authorized MACs from YAML (CONNECTED TO AUTH MANAGER)
# =====================================================
def load_authorized_macs(file_path: Path) -> set:
    """
    Loads authorized MACs from YAML.
    Handles:
    1) List[str]
    2) Dict -> list under stem key or first list value
    3) List[dict] with {"mac": "..."}
    Also: if .txt passed but .yaml exists, auto-switch.
    """
    if file_path.suffix == ".txt":
        yaml_path = file_path.with_suffix(".yaml")
        if yaml_path.exists():
            file_path = yaml_path

    if not file_path.exists():
        st.warning(f"Authorized file not found ({file_path.name}) — all devices Unauthorized")
        return set()

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if data is None:
            return set()

        raw_list = []

        if isinstance(data, list):
            raw_list = data
        elif isinstance(data, dict):
            if file_path.stem in data and isinstance(data[file_path.stem], list):
                raw_list = data[file_path.stem]
            else:
                for val in data.values():
                    if isinstance(val, list):
                        raw_list = val
                        break

        final_macs = set()
        for item in raw_list:
            if isinstance(item, str):
                if item.strip():
                    final_macs.add(item.strip().lower())
            elif isinstance(item, dict):
                mac_val = item.get("mac")
                if mac_val and isinstance(mac_val, str) and mac_val.strip():
                    final_macs.add(mac_val.strip().lower())

        return final_macs

    except Exception as e:
        st.error(f"Error reading YAML: {e}")
        return set()

# =====================================================
# 4. POP-UP DIALOG FUNCTIONS
# =====================================================

@st.dialog("Device Details", width="large")
def forensic_popup(parquet_root, mac, ip, available_dates_list):
    st.markdown(f"<span style='color:#81c995; font-weight:bold;'>Mac address: {mac}</span>", unsafe_allow_html=True)

    col_btn, col_rest = st.columns([0.2, 0.8])
    with col_btn:
        if st.button("⬅ Back", key="btn_back_details"):
            st.session_state.active_dialog = "list"
            st.rerun()

    st.caption(f"Associated IP: {ip}")
    st.markdown("---")

    if not available_dates_list:
        st.warning("No dates available for analysis.")
        return

    c1, c2 = st.columns([1, 2])
    with c1:
        f_date = st.selectbox("Select Activity Date:", available_dates_list, key="popup_forensic_date")
    with c2:
        f_service = st.radio("Filter Service:", ["All Services", "DNS", "HTTP", "SSL"], horizontal=True, key="popup_forensic_service")

    activity_df = get_device_activity(parquet_root, mac, ip, f_date)

    if not activity_df.empty:
        if f_service != "All Services":
            activity_df = activity_df[activity_df["Service"] == f_service]

        st.markdown("#### Traffic Volume")
        vol = activity_df.set_index("ts").groupby(["Service"]).resample("1H").size().reset_index(name="Events")
        color_map = {"DNS": "#F63049", "HTTP": "#00F7FF", "SSL": "#F3AE4B"}

        fig = px.area(vol, x="ts", y="Events", color="Service", color_discrete_map=color_map, template="plotly_dark")
        fig.update_layout(
            height=300,
            margin=dict(l=10, r=10, t=30, b=10),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        )
        st.plotly_chart(fig, use_container_width=True)

        st.markdown("#### Top Destinations")
        top = activity_df["Destination"].value_counts().head(5).reset_index()
        top.columns = ["Destination", "Count"]
        top.index = top.index + 1
        st.dataframe(top, use_container_width=True)
    else:
        st.warning(f"No activity logs found for {mac} on {f_date}")

@st.dialog("Device List", width="large")
def device_list_popup(status_type, df, parquet_root, available_dates_list):
    col_d1, col_d2 = st.columns([1, 2])
    with col_d1:
        date_filter_mode = st.selectbox("Time Range:", ["Last 7 Days", "Specific Date", "All Time"], index=0, key="popup_list_mode")

    filtered_df = df[df["status"] == status_type].copy()

    if date_filter_mode == "Last 7 Days":
        seven_days_ago = datetime.now().date() - timedelta(days=7)
        if not filtered_df.empty:
            filtered_df = filtered_df[filtered_df["date"] >= seven_days_ago]

    elif date_filter_mode == "Specific Date":
        with col_d2:
            spec_date = st.selectbox("Choose Date:", available_dates_list, key="popup_list_spec_date")
        if spec_date:
            filtered_df = filtered_df[filtered_df["date"].astype(str) == spec_date]

    elif date_filter_mode == "All Time":
        pass

    if not filtered_df.empty:
        inventory = (
            filtered_df.sort_values("ts", ascending=False)
            .groupby("mac")
            .agg(
                ip=("host", "first"),
                host_name=("host_name", "first"),
                last_seen=("ts", "max"),
            )
            .reset_index()
        )

        inventory["vendor"] = inventory["mac"].apply(get_mac_vendor)
        inventory = inventory.sort_values("last_seen", ascending=False)
        inventory["last_seen_str"] = inventory["last_seen"].dt.strftime("%Y-%m-%d %H:%M:%S")

        inventory = inventory.reset_index(drop=True)
        inventory.insert(0, "#", inventory.index + 1)

        gb = GridOptionsBuilder.from_dataframe(inventory)
        gb.configure_selection(selection_mode="single", use_checkbox=False)

        gb.configure_column("#", header_name="#", width=50, pinned="left")
        gb.configure_column("mac", header_name="MAC Address")
        gb.configure_column("ip", header_name="IP Address")
        gb.configure_column("host_name", header_name="Host Name")
        gb.configure_column("vendor", header_name="Vendor")
        gb.configure_column("last_seen_str", header_name="Last Seen / Date")
        gb.configure_column("last_seen", hide=True)

        gridOptions = gb.build()

        grid_response = AgGrid(
            inventory,
            gridOptions=gridOptions,
            update_mode=GridUpdateMode.SELECTION_CHANGED,
            height=400,
            allow_unsafe_jscode=True,
            theme="streamlit",
        )

        selected = grid_response["selected_rows"]

        if selected is not None:
            if isinstance(selected, pd.DataFrame):
                selected = selected.to_dict("records")

            if len(selected) > 0:
                row = selected[0]
                st.session_state.selected_forensic_mac = row.get("mac")
                st.session_state.selected_forensic_ip = row.get("ip")
                st.session_state.active_dialog = "forensics"
                st.rerun()
    else:
        st.info(f"No {status_type.lower()} devices found for this criteria.")

# =====================================================
# 5. Main Render Function
# =====================================================
def render(logs_root: Path, authorized_mac_file: Path):
    st.set_page_config(page_title="Network Overview", layout="wide")

    if "active_dialog" not in st.session_state:
        st.session_state.active_dialog = None
    if "list_status_type" not in st.session_state:
        st.session_state.list_status_type = "Unauthorized"
    if "selected_forensic_mac" not in st.session_state:
        st.session_state.selected_forensic_mac = None

    st.markdown(
        """
    <style>
    [data-testid="stMetric"] > div { width: fit-content; margin-right: auto; }
    [data-testid="stMetricValue"] { display: grid !important; grid-template-columns: auto auto; align-items: baseline; column-gap: 15px; width: max-content; }
    [data-testid="stMetricDelta"] { white-space: nowrap !important; font-size: 16px !important; }
    div.stButton > button { width: 100%; }
    </style>
    """,
        unsafe_allow_html=True,
    )

    st.title("Device Overview")
    PARQUET_ROOT = Path("data/parquet")
    known_hosts, dhcp = load_visual_metrics_from_parquet(PARQUET_ROOT)

    authorized_macs = load_authorized_macs(authorized_mac_file)

    if known_hosts.empty:
        st.info("No device data available")
        return

    if "mac" in known_hosts.columns:
        known_hosts["mac"] = known_hosts["mac"].str.lower().str.strip()

    if not dhcp.empty:
        if "mac" in dhcp.columns:
            dhcp["mac"] = dhcp["mac"].str.lower().str.strip()
            dhcp_cols = [c for c in ["mac", "host_name", "domain"] if c in dhcp.columns]
            dhcp_norm = dhcp[dhcp_cols].drop_duplicates(subset=["mac"])
            merged = pd.merge(known_hosts, dhcp_norm, how="left", on="mac")
        else:
            dhcp_cols = [c for c in ["client_addr", "host_name", "domain"] if c in dhcp.columns]
            dhcp_norm = dhcp[dhcp_cols].drop_duplicates(subset=["client_addr"])
            merged = pd.merge(known_hosts, dhcp_norm, how="left", left_on="host", right_on="client_addr")
    else:
        merged = known_hosts.copy()
        merged["host_name"] = "-"
        merged["domain"] = None

    merged["host_name"] = merged.get("host_name", "-").fillna("-")
    merged["status"] = merged["mac"].apply(lambda m: "Authorized" if m in authorized_macs else "Unauthorized")

    if "ts" in merged.columns:
        merged["ts"] = pd.to_numeric(merged["ts"], errors="coerce")
        merged["ts"] = pd.to_datetime(merged["ts"], unit="s", errors="coerce")
        merged = merged.dropna(subset=["ts"])
        merged["date"] = merged["ts"].dt.date

    # -----------------------------
    # METRICS & TRENDS (same as your friend's UI)
    # -----------------------------
    total_u = merged["mac"].nunique()
    auth_u = merged[merged["status"] == "Authorized"]["mac"].nunique()
    unauth_u = merged[merged["status"] == "Unauthorized"]["mac"].nunique()
    risk = round((unauth_u / total_u * 100), 2) if total_u else 0

    if "metrics_history" not in st.session_state:
        st.session_state.metrics_history = {"total": total_u, "auth": auth_u, "unauth": unauth_u, "risk": risk}

    d_total = total_u - st.session_state.metrics_history["total"]
    d_auth = auth_u - st.session_state.metrics_history["auth"]
    d_unauth = unauth_u - st.session_state.metrics_history["unauth"]
    d_risk = round(risk - st.session_state.metrics_history["risk"], 2)

    def format_delta(val, is_percent=False):
        if val == 0:
            return None
        suffix = "%" if is_percent else ""
        if val > 0:
            return f"+{val}{suffix} (Increase)"
        return f"{val}{suffix} (Decrease)"

    m1, m2, m3, m4 = st.columns(4)

    with m1:
        st.metric("Active Devices", total_u, delta=format_delta(d_total), delta_color="normal")

    with m2:
        st.metric("Authorized", auth_u, delta=format_delta(d_auth), delta_color="normal")
        if st.button("View Authorized", key="btn_auth_pop"):
            st.session_state.list_status_type = "Authorized"
            st.session_state.active_dialog = "list"
            st.rerun()

    with m3:
        st.metric("Unauthorized", unauth_u, delta=format_delta(d_unauth), delta_color="inverse")
        if st.button("View Unauthorized", key="btn_unauth_pop"):
            st.session_state.list_status_type = "Unauthorized"
            st.session_state.active_dialog = "list"
            st.rerun()

    with m4:
        st.metric("Risk Ratio", f"{risk}%", delta=format_delta(d_risk, is_percent=True), delta_color="off")

    st.markdown("---")

    # Activity Chart
    st.subheader("Activity Overview")
    hourly = pd.DataFrame()
    if not merged.empty:
        hourly = merged.set_index("ts").groupby("status").resample("1H").size().reset_index(name="events")
    if not hourly.empty:
        fig = px.line(
            hourly,
            x="ts",
            y="events",
            color="status",
            template="plotly_dark",
            color_discrete_map={"Authorized": "#00F7FF", "Unauthorized": "#F63049"},
        )
        st.plotly_chart(fig, use_container_width=True)

    # ==========================================================
    # UNAUTHORIZED DEVICE RATIO
    # ==========================================================
    st.markdown("<h2 style='color:white; text-align:left;'>Unauthorized Device Ratio</h2>", unsafe_allow_html=True)

    warning_text, warning_color, warning_icon = "STATUS: SAFE", "#6CA651", "✅"
    if risk > 20:
        warning_text, warning_color, warning_icon = "STATUS: WARNING", "#F3AE4B", "⚠️"
    if risk > 50:
        warning_text, warning_color, warning_icon = "STATUS: HIGH RISK", "#D63447", "🛑"

    gauge_fig = go.Figure()
    gauge_fig.add_trace(
        go.Indicator(
            mode="gauge+number",
            value=risk,
            number={"suffix": "%", "font": {"size": 48}},
            gauge={
                "axis": {"range": [0, 100], "tickfont": {"size": 16}},
                "bar": {"color": "#30C1F6"},
                "steps": [
                    {"range": [0, 20], "color": "#6CA651"},
                    {"range": [20, 50], "color": "#F3AE4B"},
                    {"range": [50, 100], "color": "#D63447"},
                ],
                "threshold": {"line": {"color": "white", "width": 2}, "thickness": 0.75, "value": 50},
            },
        )
    )

    for label, color in [
        ("Current Level", "#30C1F6"),
        ("Safe (0-20%)", "#6CA651"),
        ("Warning (20-50%)", "#F3AE4B"),
        ("High Risk (50%+)", "#D63447"),
    ]:
        gauge_fig.add_trace(go.Scatter(x=[None], y=[None], mode="markers", marker=dict(size=10, color=color), name=label))

    gauge_fig.add_annotation(
        x=0.5,
        y=0.15,
        text=f"<b>{warning_icon} {warning_text}</b>",
        showarrow=False,
        font=dict(size=20, color=warning_color),
    )

    gauge_fig.update_layout(
        template="plotly_dark",
        height=450,
        margin=dict(l=50, r=50, t=80, b=50),
        legend=dict(orientation="v", yanchor="top", y=1.0, xanchor="right", x=1.0, font=dict(size=12)),
        xaxis={"visible": False},
        yaxis={"visible": False},
    )
    st.plotly_chart(gauge_fig, use_container_width=True)

    # =====================================================
    # 6. DIALOG MANAGER
    # =====================================================
    if st.session_state.active_dialog == "list":
        # Use available dates from merged
        raw_dates = sorted([str(d) for d in merged["date"].unique() if pd.notnull(d)], reverse=True)
        device_list_popup(st.session_state.list_status_type, merged, PARQUET_ROOT, raw_dates)

    elif st.session_state.active_dialog == "forensics":
        raw_dates = sorted([str(d) for d in merged["date"].unique() if pd.notnull(d)], reverse=True)
        forensic_popup(PARQUET_ROOT, st.session_state.selected_forensic_mac, st.session_state.selected_forensic_ip, raw_dates)
