# ui/pages/device.py
import json
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st
import yaml

# --- IMPORTS FOR CLICKABLE TABLE ---
try:
    from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode
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

    target_mac_norm = (target_mac or "").strip().lower()
    target_ip_norm = (target_ip or "").strip()

    if selected_date_str and selected_date_str != "All Dates":
        day_dirs = [parquet_root / selected_date_str]
    else:
        day_dirs = sorted(p for p in parquet_root.iterdir() if p.is_dir())

    def _normalize_mac_series(s: pd.Series) -> pd.Series:
        # handles bytes(6) and strings
        def norm_one(x):
            if x is None:
                return ""
            if isinstance(x, (bytes, bytearray)) and len(x) == 6:
                hx = bytes(x).hex()
                return ":".join(hx[i:i+2] for i in range(0, 12, 2))
            return str(x).strip().lower()
        return s.map(norm_one)

    def _coerce_ts(series: pd.Series) -> pd.Series:
        # 1) already datetime
        if pd.api.types.is_datetime64_any_dtype(series):
            return series

        # 2) try parse strings directly
        if pd.api.types.is_object_dtype(series):
            parsed = pd.to_datetime(series, errors="coerce", utc=False)
            if parsed.notna().any():
                return parsed

        # 3) numeric: determine unit by magnitude (ns/us/ms/s)
        num = pd.to_numeric(series, errors="coerce")
        if not num.notna().any():
            return pd.to_datetime(series, errors="coerce")

        m = float(num.dropna().abs().max())
        # Zeek seconds ~ 1.7e9, ms ~ 1.7e12, us ~ 1.7e15, ns ~ 1.7e18
        if m > 1e17:
            unit = "ns"
        elif m > 1e14:
            unit = "us"
        elif m > 1e11:
            unit = "ms"
        else:
            unit = "s"
        return pd.to_datetime(num, unit=unit, errors="coerce")

    for day_dir in day_dirs:
        if not day_dir.exists():
            continue

        for file_prefix, service, detail_col in log_types:
            pq_file = day_dir / f"{file_prefix}.parquet"
            if not pq_file.exists():
                continue

            try:
                df = pd.read_parquet(pq_file)
                if df.empty or "ts" not in df.columns:
                    continue

                filtered = pd.DataFrame()

                # Prefer MAC match when present
                if "mac" in df.columns and target_mac_norm:
                    mac_norm = _normalize_mac_series(df["mac"])
                    filtered = df[mac_norm == target_mac_norm]

                # Else fallback to IP match if possible
                elif target_ip_norm:
                    if "id.orig_h" in df.columns:
                        filtered = df[df["id.orig_h"].astype(str) == target_ip_norm]
                    elif "host" in df.columns:
                        filtered = df[df["host"].astype(str) == target_ip_norm]

                if filtered.empty:
                    continue

                if detail_col not in filtered.columns:
                    filtered = filtered.copy()
                    filtered[detail_col] = "-"

                norm = pd.DataFrame()
                norm["ts"] = filtered["ts"]
                norm["Service"] = service
                norm["Destination"] = filtered[detail_col].astype(str)

                if service == "HTTP" and "uri" in filtered.columns:
                    norm["Details"] = filtered["uri"].astype(str)
                elif service == "DNS" and "qtype_name" in filtered.columns:
                    norm["Details"] = filtered["qtype_name"].astype(str)
                elif service == "SSL" and "version" in filtered.columns:
                    norm["Details"] = filtered["version"].astype(str)
                else:
                    norm["Details"] = "-"

                activity_log.append(norm)

            except Exception:
                continue

    if not activity_log:
        return pd.DataFrame()

    final_df = pd.concat(activity_log, ignore_index=True)

    # SMART timestamp conversion (doesn't destroy datetime ts)
    final_df["ts"] = _coerce_ts(final_df["ts"])
    final_df = final_df.dropna(subset=["ts"])

    return final_df.sort_values("ts", ascending=False)


# =====================================================
# 3. Helpers
# =====================================================
@st.cache_data(show_spinner=False)
def get_mac_vendor(mac: str) -> str:
    """
    Kept for compatibility (other pages may import it),
    but the devices table no longer shows vendor.
    """
    if not mac or mac == "unknown":
        return "Unknown"
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text if r.status_code == 200 else "Unknown"
    except Exception:
        return "Unknown"


def load_authorized_macs(file_path: Path) -> set:
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
    except Exception as e:
        st.error(f"Error reading YAML: {e}")
        return set()

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
            m = item.strip().lower()
            if m:
                final_macs.add(m)
        elif isinstance(item, dict):
            m = str(item.get("mac", "")).strip().lower()
            if m:
                final_macs.add(m)

    return final_macs


def _extract_list_from_yaml(data, stem_key: str):
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if stem_key in data and isinstance(data[stem_key], list):
            return data[stem_key]
        for v in data.values():
            if isinstance(v, list):
                return v
    return []


def load_banned_macs(ban_file: Path) -> set:
    if not ban_file.exists():
        return set()
    try:
        data = yaml.safe_load(ban_file.read_text(encoding="utf-8"))
    except Exception:
        return set()

    raw_list = _extract_list_from_yaml(data, ban_file.stem)

    banned = set()
    for it in raw_list:
        if isinstance(it, str):
            m = it.strip().lower()
            if m:
                banned.add(m)
        elif isinstance(it, dict):
            m = str(it.get("mac", "")).strip().lower()
            if m:
                banned.add(m)
    return banned


def save_banned_macs(ban_file: Path, banned_set: set) -> None:
    ban_file.parent.mkdir(parents=True, exist_ok=True)
    payload = {ban_file.stem: sorted(list(banned_set))}
    ban_file.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _metrics_store_file(authorized_mac_file: Path) -> Path:
    return authorized_mac_file.with_name("device_metrics_store.json")


def load_metrics_store(authorized_mac_file: Path) -> dict:
    fp = _metrics_store_file(authorized_mac_file)
    if not fp.exists():
        return {}
    try:
        return json.loads(fp.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_metrics_store(authorized_mac_file: Path, store: dict) -> None:
    fp = _metrics_store_file(authorized_mac_file)
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(json.dumps(store, indent=2), encoding="utf-8")


# =====================================================
# Dialog header hide + custom topbar
# =====================================================
def hide_dialog_header():
    st.markdown(
        """
        <style>
        div[role="dialog"] header,
        div[data-testid="stDialog"] header {
            display: none !important;
            visibility: hidden !important;
            height: 0 !important;
        }
        div[role="dialog"] button[aria-label="Close"],
        div[role="dialog"] button[title="Close"],
        div[data-testid="stDialog"] button[aria-label="Close"],
        div[data-testid="stDialog"] button[title="Close"] {
            display: none !important;
            visibility: hidden !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _close_dialog():
    st.session_state.active_dialog = None
    st.session_state.selected_forensic_mac = None
    st.session_state.selected_forensic_ip = None
    st.rerun()


# =====================================================
# Forensic popup: add Last 7 Days + Specific Date + All Time
# =====================================================
@st.dialog(" ", width="large", dismissible=False)
def forensic_popup(parquet_root, mac, ip, available_dates_list):
    hide_dialog_header()

    col_left, col_right = st.columns([0.9, 0.0325], vertical_alignment="center")
    with col_left:
        if st.button("Back", key="dlg_back_forensics"):
            st.session_state.active_dialog = "list"
            st.rerun()
    with col_right:
        if st.button("X", key="dlg_close_forensics"):
            _close_dialog()

    st.markdown(
        f"<span style='color:#81c995; font-weight:bold;'>Mac address: {mac}</span>",
        unsafe_allow_html=True,
    )
    st.caption(f"Associated IP: {ip}")
    st.markdown("---")

    if not available_dates_list:
        st.warning("No dates available for analysis.")
        return

    # --- ROW 1: Time Range (LEFT) + Service Filter (RIGHT) ---
    c1, c2 = st.columns([1.2, 2.8], vertical_alignment="center")

    with c1:
        forensic_mode = st.selectbox(
            "Time Range:",
            ["Last 7 Days", "Specific Date", "All Time"],
            index=0,
            key="popup_forensic_mode",
        )

    with c2:
        f_service = st.radio(
            "Filter Service:",
            ["All Services", "DNS", "HTTP", "SSL"],
            horizontal=True,
            key="popup_forensic_service",
        )

    # --- ROW 2: Specific Date dropdown (ONLY when needed) ---
    date_filter_set = None
    f_date = "All Dates"

    if forensic_mode == "Last 7 Days":
        # last 7 available folders
        date_filter_set = set(available_dates_list[:7])
        f_date = "All Dates"  # load all, filter by date_str after
    elif forensic_mode == "Specific Date":
        c3, c4 = st.columns([1.2, 2.8], vertical_alignment="center")
        with c3:
            st.write("")  # small alignment helper
        with c4:
            f_date = st.selectbox("Select Activity Date:", available_dates_list, key="popup_forensic_date")
        date_filter_set = {f_date}
    else:
        # All Time
        date_filter_set = None
        f_date = "All Dates"

    # --- Load activity (fast path: if specific date, load that day only) ---
    activity_df = get_device_activity(parquet_root, mac, ip, f_date)

    # --- Apply date and service filtering ---
    if not activity_df.empty:
        activity_df = activity_df.copy()
        activity_df["date_str"] = activity_df["ts"].dt.date.astype(str)

        if date_filter_set is not None:
            activity_df = activity_df[activity_df["date_str"].isin(date_filter_set)]

        if f_service != "All Services":
            activity_df = activity_df[activity_df["Service"] == f_service]

    if activity_df.empty:
        if forensic_mode == "Last 7 Days":
            st.warning(f"No activity logs found for {mac} in the last 7 available days.")
        elif forensic_mode == "Specific Date":
            st.warning(f"No activity logs found for {mac} on {f_date}.")
        else:
            st.warning(f"No activity logs found for {mac} (all time).")
        return

    # =========================
    # Traffic Volume (NO overlay + always 3 colors)
    # =========================
    st.markdown("#### Traffic Volume")

    # Build hourly counts
    tmp = activity_df.copy()
    tmp["hour"] = tmp["ts"].dt.floor("H")

    counts = tmp.groupby(["hour", "Service"]).size().reset_index(name="Events")

    # Ensure DNS/HTTP/SSL always exist (even 0)
    services = ["DNS", "HTTP", "SSL"]
    hour_min = counts["hour"].min()
    hour_max = counts["hour"].max()
    all_hours = pd.date_range(start=hour_min, end=hour_max, freq="H")

    full_index = pd.MultiIndex.from_product([all_hours, services], names=["hour", "Service"])
    counts_full = (
        counts.set_index(["hour", "Service"])
        .reindex(full_index, fill_value=0)
        .reset_index()
    )

    color_map = {"DNS": "#F63049", "HTTP": "#00F7FF", "SSL": "#F3AE4B"}

    # Stacked area via go.Scatter stackgroup (prevents overlay hiding)
    fig = go.Figure()
    for svc in services:
        svc_df = counts_full[counts_full["Service"] == svc]
        fig.add_trace(
            go.Scatter(
                x=svc_df["hour"],
                y=svc_df["Events"],
                mode="lines",
                name=svc,
                stackgroup="one",
                line=dict(color=color_map[svc], width=2),
            )
        )

    fig.update_layout(
        template="plotly_dark",
        height=300,
        margin=dict(l=10, r=10, t=30, b=10),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        xaxis_title=None,
        yaxis_title="Events",
        hovermode="x unified",
    )
    st.plotly_chart(fig, use_container_width=True)

    # =========================
    # Top Destinations
    # =========================
    st.markdown("#### Top Destinations")
    top = activity_df["Destination"].value_counts().head(5).reset_index()
    top.columns = ["Destination", "Count"]
    top.index = top.index + 1
    st.dataframe(top, use_container_width=True)


# =====================================================
# Device list popup: remove Vendor column
# =====================================================
@st.dialog("  ", width="large", dismissible=False)
def device_list_popup(status_type, df, parquet_root, available_dates_list):
    hide_dialog_header()

    col_left, col_right = st.columns([0.9, 0.0325], vertical_alignment="center")
    with col_left:
        if st.button("Back", key="dlg_list_back"):
            _close_dialog()
    with col_right:
        if st.button("X", key="dlg_list_close"):
            _close_dialog()

    st.markdown(f"### {status_type} Devices")

    col_d1, col_d2 = st.columns([1, 7])
    with col_d1:
        date_filter_mode = st.selectbox(
            "Time Range:",
            ["Last 7 Days", "Specific Date", "All Time"],
            index=0,
            key="popup_list_mode",
        )

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

        # Vendor removed
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
# Custom metric block (NO Streamlit pill arrows)
# =====================================================
def render_metric(
    label: str,
    value,
    delta_value,
    *,
    delta_is_percent: bool = False,
    up_color: str = "#2ecc71",     # default green
    down_color: str = "#9aa0a6",   # default grey
):
    value_str = str(value)

    try:
        dv = float(delta_value)
    except Exception:
        dv = 0.0

    show = abs(dv) >= 1e-12
    if show:
        suffix = "%" if delta_is_percent else ""
        if delta_is_percent:
            disp = f"{dv:.2f}".rstrip("0").rstrip(".")
        else:
            disp = str(int(dv)) if abs(dv - int(dv)) < 1e-12 else f"{dv:.2f}".rstrip("0").rstrip(".")

        up = dv > 0
        arrow = "↑" if up else "↓"
        sign = "+" if up else ""
        label_txt = "Increase" if up else "Decrease"
        color = up_color if up else down_color
        delta_text = f"{arrow} {sign}{disp}{suffix} ({label_txt})"
    else:
        delta_text = ""
        color = down_color

    st.markdown(f"<div style='font-size:14px; opacity:0.85'>{label}</div>", unsafe_allow_html=True)
    st.markdown(
        f"<div style='font-size:42px; font-weight:650; line-height:1.1'>{value_str}</div>",
        unsafe_allow_html=True,
    )

    if show:
        st.markdown(
            f"<div style='display:inline-block; margin-top:6px; padding:4px 10px; border-radius:999px; "
            f"background:rgba(255,255,255,0.06); color:{color}; font-size:16px; font-weight:600;'>"
            f"{delta_text}</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown("<div style='height:30px;'></div>", unsafe_allow_html=True)


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
    if "selected_forensic_ip" not in st.session_state:
        st.session_state.selected_forensic_ip = None

    st.title("Device Overview")

    PARQUET_ROOT = Path(logs_root)
    known_hosts, dhcp = load_visual_metrics_from_parquet(PARQUET_ROOT)

    authorized_macs = load_authorized_macs(authorized_mac_file)

    BAN_FILE = authorized_mac_file.with_name("banned_macs.yaml")
    banned_macs = load_banned_macs(BAN_FILE)

    intersect = banned_macs.intersection(authorized_macs)
    if intersect:
        banned_macs = banned_macs - intersect
        save_banned_macs(BAN_FILE, banned_macs)

    if known_hosts.empty:
        st.info("No device data available")
        return

    if "mac" in known_hosts.columns:
        known_hosts["mac"] = known_hosts["mac"].astype(str).str.lower().str.strip()

    if not dhcp.empty:
        if "mac" in dhcp.columns:
            dhcp = dhcp.copy()
            dhcp["mac"] = dhcp["mac"].astype(str).str.lower().str.strip()
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
    # METRICS (exclude banned everywhere)
    # -----------------------------
    in_scope = merged[~merged["mac"].isin(banned_macs)]

    total_u = int(in_scope["mac"].nunique())
    auth_u = int(in_scope[in_scope["status"] == "Authorized"]["mac"].nunique())
    unauth_u = int(in_scope[in_scope["status"] == "Unauthorized"]["mac"].nunique())
    risk = round((unauth_u / total_u * 100), 2) if total_u else 0.0

    # -----------------------------
    # RETAIN LAST CHANGE ACROSS REFRESH
    # -----------------------------
    current_state = {"total": total_u, "auth": auth_u, "unauth": unauth_u, "risk": float(risk)}

    store = load_metrics_store(authorized_mac_file)
    stored_state = store.get("state")
    stored_delta = store.get("last_delta")

    if not isinstance(stored_state, dict):
        store = {
            "state": current_state,
            "last_delta": {"total": 0, "auth": 0, "unauth": 0, "risk": 0.0},
            "last_change_at": None,
        }
        save_metrics_store(authorized_mac_file, store)
        d_total = d_auth = d_unauth = 0
        d_risk = 0.0
    else:
        prev = {
            "total": int(stored_state.get("total", current_state["total"])),
            "auth": int(stored_state.get("auth", current_state["auth"])),
            "unauth": int(stored_state.get("unauth", current_state["unauth"])),
            "risk": float(stored_state.get("risk", current_state["risk"])),
        }

        changed = (
            prev["total"] != current_state["total"]
            or prev["auth"] != current_state["auth"]
            or prev["unauth"] != current_state["unauth"]
            or abs(prev["risk"] - current_state["risk"]) > 1e-9
        )

        if changed:
            d_total = current_state["total"] - prev["total"]
            d_auth = current_state["auth"] - prev["auth"]
            d_unauth = current_state["unauth"] - prev["unauth"]
            d_risk = round(current_state["risk"] - prev["risk"], 2)

            store["state"] = current_state
            store["last_delta"] = {"total": d_total, "auth": d_auth, "unauth": d_unauth, "risk": d_risk}
            store["last_change_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            save_metrics_store(authorized_mac_file, store)
        else:
            if not isinstance(stored_delta, dict):
                stored_delta = {"total": 0, "auth": 0, "unauth": 0, "risk": 0.0}
            d_total = int(stored_delta.get("total", 0))
            d_auth = int(stored_delta.get("auth", 0))
            d_unauth = int(stored_delta.get("unauth", 0))
            d_risk = float(stored_delta.get("risk", 0.0))

    # -----------------------------
    # METRIC UI (custom deltas + requested colors)
    # -----------------------------
    RED = "#F63049"
    GREEN = "#2ecc71"
    GREY = "#9aa0a6"

    m1, m2, m3, m4 = st.columns(4)

    with m1:
        render_metric("Active Devices", total_u, d_total, up_color=GREEN, down_color=GREY)

    with m2:
        render_metric("Authorized", auth_u, d_auth, up_color=GREEN, down_color=GREY)
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        if st.button("View Authorized", key="btn_auth_pop"):
            st.session_state.list_status_type = "Authorized"
            st.session_state.active_dialog = "list"
            st.rerun()

    with m3:
        render_metric("Unauthorized", unauth_u, d_unauth, up_color=RED, down_color=GREY)
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        if st.button("View Unauthorized", key="btn_unauth_pop"):
            st.session_state.list_status_type = "Unauthorized"
            st.session_state.active_dialog = "list"
            st.rerun()

    with m4:
        render_metric("Risk Ratio", f"{risk}%", d_risk, delta_is_percent=True, up_color=RED, down_color=GREY)

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
    raw_dates = sorted([str(d) for d in merged["date"].unique() if pd.notnull(d)], reverse=True)

    if st.session_state.active_dialog == "list":
        device_list_popup(st.session_state.list_status_type, merged, PARQUET_ROOT, raw_dates)

    elif st.session_state.active_dialog == "forensics":
        forensic_popup(
            PARQUET_ROOT,
            st.session_state.selected_forensic_mac,
            st.session_state.selected_forensic_ip,
            raw_dates,
        )
