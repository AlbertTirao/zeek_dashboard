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
# 1) Load Visual Metrics from Parquet
# =====================================================
@st.cache_data(show_spinner=False)
def load_visual_metrics_from_parquet(parquet_root: Path):
    known_hosts_all = []
    dhcp_all = []
    if not parquet_root.exists():
        return pd.DataFrame(), pd.DataFrame()

    for day_dir in sorted((p for p in parquet_root.iterdir() if p.is_dir())):
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
# 2) Drill-Down Log Loader (robust ts + robust MAC)
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
        day_dirs = sorted((p for p in parquet_root.iterdir() if p.is_dir()))

    def _normalize_mac_one(x) -> str:
        if x is None:
            return ""
        # parquet sometimes stores MAC as 6 bytes
        if isinstance(x, (bytes, bytearray)) and len(x) == 6:
            hx = bytes(x).hex()
            return ":".join(hx[i : i + 2] for i in range(0, 12, 2))
        return str(x).strip().lower()

    def _normalize_mac_series(s: pd.Series) -> pd.Series:
        return s.map(_normalize_mac_one)

    def _coerce_ts(series: pd.Series) -> pd.Series:
        if pd.api.types.is_datetime64_any_dtype(series):
            return series

        if pd.api.types.is_object_dtype(series):
            parsed = pd.to_datetime(series, errors="coerce", utc=False)
            if parsed.notna().any():
                return parsed

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
    final_df["ts"] = _coerce_ts(final_df["ts"])
    final_df = final_df.dropna(subset=["ts"])
    return final_df.sort_values("ts", ascending=False)


# =====================================================
# 3) Helpers
# =====================================================
@st.cache_data(show_spinner=False)
def get_mac_vendor(mac: str) -> str:
    # kept for compatibility with other pages
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
    """
    Supports:
      banned_macs.yaml:
        banned_macs:
          - "aa:bb:.."
          - {mac: "aa:bb:..", date_modified: "..."}   (from authorization page)
    """
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
# 3b) Authorized "Added At" store (persistent, safe, does not touch YAML)
# =====================================================
def _auth_history_store_file(authorized_mac_file: Path) -> Path:
    return authorized_mac_file.with_name("authorized_macs_history.json")


def _load_auth_history_store(authorized_mac_file: Path) -> dict:
    fp = _auth_history_store_file(authorized_mac_file)
    if not fp.exists():
        return {}
    try:
        data = json.loads(fp.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_auth_history_store(authorized_mac_file: Path, store: dict) -> None:
    fp = _auth_history_store_file(authorized_mac_file)
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(json.dumps(store, indent=2), encoding="utf-8")


def _parse_any_dt(value):
    if value is None:
        return None
    try:
        ts = pd.to_datetime(value, errors="coerce", utc=False)
        if pd.isna(ts):
            return None
        return ts.to_pydatetime()
    except Exception:
        return None


def _humanize_ago(delta: timedelta) -> str:
    secs = int(delta.total_seconds())
    if secs < 0:
        secs = 0

    if secs < 5:
        return "just now"
    if secs < 60:
        return f"{secs} seconds ago" if secs != 1 else "1 second ago"

    mins = secs // 60
    if mins < 60:
        return f"{mins} minutes ago" if mins != 1 else "1 minute ago"

    hours = mins // 60
    if hours < 24:
        return f"{hours} hours ago" if hours != 1 else "1 hour ago"

    days = hours // 24
    if days < 7:
        return f"{days} days ago" if days != 1 else "1 day ago"

    weeks = days // 7
    if weeks < 5:
        return f"{weeks} weeks ago" if weeks != 1 else "1 week ago"

    months = days // 30
    if months < 12:
        return f"{months} months ago" if months != 1 else "1 month ago"

    years = days // 365
    return f"{years} years ago" if years != 1 else "1 year ago"


def load_authorized_macs_with_history(file_path: Path, authorized_mac_file_for_store: Path):
    """
    Returns:
      - authorized_set: set[str] normalized mac
      - added_at_map: dict[str, datetime] when it was first seen in the authorized list
    Rules:
      - If YAML item is dict and has timestamp fields, use them (best-effort)
      - Else use persistent JSON store authorized_macs_history.json
      - If newly authorized and no timestamp exists, set to now (first moment this code sees it authorized)
    """
    if file_path.suffix == ".txt":
        yaml_path = file_path.with_suffix(".yaml")
        if yaml_path.exists():
            file_path = yaml_path

    if not file_path.exists():
        st.warning(f"Authorized file not found ({file_path.name}) — all devices Unauthorized")
        return set(), {}

    try:
        data = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except Exception as e:
        st.error(f"Error reading YAML: {e}")
        return set(), {}

    raw_list = _extract_list_from_yaml(data, file_path.stem)

    store = _load_auth_history_store(authorized_mac_file_for_store)
    store_norm = {str(k).strip().lower(): v for k, v in store.items() if isinstance(k, str)}

    now = datetime.now()
    authorized_set = set()
    added_at_map = {}

    for item in raw_list:
        mac = None
        added_dt = None

        if isinstance(item, str):
            mac = item.strip().lower()
        elif isinstance(item, dict):
            mac = str(item.get("mac", "")).strip().lower()
            for k in ["date_added", "added_at", "timestamp", "created_at", "date_modified"]:
                if k in item and item.get(k):
                    added_dt = _parse_any_dt(item.get(k))
                    if added_dt:
                        break

        if not mac:
            continue

        authorized_set.add(mac)

        if added_dt:
            added_at_map[mac] = added_dt
            store_norm[mac] = added_dt.strftime("%Y-%m-%d %H:%M:%S")
            continue

        stored_str = store_norm.get(mac)
        stored_dt = _parse_any_dt(stored_str) if stored_str else None
        if stored_dt:
            added_at_map[mac] = stored_dt
        else:
            added_at_map[mac] = now
            store_norm[mac] = now.strftime("%Y-%m-%d %H:%M:%S")

    _save_auth_history_store(authorized_mac_file_for_store, store_norm)
    return authorized_set, added_at_map


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
# Forensic popup (aligned row: Time Range | Service | Date)
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

    col_time, col_service, col_date = st.columns([1.35, 2.25, 2.40], vertical_alignment="bottom")

    with col_time:
        forensic_mode = st.selectbox(
            "Time Range:",
            ["Last 7 Days", "Specific Date", "All Time"],
            index=0,
            key="popup_forensic_mode",
        )

    with col_service:
        f_service = st.radio(
            "Filter Service:",
            ["All Services", "DNS", "HTTP", "SSL"],
            horizontal=True,
            key="popup_forensic_service",
        )

    f_date = "All Dates"
    date_filter_set = None

    with col_date:
        if forensic_mode == "Specific Date":
            f_date = st.selectbox("Select Activity Date:", available_dates_list, key="popup_forensic_date")
            date_filter_set = {f_date}
        else:
            st.markdown("<div style='height: 2.55rem;'></div>", unsafe_allow_html=True)

    if forensic_mode == "Last 7 Days":
        date_filter_set = set(available_dates_list[:7])
        f_date = "All Dates"
    elif forensic_mode == "All Time":
        date_filter_set = None
        f_date = "All Dates"

    activity_df = get_device_activity(parquet_root, mac, ip, f_date)

    if not activity_df.empty:
        activity_df = activity_df.copy()
        activity_df["date_str"] = activity_df["ts"].dt.date.astype(str)

        if date_filter_set is not None:
            activity_df = activity_df[activity_df["date_str"].isin(date_filter_set)]

        if f_service != "All Services":
            activity_df = activity_df[activity_df["Service"] == f_service]

    if activity_df.empty:
        st.warning("No activity logs found for the selected filter.")
        return

    # =========================
    # Traffic Volume (small dataset fix)
    # =========================
    st.markdown("#### Traffic Volume")

    tmp = activity_df.copy()
    tmp["hour"] = tmp["ts"].dt.floor("H")

    counts = tmp.groupby(["hour", "Service"]).size().reset_index(name="Events")

    services = ["DNS", "HTTP", "SSL"]
    color_map = {"DNS": "#F63049", "HTTP": "#00F7FF", "SSL": "#F3AE4B"}

    hour_min = counts["hour"].min()
    hour_max = counts["hour"].max()
    if pd.isna(hour_min) or pd.isna(hour_max):
        st.info("No traffic volume data to chart.")
        return

    # Key fix: if only one hour exists, extend the range by 1 hour
    if hour_min == hour_max:
        hour_max = hour_min + pd.Timedelta(hours=1)

    all_hours = pd.date_range(start=hour_min, end=hour_max, freq="H")

    full_index = pd.MultiIndex.from_product([all_hours, services], names=["hour", "Service"])
    counts_full = (
        counts.set_index(["hour", "Service"])
        .reindex(full_index, fill_value=0)
        .reset_index()
    )

    fig = go.Figure()
    for svc in services:
        svc_df = counts_full[counts_full["Service"] == svc]
        fig.add_trace(
            go.Scatter(
                x=svc_df["hour"],
                y=svc_df["Events"],
                mode="lines+markers",
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
    fig.update_yaxes(rangemode="tozero")
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("#### Top Destinations")
    top = activity_df["Destination"].value_counts().head(5).reset_index()
    top.columns = ["Destination", "Count"]
    top.index = top.index + 1
    st.dataframe(top, use_container_width=True)


# =====================================================
# Device list popup (EXCLUDES banned + adds Download)
# Authorized:
#   - Date column shows Authorized At
# Unauthorized:
#   - Date column shows Last Seen
# NOTE: History column removed per request.
# =====================================================
@st.dialog("  ", width="large", dismissible=False)
def device_list_popup(status_type, df, parquet_root, available_dates_list, banned_macs: set, authorized_added_at_map: dict):
    hide_dialog_header()

    col_left, col_right = st.columns([0.9, 0.0325], vertical_alignment="center")
    with col_left:
        if st.button("Back", key="dlg_list_back"):
            _close_dialog()
    with col_right:
        if st.button("X", key="dlg_list_close"):
            _close_dialog()

    st.markdown(f"### {status_type} Devices")

    col_d1, col_d2 = st.columns([1.2, 2.8], vertical_alignment="bottom")
    with col_d1:
        date_filter_mode = st.selectbox(
            "Time Range:",
            ["Last 7 Days", "Specific Date", "All Time"],
            index=0,
            key="popup_list_mode",
        )
    with col_d2:
        if date_filter_mode == "Specific Date":
            spec_date = st.selectbox("Choose Date:", available_dates_list, key="popup_list_spec_date")
        else:
            spec_date = None
            st.markdown("<div style='height: 2.55rem;'></div>", unsafe_allow_html=True)

    filtered_df = df[df["status"] == status_type].copy()
    if not filtered_df.empty and "mac" in filtered_df.columns and banned_macs:
        filtered_df = filtered_df[~filtered_df["mac"].isin(banned_macs)]

    if date_filter_mode == "Last 7 Days":
        seven_days_ago = datetime.now().date() - timedelta(days=7)
        if not filtered_df.empty:
            filtered_df = filtered_df[filtered_df["date"] >= seven_days_ago]
    elif date_filter_mode == "Specific Date" and spec_date:
        if not filtered_df.empty:
            filtered_df = filtered_df[filtered_df["date"].astype(str) == spec_date]

    if filtered_df.empty:
        st.info(f"No {status_type.lower()} devices found for this criteria.")
        return

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

    inventory = inventory.sort_values("last_seen", ascending=False)

    if status_type == "Authorized":
        def _get_added_dt(mac: str):
            m = str(mac).strip().lower()
            dtv = authorized_added_at_map.get(m)
            return dtv if isinstance(dtv, datetime) else None

        inventory["authorized_at"] = inventory["mac"].map(_get_added_dt)

        # Date shows when you authorized it
        inventory["date_str"] = inventory["authorized_at"].apply(
            lambda d: d.strftime("%Y-%m-%d %H:%M:%S") if isinstance(d, datetime) else "-"
        )
    else:
        # Date shows last seen from logs
        inventory["date_str"] = inventory["last_seen"].dt.strftime("%Y-%m-%d %H:%M:%S")

    # Keep only requested visible columns (history removed)
    inventory = inventory[["mac", "ip", "host_name", "date_str", "last_seen"]].copy()

    inventory = inventory.reset_index(drop=True)
    inventory.insert(0, "#", inventory.index + 1)

    # Download CSV
    csv_bytes = inventory.drop(columns=["last_seen"], errors="ignore").to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Download CSV",
        data=csv_bytes,
        file_name=f"{status_type.lower()}_devices.csv",
        mime="text/csv",
        key=f"dl_{status_type.lower()}",
    )

    gb = GridOptionsBuilder.from_dataframe(inventory)
    gb.configure_selection(selection_mode="single", use_checkbox=False)
    gb.configure_column("#", header_name="#", width=50, pinned="left")
    gb.configure_column("mac", header_name="MAC Address")
    gb.configure_column("ip", header_name="IP Address")
    gb.configure_column("host_name", header_name="Host Name")

    gb.configure_column(
        "date_str",
        header_name=("Date" if status_type == "Authorized" else "Date"),
    )
    gb.configure_column("last_seen", hide=True)

    grid_response = AgGrid(
        inventory,
        gridOptions=gb.build(),
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


# =====================================================
# Custom metric block (UPDATED delta text -> "+2 (today)")
# =====================================================
def render_metric(
    label: str,
    value,
    delta_value,
    *,
    delta_is_percent: bool = False,
    up_color: str = "#2ecc71",
    down_color: str = "#9aa0a6",
):
    value_str = str(value)

    try:
        dv = float(delta_value)
    except Exception:
        dv = 0.0

    show = abs(dv) >= 1e-12

    # ---- fixed delta slot height so buttons never move ----
    SLOT_H = 38  # px (same space whether pill or empty)

    if show:
        suffix = "%" if delta_is_percent else ""
        if delta_is_percent:
            disp = f"{dv:.2f}".rstrip("0").rstrip(".")
        else:
            disp = str(int(dv)) if abs(dv - int(dv)) < 1e-12 else f"{dv:.2f}".rstrip("0").rstrip(".")

        up = dv > 0
        arrow = "↑" if up else "↓"
        sign = "+" if up else ""
        color = up_color if up else down_color
        delta_text = f"{arrow} {sign}{disp}{suffix} (today)"

        delta_html = (
            f"<div style='height:{SLOT_H}px; display:flex; align-items:center;'>"
            f"  <div style='display:inline-flex; align-items:center; justify-content:center;"
            f"      padding:4px 10px; border-radius:999px;"
            f"      background:rgba(255,255,255,0.06);"
            f"      color:{color}; font-size:16px; font-weight:600;'>"
            f"    {delta_text}"
            f"  </div>"
            f"</div>"
        )
    else:
        # empty but SAME HEIGHT as delta pill slot
        delta_html = f"<div style='height:{SLOT_H}px;'></div>"

    st.markdown(f"<div style='font-size:14px; opacity:0.85'>{label}</div>", unsafe_allow_html=True)
    st.markdown(
        f"<div style='font-size:42px; font-weight:650; line-height:1.1'>{value_str}</div>",
        unsafe_allow_html=True,
    )
    st.markdown(delta_html, unsafe_allow_html=True)


# =====================================================
# Main Render
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

    # track Authorized "added at" timestamps
    authorized_macs, authorized_added_at_map = load_authorized_macs_with_history(
        authorized_mac_file, authorized_mac_file
    )

    BAN_FILE = authorized_mac_file.with_name("banned_macs.yaml")
    banned_macs = load_banned_macs(BAN_FILE)

    # if now authorized, auto-remove from ban list
    intersect = banned_macs.intersection(authorized_macs)
    if intersect:
        banned_macs = banned_macs - intersect
        save_banned_macs(BAN_FILE, banned_macs)

    if known_hosts.empty:
        st.info("No device data available")
        return

    if "mac" in known_hosts.columns:
        known_hosts = known_hosts.copy()
        known_hosts["mac"] = known_hosts["mac"].astype(str).str.lower().str.strip()

    # Merge DHCP (optional)
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

    # ts -> datetime + date
    if "ts" in merged.columns:
        merged = merged.copy()
        merged["ts"] = pd.to_numeric(merged["ts"], errors="coerce")
        merged["ts"] = pd.to_datetime(merged["ts"], unit="s", errors="coerce")
        merged = merged.dropna(subset=["ts"])
        merged["date"] = merged["ts"].dt.date

    # STRICT RULE:
    merged["status"] = merged["mac"].apply(
        lambda m: "Authorized" if (str(m).strip().lower() in authorized_macs) else "Unauthorized"
    )

    # EXCLUDE BANNED EVERYWHERE
    in_scope = merged.copy()
    if "mac" in in_scope.columns and banned_macs:
        in_scope = in_scope[~in_scope["mac"].isin(banned_macs)]

    # Metrics
    today = datetime.now().date()

    total_devices = int(in_scope["mac"].nunique())
    active_today = int(in_scope[in_scope["date"] == today]["mac"].nunique()) if "date" in in_scope.columns else 0
    auth_seen = int(in_scope[in_scope["status"] == "Authorized"]["mac"].nunique())
    unauth_seen = int(in_scope[in_scope["status"] == "Unauthorized"]["mac"].nunique())
    risk = round((unauth_seen / total_devices * 100), 2) if total_devices else 0.0

    current_state = {
        "total": total_devices,
        "active_today": active_today,
        "auth": auth_seen,
        "unauth": unauth_seen,
        "risk": float(risk),
    }

    # =====================================================
    # DAILY DELTA LOGIC (UPDATED)
    # - Shows: "+2 (today)" / "-1 (today)"
    # - Locks for the day (refresh won't change delta)
    # - Resets tomorrow; if no change tomorrow => hides delta
    # =====================================================
    today_str = datetime.now().strftime("%Y-%m-%d")

    def _delta_is_zero(d: dict) -> bool:
        if not isinstance(d, dict):
            return True
        if int(d.get("total", 0)) != 0:
            return False
        if int(d.get("active_today", 0)) != 0:
            return False
        if int(d.get("auth", 0)) != 0:
            return False
        if int(d.get("unauth", 0)) != 0:
            return False
        if abs(float(d.get("risk", 0.0))) > 1e-12:
            return False
        return True

    store = load_metrics_store(authorized_mac_file)
    if not isinstance(store, dict):
        store = {}

    prev_state = store.get("state") if isinstance(store.get("state"), dict) else None

    # New day -> set baseline to last known state (yesterday end), reset delta and unlock
    if store.get("daily_date") != today_str:
        baseline = prev_state if isinstance(prev_state, dict) else current_state
        store["daily_date"] = today_str
        store["daily_baseline"] = baseline
        store["daily_delta"] = {"total": 0, "active_today": 0, "auth": 0, "unauth": 0, "risk": 0.0}
        store["daily_locked"] = False

    baseline = store.get("daily_baseline") if isinstance(store.get("daily_baseline"), dict) else current_state
    daily_delta = store.get("daily_delta") if isinstance(store.get("daily_delta"), dict) else {
        "total": 0, "active_today": 0, "auth": 0, "unauth": 0, "risk": 0.0
    }
    locked = bool(store.get("daily_locked", False))

    if not locked:
        b_total = int(baseline.get("total", current_state["total"]))
        b_active = int(baseline.get("active_today", current_state["active_today"]))
        b_auth = int(baseline.get("auth", current_state["auth"]))
        b_unauth = int(baseline.get("unauth", current_state["unauth"]))
        b_risk = float(baseline.get("risk", current_state["risk"]))

        computed = {
            "total": current_state["total"] - b_total,
            "active_today": current_state["active_today"] - b_active,
            "auth": current_state["auth"] - b_auth,
            "unauth": current_state["unauth"] - b_unauth,
            "risk": round(current_state["risk"] - b_risk, 2),
        }

        # Only lock if something changed today. If still zero, keep unlocked so it stays hidden.
        if not _delta_is_zero(computed):
            store["daily_delta"] = computed
            store["daily_locked"] = True
            daily_delta = computed
        else:
            daily_delta = computed  # zero -> UI hides it

    # Always update last known state for tomorrow’s baseline
    store["state"] = current_state
    save_metrics_store(authorized_mac_file, store)

    d_total = int(daily_delta.get("total", 0))
    d_active = int(daily_delta.get("active_today", 0))
    d_auth = int(daily_delta.get("auth", 0))
    d_unauth = int(daily_delta.get("unauth", 0))
    d_risk = float(daily_delta.get("risk", 0.0))

    RED = "#F63049"
    GREEN = "#2ecc71"
    GREY = "#9aa0a6"
    CYAN = "#00F7FF"

    # 5 metrics
    m1, m2, m3, m4, m5 = st.columns(5)

    with m1:
        render_metric("Total Devices", total_devices, d_total, up_color=GREEN, down_color=GREY)

    with m2:
        render_metric("Active Today", active_today, d_active, up_color=GREEN, down_color=GREY)

    with m3:
        render_metric("Authorized", auth_seen, d_auth, up_color=GREEN, down_color=GREY)
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        if st.button("View Authorized", key="btn_auth_pop"):
            st.session_state.list_status_type = "Authorized"
            st.session_state.active_dialog = "list"
            st.rerun()

    with m4:
        render_metric("Unauthorized", unauth_seen, d_unauth, up_color=RED, down_color=GREY)
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        if st.button("View Unauthorized", key="btn_unauth_pop"):
            st.session_state.list_status_type = "Unauthorized"
            st.session_state.active_dialog = "list"
            st.rerun()

    with m5:
        render_metric("Risk Ratio", f"{risk}%", d_risk, delta_is_percent=True, up_color=RED, down_color=GREY)

    st.markdown("---")

    # Activity Overview
    st.subheader("Activity Overview")
    hourly = pd.DataFrame()
    if not in_scope.empty:
        hourly = (
            in_scope.set_index("ts")
            .groupby("status")
            .resample("1H")
            .size()
            .reset_index(name="events")
        )

    if not hourly.empty:
        fig = px.line(
            hourly,
            x="ts",
            y="events",
            color="status",
            template="plotly_dark",
            color_discrete_map={"Authorized": CYAN, "Unauthorized": RED},
        )
        st.plotly_chart(fig, use_container_width=True)

    # Unauthorized Device Ratio
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

    # Dialog manager
    raw_dates = sorted([str(d) for d in merged["date"].unique() if pd.notnull(d)], reverse=True)

    if st.session_state.active_dialog == "list":
        device_list_popup(
            st.session_state.list_status_type,
            in_scope,
            PARQUET_ROOT,
            raw_dates,
            banned_macs,
            authorized_added_at_map,
        )

    elif st.session_state.active_dialog == "forensics":
        forensic_popup(
            PARQUET_ROOT,
            st.session_state.selected_forensic_mac,
            st.session_state.selected_forensic_ip,
            raw_dates,
        )