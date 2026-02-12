# ui/pages/alerts.py
# Streamlit module: detects Unauthorized/Verified devices from Zeek parquet (DHCP/ARP/CONN),
# keeps "Last Seen" per MAC, and enriches IP/Host/Vendor where available.
#
# Fixes applied:
# 1) Deterministic YAML list selection (preferred keys + stem key) to match Devices page
# 2) Keeps robust MAC normalization (aa:bb:cc:dd:ee:ff) for both logs + YAML

import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Tuple

import pandas as pd
import streamlit as st
import yaml

# --- VENDOR LOOKUP SETUP ---
try:
    from mac_vendor_lookup import MacLookup
    VENDOR_LIB_AVAILABLE = True
except ImportError:
    VENDOR_LIB_AVAILABLE = False

# =============================================================================
# CONSTANTS / REGEX
# =============================================================================
_MAC_HEX_RE = re.compile(r"[^0-9a-fA-F]")
_DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# YAML list key preference (must match Devices)
PREFERRED_AUTH_KEYS = [
    "authorized_macs",
    "allowlist",
    "authorized_devices",
    "devices",
    "authorized",
]


# =============================================================================
# NORMALIZATION
# =============================================================================
def normalize_mac(x) -> Optional[str]:
    """Normalize MAC to 'aa:bb:cc:dd:ee:ff'. Return None if invalid."""
    if x is None:
        return None

    # parquet may store MAC as 6 raw bytes
    if isinstance(x, (bytes, bytearray)) and len(x) == 6:
        hx = bytes(x).hex()
    else:
        hx = _MAC_HEX_RE.sub("", str(x))

    if len(hx) != 12:
        return None
    return ":".join(hx[i : i + 2] for i in range(0, 12, 2)).lower()


def is_broadcast_mac(mac: Optional[str]) -> bool:
    return mac == "ff:ff:ff:ff:ff:ff"


def to_datetime_series(s: pd.Series) -> pd.Series:
    """
    Robust timestamp conversion:
    - If already datetime => return as-is
    - If object => try parse
    - If numeric => infer unit by magnitude (ns/us/ms/s)
    """
    if s is None:
        return pd.Series([pd.NaT] * 0, dtype="datetime64[ns]")

    if pd.api.types.is_datetime64_any_dtype(s):
        return s

    if pd.api.types.is_object_dtype(s):
        parsed = pd.to_datetime(s, errors="coerce", utc=False)
        if parsed.notna().any():
            return parsed

    num = pd.to_numeric(s, errors="coerce")
    if not num.notna().any():
        return pd.to_datetime(s, errors="coerce", utc=False)

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

    return pd.to_datetime(num, unit=unit, errors="coerce", utc=False)


# =============================================================================
# YAML LIST EXTRACTION (DETERMINISTIC)
# =============================================================================
def _extract_yaml_list(data, stem_key: str, preferred_keys: List[str]) -> List:
    """
    Deterministic selection:
      1) preferred keys in order (if dict)
      2) stem key (filename stem) (if dict)
      3) first list value in dict (fallback)
      4) if YAML is a list => return it
    """
    if data is None:
        return []

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for k in preferred_keys:
            if k in data and isinstance(data[k], list):
                return data[k]

        if stem_key and stem_key in data and isinstance(data[stem_key], list):
            return data[stem_key]

        for v in data.values():
            if isinstance(v, list):
                return v

    return []


# =============================================================================
# AUTO-DETECT BEST COLUMNS
# =============================================================================
def score_mac_column(df: pd.DataFrame, col: str, sample_n: int = 500) -> int:
    if col not in df.columns:
        return 0
    s = df[col].head(sample_n)
    return int(s.map(normalize_mac).notna().sum())


def score_ip_column(df: pd.DataFrame, col: str, sample_n: int = 500) -> int:
    if col not in df.columns:
        return 0
    s = df[col].head(sample_n).astype(str)
    return int(s.str.match(r"^\d{1,3}(\.\d{1,3}){3}$", na=False).sum())


def score_ts_column(df: pd.DataFrame, col: str, sample_n: int = 500) -> int:
    if col not in df.columns:
        return 0
    s = df[col].head(sample_n)
    dt = to_datetime_series(s)
    return int(dt.notna().sum())


def best_column(df: pd.DataFrame, scorer_fn, preferred: List[str]) -> Optional[str]:
    # 1) preferred first
    best = None
    best_score = 0
    for c in preferred:
        if c in df.columns:
            sc = scorer_fn(df, c)
            if sc > best_score:
                best_score = sc
                best = c
    if best_score > 0:
        return best

    # 2) scan all columns
    for c in df.columns:
        sc = scorer_fn(df, c)
        if sc > best_score:
            best_score = sc
            best = c

    return best if best_score > 0 else None


# =============================================================================
# FILE DISCOVERY + READ
# =============================================================================
def read_parquet_safe(path: Optional[Path]) -> pd.DataFrame:
    if not path:
        return pd.DataFrame()
    try:
        return pd.read_parquet(path)
    except Exception:
        return pd.DataFrame()


def _find_log_file_in_day(day_dir: Path, keywords: List[str]) -> Optional[Path]:
    """
    Find a parquet file inside a day directory matching any keyword.
    Prefers exact '<keyword>.parquet' but falls back to rglob match.
    """
    for k in keywords:
        exact = day_dir / f"{k}.parquet"
        if exact.exists():
            return exact

    files = list(day_dir.rglob("*.parquet"))
    if not files:
        return None

    matches = [f for f in files if any(k in f.name.lower() for k in keywords)]
    if not matches:
        return None

    matches.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return matches[0]


def _discover_date_dirs(parquet_root: Path) -> Dict[str, List[Path]]:
    """
    Return mapping: { 'YYYY-MM-DD': [Path(...), ...] }
    Supports both:
      - parquet_root/YYYY-MM-DD/*.parquet
      - parquet_root/**/YYYY-MM-DD/*.parquet
    """
    by_date: Dict[str, List[Path]] = {}

    immediate = [p for p in parquet_root.iterdir() if p.is_dir() and _DATE_DIR_RE.match(p.name)]
    candidates = immediate

    if not candidates:
        candidates = [p for p in parquet_root.rglob("*") if p.is_dir() and _DATE_DIR_RE.match(p.name)]

    for d in candidates:
        by_date.setdefault(d.name, []).append(d)

    for k in list(by_date.keys()):
        by_date[k] = sorted(by_date[k], key=lambda p: str(p))
    return by_date


# =============================================================================
# AUTHORIZED MACS (YAML) - FIXED LIST SELECTION
# =============================================================================
def load_authorized_macs(auth_file: str) -> set:
    """
    Supports YAML forms:
      - authorized_macs: ["aa:bb:..", ...]
      - authorized_macs: [{"mac": "aa:bb:.."}, ...]
      - ["aa:bb:..", ...]
    Deterministic list selection to match Devices.
    """
    allowed = set()
    file_path = Path(auth_file)

    if file_path.suffix != ".yaml":
        yaml_path = file_path.with_suffix(".yaml")
        if yaml_path.exists():
            file_path = yaml_path

    if not file_path.exists():
        return allowed

    try:
        data = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except Exception as e:
        st.error(f"Error reading authorized MACs file: {e}")
        return allowed

    raw_list = _extract_yaml_list(data, file_path.stem, PREFERRED_AUTH_KEYS)

    for item in raw_list:
        if isinstance(item, dict) and "mac" in item:
            m = normalize_mac(item.get("mac"))
        else:
            m = normalize_mac(item)
        if m:
            allowed.add(m)

    return allowed


# =============================================================================
# KNOWN HOSTS ENRICHMENT
# =============================================================================
def build_known_maps(known_hosts_df: pd.DataFrame) -> Tuple[Dict[str, str], Dict[str, str]]:
    mac_to_ip: Dict[str, str] = {}
    mac_to_vendor: Dict[str, str] = {}

    if known_hosts_df is None or known_hosts_df.empty:
        return mac_to_ip, mac_to_vendor

    mac_col = best_column(known_hosts_df, score_mac_column, ["mac", "MAC Address", "host_mac", "l2addr"])
    ip_col = best_column(known_hosts_df, score_ip_column, ["host_ip", "ip", "IP Address", "addr"])
    vendor_col = next((c for c in ["vendor", "Vendor", "manuf", "manufacturer"] if c in known_hosts_df.columns), None)

    if not mac_col:
        return mac_to_ip, mac_to_vendor

    tmp = known_hosts_df.copy()
    tmp["_mac_norm"] = tmp[mac_col].map(normalize_mac)

    if ip_col:
        tmp_ip = tmp.dropna(subset=["_mac_norm", ip_col])
        mac_to_ip = dict(zip(tmp_ip["_mac_norm"], tmp_ip[ip_col].astype(str)))

    if vendor_col:
        tmp_v = tmp.dropna(subset=["_mac_norm", vendor_col])
        mac_to_vendor = dict(zip(tmp_v["_mac_norm"], tmp_v[vendor_col].astype(str)))

    return mac_to_ip, mac_to_vendor


# =============================================================================
# VENDOR LOOKUP
# =============================================================================
@st.cache_resource
def get_vendor_lookup_instance():
    if not VENDOR_LIB_AVAILABLE:
        return None
    try:
        return MacLookup()
    except Exception:
        return None


def resolve_vendor(mac_norm: Optional[str], mac_to_vendor: Dict[str, str], mac_lookup) -> str:
    if not mac_norm:
        return "Unknown Vendor"
    if mac_norm in mac_to_vendor:
        return mac_to_vendor[mac_norm]
    if mac_lookup:
        try:
            return mac_lookup.lookup(mac_norm)
        except Exception:
            pass
    if not VENDOR_LIB_AVAILABLE:
        return "Unknown (install mac-vendor-lookup)"
    return "Unknown Vendor"


# =============================================================================
# EXTRACT GENERIC "DEVICE EVENTS" FROM ANY LOG
# =============================================================================
def extract_device_events(df: pd.DataFrame, source: str, fallback_ts: Optional[pd.Timestamp]) -> pd.DataFrame:
    """
    Extract:
      ts_dt, mac_norm, ip, host, source
    using auto-detected best columns.
    """
    if df is None or df.empty:
        return pd.DataFrame(columns=["ts_dt", "mac_norm", "ip", "host", "source"])

    ts_col = best_column(df, score_ts_column, ["ts", "timestamp", "time"])
    mac_col = best_column(
        df,
        score_mac_column,
        [
            "client_chaddr",
            "chaddr",
            "client_mac",
            "mac",
            "MAC Address",
            "orig_l2_addr",
            "resp_l2_addr",
            "orig_mac",
            "resp_mac",
            "hardware_address",
        ],
    )
    ip_col = best_column(
        df,
        score_ip_column,
        [
            "assigned_addr",
            "client_addr",
            "id.orig_h",
            "id.resp_h",
            "src_ip",
            "dst_ip",
            "ip",
            "host_ip",
        ],
    )

    host_col = next(
        (c for c in ["host_name", "client_fqdn", "hostname", "host", "Host Name", "computer_name"] if c in df.columns),
        None,
    )

    if not mac_col:
        return pd.DataFrame(columns=["ts_dt", "mac_norm", "ip", "host", "source"])

    tmp = df.copy()

    if ts_col:
        tmp["ts_dt"] = to_datetime_series(tmp[ts_col])
        if fallback_ts is not None:
            tmp["ts_dt"] = tmp["ts_dt"].fillna(fallback_ts)
    else:
        tmp["ts_dt"] = fallback_ts if fallback_ts is not None else pd.NaT

    tmp["mac_norm"] = tmp[mac_col].map(normalize_mac)

    if ip_col:
        tmp["ip"] = tmp[ip_col].astype("string")
        tmp["ip"] = tmp["ip"].replace(["None", "none", "-", "nan", "0.0.0.0", "Unknown IP", ""], pd.NA)
    else:
        tmp["ip"] = pd.NA

    if host_col:
        tmp["host"] = tmp[host_col].astype("string")
        tmp["host"] = tmp["host"].replace(["nan", "None", "none", "-", ""], pd.NA)
    else:
        tmp["host"] = pd.NA

    tmp["source"] = source

    out = tmp[["ts_dt", "mac_norm", "ip", "host", "source"]].copy()
    out = out.dropna(subset=["mac_norm"])
    out = out.dropna(subset=["ts_dt"])
    return out


# =============================================================================
# BUILD DEVICE TABLE (latest record per MAC within the selected time range)
# =============================================================================
def build_device_table(events: pd.DataFrame, mac_to_ip: Dict[str, str]) -> pd.DataFrame:
    if events is None or events.empty:
        return pd.DataFrame()

    tmp = events.copy().dropna(subset=["mac_norm"])
    tmp = tmp[~tmp["mac_norm"].map(is_broadcast_mac)]

    tmp["ts_dt"] = pd.to_datetime(tmp["ts_dt"], errors="coerce")
    tmp = tmp.dropna(subset=["ts_dt"])
    if tmp.empty:
        return pd.DataFrame()

    if "host" in tmp.columns:
        tmp["host"] = tmp["host"].astype("string").replace(["nan", "None", "none", "-", ""], pd.NA)
    if "ip" in tmp.columns:
        tmp["ip"] = tmp["ip"].astype("string").replace(["None", "none", "-", "nan", "0.0.0.0", "Unknown IP", ""], pd.NA)

    idx = tmp.groupby("mac_norm")["ts_dt"].idxmax()
    latest = tmp.loc[idx].copy()

    host_last = (
        tmp.dropna(subset=["host"])
        .sort_values("ts_dt")
        .groupby("mac_norm")["host"]
        .last()
    )
    latest["host"] = latest["mac_norm"].map(host_last)

    ip_last = (
        tmp.dropna(subset=["ip"])
        .sort_values("ts_dt")
        .groupby("mac_norm")["ip"]
        .last()
    )
    latest["ip"] = latest["mac_norm"].map(ip_last)

    # Fill IP from known_hosts if still missing
    latest["ip"] = latest.apply(
        lambda r: mac_to_ip.get(r["mac_norm"]) if pd.isna(r["ip"]) else r["ip"],
        axis=1,
    )

    src_agg = (
        tmp.groupby("mac_norm")["source"]
        .apply(lambda s: ", ".join(sorted(set(map(str, s)))))
        .to_dict()
    )
    latest["seen_in"] = latest["mac_norm"].map(lambda m: src_agg.get(m, ""))

    return latest.sort_values("ts_dt", ascending=False)


# =============================================================================
# TABLE RENDER HELPERS
# =============================================================================
def build_display_table(df: pd.DataFrame) -> pd.DataFrame:
    return (
        df[["ts_dt", "ip", "mac_norm", "vendor", "host", "seen_in", "status"]]
        .rename(
            columns={
                "ts_dt": "Last Seen",
                "ip": "IP Address",
                "mac_norm": "MAC Address",
                "vendor": "Vendor",
                "host": "Host Name",
                "seen_in": "Source",
                "status": "Status",
            }
        )
        .copy()
    )


def style_status(val):
    return "color:#ff4b4b;font-weight:bold;" if str(val) == "Unauthorized" else ""


# =============================================================================
# TIME-RANGE LOADERS (cached)
# =============================================================================
@st.cache_data(show_spinner=False)
def _load_events_and_known_hosts_for_dirs(dir_paths: Tuple[str, ...]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Cached disk I/O: read parquet files inside the provided date directories, then return:
      (all_events, known_hosts_concat)
    """
    events: List[pd.DataFrame] = []
    known_hosts_all: List[pd.DataFrame] = []

    for dir_str in dir_paths:
        day_dir = Path(dir_str)

        dhcp_file = _find_log_file_in_day(day_dir, ["dhcp"])
        arp_file = _find_log_file_in_day(day_dir, ["arp"])
        conn_file = _find_log_file_in_day(day_dir, ["conn"])
        known_hosts_file = _find_log_file_in_day(day_dir, ["known_hosts", "knownhost"])

        if known_hosts_file:
            kh_df = read_parquet_safe(known_hosts_file)
            if not kh_df.empty:
                known_hosts_all.append(kh_df)

        for fpath, src in [(dhcp_file, "dhcp"), (arp_file, "arp"), (conn_file, "conn")]:
            if not fpath:
                continue
            df = read_parquet_safe(fpath)
            if df.empty:
                continue
            fallback = pd.Timestamp.fromtimestamp(os.path.getmtime(fpath))
            ev = extract_device_events(df, src, fallback)
            if not ev.empty:
                events.append(ev)

    all_events = (
        pd.concat(events, ignore_index=True)
        if events
        else pd.DataFrame(columns=["ts_dt", "mac_norm", "ip", "host", "source"])
    )
    known_hosts = pd.concat(known_hosts_all, ignore_index=True) if known_hosts_all else pd.DataFrame()
    return all_events, known_hosts


def _apply_time_filter(events: pd.DataFrame, mode: str, selected_date: Optional[str]) -> Tuple[pd.DataFrame, str]:
    """
    Apply the final time filter to events (even if we pre-selected directories),
    returning (filtered_events, human_label).
    """
    if events is None or events.empty:
        return events, ""

    now = datetime.now()
    tmp = events.copy()
    tmp["ts_dt"] = pd.to_datetime(tmp["ts_dt"], errors="coerce")
    tmp = tmp.dropna(subset=["ts_dt"])

    if mode == "Last 7 Days":
        cutoff = now - timedelta(days=7)
        tmp = tmp[tmp["ts_dt"] >= cutoff]
        return tmp, f"Last 7 Days (since {cutoff.strftime('%Y-%m-%d %H:%M')})"

    if mode == "Specific Date" and selected_date:
        start = datetime.strptime(selected_date, "%Y-%m-%d")
        end = start + timedelta(days=1)
        tmp = tmp[(tmp["ts_dt"] >= start) & (tmp["ts_dt"] < end)]
        return tmp, f"Specific Date ({selected_date})"

    return tmp, "All Time"


# =============================================================================
# MAIN RENDER
# =============================================================================
def render(parquet_root: str, authorized_macs_file: str):
    root = Path(parquet_root)
    if not root.exists():
        st.error(f"Directory '{parquet_root}' not found.")
        return

    by_date = _discover_date_dirs(root)
    available_dates = sorted(by_date.keys(), reverse=True)

    st.session_state.setdefault("alerts_time_mode", "Last 7 Days")
    st.session_state.setdefault("alerts_time_date", available_dates[0] if available_dates else None)

    tr_col1, tr_col2 = st.columns([1.2, 2.8], vertical_alignment="center")
    with tr_col1:
        time_mode = st.selectbox(
            "Time Range:",
            ["Last 7 Days", "Specific Date", "All Time"],
            index=["Last 7 Days", "Specific Date", "All Time"].index(st.session_state["alerts_time_mode"])
            if st.session_state["alerts_time_mode"] in ["Last 7 Days", "Specific Date", "All Time"]
            else 0,
            key="alerts_time_mode",
        )

    selected_date = None
    with tr_col2:
        if time_mode == "Specific Date":
            if not available_dates:
                st.info("No date folders (YYYY-MM-DD) found under your parquet root.")
            else:
                selected_date = st.selectbox(
                    "Select Date:",
                    options=available_dates,
                    index=0
                    if st.session_state.get("alerts_time_date") not in available_dates
                    else available_dates.index(st.session_state["alerts_time_date"]),
                    key="alerts_time_date",
                )
        else:
            st.write("")

    dir_paths: List[str] = []

    if not available_dates:
        st.info("Date folders not detected. Falling back to latest DHCP/ARP/CONN parquet files found in the tree.")

        allowed_macs = load_authorized_macs(authorized_macs_file)

        def _find_latest_matching(parquet_root_path: Path, keywords: List[str]) -> Optional[Path]:
            files = list(parquet_root_path.rglob("*.parquet"))
            if not files:
                return None
            matches = [f for f in files if any(k in f.name.lower() for k in keywords)]
            if not matches:
                return None
            matches.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            return matches[0]

        dhcp_file = _find_latest_matching(root, ["dhcp"])
        arp_file = _find_latest_matching(root, ["arp"])
        conn_file = _find_latest_matching(root, ["conn"])
        known_hosts_file = _find_latest_matching(root, ["known_hosts", "knownhost"])

        known_hosts_df = read_parquet_safe(known_hosts_file)
        mac_to_ip, mac_to_vendor = build_known_maps(known_hosts_df)

        dhcp_df = read_parquet_safe(dhcp_file)
        arp_df = read_parquet_safe(arp_file)
        conn_df = read_parquet_safe(conn_file)

        dhcp_mtime = pd.Timestamp.fromtimestamp(os.path.getmtime(dhcp_file)) if dhcp_file else None
        arp_mtime = pd.Timestamp.fromtimestamp(os.path.getmtime(arp_file)) if arp_file else None
        conn_mtime = pd.Timestamp.fromtimestamp(os.path.getmtime(conn_file)) if conn_file else None

        events = []
        for df, src, fb in [(dhcp_df, "dhcp", dhcp_mtime), (arp_df, "arp", arp_mtime), (conn_df, "conn", conn_mtime)]:
            ev = extract_device_events(df, src, fb)
            if not ev.empty:
                events.append(ev)

        if not events:
            st.warning(
                "No MAC-bearing device events found. "
                "Usually means your parquet logs don't include MAC fields (DHCP/ARP) or the MAC column names differ."
            )
            return

        all_events = pd.concat(events, ignore_index=True)
        all_events, range_label = _apply_time_filter(all_events, time_mode, selected_date)

        if all_events.empty:
            st.info(f"No events found for the selected time range: {range_label}.")
            return

        devices = build_device_table(all_events, mac_to_ip)
        if devices.empty:
            st.info(f"No devices found for the selected time range: {range_label}.")
            return

        mac_lookup = get_vendor_lookup_instance()
        devices["vendor"] = devices["mac_norm"].map(lambda m: resolve_vendor(m, mac_to_vendor, mac_lookup))
        devices["status"] = devices["mac_norm"].map(lambda m: "Verified" if m in allowed_macs else "Unauthorized")

        _render_alerts_ui(devices, range_label)
        return

    if time_mode == "All Time":
        for d in available_dates:
            for p in by_date[d]:
                dir_paths.append(str(p))
    elif time_mode == "Specific Date" and selected_date:
        for p in by_date.get(selected_date, []):
            dir_paths.append(str(p))
    else:
        cutoff_date = (datetime.now().date() - timedelta(days=7))
        for d in available_dates:
            try:
                dd = datetime.strptime(d, "%Y-%m-%d").date()
            except Exception:
                continue
            if dd >= cutoff_date:
                for p in by_date[d]:
                    dir_paths.append(str(p))

    if not dir_paths:
        st.info("No parquet date folders matched the selected time range.")
        return

    all_events, known_hosts_df = _load_events_and_known_hosts_for_dirs(tuple(dir_paths))
    all_events, range_label = _apply_time_filter(all_events, time_mode, selected_date)

    if all_events.empty:
        st.info(f"No events found for the selected time range: {range_label}.")
        return

    mac_to_ip, mac_to_vendor = build_known_maps(known_hosts_df)
    devices = build_device_table(all_events, mac_to_ip)

    if devices.empty:
        st.info(f"No devices found for the selected time range: {range_label}.")
        return

    allowed_macs = load_authorized_macs(authorized_macs_file)
    mac_lookup = get_vendor_lookup_instance()
    devices["vendor"] = devices["mac_norm"].map(lambda m: resolve_vendor(m, mac_to_vendor, mac_lookup))
    devices["status"] = devices["mac_norm"].map(lambda m: "Verified" if m in allowed_macs else "Unauthorized")

    _render_alerts_ui(devices, range_label)


# =============================================================================
# UI RENDER (kept isolated so render() stays readable)
# =============================================================================
def _render_alerts_ui(devices: pd.DataFrame, range_label: str) -> None:
    verified_df = devices[devices["status"] == "Verified"].copy()
    unauth_df = devices[devices["status"] == "Unauthorized"].copy()

    st.session_state.setdefault("unauth_macs_view", "Unauthorized")

    st.divider()
    colA, colB, colC = st.columns(3)

    with colA:
        st.metric("Total Devices Seen", int(len(devices)))
        if st.button("View Total Devices", use_container_width=True, key="view_total_devices"):
            st.session_state["unauth_macs_view"] = "Total"

    with colB:
        st.metric("Verified Devices", int(len(verified_df)))
        if st.button("View Verified Devices", use_container_width=True, key="view_verified_devices"):
            st.session_state["unauth_macs_view"] = "Verified"

    with colC:
        st.metric("Unauthorized Devices", int(len(unauth_df)))
        if st.button("View Unauthorized Devices", use_container_width=True, key="view_unauthorized_devices"):
            st.session_state["unauth_macs_view"] = "Unauthorized"

    if len(unauth_df) > 0:
        st.error(f"SECURITY ALERT: {len(unauth_df)} UNAUTHORIZED DEVICE(S) DETECTED — {range_label}")
    else:
        st.success(f"System Secure. No unauthorized devices detected — {range_label}")

    view = st.session_state.get("unauth_macs_view", "Unauthorized")

    if view == "Total":
        st.subheader(f"All Devices (Latest Seen) — {range_label}")
        df_to_show = devices.copy()
    elif view == "Verified":
        st.subheader(f"Verified Devices (Latest Seen) — {range_label}")
        df_to_show = verified_df
    else:
        st.subheader(f"Unauthorized Devices (Latest Seen) — {range_label}")
        df_to_show = unauth_df

    if df_to_show.empty:
        st.info("No records to display.")
        return

    table = build_display_table(df_to_show)

    st.dataframe(
        table.style.map(style_status, subset=["Status"]),
        use_container_width=True,
        hide_index=True,
        column_config={"Last Seen": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD HH:mm:ss")},
    )
