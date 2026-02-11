# ui/pages/unauthorized_macs.py
# Streamlit module: detects Unauthorized MACs from Zeek parquet (DHCP/ARP/CONN),
# keeps "Last Seen" per MAC, and fills Host Name/IP using the latest non-null value per MAC.
#
# UI:
# - No auto-refresh controls
# - Adds buttons to view details:
#   View Total Devices / View Verified / View Unauthorized

import os
import re
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
# NORMALIZATION
# =============================================================================
_MAC_HEX_RE = re.compile(r"[^0-9a-fA-F]")


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
    return ":".join(hx[i:i + 2] for i in range(0, 12, 2)).lower()


def is_broadcast_mac(mac: Optional[str]) -> bool:
    return mac == "ff:ff:ff:ff:ff:ff"


def to_datetime_series(s: pd.Series) -> pd.Series:
    """Convert Zeek ts float seconds or strings to pandas datetime."""
    if s is None:
        return pd.Series([pd.NaT] * 0, dtype="datetime64[ns]")
    if pd.api.types.is_numeric_dtype(s):
        return pd.to_datetime(s, unit="s", errors="coerce")
    return pd.to_datetime(s, errors="coerce")


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
def find_latest_matching(parquet_root: Path, keywords: List[str]) -> Optional[Path]:
    files = list(parquet_root.rglob("*.parquet"))
    if not files:
        return None

    matches = [f for f in files if any(k in f.name.lower() for k in keywords)]
    if not matches:
        return None

    matches.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return matches[0]


def read_parquet_safe(path: Optional[Path]) -> pd.DataFrame:
    if not path:
        return pd.DataFrame()
    try:
        return pd.read_parquet(path)
    except Exception:
        return pd.DataFrame()


# =============================================================================
# AUTHORIZED MACS (YAML)
# =============================================================================
def load_authorized_macs(auth_file: str) -> set:
    """
    Supports YAML forms:
      - authorized_macs: ["aa:bb:..", ...]
      - authorized_macs: [{"mac": "aa:bb:.."}, ...]
      - ["aa:bb:..", ...]
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
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        st.error(f"Error reading authorized MACs file: {e}")
        return allowed

    raw_list = []
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                raw_list = v
                break
    elif isinstance(data, list):
        raw_list = data

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
    mac_to_ip = {}
    mac_to_vendor = {}

    if known_hosts_df is None or known_hosts_df.empty:
        return mac_to_ip, mac_to_vendor

    mac_col = best_column(known_hosts_df, score_mac_column, ["mac", "MAC Address", "host_mac", "l2addr"])
    ip_col = best_column(known_hosts_df, score_ip_column, ["host_ip", "ip", "IP Address", "addr"])
    vendor_col = None
    for c in ["vendor", "Vendor", "manuf", "manufacturer"]:
        if c in known_hosts_df.columns:
            vendor_col = c
            break

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

    host_col = None
    for c in ["host_name", "client_fqdn", "hostname", "host", "Host Name", "computer_name"]:
        if c in df.columns:
            host_col = c
            break

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
    return out


# =============================================================================
# BUILD DEVICE TABLE
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
        tmp["ip"] = tmp["ip"].astype("string").replace(
            ["None", "none", "-", "nan", "0.0.0.0", "Unknown IP", ""], pd.NA
        )

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
                "seen_in": "Seen In",
                "status": "Status",
            }
        )
        .copy()
    )


def style_status(val):
    return "color:#ff4b4b;font-weight:bold;" if str(val) == "Unauthorized" else ""


# =============================================================================
# MAIN RENDER
# =============================================================================
def render(parquet_root: str, authorized_macs_file: str):
    root = Path(parquet_root)
    if not root.exists():
        st.error(f"Directory '{parquet_root}' not found.")
        return

    allowed_macs = load_authorized_macs(authorized_macs_file)

    dhcp_file = find_latest_matching(root, ["dhcp"])
    arp_file = find_latest_matching(root, ["arp"])
    conn_file = find_latest_matching(root, ["conn"])
    known_hosts_file = find_latest_matching(root, ["known_hosts", "knownhost"])

    known_hosts_df = read_parquet_safe(known_hosts_file)
    mac_to_ip, mac_to_vendor = build_known_maps(known_hosts_df)

    dhcp_df = read_parquet_safe(dhcp_file)
    arp_df = read_parquet_safe(arp_file)
    conn_df = read_parquet_safe(conn_file)

    dhcp_mtime = pd.Timestamp.fromtimestamp(os.path.getmtime(dhcp_file)) if dhcp_file else None
    arp_mtime = pd.Timestamp.fromtimestamp(os.path.getmtime(arp_file)) if arp_file else None
    conn_mtime = pd.Timestamp.fromtimestamp(os.path.getmtime(conn_file)) if conn_file else None

    events = []
    e1 = extract_device_events(dhcp_df, "dhcp", dhcp_mtime)
    if not e1.empty:
        events.append(e1)

    e2 = extract_device_events(arp_df, "arp", arp_mtime)
    if not e2.empty:
        events.append(e2)

    e3 = extract_device_events(conn_df, "conn", conn_mtime)
    if not e3.empty:
        events.append(e3)

    if not events:
        st.warning(
            "No MAC-bearing device events found. "
            "Usually means your parquet logs don't include MAC fields (DHCP/ARP) or the MAC column names differ."
        )
        return

    all_events = pd.concat(events, ignore_index=True)
    devices = build_device_table(all_events, mac_to_ip)

    if devices.empty:
        st.warning(
            "No valid device MAC events found after normalization. "
            "Most common reason: MAC column exists but values are not valid MAC format, or timestamps are missing."
        )
        return

    mac_lookup = get_vendor_lookup_instance()
    devices["vendor"] = devices["mac_norm"].map(lambda m: resolve_vendor(m, mac_to_vendor, mac_lookup))
    devices["status"] = devices["mac_norm"].map(lambda m: "Verified" if m in allowed_macs else "Unauthorized")

    verified_df = devices[devices["status"] == "Verified"].copy()
    unauth_df = devices[devices["status"] == "Unauthorized"].copy()

    # Default view mode
    st.session_state.setdefault("unauth_macs_view", "Unauthorized")

    # Metrics + View Buttons
    st.divider()
    colA, colB, colC = st.columns(3)

    with colA:
        st.metric("Total Devices Seen", len(devices))
        if st.button("View Total Devices", use_container_width=True, key="view_total_devices"):
            st.session_state["unauth_macs_view"] = "Total"

    with colB:
        st.metric("Verified Devices", len(verified_df))
        if st.button("View Verified Devices", use_container_width=True, key="view_verified_devices"):
            st.session_state["unauth_macs_view"] = "Verified"

    with colC:
        st.metric("Unauthorized Devices", len(unauth_df))
        if st.button("View Unauthorized Devices", use_container_width=True, key="view_unauthorized_devices"):
            st.session_state["unauth_macs_view"] = "Unauthorized"

    # Summary banner
    if len(unauth_df) > 0:
        st.error(f"SECURITY ALERT: {len(unauth_df)} UNAUTHORIZED DEVICE(S) DETECTED")
    else:
        st.success("System Secure. No unauthorized devices detected in MAC-bearing logs.")

    # Render selected table
    view = st.session_state.get("unauth_macs_view", "Unauthorized")

    if view == "Total":
        st.subheader("All Devices (Latest Seen)")
        df_to_show = devices.copy()
    elif view == "Verified":
        st.subheader("Verified Devices (Latest Seen)")
        df_to_show = verified_df
    else:
        st.subheader("Unauthorized Devices (Latest Seen)")
        df_to_show = unauth_df

    if df_to_show.empty:
        st.info("No records to display.")
        return

    table = build_display_table(df_to_show)

    st.dataframe(
        table.style.map(style_status, subset=["Status"]),
        use_container_width=True,
        hide_index=True,
        column_config={
            "Last Seen": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD HH:mm:ss")
        },
    )
