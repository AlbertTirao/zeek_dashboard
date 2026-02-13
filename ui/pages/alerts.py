# ui/pages/alerts.py
# Fast + accurate Alerts page (DuckDB + per-date/per-dir cache) for Zeek parquet (DHCP/ARP/CONN + known_hosts)
#
# UI change requested:
# - ✅ REMOVE: "Removed from Allowlist (since last check)" metric
# - ✅ REMOVE: "Show removed allowlist MACs" checkbox
# - ✅ KEEP LOGIC ALWAYS ON: removed-from-allowlist MACs are still surfaced as alerts + rows

import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import duckdb
import pandas as pd
import streamlit as st
import yaml

# --- Optional vendor lookup (fallback) ---
try:
    from mac_vendor_lookup import MacLookup  # pip install mac-vendor-lookup
    VENDOR_LIB_AVAILABLE = True
except Exception:
    VENDOR_LIB_AVAILABLE = False


# =============================================================================
# CONFIG
# =============================================================================
CACHE_VERSION = "alerts-cache-v2-duckdb-tsfix-schemaprobe-tzfix-ui2"
CACHE_DIRNAME = "_cache_alerts"

DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAC_HEX_RE = re.compile(r"[^0-9a-fA-F]")

PREFERRED_AUTH_KEYS = [
    "authorized_macs",
    "allowlist",
    "authorized_devices",
    "devices",
    "authorized",
]

SRC_DEFS = [
    ("dhcp", ["dhcp"]),
    ("arp", ["arp"]),
    ("conn", ["conn"]),
]
KNOWN_HOSTS_KEYWORDS = ["known_hosts", "knownhost", "known-hosts"]


# =============================================================================
# DUCKDB
# =============================================================================
@st.cache_resource(show_spinner=False)
def _duckdb_conn():
    con = duckdb.connect(database=":memory:")
    try:
        con.execute("PRAGMA threads=4")
    except Exception:
        pass
    return con


def _duckdb_schema_cols(con: duckdb.DuckDBPyConnection, parquet_path: Path) -> List[str]:
    try:
        df = con.execute("DESCRIBE SELECT * FROM parquet_scan(?)", [str(parquet_path)]).df()
        return [str(x) for x in df["column_name"].tolist()]
    except Exception:
        return []


# =============================================================================
# NORMALIZATION
# =============================================================================
def normalize_mac(x) -> Optional[str]:
    if x is None:
        return None
    if isinstance(x, (bytes, bytearray)) and len(x) == 6:
        hx = bytes(x).hex()
    else:
        hx = MAC_HEX_RE.sub("", str(x))
    if len(hx) != 12:
        return None
    return ":".join(hx[i : i + 2] for i in range(0, 12, 2)).lower()


def is_broadcast_mac(mac: Optional[str]) -> bool:
    return mac == "ff:ff:ff:ff:ff:ff"


# =============================================================================
# YAML ALLOWLIST
# =============================================================================
def _extract_yaml_list(data, stem_key: str, preferred_keys: List[str]) -> List:
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


def load_authorized_macs(auth_file: str) -> set:
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
# CACHE HELPERS (per-date + per-physical-dir)
# =============================================================================
def cache_dir(parquet_root: Path) -> Path:
    return parquet_root / CACHE_DIRNAME


def _dir_key(date_dir: Path) -> str:
    return hashlib.md5(str(date_dir).encode("utf-8")).hexdigest()[:10]


def _cache_dir_for(parquet_root: Path, date_str: str, date_dir: Path) -> Path:
    return cache_dir(parquet_root) / f"date={date_str}" / f"src={_dir_key(date_dir)}"


def _events_cache_path(parquet_root: Path, date_str: str, date_dir: Path) -> Path:
    return _cache_dir_for(parquet_root, date_str, date_dir) / "alerts_events.parquet"


def _known_hosts_cache_path(parquet_root: Path, date_str: str, date_dir: Path) -> Path:
    return _cache_dir_for(parquet_root, date_str, date_dir) / "known_hosts_norm.parquet"


def _meta_path(parquet_root: Path, date_str: str, date_dir: Path) -> Path:
    return _cache_dir_for(parquet_root, date_str, date_dir) / "meta.json"


def _file_sig(p: Optional[Path]) -> Optional[dict]:
    if not p or not p.exists():
        return None
    try:
        st_ = p.stat()
        return {"path": str(p), "mtime": float(st_.st_mtime), "size": int(st_.st_size)}
    except Exception:
        return {"path": str(p), "mtime": None, "size": None}


def _compute_signature(
    date_str: str,
    date_dir: Path,
    dhcp_path: Optional[Path],
    arp_path: Optional[Path],
    conn_path: Optional[Path],
    known_hosts_path: Optional[Path],
) -> dict:
    return {
        "cache_version": CACHE_VERSION,
        "date": date_str,
        "date_dir": str(date_dir),
        "inputs": {
            "dhcp": _file_sig(dhcp_path),
            "arp": _file_sig(arp_path),
            "conn": _file_sig(conn_path),
            "known_hosts": _file_sig(known_hosts_path),
        },
    }


def _read_meta(meta_p: Path) -> Optional[dict]:
    if not meta_p.exists():
        return None
    try:
        return json.loads(meta_p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_meta(meta_p: Path, meta: dict) -> None:
    meta_p.parent.mkdir(parents=True, exist_ok=True)
    meta_p.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")


def _cache_is_fresh(meta_p: Path, expected_meta: dict) -> bool:
    return _read_meta(meta_p) == expected_meta


# =============================================================================
# PARQUET DISCOVERY
# =============================================================================
def _extract_date_from_dirname(name: str) -> Optional[str]:
    if DATE_DIR_RE.match(name):
        return name
    if name.startswith("date="):
        tail = name.split("date=", 1)[1]
        if DATE_DIR_RE.match(tail):
            return tail
    return None


def _discover_date_dirs(parquet_root: Path) -> Dict[str, List[Path]]:
    by_date: Dict[str, List[Path]] = {}
    for d in parquet_root.rglob("*"):
        if not d.is_dir():
            continue
        ds = _extract_date_from_dirname(d.name)
        if ds:
            by_date.setdefault(ds, []).append(d)
    for k in list(by_date.keys()):
        by_date[k] = sorted(by_date[k], key=lambda p: str(p))
    return by_date


def _find_log_file_in_day(day_dir: Path, keywords: List[str]) -> Optional[Path]:
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


# =============================================================================
# DUCKDB SQL HELPERS
# =============================================================================
def _duck_mac_norm_expr(col_sql: str) -> str:
    hx = f"regexp_replace(lower(cast({col_sql} as varchar)), '[^0-9a-f]', '', 'g')"
    return (
        "case "
        f"when length({hx}) = 12 then "
        f"substr({hx},1,2)||':'||substr({hx},3,2)||':'||substr({hx},5,2)||':'||substr({hx},7,2)||':'||substr({hx},9,2)||':'||substr({hx},11,2) "
        "else NULL end"
    )


def _duck_ts_expr(col_sql: str) -> str:
    ts_as_ts = f"try_cast({col_sql} as timestamp)"
    v = f"try_cast({col_sql} as double)"

    v_as_seconds = (
        "case "
        f"when {v} is null then null "
        f"when abs({v}) > 1e17 then ({v} / 1e9) "
        f"when abs({v}) > 1e14 then ({v} / 1e6) "
        f"when abs({v}) > 1e11 then ({v} / 1e3) "
        f"else {v} end"
    )

    ts_from_num = f"to_timestamp({v_as_seconds})"
    return (
        "case "
        f"when {ts_as_ts} is not null then {ts_as_ts} "
        f"when {v} is not null then {ts_from_num} "
        "else null end"
    )


def _choose_first_present(cols: List[str], preferred: List[str]) -> Optional[str]:
    colset = set(cols)
    for c in preferred:
        if c in colset:
            return c
    return None


# =============================================================================
# BUILD PER-DIR CACHE
# =============================================================================
def _build_cache_for_date_dir(
    con: duckdb.DuckDBPyConnection,
    parquet_root: Path,
    date_str: str,
    date_dir: Path,
) -> Tuple[Path, Path]:
    dhcp_path = _find_log_file_in_day(date_dir, ["dhcp"])
    arp_path = _find_log_file_in_day(date_dir, ["arp"])
    conn_path = _find_log_file_in_day(date_dir, ["conn"])
    known_hosts_path = _find_log_file_in_day(date_dir, KNOWN_HOSTS_KEYWORDS)

    expected_meta = _compute_signature(date_str, date_dir, dhcp_path, arp_path, conn_path, known_hosts_path)

    events_out = _events_cache_path(parquet_root, date_str, date_dir)
    kh_out = _known_hosts_cache_path(parquet_root, date_str, date_dir)
    meta_p = _meta_path(parquet_root, date_str, date_dir)

    events_out.parent.mkdir(parents=True, exist_ok=True)

    if events_out.exists() and kh_out.exists() and _cache_is_fresh(meta_p, expected_meta):
        return events_out, kh_out

    # 1) Events
    parts: List[str] = []
    for src_name, src_path, mac_pref, ip_pref, host_pref, ts_pref in [
        (
            "dhcp",
            dhcp_path,
            ["client_chaddr", "chaddr", "client_mac", "mac", "hardware_address"],
            ["assigned_addr", "client_addr", "id.orig_h", "id.resp_h", "src_ip", "dst_ip", "ip"],
            ["host_name", "client_fqdn", "hostname", "host"],
            ["ts", "timestamp", "time"],
        ),
        (
            "arp",
            arp_path,
            ["mac", "orig_l2_addr", "resp_l2_addr", "orig_mac", "resp_mac", "hardware_address"],
            ["id.orig_h", "id.resp_h", "src_ip", "dst_ip", "ip"],
            ["host_name", "hostname", "host"],
            ["ts", "timestamp", "time"],
        ),
        (
            "conn",
            conn_path,
            ["orig_l2_addr", "resp_l2_addr", "orig_mac", "resp_mac", "mac"],
            ["id.orig_h", "id.resp_h", "src_ip", "dst_ip", "ip"],
            ["host_name", "hostname", "host"],
            ["ts", "timestamp", "time"],
        ),
    ]:
        if not src_path or not src_path.exists():
            continue

        cols = _duckdb_schema_cols(con, src_path)
        if not cols:
            continue

        mac_col = _choose_first_present(cols, mac_pref)
        ts_col = _choose_first_present(cols, ts_pref)
        ip_col = _choose_first_present(cols, ip_pref)
        host_col = _choose_first_present(cols, host_pref)
        if not mac_col:
            continue

        mac_norm = _duck_mac_norm_expr(f'"{mac_col}"')
        ts_dt = _duck_ts_expr(f'"{ts_col}"') if ts_col else "NULL"
        ip_sql = f'cast("{ip_col}" as varchar)' if ip_col else "NULL"
        host_sql = f'cast("{host_col}" as varchar)' if host_col else "NULL"

        parts.append(
            f"""
            SELECT
              {ts_dt} AS ts_dt,
              {mac_norm} AS mac_norm,
              NULLIF(NULLIF({ip_sql}, ''), 'nan') AS ip,
              NULLIF(NULLIF({host_sql}, ''), 'nan') AS host,
              '{src_name}' AS source
            FROM parquet_scan('{str(src_path).replace("'", "''")}')
            """
        )

    if parts:
        union_sql = "\nUNION ALL\n".join(parts)
        final_sql = f"""
        SELECT ts_dt, mac_norm, ip, host, source
        FROM ({union_sql})
        WHERE mac_norm IS NOT NULL
          AND ts_dt IS NOT NULL
          AND mac_norm != 'ff:ff:ff:ff:ff:ff'
        """
        con.execute(f"COPY ({final_sql}) TO '{str(events_out).replace("'", "''")}' (FORMAT PARQUET)")
    else:
        pd.DataFrame(columns=["ts_dt", "mac_norm", "ip", "host", "source"]).to_parquet(events_out, index=False)

    # 2) known_hosts
    if known_hosts_path and known_hosts_path.exists():
        cols = _duckdb_schema_cols(con, known_hosts_path)
        mac_col = _choose_first_present(cols, ["mac", "MAC Address", "host_mac", "l2addr"])
        ip_col = _choose_first_present(cols, ["host_ip", "ip", "addr", "IP Address", "host"])
        vendor_col = _choose_first_present(cols, ["vendor", "Vendor", "manuf", "manufacturer"])

        if mac_col:
            mac_norm = _duck_mac_norm_expr(f'"{mac_col}"')
            ip_sql = f'cast("{ip_col}" as varchar)' if ip_col else "NULL"
            vendor_sql = f'cast("{vendor_col}" as varchar)' if vendor_col else "NULL"
            kh_sql = f"""
            SELECT
              {mac_norm} AS mac_norm,
              NULLIF(NULLIF({ip_sql}, ''), 'nan') AS ip,
              NULLIF(NULLIF({vendor_sql}, ''), 'nan') AS vendor
            FROM parquet_scan('{str(known_hosts_path).replace("'", "''")}')
            WHERE {mac_norm} IS NOT NULL
            """
            con.execute(f"COPY ({kh_sql}) TO '{str(kh_out).replace("'", "''")}' (FORMAT PARQUET)")
        else:
            pd.DataFrame(columns=["mac_norm", "ip", "vendor"]).to_parquet(kh_out, index=False)
    else:
        pd.DataFrame(columns=["mac_norm", "ip", "vendor"]).to_parquet(kh_out, index=False)

    _write_meta(meta_p, expected_meta)
    return events_out, kh_out


def _load_cached_for_date_dirs(
    parquet_root: Path,
    selected_date_dirs: List[Tuple[str, Path]],
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    con = _duckdb_conn()
    ev_all: List[pd.DataFrame] = []
    kh_all: List[pd.DataFrame] = []

    for date_str, date_dir in selected_date_dirs:
        events_p, kh_p = _build_cache_for_date_dir(con, parquet_root, date_str, date_dir)

        try:
            df = pd.read_parquet(events_p)
            if not df.empty:
                ev_all.append(df)
        except Exception:
            pass

        try:
            kh = pd.read_parquet(kh_p)
            if not kh.empty:
                kh_all.append(kh)
        except Exception:
            pass

    events = pd.concat(ev_all, ignore_index=True) if ev_all else pd.DataFrame(
        columns=["ts_dt", "mac_norm", "ip", "host", "source"]
    )
    known_hosts = pd.concat(kh_all, ignore_index=True) if kh_all else pd.DataFrame(
        columns=["mac_norm", "ip", "vendor"]
    )
    return events, known_hosts


# =============================================================================
# BUSINESS LOGIC
# =============================================================================
def _apply_time_filter(events: pd.DataFrame, mode: str, selected_date: Optional[str]) -> Tuple[pd.DataFrame, str]:
    if events is None or events.empty:
        return events, ""

    tmp = events.copy()
    tmp["ts_dt"] = pd.to_datetime(tmp["ts_dt"], errors="coerce")

    tz = getattr(tmp["ts_dt"].dtype, "tz", None)
    is_tz_aware = tz is not None
    now = pd.Timestamp.now(tz="UTC") if is_tz_aware else pd.Timestamp.now()

    tmp = tmp.dropna(subset=["ts_dt", "mac_norm"])

    if mode == "Last 7 Days":
        cutoff = now - pd.Timedelta(days=7)
        tmp = tmp[tmp["ts_dt"] >= cutoff]
        return tmp, f"Last 7 Days (since {cutoff.strftime('%Y-%m-%d %H:%M')})"

    if mode == "Specific Date" and selected_date:
        start_naive = datetime.strptime(selected_date, "%Y-%m-%d")
        if is_tz_aware:
            start = pd.Timestamp(start_naive, tz="UTC")
            end = start + pd.Timedelta(days=1)
        else:
            start = pd.Timestamp(start_naive)
            end = start + pd.Timedelta(days=1)
        tmp = tmp[(tmp["ts_dt"] >= start) & (tmp["ts_dt"] < end)]
        return tmp, f"Specific Date ({selected_date})"

    return tmp, "All Time"


def build_known_maps(known_hosts_df: pd.DataFrame) -> Tuple[Dict[str, str], Dict[str, str]]:
    mac_to_ip: Dict[str, str] = {}
    mac_to_vendor: Dict[str, str] = {}

    if known_hosts_df is None or known_hosts_df.empty:
        return mac_to_ip, mac_to_vendor

    kh = known_hosts_df.copy()
    kh["mac_norm"] = kh["mac_norm"].astype("string")
    kh = kh.dropna(subset=["mac_norm"])

    if "ip" in kh.columns:
        kh_ip = kh.dropna(subset=["ip"]).copy()
        mac_to_ip = dict(zip(kh_ip["mac_norm"].astype(str), kh_ip["ip"].astype(str)))

    if "vendor" in kh.columns:
        kh_v = kh.dropna(subset=["vendor"]).copy()
        mac_to_vendor = dict(zip(kh_v["mac_norm"].astype(str), kh_v["vendor"].astype(str)))

    return mac_to_ip, mac_to_vendor


def build_device_table(events: pd.DataFrame, mac_to_ip: Dict[str, str]) -> pd.DataFrame:
    if events is None or events.empty:
        return pd.DataFrame()

    tmp = events.copy()
    tmp["mac_norm"] = tmp["mac_norm"].astype("string")
    tmp["ts_dt"] = pd.to_datetime(tmp["ts_dt"], errors="coerce")
    tmp = tmp.dropna(subset=["mac_norm", "ts_dt"])

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
        lambda r: mac_to_ip.get(str(r["mac_norm"])) if pd.isna(r.get("ip")) else r.get("ip"),
        axis=1,
    )

    src_agg = (
        tmp.groupby("mac_norm")["source"]
        .apply(lambda s: ", ".join(sorted(set(map(str, s)))))
        .to_dict()
    )
    latest["seen_in"] = latest["mac_norm"].map(lambda m: src_agg.get(str(m), ""))

    return latest.sort_values("ts_dt", ascending=False)


# =============================================================================
# VENDOR LOOKUP
# =============================================================================
@st.cache_resource(show_spinner=False)
def _vendor_lookup():
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
# UI HELPERS
# =============================================================================
def build_display_table(df: pd.DataFrame) -> pd.DataFrame:
    cols = ["ts_dt", "ip", "mac_norm", "vendor", "host", "seen_in", "status"]
    if "note" in df.columns:
        cols.append("note")

    out = df[cols].rename(
        columns={
            "ts_dt": "Last Seen",
            "ip": "IP Address",
            "mac_norm": "MAC Address",
            "vendor": "Vendor",
            "host": "Host Name",
            "seen_in": "Source",
            "status": "Status",
            "note": "Note",
        }
    ).copy()
    return out


def style_status(val):
    return "color:#ff4b4b;font-weight:bold;" if str(val).startswith("Unauthorized") else ""


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

    if not available_dates:
        st.info("No date folders found. Expected 'YYYY-MM-DD' or 'date=YYYY-MM-DD' under parquet root.")
        return

    st.session_state.setdefault("alerts_time_mode", "Last 7 Days")
    st.session_state.setdefault("alerts_time_date", available_dates[0])

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

    allowed_macs = load_authorized_macs(authorized_macs_file)

    # Allowlist-change detection (session-based)
    st.session_state.setdefault("_alerts_prev_allowed_set", None)
    prev_allowed = st.session_state.get("_alerts_prev_allowed_set")
    if prev_allowed is None:
        prev_allowed = set(allowed_macs)
    removed_from_allowlist = sorted(set(prev_allowed) - set(allowed_macs))
    added_to_allowlist = sorted(set(allowed_macs) - set(prev_allowed))
    st.session_state["_alerts_prev_allowed_set"] = set(allowed_macs)

    # Select dirs
    selected_date_dirs: List[Tuple[str, Path]] = []

    if time_mode == "All Time":
        for d in available_dates:
            for p in by_date[d]:
                selected_date_dirs.append((d, p))
    elif time_mode == "Specific Date" and selected_date:
        for p in by_date.get(selected_date, []):
            selected_date_dirs.append((selected_date, p))
    else:
        cutoff = (datetime.now().date() - pd.Timedelta(days=7))
        for d in available_dates:
            try:
                dd = datetime.strptime(d, "%Y-%m-%d").date()
            except Exception:
                continue
            if dd >= cutoff:
                for p in by_date[d]:
                    selected_date_dirs.append((d, p))

    if not selected_date_dirs:
        st.info("No parquet date folders matched the selected time range.")
        _render_alerts_ui(
            devices=pd.DataFrame(columns=["ts_dt", "ip", "mac_norm", "vendor", "host", "seen_in", "status"]),
            range_label="No date folders matched",
            allowed_macs=allowed_macs,
            removed_from_allowlist=removed_from_allowlist,
            added_to_allowlist=added_to_allowlist,
            mac_to_ip={},
            mac_to_vendor={},
            mac_lookup=_vendor_lookup(),
            events=pd.DataFrame(columns=["ts_dt", "mac_norm", "ip", "host", "source"]),
        )
        return

    with st.spinner("Loading alerts (DuckDB cache)…"):
        raw_events, known_hosts_norm = _load_cached_for_date_dirs(root, selected_date_dirs)

    events, range_label = _apply_time_filter(raw_events, time_mode, selected_date)

    mac_to_ip, mac_to_vendor = build_known_maps(known_hosts_norm)
    devices = build_device_table(events, mac_to_ip) if not events.empty else pd.DataFrame(
        columns=["ts_dt", "ip", "mac_norm", "host", "seen_in", "source"]
    )

    mac_lookup = _vendor_lookup()

    if not devices.empty:
        devices["vendor"] = devices["mac_norm"].astype(str).map(lambda m: resolve_vendor(m, mac_to_vendor, mac_lookup))
        devices["status"] = devices["mac_norm"].astype(str).map(
            lambda m: "Verified" if m in allowed_macs else "Unauthorized"
        )
    else:
        devices = pd.DataFrame(columns=["ts_dt", "ip", "mac_norm", "vendor", "host", "seen_in", "status"])

    _render_alerts_ui(
        devices=devices,
        range_label=range_label,
        allowed_macs=allowed_macs,
        removed_from_allowlist=removed_from_allowlist,
        added_to_allowlist=added_to_allowlist,
        mac_to_ip=mac_to_ip,
        mac_to_vendor=mac_to_vendor,
        mac_lookup=mac_lookup,
        events=events,
    )


# =============================================================================
# UI RENDER (removed allowlist logic ALWAYS ON, but UI elements removed)
# =============================================================================
def _render_alerts_ui(
    devices: pd.DataFrame,
    range_label: str,
    allowed_macs: set,
    removed_from_allowlist: List[str],
    added_to_allowlist: List[str],
    mac_to_ip: Dict[str, str],
    mac_to_vendor: Dict[str, str],
    mac_lookup,
    events: pd.DataFrame,
) -> None:
    if devices is None:
        devices = pd.DataFrame()

    verified_df = devices[devices.get("status", "") == "Verified"].copy() if not devices.empty else pd.DataFrame()
    unauth_df = devices[devices.get("status", "") == "Unauthorized"].copy() if not devices.empty else pd.DataFrame()

    # "new unauthorized since last check" (session-based)
    st.session_state.setdefault("_alerts_prev_unauth_set", set())
    current_unauth_set = set(unauth_df["mac_norm"].dropna().astype(str).tolist()) if not unauth_df.empty else set()
    prev_unauth_set = st.session_state.get("_alerts_prev_unauth_set", set()) or set()
    new_unauth = sorted(current_unauth_set - prev_unauth_set)
    st.session_state["_alerts_prev_unauth_set"] = current_unauth_set

    # ---- removed allowlist ALWAYS ON ----
    removed_set = set(removed_from_allowlist)

    last_seen_map = {}
    last_ip_map = {}
    last_host_map = {}
    last_src_map = {}

    if events is not None and not events.empty:
        ev = events.copy()
        ev["ts_dt"] = pd.to_datetime(ev["ts_dt"], errors="coerce")
        ev = ev.dropna(subset=["mac_norm", "ts_dt"])
        if not ev.empty:
            ev = ev.sort_values("ts_dt")
            last_seen_map = ev.groupby("mac_norm")["ts_dt"].last().to_dict()
            last_ip_map = ev.dropna(subset=["ip"]).groupby("mac_norm")["ip"].last().to_dict()
            last_host_map = ev.dropna(subset=["host"]).groupby("mac_norm")["host"].last().to_dict()
            last_src_map = ev.groupby("mac_norm")["source"].apply(lambda s: ", ".join(sorted(set(map(str, s))))).to_dict()

    # Synthetic rows for removed allowlist MACs not currently in devices table (ALWAYS ON)
    if removed_from_allowlist:
        existing = set(devices["mac_norm"].astype(str).tolist()) if not devices.empty and "mac_norm" in devices.columns else set()
        removed_rows = []
        for m in removed_from_allowlist:
            if m in existing:
                continue
            removed_rows.append(
                {
                    "ts_dt": last_seen_map.get(m, pd.NaT),
                    "mac_norm": m,
                    "ip": last_ip_map.get(m) or mac_to_ip.get(m) or pd.NA,
                    "host": last_host_map.get(m) or pd.NA,
                    "seen_in": last_src_map.get(m, ""),
                    "vendor": resolve_vendor(m, mac_to_vendor, mac_lookup),
                    "status": "Unauthorized",
                    "note": "Removed from allowlist",
                }
            )
        if removed_rows:
            devices = pd.concat([devices, pd.DataFrame(removed_rows)], ignore_index=True)

    # annotate existing rows that are removed from allowlist (ALWAYS ON)
    if not devices.empty and "mac_norm" in devices.columns and removed_set:
        if "note" not in devices.columns:
            devices["note"] = ""
        mask = devices["mac_norm"].astype(str).isin(list(removed_set))
        devices.loc[mask, "note"] = devices.loc[mask, "note"].replace("", "Removed from allowlist")

    # Rebuild derived views after augment
    if not devices.empty and "status" in devices.columns:
        verified_df = devices[devices["status"] == "Verified"].copy()
        unauth_df = devices[devices["status"] == "Unauthorized"].copy()
    else:
        verified_df = pd.DataFrame()
        unauth_df = pd.DataFrame()

    st.session_state.setdefault("unauth_macs_view", "Unauthorized")

    st.divider()
    colA, colB, colC, colD = st.columns([1, 1, 1, 1.2])

    with colA:
        st.metric("Total Devices Seen", int(len(devices)) if devices is not None else 0)
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

    with colD:
        st.metric("New Unauthorized (since last check)", int(len(new_unauth)))

    # Priority alerts (removed allowlist still has highest priority, but no "show removed" expander)
    if removed_from_allowlist:
        st.error(f"ALLOWLIST ALERT: {len(removed_from_allowlist)} MAC(s) REMOVED from allowlist — {range_label}")
        st.caption("Removed MACs are included in the table below as 'Unauthorized' with note 'Removed from allowlist'.")
    elif len(new_unauth) > 0:
        st.error(f"ALERT: {len(new_unauth)} NEW UNAUTHORIZED DEVICE(S) DETECTED — {range_label}")
        with st.expander("Show new unauthorized MACs"):
            st.code("\n".join(new_unauth))
    elif len(unauth_df) > 0:
        st.warning(f"Unauthorized devices present: {len(unauth_df)} — {range_label}")
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

    if df_to_show is None or df_to_show.empty:
        st.info("No records to display.")
        return

    if "ts_dt" in df_to_show.columns:
        df_to_show["ts_dt"] = pd.to_datetime(df_to_show["ts_dt"], errors="coerce")

    table = build_display_table(df_to_show)

    st.dataframe(
        table.style.map(style_status, subset=["Status"]),
        use_container_width=True,
        hide_index=True,
        column_config={
            "Last Seen": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD HH:mm:ss"),
        },
    )