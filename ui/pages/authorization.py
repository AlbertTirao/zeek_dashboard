import streamlit as st
from pathlib import Path
import pandas as pd
import datetime
import yaml
import re
import requests
import time
import inspect
from uuid import uuid4

# -----------------------------
# Configuration & Constants
# -----------------------------
MAC_REGEX_PATTERN = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
DOMAIN_REGEX_PATTERN = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
PARQUET_ROOT = Path("data/parquet")
MAC_HEX_RE = re.compile(r"[^0-9a-fA-F]")

# -----------------------------
# Styling & Assets
# -----------------------------
def inject_custom_css():
    """Injects strict, professional CSS for Enterprise Dark Mode."""
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');

        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
        }

        /* Metric Styling */
        div[data-testid="stMetricValue"] {
            font-size: 28px;
            font-weight: 600;
        }
        div[data-testid="stMetricLabel"] {
            font-size: 14px;
            font-weight: 500;
            color: #888;
        }

        /* Inputs & Tables */
        .stTextInput input, .stTextArea textarea, .stSelectbox, div[data-testid="stDataEditor"] {
            border-radius: 4px !important;
        }

        /* Headers */
        h1, h2, h3 {
            font-weight: 600 !important;
            letter-spacing: -0.5px;
        }

        /* Spacing */
        .block-container {
            padding-top: 2rem;
            padding-bottom: 3rem;
        }
        </style>
    """, unsafe_allow_html=True)

# -----------------------------
# Streamlit Compatibility Helpers
# -----------------------------
_DATA_EDITOR_SUPPORTS_HIDE_INDEX = "hide_index" in inspect.signature(st.data_editor).parameters
_DATAFRAME_SUPPORTS_HIDE_INDEX = "hide_index" in inspect.signature(st.dataframe).parameters

def _st_data_editor(df, **kwargs):
    """Wrapper to enforce hide_index=True when supported."""
    if _DATA_EDITOR_SUPPORTS_HIDE_INDEX:
        kwargs.setdefault("hide_index", True)
    return st.data_editor(df, **kwargs)

def _st_dataframe(df, **kwargs):
    """Wrapper to enforce hide_index=True when supported."""
    if _DATAFRAME_SUPPORTS_HIDE_INDEX:
        kwargs.setdefault("hide_index", True)
    return st.dataframe(df, **kwargs)

def _with_row_numbers(df: pd.DataFrame) -> pd.DataFrame:
    """Returns a copy of df with a disabled display-only '#' column inserted first."""
    out = df.copy().reset_index(drop=True)
    out.insert(0, "#", pd.Series(range(1, len(out) + 1), dtype="int64"))
    return out

# -----------------------------
# Helpers
# -----------------------------
def _now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _parse_dt(s: str):
    if not s:
        return None
    try:
        return datetime.datetime.strptime(str(s), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def _file_mtime_str(p: Path):
    try:
        ts = p.stat().st_mtime
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return _now_str()

def normalize_mac(value) -> str:
    """
    Canonicalize MAC to lowercase colon form: aa:bb:cc:dd:ee:ff
    Supports:
      - bytes length 6
      - aa-bb-cc-dd-ee-ff
      - aabb.ccdd.eeff
      - aabbccddeeff
      - aa:bb:cc:dd:ee:ff
    Returns "" if invalid.
    """
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        b = bytes(value)
        if len(b) == 6:
            return ":".join(f"{x:02x}" for x in b)
        try:
            value = b.decode("utf-8", errors="ignore")
        except Exception:
            value = str(b)

    s = str(value).strip().lower()
    if not s:
        return ""

    hx = MAC_HEX_RE.sub("", s)
    if len(hx) != 12:
        return ""
    return ":".join(hx[i:i+2] for i in range(0, 12, 2))

def _mac_is_valid(mac: str) -> bool:
    mac = normalize_mac(mac)
    return bool(re.match(MAC_REGEX_PATTERN, mac))

def _domain_is_valid(domain: str) -> bool:
    return bool(re.match(DOMAIN_REGEX_PATTERN, (domain or "").strip()))

def _dedupe_keep_last(rows: list[dict], key: str) -> list[dict]:
    """Dedupe list of dicts by key, keep the last occurrence."""
    out = {}
    for r in rows:
        k = str(r.get(key, "")).strip().lower()
        if k:
            out[k] = r
    return list(out.values())

# -----------------------------
# Data Logic - Structured (Devices)
# -----------------------------
def load_devices(filepath: Path) -> list[dict]:
    default_structure = {"mac": "", "ip": "", "hostname": "", "vendor": "", "date_modified": ""}

    if not filepath.exists():
        return []

    try:
        data = yaml.safe_load(filepath.read_text(encoding="utf-8"))
        if not data:
            return []

        raw_list = []
        if isinstance(data, list):
            raw_list = data
        elif isinstance(data, dict):
            target_key = filepath.stem
            if target_key in data and isinstance(data[target_key], list):
                raw_list = data[target_key]
            else:
                for val in data.values():
                    if isinstance(val, list):
                        raw_list = val
                        break

        structured = []
        file_stamp = _file_mtime_str(filepath)

        for item in raw_list:
            if isinstance(item, str):
                m = normalize_mac(item)
                if not m:
                    continue
                structured.append({
                    "mac": m,
                    "ip": "", "hostname": "", "vendor": "",
                    "date_modified": file_stamp
                })
            elif isinstance(item, dict):
                entry = default_structure.copy()
                clean_item = {str(k).lower(): v for k, v in item.items()}
                entry.update(clean_item)

                m = normalize_mac(entry.get("mac", ""))
                if not m:
                    continue

                entry["mac"] = m
                entry["ip"] = str(entry.get("ip", "") or "").strip()
                entry["hostname"] = str(entry.get("hostname", "") or "").strip()
                entry["vendor"] = str(entry.get("vendor", "") or "").strip()
                entry["date_modified"] = str(entry.get("date_modified") or file_stamp).strip()
                structured.append(entry)

        structured = _dedupe_keep_last(structured, "mac")
        structured.sort(key=lambda x: x.get("mac", ""))
        return structured

    except Exception as e:
        st.error(f"Error loading devices: {e}")
        return []

def save_devices(filepath: Path, device_list: list[dict]) -> None:
    filepath.parent.mkdir(exist_ok=True, parents=True)
    key_name = filepath.stem

    # normalize + validate + dedupe
    cleaned = []
    for d in device_list:
        m = normalize_mac(d.get("mac", ""))
        if not m or not _mac_is_valid(m):
            continue
        cleaned.append({
            "mac": m,
            "ip": str(d.get("ip", "") or "").strip(),
            "hostname": str(d.get("hostname", "") or "").strip(),
            "vendor": str(d.get("vendor", "") or "").strip(),
            "date_modified": str(d.get("date_modified") or _now_str()).strip(),
        })

    cleaned = _dedupe_keep_last(cleaned, "mac")
    cleaned.sort(key=lambda x: x.get("mac", ""))

    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump({key_name: cleaned}, f, sort_keys=False)

# -----------------------------
# Data Logic - Domains (Date Modified ONLY)
# -----------------------------
def load_domain_whitelist(filepath: Path) -> list[dict]:
    if not filepath.exists():
        return []
    default_row = {"domain": "", "date_modified": ""}

    try:
        data = yaml.safe_load(filepath.read_text(encoding="utf-8"))
        if not data:
            return []

        raw_list = []
        if isinstance(data, list):
            raw_list = data
        elif isinstance(data, dict):
            target_key = filepath.stem
            if target_key in data and isinstance(data[target_key], list):
                raw_list = data[target_key]
            else:
                for v in data.values():
                    if isinstance(v, list):
                        raw_list = v
                        break

        file_stamp = _file_mtime_str(filepath)
        out = []
        for it in raw_list:
            if isinstance(it, str):
                dom = it.strip().lower()
                if dom:
                    out.append({"domain": dom, "date_modified": file_stamp})
            elif isinstance(it, dict):
                row = default_row.copy()
                clean = {str(k).lower(): v for k, v in it.items()}
                row.update(clean)

                dom = str(row.get("domain", "")).strip().lower()
                if not dom and "domain name" in clean:
                    dom = str(clean.get("domain name", "")).strip().lower()
                if not dom:
                    continue
                dm = str(row.get("date_modified") or file_stamp).strip()
                out.append({"domain": dom, "date_modified": dm})

        out = _dedupe_keep_last(out, "domain")
        out.sort(key=lambda x: x.get("domain", ""))
        return out
    except Exception:
        return []

def save_domain_whitelist(filepath: Path, rows: list[dict]) -> None:
    filepath.parent.mkdir(exist_ok=True, parents=True)
    key_name = filepath.stem

    cleaned = []
    for r in rows:
        dom = str(r.get("domain", "")).strip().lower()
        if not dom or not _domain_is_valid(dom):
            continue
        cleaned.append({"domain": dom, "date_modified": str(r.get("date_modified") or _now_str()).strip()})

    cleaned = _dedupe_keep_last(cleaned, "domain")
    cleaned.sort(key=lambda x: x.get("domain", ""))

    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump({key_name: cleaned}, f, sort_keys=False)

# -----------------------------
# BAN LIST
# -----------------------------
def load_ban_list(filepath: Path) -> list[dict]:
    if not filepath.exists():
        return []
    try:
        data = yaml.safe_load(filepath.read_text(encoding="utf-8"))
        if not data:
            return []
        raw_list = []
        if isinstance(data, list):
            raw_list = data
        elif isinstance(data, dict):
            if filepath.stem in data and isinstance(data[filepath.stem], list):
                raw_list = data[filepath.stem]
            else:
                for v in data.values():
                    if isinstance(v, list):
                        raw_list = v
                        break

        out = []
        file_stamp = _file_mtime_str(filepath)
        for it in raw_list:
            if isinstance(it, str):
                m = normalize_mac(it)
                if m:
                    out.append({"mac": m, "date_modified": file_stamp})
            elif isinstance(it, dict):
                m = normalize_mac(it.get("mac", ""))
                if m:
                    out.append({"mac": m, "date_modified": str(it.get("date_modified") or file_stamp)})

        out = _dedupe_keep_last(out, "mac")
        out.sort(key=lambda x: x.get("mac", ""))
        return out
    except Exception:
        return []

def save_ban_list(filepath: Path, ban_list: list[dict]) -> None:
    filepath.parent.mkdir(exist_ok=True, parents=True)
    key_name = filepath.stem

    cleaned = []
    for r in ban_list:
        m = normalize_mac(r.get("mac", ""))
        if not m or not _mac_is_valid(m):
            continue
        cleaned.append({"mac": m, "date_modified": str(r.get("date_modified") or _now_str()).strip()})

    cleaned = _dedupe_keep_last(cleaned, "mac")
    cleaned.sort(key=lambda x: x.get("mac", ""))

    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump({key_name: cleaned}, f, sort_keys=False)

# -----------------------------
# Metadata Enrichment Logic
# -----------------------------
@st.cache_data(show_spinner=False)
def get_mac_vendor(mac: str) -> str:
    mac = normalize_mac(mac)
    if not mac:
        return "Unknown"
    try:
        # soft rate limit for public API
        time.sleep(0.25)
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text if r.status_code == 200 else "Unknown"
    except Exception:
        return "Unknown"

def get_latest_network_info() -> pd.DataFrame:
    known_hosts_all = []
    dhcp_all = []

    if not PARQUET_ROOT.exists():
        return pd.DataFrame()

    for day_dir in sorted(p for p in PARQUET_ROOT.iterdir() if p.is_dir()):
        kh = day_dir / "known_hosts.parquet"
        dh = day_dir / "dhcp.parquet"
        if kh.exists():
            known_hosts_all.append(pd.read_parquet(kh))
        if dh.exists():
            dhcp_all.append(pd.read_parquet(dh))

    known_hosts = pd.concat(known_hosts_all, ignore_index=True) if known_hosts_all else pd.DataFrame()
    dhcp = pd.concat(dhcp_all, ignore_index=True) if dhcp_all else pd.DataFrame()

    if known_hosts.empty:
        return pd.DataFrame()

    if "mac" in known_hosts.columns:
        known_hosts = known_hosts.copy()
        known_hosts["mac"] = known_hosts["mac"].map(normalize_mac)
        known_hosts = known_hosts[known_hosts["mac"] != ""]

    if not dhcp.empty:
        if "mac" in dhcp.columns:
            dhcp = dhcp.copy()
            dhcp["mac"] = dhcp["mac"].map(normalize_mac)
            dhcp = dhcp[dhcp["mac"] != ""]
            dhcp_cols = [c for c in ["mac", "host_name"] if c in dhcp.columns]
            dhcp_norm = dhcp[dhcp_cols].drop_duplicates(subset=["mac"], keep="last")
            merged = pd.merge(known_hosts, dhcp_norm, how="left", on="mac")
        else:
            dhcp_cols = [c for c in ["client_addr", "host_name"] if c in dhcp.columns]
            dhcp_norm = dhcp[dhcp_cols].drop_duplicates(subset=["client_addr"], keep="last")
            merged = pd.merge(known_hosts, dhcp_norm, how="left", left_on="host", right_on="client_addr")
    else:
        merged = known_hosts.copy()
        merged["host_name"] = ""

    if "ts" in merged.columns:
        merged = merged.sort_values("ts")

    final_info = merged.groupby("mac").agg({
        "host": "last",
        "host_name": "last"
    }).reset_index()

    final_info.rename(columns={"host": "latest_ip", "host_name": "latest_host"}, inplace=True)
    return final_info

# -----------------------------
# AI Config
# -----------------------------
def load_ai_config(filepath: Path):
    if not filepath.exists():
        return {"authorized_providers": [], "ai_signatures": {}}
    try:
        config = yaml.safe_load(filepath.read_text(encoding="utf-8"))
        return config if config else {"authorized_providers": [], "ai_signatures": {}}
    except Exception:
        return {"authorized_providers": [], "ai_signatures": {}}

def save_ai_config(filepath: Path, config_dict: dict):
    filepath.parent.mkdir(exist_ok=True, parents=True)
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump(config_dict, f, sort_keys=False)

# -----------------------------
# Logging
# -----------------------------
def log_activity(filepath: Path, action: str, item_type: str, items: list[str]):
    if not items:
        return
    log_file = filepath.parent / "activity_log.csv"
    timestamp = _now_str()
    new_rows = [{"Timestamp": timestamp, "Action": action, "Type": item_type, "Item": item} for item in items]
    df_new = pd.DataFrame(new_rows)
    header_needed = not log_file.exists()
    df_new.to_csv(log_file, mode="a", header=header_needed, index=False)

def load_history(filepath: Path) -> pd.DataFrame:
    log_file = filepath.parent / "activity_log.csv"
    if not log_file.exists():
        return pd.DataFrame(columns=["Timestamp", "Action", "Type", "Item"])
    try:
        df = pd.read_csv(log_file)
        return df.drop_duplicates().sort_values(by="Timestamp", ascending=False)
    except Exception:
        return pd.DataFrame(columns=["Timestamp", "Action", "Type", "Item"])

# -----------------------------
# AUTO ENRICH DEVICES
# -----------------------------
def auto_enrich_devices(device_list):
    net_df = get_latest_network_info()
    net_map = {}
    if not net_df.empty:
        net_map = net_df.set_index("mac").to_dict(orient="index")

    changes_detected = False

    for device in device_list:
        mac = normalize_mac(device.get("mac", ""))
        if not mac:
            continue
        device["mac"] = mac

        if mac in net_map:
            found_ip = str(net_map[mac].get("latest_ip", "") or "")
            found_host = str(net_map[mac].get("latest_host", "") or "")

            if found_ip and found_ip != "nan" and found_ip != device.get("ip", ""):
                device["ip"] = found_ip
                changes_detected = True

            if found_host and found_host != "nan" and found_host != device.get("hostname", ""):
                device["hostname"] = found_host
                changes_detected = True

        if not device.get("vendor") or device.get("vendor") == "Unknown":
            found_vendor = get_mac_vendor(mac)
            if found_vendor and found_vendor != "Unknown":
                device["vendor"] = found_vendor
                changes_detected = True

        if not device.get("date_modified"):
            device["date_modified"] = _now_str()

    # dedupe, keep last
    device_list = _dedupe_keep_last(device_list, "mac")
    return device_list, changes_detected

# -----------------------------
# Robust Editor State Helpers (fix add/delete when filtered)
# -----------------------------
def _ensure_ids(rows: list[dict], id_key="_id") -> list[dict]:
    out = []
    for r in rows:
        rr = dict(r)
        if not rr.get(id_key):
            rr[id_key] = str(uuid4())
        out.append(rr)
    return out

def _rows_to_df(rows: list[dict], cols: list[str]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df[cols].copy()

# -----------------------------
# 1) Device Manager (FIXED add/delete)
# -----------------------------
def render_device_manager(device_list: list[dict], filepath: Path):
    st.markdown("**Device Management**")

    # Session key for stable IDs across reruns
    if "device_rows_state" not in st.session_state:
        st.session_state.device_rows_state = _ensure_ids(device_list)

    # On first load, enrich once
    if "has_scanned" not in st.session_state:
        with st.spinner("Auto-detecting network metadata..."):
            updated_list, changes = auto_enrich_devices(st.session_state.device_rows_state)
            if changes:
                st.session_state.device_rows_state = updated_list
                # persist without IDs
                save_devices(filepath, [{k: v for k, v in d.items() if k != "_id"} for d in updated_list])
                st.toast("Network metadata updated automatically")
        st.session_state["has_scanned"] = True

    # Filters
    f1, _ = st.columns([2, 3])
    with f1:
        date_filter = st.selectbox(
            "Filter by Date Modified",
            ["All", "Today", "Last 7 Days", "Last 30 Days"],
            index=0
        )

    # Quick add
    col_input, col_btn = st.columns([4, 1])
    with col_input:
        new_text = st.text_input(
            "Quick Add Device",
            placeholder="Paste MAC Address (you can paste multiple, separated by space/comma/newline)",
            label_visibility="collapsed",
            key="device_quick_add"
        )
    with col_btn:
        if st.button("Add Device", key="btn_import_mac", type="primary"):
            entries = [x for x in re.split(r"[,\s\n]+", (new_text or "")) if x.strip()]
            entries = [normalize_mac(x) for x in entries]
            entries = [m for m in entries if m and _mac_is_valid(m)]

            existing = {normalize_mac(d.get("mac")) for d in st.session_state.device_rows_state}
            added = []
            for m in entries:
                if m in existing:
                    continue
                st.session_state.device_rows_state.append({
                    "_id": str(uuid4()),
                    "mac": m,
                    "ip": "",
                    "hostname": "",
                    "vendor": "",
                    "date_modified": _now_str()
                })
                existing.add(m)
                added.append(m)

            if added:
                save_devices(filepath, [{k: v for k, v in d.items() if k != "_id"} for d in st.session_state.device_rows_state])
                log_activity(filepath, "Added", "Device", added)
                st.toast(f"Added {len(added)} device(s)")
                st.rerun()
            else:
                st.info("No new valid MACs were added (duplicates/invalid).")

    st.divider()

    search_query = st.text_input("Search Devices", placeholder="Search MAC / IP / Hostname..", label_visibility="collapsed")

    # Build DF from state
    rows = st.session_state.device_rows_state
    cols_all = ["_id", "mac", "ip", "hostname", "vendor", "date_modified"]
    df = _rows_to_df(rows, cols_all)

    # Apply date filter (on df)
    if date_filter != "All" and not df.empty:
        df["_dt"] = df["date_modified"].apply(_parse_dt)
        now = datetime.datetime.now()
        if date_filter == "Today":
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif date_filter == "Last 7 Days":
            start = now - datetime.timedelta(days=7)
        else:
            start = now - datetime.timedelta(days=30)
        df = df[df["_dt"].notna() & (df["_dt"] >= start)].copy()
        df.drop(columns=["_dt"], inplace=True, errors="ignore")

    # Search filter
    if search_query:
        q = search_query.strip()
        mask = df.apply(lambda r: r.astype(str).str.contains(q, case=False).any(), axis=1)
        df = df[mask].copy()

    # Sort by date_modified desc
    df["_dt_sort"] = df["date_modified"].apply(_parse_dt)
    df = df.sort_values(by="_dt_sort", ascending=False, na_position="last").drop(columns=["_dt_sort"])

    # Show editor (include hidden _id for stable diff)
    display_cols = ["_id", "mac", "ip", "hostname", "date_modified"]
    editor_df = df[display_cols].copy()
    editor_df = _with_row_numbers(editor_df)

    edited_df = _st_data_editor(
        editor_df,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "#": st.column_config.NumberColumn("#", disabled=True, width="small"),
            "_id": st.column_config.TextColumn("_id", disabled=True, width="small"),  # hidden-ish identifier
            "mac": st.column_config.TextColumn("MAC Address", required=True, width="medium"),
            "ip": st.column_config.TextColumn("IP Address", disabled=False, width="small"),
            "hostname": st.column_config.TextColumn("Host Name", disabled=False, width="medium"),
            "date_modified": st.column_config.TextColumn("Date Modified", disabled=True, width="medium"),
        },
        key="device_editor",
        height=400
    )

    st.caption("Tip: To delete, remove the row from the table then click **Save Device Changes**.")

    if st.button("Save Device Changes", type="secondary", key="save_devices"):
        # Drop display "#"
        if "#" in edited_df.columns:
            edited_df = edited_df.drop(columns=["#"], errors="ignore")

        # Clean edited rows
        edited_rows = edited_df.to_dict("records")

        cleaned = []
        invalid = []
        seen_macs = set()

        for r in edited_rows:
            rid = str(r.get("_id", "")).strip()
            mac = normalize_mac(r.get("mac", ""))
            if not rid and not mac:
                continue  # blank row from dynamic editor

            if not mac or not _mac_is_valid(mac):
                invalid.append(str(r.get("mac", "")))
                continue

            if mac in seen_macs:
                continue
            seen_macs.add(mac)

            cleaned.append({
                "_id": rid or str(uuid4()),
                "mac": mac,
                "ip": str(r.get("ip", "") or "").strip(),
                "hostname": str(r.get("hostname", "") or "").strip(),
                "date_modified": str(r.get("date_modified") or "").strip() or _now_str(),
            })

        # Map current full state
        full = st.session_state.device_rows_state
        full_by_id = {str(x.get("_id")): x for x in full if x.get("_id")}
        full_by_mac = {normalize_mac(x.get("mac")): x for x in full if normalize_mac(x.get("mac"))}

        # IDs visible in current view before editing (for deletion detection limited to view)
        view_ids_before = set(df["_id"].astype(str).tolist())

        # IDs after editing (still in view)
        view_ids_after = set([str(x.get("_id", "")) for x in cleaned if x.get("_id")])

        deleted_ids = view_ids_before - view_ids_after

        # Apply deletions to full
        new_full = [x for x in full if str(x.get("_id")) not in deleted_ids]

        # Apply updates/additions from cleaned
        added_macs = []
        updated_macs = []

        for row in cleaned:
            mac = row["mac"]
            rid = row["_id"]

            # If this _id exists, update it
            if rid in full_by_id:
                old = full_by_id[rid]
                changed = (row.get("ip", "") != str(old.get("ip", "") or "").strip()) or (row.get("hostname", "") != str(old.get("hostname", "") or "").strip())
                # Keep vendor from old
                vendor = str(old.get("vendor", "") or "").strip()
                row_final = {
                    "_id": rid,
                    "mac": mac,
                    "ip": row.get("ip", ""),
                    "hostname": row.get("hostname", ""),
                    "vendor": vendor,
                    "date_modified": _now_str() if changed else str(old.get("date_modified") or _now_str()).strip(),
                }
                # replace in new_full
                for i in range(len(new_full)):
                    if str(new_full[i].get("_id")) == rid:
                        new_full[i] = row_final
                        break
                updated_macs.append(mac)
                continue

            # Else if mac exists with different _id, treat as update/merge
            if mac in full_by_mac:
                old = full_by_mac[mac]
                rid_old = str(old.get("_id"))
                changed = (row.get("ip", "") != str(old.get("ip", "") or "").strip()) or (row.get("hostname", "") != str(old.get("hostname", "") or "").strip())
                vendor = str(old.get("vendor", "") or "").strip()
                row_final = {
                    "_id": rid_old,
                    "mac": mac,
                    "ip": row.get("ip", ""),
                    "hostname": row.get("hostname", ""),
                    "vendor": vendor,
                    "date_modified": _now_str() if changed else str(old.get("date_modified") or _now_str()).strip(),
                }
                for i in range(len(new_full)):
                    if str(new_full[i].get("_id")) == rid_old:
                        new_full[i] = row_final
                        break
                updated_macs.append(mac)
                continue

            # Brand new row
            new_full.append({
                "_id": rid or str(uuid4()),
                "mac": mac,
                "ip": row.get("ip", ""),
                "hostname": row.get("hostname", ""),
                "vendor": "",
                "date_modified": _now_str(),
            })
            added_macs.append(mac)

        # Dedupe full by mac (keep last)
        new_full = _dedupe_keep_last(new_full, "mac")
        new_full = _ensure_ids(new_full)

        # Persist
        st.session_state.device_rows_state = new_full
        save_devices(filepath, [{k: v for k, v in d.items() if k != "_id"} for d in new_full])

        # Logging
        deleted_macs = []
        for rid in deleted_ids:
            old = full_by_id.get(rid)
            if old:
                m = normalize_mac(old.get("mac", ""))
                if m:
                    deleted_macs.append(m)

        if added_macs:
            log_activity(filepath, "Added", "Device", sorted(list(set(added_macs))))
        if deleted_macs:
            log_activity(filepath, "Deleted", "Device", sorted(list(set(deleted_macs))))

        if invalid:
            st.warning(f"Skipped invalid MAC(s): {', '.join([x for x in invalid if x])}")

        st.success("Device database updated successfully.")
        st.rerun()

# -----------------------------
# 2) Domain Whitelist Manager (FIXED add/delete)
# -----------------------------
def render_domain_manager(domain_rows: list[dict], filepath: Path):
    st.markdown("**Domain Whitelist**")

    # Session state with stable ids
    if "domain_rows_state" not in st.session_state:
        rows = []
        for r in domain_rows:
            rr = dict(r)
            rr["_id"] = rr.get("_id") or str(uuid4())
            rows.append(rr)
        st.session_state.domain_rows_state = rows

    col_input, col_btn = st.columns([4, 1])
    with col_input:
        new_domain = st.text_input("Add Domain", placeholder="example.com", label_visibility="collapsed", key="dom_add")
    with col_btn:
        if st.button("Add", key="btn_import_domain"):
            entries = [x.strip().lower() for x in re.split(r"[,\s\n]+", (new_domain or "")) if x.strip()]
            entries = [d for d in entries if _domain_is_valid(d)]

            existing = {str(r.get("domain", "")).strip().lower() for r in st.session_state.domain_rows_state}
            added = []
            for dom in entries:
                if dom in existing:
                    continue
                st.session_state.domain_rows_state.append({"_id": str(uuid4()), "domain": dom, "date_modified": _now_str()})
                existing.add(dom)
                added.append(dom)

            if added:
                # persist
                save_domain_whitelist(filepath, [{k: v for k, v in r.items() if k != "_id"} for r in st.session_state.domain_rows_state])
                log_activity(filepath, "Added", "Domain", added)
                st.toast(f"Added {len(added)} domain(s)")
                st.rerun()
            else:
                st.info("No new valid domains were added (duplicates/invalid).")

    st.divider()

    search_query = st.text_input(
        "Search Whitelist",
        placeholder="Filter domains...",
        label_visibility="collapsed",
        key="dom_search"
    ).strip().lower()

    df = pd.DataFrame(st.session_state.domain_rows_state)
    if df.empty:
        df = pd.DataFrame(columns=["_id", "domain", "date_modified"])

    for c in ["_id", "domain", "date_modified"]:
        if c not in df.columns:
            df[c] = ""

    if search_query:
        df = df[df["domain"].astype(str).str.lower().str.contains(search_query, na=False)].copy()

    df["_dt_sort"] = df["date_modified"].apply(_parse_dt)
    df = df.sort_values(by="_dt_sort", ascending=False, na_position="last").drop(columns=["_dt_sort"])

    editor_df = _with_row_numbers(df[["_id", "domain", "date_modified"]].copy())

    edited_df = _st_data_editor(
        editor_df,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "#": st.column_config.NumberColumn("#", disabled=True, width="small"),
            "_id": st.column_config.TextColumn("_id", disabled=True, width="small"),
            "domain": st.column_config.TextColumn("Domain Name", required=True, width="large"),
            "date_modified": st.column_config.TextColumn("Date Modified", disabled=True, width="medium"),
        },
        key="domain_editor",
        height=400
    )

    st.caption("Tip: To delete, remove the row from the table then click **Save Changes**.")

    if st.button("Save Changes", type="secondary", key="save_domain"):
        if "#" in edited_df.columns:
            edited_df = edited_df.drop(columns=["#"], errors="ignore")

        edited_rows = edited_df.to_dict("records")

        cleaned = []
        invalid = []
        seen = set()

        for r in edited_rows:
            rid = str(r.get("_id", "")).strip()
            dom = str(r.get("domain", "")).strip().lower()
            if not rid and not dom:
                continue

            if not dom or not _domain_is_valid(dom):
                invalid.append(dom)
                continue

            if dom in seen:
                continue
            seen.add(dom)

            cleaned.append({"_id": rid or str(uuid4()), "domain": dom, "date_modified": str(r.get("date_modified") or "").strip() or _now_str()})

        full = st.session_state.domain_rows_state
        full_by_id = {str(x.get("_id")): x for x in full if x.get("_id")}
        view_ids_before = set(df["_id"].astype(str).tolist())
        view_ids_after = set([x["_id"] for x in cleaned if x.get("_id")])
        deleted_ids = view_ids_before - view_ids_after

        new_full = [x for x in full if str(x.get("_id")) not in deleted_ids]

        # apply updates / additions
        added = []
        removed = []
        for rid in deleted_ids:
            old = full_by_id.get(rid)
            if old and old.get("domain"):
                removed.append(str(old["domain"]).strip().lower())

        # update existing by id, else add
        new_full_by_id = {str(x.get("_id")): x for x in new_full if x.get("_id")}
        existing_domains = {str(x.get("domain", "")).strip().lower() for x in new_full}

        for r in cleaned:
            rid = r["_id"]
            dom = r["domain"]
            if rid in new_full_by_id:
                new_full_by_id[rid]["domain"] = dom
                # keep original date_modified unless new
                if not new_full_by_id[rid].get("date_modified"):
                    new_full_by_id[rid]["date_modified"] = _now_str()
            else:
                if dom in existing_domains:
                    # skip duplicate domain
                    continue
                new_full.append({"_id": rid, "domain": dom, "date_modified": _now_str()})
                existing_domains.add(dom)
                added.append(dom)

        # dedupe by domain
        new_full = _dedupe_keep_last(new_full, "domain")

        st.session_state.domain_rows_state = new_full
        save_domain_whitelist(filepath, [{k: v for k, v in r.items() if k != "_id"} for r in new_full])

        if added:
            log_activity(filepath, "Added", "Domain", sorted(list(set(added))))
        if removed:
            log_activity(filepath, "Deleted", "Domain", sorted(list(set(removed))))

        if invalid:
            bad = [x for x in invalid if x]
            if bad:
                st.warning(f"Skipped invalid domain(s): {', '.join(bad[:30])}")

        st.success("Domain whitelist updated.")
        st.rerun()

# -----------------------------
# 3) AI Signature Manager (kept; minor safety)
# -----------------------------
def render_ai_signature_manager(yaml_path: Path):
    config = load_ai_config(yaml_path)

    st.subheader("Sanctioned AI Providers")
    auth_list = config.get("authorized_providers", [])
    sigs_dict = config.get("ai_signatures", {})
    available_providers = list(sigs_dict.keys())
    valid_defaults = [x for x in auth_list if x in available_providers]

    new_auth = st.multiselect("Select Authorized Providers", options=available_providers, default=valid_defaults)

    if set(new_auth) != set(auth_list):
        if st.button("Update Sanctioned List"):
            config["authorized_providers"] = new_auth
            save_ai_config(yaml_path, config)
            st.toast("Sanctioned list updated")
            st.rerun()

    st.divider()
    st.subheader("Detection Signatures")

    sig_data = []
    for provider, patterns in sigs_dict.items():
        pat_str = ", ".join(patterns) if isinstance(patterns, list) else str(patterns)
        sig_data.append({"Provider": provider, "Patterns": pat_str})

    sig_df = pd.DataFrame(sig_data)
    if sig_df.empty:
        sig_df = pd.DataFrame(columns=["Provider", "Patterns"])

    sig_df = _with_row_numbers(sig_df)

    edited_sigs = _st_data_editor(
        sig_df[["#", "Provider", "Patterns"]],
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "#": st.column_config.NumberColumn("#", disabled=True, width="small"),
            "Provider": st.column_config.TextColumn("Provider Name", required=True),
            "Patterns": st.column_config.TextColumn("Regex Patterns (Comma Separated)", width="large", required=True)
        },
        key="ai_sig_editor"
    )

    if st.button("Save AI Policies", type="primary", key="save_ai"):
        if "#" in edited_sigs.columns:
            edited_sigs = edited_sigs.drop(columns=["#"])

        new_sigs = {}
        for _, row in edited_sigs.iterrows():
            if pd.notna(row.get("Provider")) and pd.notna(row.get("Patterns")):
                p_name = str(row["Provider"]).strip()
                p_pats = [p.strip() for p in str(row["Patterns"]).split(",") if p.strip()]
                if p_name:
                    new_sigs[p_name] = p_pats

        config["ai_signatures"] = new_sigs
        save_ai_config(yaml_path, config)
        log_activity(yaml_path, "Edited", "AI Signatures", ["Bulk Configuration Update"])
        st.success("AI policies updated successfully.")

# -----------------------------
# 4) Banning List Manager (FIXED add/delete)
# -----------------------------
def render_banning_list(ban_file: Path):
    st.markdown("**Banning List**")

    if "ban_rows_state" not in st.session_state:
        rows = []
        for r in load_ban_list(ban_file):
            rr = dict(r)
            rr["_id"] = rr.get("_id") or str(uuid4())
            rr["mac"] = normalize_mac(rr.get("mac", ""))
            rows.append(rr)
        st.session_state.ban_rows_state = rows

    col_input, col_btn = st.columns([4, 1])
    with col_input:
        new_text = st.text_input(
            "Add MAC to Ban List",
            placeholder="Paste MAC Address (supports multiple)",
            label_visibility="collapsed",
            key="ban_add_input"
        )
    with col_btn:
        if st.button("Enter", type="primary", key="ban_add_btn"):
            entries = [x for x in re.split(r"[,\s\n]+", (new_text or "")) if x.strip()]
            entries = [normalize_mac(x) for x in entries]
            entries = [m for m in entries if m and _mac_is_valid(m)]

            existing = {normalize_mac(d.get("mac")) for d in st.session_state.ban_rows_state}
            added = []
            for m in entries:
                if m in existing:
                    continue
                st.session_state.ban_rows_state.append({"_id": str(uuid4()), "mac": m, "date_modified": _now_str()})
                existing.add(m)
                added.append(m)

            if added:
                save_ban_list(ban_file, [{k: v for k, v in r.items() if k != "_id"} for r in st.session_state.ban_rows_state])
                log_activity(ban_file, "Added", "Banned MAC", added)
                st.toast(f"Banned {len(added)} MAC(s)")
                st.rerun()
            else:
                st.info("No new valid MACs were added (duplicates/invalid).")

    st.divider()

    search_query = st.text_input(
        "Search Banned MACs",
        placeholder="Search MAC Address..",
        label_visibility="collapsed",
        key="ban_search"
    ).strip().lower()

    df = pd.DataFrame(st.session_state.ban_rows_state)
    if df.empty:
        df = pd.DataFrame(columns=["_id", "mac", "date_modified"])

    for c in ["_id", "mac", "date_modified"]:
        if c not in df.columns:
            df[c] = ""

    if search_query:
        df = df[df["mac"].astype(str).str.contains(search_query, case=False, na=False)].copy()

    df["_dt_sort"] = df["date_modified"].apply(_parse_dt)
    df = df.sort_values(by="_dt_sort", ascending=False, na_position="last").drop(columns=["_dt_sort"])

    editor_df = _with_row_numbers(df[["_id", "mac", "date_modified"]].copy())

    edited_df = _st_data_editor(
        editor_df,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "#": st.column_config.NumberColumn("#", disabled=True, width="small"),
            "_id": st.column_config.TextColumn("_id", disabled=True, width="small"),
            "mac": st.column_config.TextColumn("MAC Address", required=True, width="medium"),
            "date_modified": st.column_config.TextColumn("Date Modified", disabled=True, width="medium"),
        },
        key="ban_editor",
        height=400
    )

    st.caption("Tip: To delete, remove the row from the table then click **Save Ban List Changes**.")

    if st.button("Save Ban List Changes", type="secondary", key="ban_save"):
        if "#" in edited_df.columns:
            edited_df = edited_df.drop(columns=["#"], errors="ignore")

        edited_rows = edited_df.to_dict("records")

        cleaned = []
        invalid = []
        seen = set()

        for r in edited_rows:
            rid = str(r.get("_id", "")).strip()
            mac = normalize_mac(r.get("mac", ""))
            if not rid and not mac:
                continue

            if not mac or not _mac_is_valid(mac):
                invalid.append(str(r.get("mac", "")))
                continue

            if mac in seen:
                continue
            seen.add(mac)

            dm = str(r.get("date_modified") or "").strip() or _now_str()
            cleaned.append({"_id": rid or str(uuid4()), "mac": mac, "date_modified": dm})

        full = st.session_state.ban_rows_state
        full_by_id = {str(x.get("_id")): x for x in full if x.get("_id")}
        view_ids_before = set(df["_id"].astype(str).tolist())
        view_ids_after = set([x["_id"] for x in cleaned if x.get("_id")])
        deleted_ids = view_ids_before - view_ids_after

        removed = []
        for rid in deleted_ids:
            old = full_by_id.get(rid)
            if old and old.get("mac"):
                removed.append(old["mac"])

        new_full = [x for x in full if str(x.get("_id")) not in deleted_ids]

        # Merge cleaned into new_full by _id or by mac
        new_full_by_id = {str(x.get("_id")): x for x in new_full if x.get("_id")}
        existing_macs = {normalize_mac(x.get("mac")) for x in new_full}
        added = []

        for r in cleaned:
            rid = r["_id"]
            mac = r["mac"]
            if rid in new_full_by_id:
                new_full_by_id[rid]["mac"] = mac
                new_full_by_id[rid]["date_modified"] = new_full_by_id[rid].get("date_modified") or _now_str()
            else:
                if mac in existing_macs:
                    continue
                new_full.append({"_id": rid, "mac": mac, "date_modified": _now_str()})
                existing_macs.add(mac)
                added.append(mac)

        # Dedupe by mac
        new_full = _dedupe_keep_last(new_full, "mac")
        st.session_state.ban_rows_state = new_full

        save_ban_list(ban_file, [{k: v for k, v in r.items() if k != "_id"} for r in new_full])

        if added:
            log_activity(ban_file, "Added", "Banned MAC", sorted(list(set(added))))
        if removed:
            log_activity(ban_file, "Deleted", "Banned MAC", sorted(list(set(removed))))

        if invalid:
            st.warning(f"Skipped invalid MAC(s): {', '.join([x for x in invalid if x])}")

        st.success("Ban list updated successfully.")
        st.rerun()

# -----------------------------
# Main Render
# -----------------------------
def render(mac_file: Path):
    inject_custom_css()

    if mac_file.suffix != ".yaml":
        mac_file = mac_file.with_suffix(".yaml")

    mac_file = mac_file.resolve()
    domain_file = (mac_file.parent / "whitelist_domains.yaml").resolve()
    ai_yaml_file = (mac_file.parent / "ai_signatures.yaml").resolve()
    ban_file = (mac_file.parent / "banned_macs.yaml").resolve()

    saved_devices = load_devices(mac_file)
    saved_domains = load_domain_whitelist(domain_file)
    ai_config = load_ai_config(ai_yaml_file)

    st.title("Authorization Manager")

    m1, m2, m3 = st.columns(3)
    m1.metric("Device Whitelist", len(saved_devices))
    m2.metric("Domain Whitelist", len(saved_domains))
    m3.metric("AI Policies", len(ai_config.get("ai_signatures", {})))

    st.write("")

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["Device Access", "Domain Whitelist", "AI Policies", "Audit Log", "Ban List"]
    )

    with tab1:
        render_device_manager(saved_devices, mac_file)

    with tab2:
        render_domain_manager(saved_domains, domain_file)

    with tab3:
        render_ai_signature_manager(ai_yaml_file)

    with tab4:
        st.subheader("System Audit Log")
        history_df = load_history(mac_file)
        if not history_df.empty:
            hist_show = _with_row_numbers(history_df)
            _st_dataframe(
                hist_show,
                use_container_width=True,
                height=500,
                column_config={"#": st.column_config.NumberColumn("#", width="small")}
            )
            if st.button("Clear Audit Log", type="secondary"):
                (mac_file.parent / "activity_log.csv").unlink(missing_ok=True)
                st.rerun()
        else:
            st.info("No activity recorded yet.")

    with tab5:
        render_banning_list(ban_file)