import streamlit as st
from pathlib import Path
import pandas as pd
import datetime
import yaml
import re
import requests  # For Vendor Lookup
import time      # For API rate limiting
import inspect

# -----------------------------
# Configuration & Constants
# -----------------------------
MAC_REGEX_PATTERN = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
DOMAIN_REGEX_PATTERN = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
PARQUET_ROOT = Path("data/parquet")

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
    out = df.copy()
    out = out.reset_index(drop=True)
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

def _mac_is_valid(mac: str) -> bool:
    return bool(re.match(MAC_REGEX_PATTERN, (mac or "").strip()))

def _domain_is_valid(domain: str) -> bool:
    return bool(re.match(DOMAIN_REGEX_PATTERN, (domain or "").strip()))

# -----------------------------
# Data Logic - Structured (Devices)
# -----------------------------
def load_devices(filepath: Path) -> list[dict]:
    default_structure = {"mac": "", "ip": "", "hostname": "", "vendor": "", "date_modified": ""}

    if not filepath.exists():
        return []

    with open(filepath, "r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
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

            structured_data = []
            file_stamp = _file_mtime_str(filepath)

            for item in raw_list:
                if isinstance(item, str):
                    structured_data.append({
                        "mac": item.strip().lower(),
                        "ip": "", "hostname": "", "vendor": "",
                        "date_modified": file_stamp
                    })
                elif isinstance(item, dict):
                    entry = default_structure.copy()
                    clean_item = {str(k).lower(): v for k, v in item.items()}
                    entry.update(clean_item)
                    if entry["mac"]:
                        entry["mac"] = str(entry["mac"]).strip().lower()
                        if not entry.get("date_modified"):
                            entry["date_modified"] = file_stamp
                        structured_data.append(entry)

            return structured_data
        except Exception as e:
            print(f"Error loading devices: {e}")
            return []

def save_devices(filepath: Path, device_list: list[dict]) -> None:
    filepath.parent.mkdir(exist_ok=True, parents=True)
    key_name = filepath.stem
    device_list.sort(key=lambda x: x.get("mac", ""))
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump({key_name: device_list}, f, sort_keys=False)

# -----------------------------
# Data Logic - Domains ✅ Date Modified ONLY (Category removed)
# -----------------------------
def load_domain_whitelist(filepath: Path) -> list[dict]:
    """
    Supports:
      - Old format: list[str] OR {whitelist_domains:[str,...]}
      - New format: list[dict] OR {whitelist_domains:[{domain,date_modified},...]}
      - If your file currently contains category, we ignore it safely.
    Returns list of dicts:
      {"domain": "...", "date_modified": "..."}
    """
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

        # dedupe by domain (keep last)
        uniq = {r["domain"]: r for r in out if r.get("domain")}
        return list(uniq.values())

    except Exception:
        return []

def save_domain_whitelist(filepath: Path, rows: list[dict]) -> None:
    """Writes ONLY domain + date_modified (category removed from disk too)."""
    filepath.parent.mkdir(exist_ok=True, parents=True)
    key_name = filepath.stem
    rows = sorted(rows, key=lambda x: x.get("domain", ""))
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump({key_name: rows}, f, sort_keys=False)

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
                m = it.strip().lower()
                if m:
                    out.append({"mac": m, "date_modified": file_stamp})
            elif isinstance(it, dict):
                m = str(it.get("mac", "")).strip().lower()
                if m:
                    out.append({
                        "mac": m,
                        "date_modified": str(it.get("date_modified") or file_stamp)
                    })
        uniq = {x["mac"]: x for x in out}
        return list(uniq.values())
    except Exception:
        return []

def save_ban_list(filepath: Path, ban_list: list[dict]) -> None:
    filepath.parent.mkdir(exist_ok=True, parents=True)
    key_name = filepath.stem
    ban_list = sorted(ban_list, key=lambda x: x.get("mac", ""))
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump({key_name: ban_list}, f, sort_keys=False)

# -----------------------------
# Metadata Enrichment Logic
# -----------------------------
@st.cache_data(show_spinner=False)
def get_mac_vendor(mac: str) -> str:
    if not mac or mac == "unknown":
        return "Unknown"
    try:
        time.sleep(0.6)
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
        known_hosts["mac"] = known_hosts["mac"].astype(str).str.lower().str.strip()

    if not dhcp.empty:
        if "mac" in dhcp.columns:
            dhcp["mac"] = dhcp["mac"].astype(str).str.lower().str.strip()
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
    with open(filepath, "r", encoding="utf-8") as f:
        try:
            config = yaml.safe_load(f)
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
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
        mac = device.get("mac", "").lower()

        if mac in net_map:
            found_ip = str(net_map[mac].get("latest_ip", ""))
            found_host = str(net_map[mac].get("latest_host", ""))

            if found_ip and found_ip != "nan" and found_ip != device.get("ip"):
                device["ip"] = found_ip
                changes_detected = True

            if found_host and found_host != "nan" and found_host != device.get("hostname"):
                device["hostname"] = found_host
                changes_detected = True

        if not device.get("vendor") or device.get("vendor") == "Unknown":
            found_vendor = get_mac_vendor(mac)
            if found_vendor and found_vendor != "Unknown":
                device["vendor"] = found_vendor
                changes_detected = True

        if not device.get("date_modified"):
            device["date_modified"] = _now_str()

    return device_list, changes_detected

# -----------------------------
# 1) Device Manager
# -----------------------------
def render_device_manager(device_list: list[dict], filepath: Path):
    st.markdown("**Device Management**")

    if "has_scanned" not in st.session_state:
        with st.spinner("Auto-detecting network metadata..."):
            updated_list, changes = auto_enrich_devices(device_list)
            if changes:
                device_list[:] = updated_list
                save_devices(filepath, device_list)
                st.toast("Network metadata updated automatically")
        st.session_state["has_scanned"] = True

    f1, _ = st.columns([2, 3])
    with f1:
        date_filter = st.selectbox(
            "Filter by Date Modified",
            ["All", "Today", "Last 7 Days", "Last 30 Days"],
            index=0
        )

    col_input, col_btn = st.columns([4, 1])
    with col_input:
        new_text = st.text_input(
            "Quick Add Device",
            placeholder="Paste MAC Address",
            label_visibility="collapsed"
        )
    with col_btn:
        if st.button("Add Device", key="btn_import_mac", type="primary"):
            if new_text:
                entries = [m.strip().lower() for m in re.split(r"[,\s\n]+", new_text) if m.strip()]
                existing_macs = {d.get("mac", "").lower() for d in device_list}

                added_count = 0
                new_entries_for_log = []

                for mac in entries:
                    if not _mac_is_valid(mac):
                        continue
                    if mac in existing_macs:
                        st.warning("MAC address already available")
                        continue

                    device_list.append({
                        "mac": mac,
                        "ip": "", "hostname": "", "vendor": "",
                        "date_modified": _now_str()
                    })
                    existing_macs.add(mac)
                    new_entries_for_log.append(mac)
                    added_count += 1

                if added_count > 0:
                    if "has_scanned" in st.session_state:
                        del st.session_state["has_scanned"]
                    save_devices(filepath, device_list)
                    log_activity(filepath, "Added", "Device", new_entries_for_log)
                    st.toast(f"Added {added_count} new devices")
                    st.rerun()

    st.divider()

    search_query = st.text_input("Search Devices", placeholder="Search MAC Address..", label_visibility="collapsed")

    df = pd.DataFrame(device_list)
    if df.empty:
        df = pd.DataFrame(columns=["mac", "ip", "hostname", "vendor", "date_modified"])

    if "date_modified" not in df.columns:
        df["date_modified"] = ""

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

    if search_query:
        mask = df.apply(lambda x: x.astype(str).str.contains(search_query, case=False).any(), axis=1)
        display_df = df[mask].copy()
    else:
        display_df = df.copy()

    display_df["_dt_sort"] = display_df["date_modified"].apply(_parse_dt)
    display_df = display_df.sort_values(by="_dt_sort", ascending=False, na_position="last").drop(columns=["_dt_sort"])

    # ✅ Use your own # and hide index (fix alignment / spacing)
    display_df = _with_row_numbers(display_df)

    editor_cols = ["#", "mac", "ip", "hostname", "date_modified"]
    for c in editor_cols:
        if c not in display_df.columns:
            display_df[c] = ""
    display_df = display_df[editor_cols]

    edited_df = _st_data_editor(
        display_df,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "#": st.column_config.NumberColumn("#", disabled=True, width="small"),
            "mac": st.column_config.TextColumn("MAC Address", validate=MAC_REGEX_PATTERN, required=True, width="medium"),
            "ip": st.column_config.TextColumn("IP Address", disabled=False, width="small"),
            "hostname": st.column_config.TextColumn("Host Name", disabled=False, width="medium"),
            "date_modified": st.column_config.TextColumn("Date Modified", disabled=True, width="medium"),
        },
        key="device_editor",
        height=400
    )

    st.write("")
    if st.button("Save Device Changes", type="secondary", key="save_devices"):
        if "#" in edited_df.columns:
            edited_df = edited_df.drop(columns=["#"])

        new_state_dicts = edited_df.to_dict("records")
        visible_macs = set([str(x.get("mac", "")).strip().lower() for x in new_state_dicts if x.get("mac")])

        old_map = {d.get("mac", "").lower(): d for d in device_list if d.get("mac")}

        final_list = []
        if search_query or date_filter != "All":
            for item in device_list:
                if item.get("mac", "").lower() not in visible_macs:
                    final_list.append(item)

        for item in new_state_dicts:
            if item.get("mac") and str(item["mac"]).strip():
                mac_clean = str(item["mac"]).strip().lower()
                ip_clean = str(item.get("ip", "")).strip()
                host_clean = str(item.get("hostname", "")).strip()

                old = old_map.get(mac_clean, {})
                changed = (ip_clean != str(old.get("ip", "")).strip()) or (host_clean != str(old.get("hostname", "")).strip())

                vendor_val = str(old.get("vendor", "")).strip()
                date_mod = str(old.get("date_modified", "")).strip() or _now_str()
                if changed:
                    date_mod = _now_str()

                final_list.append({
                    "mac": mac_clean,
                    "ip": ip_clean,
                    "hostname": host_clean,
                    "vendor": vendor_val,
                    "date_modified": date_mod,
                })

        unique_map = {x["mac"]: x for x in final_list}
        final_list = list(unique_map.values())

        old_macs = set(d["mac"] for d in device_list if d.get("mac"))
        new_macs = set(d["mac"] for d in final_list if d.get("mac"))
        added = new_macs - old_macs
        removed = old_macs - new_macs

        save_devices(filepath, final_list)

        if added:
            log_activity(filepath, "Added", "Device", list(added))
        if removed:
            log_activity(filepath, "Deleted", "Device", list(removed))

        st.success("Device database updated successfully.")
        st.rerun()

# -----------------------------
# 2) Domain Whitelist Manager ✅ Date Modified ONLY (Category removed)
# -----------------------------
def render_domain_manager(domain_rows: list[dict], filepath: Path):
    st.markdown("**Domain Whitelist**")

    col_input, col_btn = st.columns([4, 1])
    with col_input:
        new_domain = st.text_input("Add Domain", placeholder="example.com", label_visibility="collapsed", key="dom_add")
    with col_btn:
        if st.button("Add", key="btn_import_domain"):
            if new_domain:
                entries = [x.strip().lower() for x in re.split(r"[,\s\n]+", new_domain) if x.strip()]
                existing = {r.get("domain", "").lower() for r in domain_rows}

                added = []
                for dom in entries:
                    if not _domain_is_valid(dom):
                        continue
                    if dom in existing:
                        continue

                    domain_rows.append({"domain": dom, "date_modified": _now_str()})
                    existing.add(dom)
                    added.append(dom)

                if added:
                    save_domain_whitelist(filepath, domain_rows)
                    log_activity(filepath, "Added", "Domain", added)
                    st.toast(f"Added {len(added)} domain(s)")
                    st.rerun()

    st.divider()

    search_query = st.text_input(
        "Search Whitelist",
        placeholder="Filter domains...",
        label_visibility="collapsed",
        key="dom_search"
    )

    df = pd.DataFrame(domain_rows)
    if df.empty:
        df = pd.DataFrame(columns=["domain", "date_modified"])

    for c in ["domain", "date_modified"]:
        if c not in df.columns:
            df[c] = ""

    if search_query:
        q = search_query.strip().lower()
        display_df = df[df["domain"].astype(str).str.lower().str.contains(q, na=False)].copy()
    else:
        display_df = df.copy()

    display_df["_dt_sort"] = display_df["date_modified"].apply(_parse_dt)
    display_df = display_df.sort_values(by="_dt_sort", ascending=False, na_position="last").drop(columns=["_dt_sort"])

    # ✅ Use your own # and hide index (fix alignment / spacing)
    display_df = _with_row_numbers(display_df)

    edited_df = _st_data_editor(
        display_df[["#", "domain", "date_modified"]],
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "#": st.column_config.NumberColumn("#", disabled=True, width="small"),
            "domain": st.column_config.TextColumn("Domain Name", validate=DOMAIN_REGEX_PATTERN, required=True, width="large"),
            "date_modified": st.column_config.TextColumn("Date Modified", disabled=True, width="medium"),
        },
        key="domain_editor",
        height=400
    )

    st.write("")
    if st.button("Save Changes", type="secondary", key="save_domain"):
        if "#" in edited_df.columns:
            edited_df = edited_df.drop(columns=["#"])

        old_map = {str(r.get("domain", "")).strip().lower(): r for r in domain_rows if r.get("domain")}

        visible_before = set(display_df["domain"].astype(str).str.strip().str.lower().tolist())
        rows = edited_df.to_dict("records")
        visible_after = set([str(r.get("domain", "")).strip().lower() for r in rows if r.get("domain")])

        deleted_from_view = visible_before - visible_after
        final_map = {d: r for d, r in old_map.items() if d not in deleted_from_view}

        for r in rows:
            dom = str(r.get("domain", "")).strip().lower()
            if not dom:
                continue
            if not _domain_is_valid(dom):
                continue

            old = old_map.get(dom, {})
            date_mod = str(old.get("date_modified", "") or "").strip() or _now_str()
            if dom not in old_map:
                date_mod = _now_str()

            final_map[dom] = {"domain": dom, "date_modified": date_mod}

        final_list = sorted(list(final_map.values()), key=lambda x: x.get("domain", ""))

        old_domains = set(old_map.keys())
        new_domains = set(final_map.keys())
        added = sorted(list(new_domains - old_domains))
        removed = sorted(list(old_domains - new_domains))

        save_domain_whitelist(filepath, final_list)

        if added:
            log_activity(filepath, "Added", "Domain", added)
        if removed:
            log_activity(filepath, "Deleted", "Domain", removed)

        st.success("Domain whitelist updated.")
        st.rerun()

# -----------------------------
# 3) AI Signature Manager ✅ add '#' column + hide index
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

    # ✅ Add your own # column, and hide the dataframe index (fix alignment / spacing)
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
# 4) Banning List Manager ✅ hide index + keep '#'
# -----------------------------
def render_banning_list(ban_file: Path):
    st.markdown("**Banning List**")

    ban_list = load_ban_list(ban_file)

    col_input, col_btn = st.columns([4, 1])
    with col_input:
        new_text = st.text_input(
            "Add MAC to Ban List",
            placeholder="Paste MAC Address",
            label_visibility="collapsed",
            key="ban_add_input"
        )
    with col_btn:
        if st.button("Enter", type="primary", key="ban_add_btn"):
            if new_text:
                entries = [m.strip().lower() for m in re.split(r"[,\s\n]+", new_text) if m.strip()]
                existing = {d.get("mac", "").lower() for d in ban_list}

                added = []
                for mac in entries:
                    if not _mac_is_valid(mac):
                        continue
                    if mac in existing:
                        st.warning("MAC address already available")
                        continue
                    ban_list.append({"mac": mac, "date_modified": _now_str()})
                    existing.add(mac)
                    added.append(mac)

                if added:
                    save_ban_list(ban_file, ban_list)
                    log_activity(ban_file, "Added", "Banned MAC", added)
                    st.toast(f"Banned {len(added)} MAC(s)")
                    st.rerun()

    st.divider()

    search_query = st.text_input(
        "Search Banned MACs",
        placeholder="Search MAC Address..",
        label_visibility="collapsed",
        key="ban_search"
    )

    df = pd.DataFrame(ban_list)
    if df.empty:
        df = pd.DataFrame(columns=["mac", "date_modified"])

    if search_query:
        df = df[df["mac"].astype(str).str.contains(search_query, case=False, na=False)].copy()

    df["_dt_sort"] = df["date_modified"].apply(_parse_dt)
    df = df.sort_values(by="_dt_sort", ascending=False, na_position="last").drop(columns=["_dt_sort"])

    # ✅ Add your own # and hide index (fix alignment / spacing)
    df = _with_row_numbers(df)

    edited_df = _st_data_editor(
        df[["#", "mac", "date_modified"]],
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "#": st.column_config.NumberColumn("#", disabled=True, width="small"),
            "mac": st.column_config.TextColumn("MAC Address", validate=MAC_REGEX_PATTERN, required=True, width="medium"),
            "date_modified": st.column_config.TextColumn("Date Modified", disabled=True, width="medium"),
        },
        key="ban_editor",
        height=400
    )

    st.write("")
    if st.button("Save Ban List Changes", type="secondary", key="ban_save"):
        if "#" in edited_df.columns:
            edited_df = edited_df.drop(columns=["#"])

        rows = edited_df.to_dict("records")
        final = []
        seen = set()
        old_map = {x["mac"]: x for x in ban_list}

        for r in rows:
            mac = str(r.get("mac", "")).strip().lower()
            if not mac:
                continue
            if not _mac_is_valid(mac):
                continue
            if mac in seen:
                continue
            seen.add(mac)

            date_mod = old_map.get(mac, {}).get("date_modified") or _now_str()
            final.append({"mac": mac, "date_modified": date_mod})

        save_ban_list(ban_file, final)
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
    saved_domains = load_domain_whitelist(domain_file)  # ✅ no category
    ai_config = load_ai_config(ai_yaml_file)

    st.title("Authorization Manager")

    m1, m2, m3 = st.columns(3)
    m1.metric("Device Whitelist", len(saved_devices))
    m2.metric("Domain Whitelist", len(saved_domains))
    m3.metric("AI Policies", len(ai_config.get("ai_signatures", {})))

    st.write("")

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["Device Access", "Domain Whitelist", "AI Policies", "Audit Log", "Banned List"]
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
                column_config={
                    "#": st.column_config.NumberColumn("#", width="small"),
                }
            )
            if st.button("Clear Audit Log", type="secondary"):
                (mac_file.parent / "activity_log.csv").unlink(missing_ok=True)
                st.rerun()
        else:
            st.info("No activity recorded yet.")

    with tab5:
        render_banning_list(ban_file)
