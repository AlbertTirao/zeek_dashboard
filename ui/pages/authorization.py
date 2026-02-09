import streamlit as st
from pathlib import Path
import pandas as pd
import datetime
import yaml
import re
import requests  # For Vendor Lookup
import time      # For API rate limiting

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
# Data Logic - Generic
# -----------------------------
def load_simple_list(filepath: Path) -> list[str]:
    if not filepath.exists():
        return []
    with open(filepath, "r") as f:
        try:
            data = yaml.safe_load(f)
            if not data: return []
            items = []
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                for val in data.values():
                    if isinstance(val, list):
                        items = val
                        break
            return sorted(list(set(str(x).strip().lower() for x in items if x)))
        except:
            return []

def save_simple_list(filepath: Path, item_list: list[str]) -> None:
    filepath.parent.mkdir(exist_ok=True, parents=True)
    key_name = filepath.stem
    data_dict = {key_name: sorted(list(set(item_list)))}
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump(data_dict, f, sort_keys=False)

# -----------------------------
# Data Logic - Structured (Devices)
# -----------------------------
def load_devices(filepath: Path) -> list[dict]:
    default_structure = {"mac": "", "ip": "", "hostname": "", "vendor": ""}
    if not filepath.exists():
        return []

    with open(filepath, "r") as f:
        try:
            data = yaml.safe_load(f)
            if not data: return []
            
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
            for item in raw_list:
                if isinstance(item, str):
                    structured_data.append({
                        "mac": item.strip().lower(),
                        "ip": "", "hostname": "", "vendor": ""
                    })
                elif isinstance(item, dict):
                    entry = default_structure.copy()
                    clean_item = {k.lower(): v for k, v in item.items()}
                    entry.update(clean_item)
                    if entry["mac"]:
                        entry["mac"] = str(entry["mac"]).strip().lower()
                        structured_data.append(entry)
            
            return structured_data
        except Exception as e:
            print(f"Error loading devices: {e}")
            return []

def save_devices(filepath: Path, device_list: list[dict]) -> None:
    filepath.parent.mkdir(exist_ok=True, parents=True)
    key_name = filepath.stem
    device_list.sort(key=lambda x: x.get("mac", ""))
    data_dict = {key_name: device_list}
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump(data_dict, f, sort_keys=False)

# -----------------------------
# Metadata Enrichment Logic
# -----------------------------
@st.cache_data(show_spinner=False)
def get_mac_vendor(mac: str) -> str:
    """Queries macvendors.com API for vendor name."""
    if not mac or mac == "unknown":
        return "Unknown"
    try:
        # Added small delay to respect API rate limits even inside cache miss
        time.sleep(0.6) 
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text if r.status_code == 200 else "Unknown"
    except Exception:
        return "Unknown"

def get_latest_network_info() -> pd.DataFrame:
    """Scans Parquet files to find the latest IP and Hostname for MACs."""
    known_hosts_all = []
    dhcp_all = []

    if not PARQUET_ROOT.exists():
        return pd.DataFrame()

    for day_dir in sorted(p for p in PARQUET_ROOT.iterdir() if p.is_dir()):
        kh = day_dir / "known_hosts.parquet"
        dh = day_dir / "dhcp.parquet"
        if kh.exists(): known_hosts_all.append(pd.read_parquet(kh))
        if dh.exists(): dhcp_all.append(pd.read_parquet(dh))

    known_hosts = pd.concat(known_hosts_all, ignore_index=True) if known_hosts_all else pd.DataFrame()
    dhcp = pd.concat(dhcp_all, ignore_index=True) if dhcp_all else pd.DataFrame()

    if known_hosts.empty:
        return pd.DataFrame()

    if "mac" in known_hosts.columns:
        known_hosts["mac"] = known_hosts["mac"].str.lower().str.strip()
    
    if not dhcp.empty:
        if "mac" in dhcp.columns:
            dhcp["mac"] = dhcp["mac"].str.lower().str.strip()
            dhcp_cols = [c for c in ["mac", "host_name"] if c in dhcp.columns]
            dhcp_norm = dhcp[dhcp_cols].drop_duplicates(subset=["mac"], keep='last')
            merged = pd.merge(known_hosts, dhcp_norm, how="left", on="mac")
        else:
            dhcp_cols = [c for c in ["client_addr","host_name"] if c in dhcp.columns]
            dhcp_norm = dhcp[dhcp_cols].drop_duplicates(subset=["client_addr"], keep='last')
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
# Configuration Logic (AI)
# -----------------------------
def load_ai_config(filepath: Path):
    if not filepath.exists():
        return {"authorized_providers": [], "ai_signatures": {}}
    with open(filepath, "r") as f:
        try:
            config = yaml.safe_load(f)
            return config if config else {"authorized_providers": [], "ai_signatures": {}}
        except:
            return {"authorized_providers": [], "ai_signatures": {}}

def save_ai_config(filepath: Path, config_dict: dict):
    filepath.parent.mkdir(exist_ok=True, parents=True)
    with open(filepath, "w") as f:
        yaml.safe_dump(config_dict, f, sort_keys=False)

# -----------------------------
# Logging Logic
# -----------------------------
def log_activity(filepath: Path, action: str, item_type: str, items: list[str]):
    if not items: return
    log_file = filepath.parent / "activity_log.csv"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_rows = [{"Timestamp": timestamp, "Action": action, "Type": item_type, "Item": item} for item in items]
    df_new = pd.DataFrame(new_rows)
    header_needed = not log_file.exists()
    df_new.to_csv(log_file, mode='a', header=header_needed, index=False)

def load_history(filepath: Path) -> pd.DataFrame:
    log_file = filepath.parent / "activity_log.csv"
    if not log_file.exists():
        return pd.DataFrame(columns=["Timestamp", "Action", "Type", "Item"])
    try:
        df = pd.read_csv(log_file)
        return df.drop_duplicates().sort_values(by="Timestamp", ascending=False)
    except:
        return pd.DataFrame(columns=["Timestamp", "Action", "Type", "Item"])

# -----------------------------
# AUTOMATIC ENRICHMENT FUNCTION
# -----------------------------
def auto_enrich_devices(device_list):
    """
    Runs automatically to fill in missing IP, Hostname, and Vendor info.
    Returns the updated list and a boolean indicating if changes were made.
    """
    # 1. Get Network Info from Parquet
    net_df = get_latest_network_info()
    net_map = {}
    if not net_df.empty:
        net_map = net_df.set_index("mac").to_dict(orient="index")

    changes_detected = False
    
    # 2. Iterate and Update in Memory
    for device in device_list:
        mac = device.get("mac", "").lower()
        
        # A. Update IP/Host from Logs
        if mac in net_map:
            found_ip = str(net_map[mac].get("latest_ip", ""))
            found_host = str(net_map[mac].get("latest_host", ""))
            
            # Fill if empty or different
            if found_ip and found_ip != "nan" and found_ip != device.get("ip"):
                device["ip"] = found_ip
                changes_detected = True
            
            if found_host and found_host != "nan" and found_host != device.get("hostname"):
                device["hostname"] = found_host
                changes_detected = True
        
        # B. Update Vendor from API (Only if missing)
        # We skip this if already known to avoid API rate limits
        if not device.get("vendor") or device.get("vendor") == "Unknown":
            found_vendor = get_mac_vendor(mac)
            if found_vendor and found_vendor != "Unknown":
                device["vendor"] = found_vendor
                changes_detected = True

    return device_list, changes_detected

# -----------------------------
# 1. Device Manager (Modified)
# -----------------------------
def render_device_manager(device_list: list[dict], filepath: Path):
    
    st.markdown("**Device Management**")
    
    # --- AUTOMATIC SCANNING LOGIC ---
    # We use session state to ensure we don't scan on every single keystroke, 
    # but we DO scan on initial load or if explicitly refreshed.
    if "has_scanned" not in st.session_state:
        with st.spinner("Auto-detecting network metadata..."):
            updated_list, changes = auto_enrich_devices(device_list)
            if changes:
                # If we found new data, we save it to session (and optionally to disk immediately)
                # Here we update the object passed by reference so the editor sees it
                device_list[:] = updated_list
                # Optional: Save to disk immediately so it persists
                save_devices(filepath, device_list) 
                st.toast("Network metadata updated automatically")
        st.session_state["has_scanned"] = True

    # --- Add New Device Input ---
    col_input, col_btn = st.columns([4, 1])
    with col_input:
        new_text = st.text_input(
            "Quick Add Device", 
            placeholder="Paste MAC Address (e.g., 00:1a:2b:3c:4d:5e)", 
            label_visibility="collapsed"
        )
    with col_btn:
        if st.button("Add Device", key="btn_import_mac", type="primary"):
            if new_text:
                entries = [m.strip().lower() for m in re.split(r'[,\s\n]+', new_text) if m.strip()]
                existing_macs = {d['mac'] for d in device_list}
                
                added_count = 0
                new_entries_for_log = []
                
                for mac in entries:
                    if mac not in existing_macs:
                        device_list.append({
                            "mac": mac,
                            "ip": "", "hostname": "", "vendor": ""
                        })
                        existing_macs.add(mac)
                        new_entries_for_log.append(mac)
                        added_count += 1
                
                if added_count > 0:
                    # Force a re-scan next time because we have new empty devices
                    if "has_scanned" in st.session_state:
                        del st.session_state["has_scanned"]
                    
                    save_devices(filepath, device_list)
                    log_activity(filepath, "Added", "Device", new_entries_for_log)
                    st.toast(f"Added {added_count} new devices")
                    st.rerun()

    st.divider()

    # --- Search ---
    search_query = st.text_input("Search Devices", placeholder="Filter by MAC, IP, Hostname...", label_visibility="collapsed")

    # --- Prepare Data for Editor ---
    df = pd.DataFrame(device_list)
    if df.empty:
        df = pd.DataFrame(columns=["mac", "ip", "hostname", "vendor"])
    
    if search_query:
        mask = df.apply(lambda x: x.astype(str).str.contains(search_query, case=False).any(), axis=1)
        display_df = df[mask].copy()
    else:
        display_df = df.copy()

    # --- Main Editor ---
    edited_df = st.data_editor(
        display_df,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "mac": st.column_config.TextColumn("MAC Address", validate=MAC_REGEX_PATTERN, required=True, width="medium"),
            "ip": st.column_config.TextColumn("IP Address", disabled=False, width="small"),
            "hostname": st.column_config.TextColumn("Host Name", disabled=False, width="medium"),
            "vendor": st.column_config.TextColumn("Vendor", disabled=True, width="small") # Vendor usually auto-filled
        },
        key="device_editor",
        height=400
    )

    # --- Save Logic ---
    st.write("")
    if st.button("Save Device Changes", type="secondary", key="save_devices"):
        new_state_dicts = edited_df.to_dict('records')
        visible_macs = set(display_df['mac'].tolist())
        
        final_list = []
        # Preserve hidden items
        if search_query:
            for item in device_list:
                if item['mac'] not in visible_macs:
                    final_list.append(item)
        
        # Add editor items
        for item in new_state_dicts:
            if item.get("mac") and str(item["mac"]).strip():
                clean_item = {
                    "mac": str(item["mac"]).strip().lower(),
                    "ip": str(item.get("ip", "")).strip(),
                    "hostname": str(item.get("hostname", "")).strip(),
                    "vendor": str(item.get("vendor", "")).strip()
                }
                final_list.append(clean_item)
        
        # Deduplicate
        unique_map = {x['mac']: x for x in final_list}
        final_list = list(unique_map.values())

        # Logging
        old_macs = set(d['mac'] for d in device_list)
        new_macs = set(d['mac'] for d in final_list)
        added = new_macs - old_macs
        removed = old_macs - new_macs
        
        save_devices(filepath, final_list)
        
        if added: log_activity(filepath, "Added", "Device", list(added))
        if removed: log_activity(filepath, "Deleted", "Device", list(removed))
        
        st.success("Device database updated successfully.")
        st.rerun()

# -----------------------------
# 2. Generic List Manager
# -----------------------------
def render_domain_manager(data_list: list[str], filepath: Path):
    item_name = "Domain"
    st.markdown(f"**{item_name} Whitelist**")
    
    col_input, col_btn = st.columns([4, 1])
    with col_input:
        new_text = st.text_input(f"Add {item_name}", placeholder="example.com", label_visibility="collapsed")
    with col_btn:
        if st.button("Add", key=f"btn_import_{item_name}"):
            if new_text:
                entries = [m.strip().lower() for m in re.split(r'[,\s\n]+', new_text) if m.strip()]
                existing_set = set(data_list)
                new_items = [x for x in entries if x not in existing_set]
                
                if new_items:
                    save_simple_list(filepath, data_list + new_items)
                    log_activity(filepath, "Added", item_name, new_items)
                    st.toast(f"Added {len(new_items)} items")
                    st.rerun()

    st.divider()
    search_query = st.text_input("Search Whitelist", placeholder=f"Filter {item_name}s...", label_visibility="collapsed")
    filtered_list = [item for item in data_list if search_query.lower() in item.lower()] if search_query else data_list
    df = pd.DataFrame({"Domain Name": filtered_list})
    
    edited_df = st.data_editor(
        df,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "Domain Name": st.column_config.TextColumn("Domain Name", validate=DOMAIN_REGEX_PATTERN, required=True, width="large")
        },
        key=f"editor_{item_name}",
        height=400
    )
    
    st.write("")
    if st.button(f"Save Changes", type="secondary", key=f"save_{item_name}"):
        current_edited_items = []
        if not edited_df.empty:
             current_edited_items = sorted(list(set(edited_df["Domain Name"].astype(str).str.strip().str.lower().tolist())))
        
        original_filtered_set = set(filtered_list)
        new_filtered_set = set(current_edited_items)
        
        deleted_from_view = original_filtered_set - new_filtered_set
        added_to_view = new_filtered_set - original_filtered_set
        
        final_set = set(data_list) - deleted_from_view | added_to_view
        final_list = sorted(list(final_set))
        
        if deleted_from_view or added_to_view:
            save_simple_list(filepath, final_list)
            if added_to_view: log_activity(filepath, "Added", item_name, list(added_to_view))
            if deleted_from_view: log_activity(filepath, "Deleted", item_name, list(deleted_from_view))
            st.success("Domain whitelist updated.")
            st.rerun()

# -----------------------------
# AI Signature Manager
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
    
    edited_sigs = st.data_editor(
        sig_df,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "Provider": st.column_config.TextColumn("Provider Name", required=True),
            "Patterns": st.column_config.TextColumn("Regex Patterns (Comma Separated)", width="large", required=True)
        },
        key="ai_sig_editor"
    )
    
    if st.button("Save AI Policies", type="primary", key="save_ai"):
        new_sigs = {}
        for _, row in edited_sigs.iterrows():
            if pd.notna(row.get("Provider")) and pd.notna(row.get("Patterns")):
                p_name = str(row["Provider"]).strip()
                p_pats = [p.strip() for p in str(row["Patterns"]).split(",") if p.strip()]
                if p_name: new_sigs[p_name] = p_pats
        
        config["ai_signatures"] = new_sigs
        save_ai_config(yaml_path, config)
        log_activity(yaml_path, "Edited", "AI Signatures", ["Bulk Configuration Update"])
        st.success("AI policies updated successfully.")

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

    saved_devices = load_devices(mac_file)
    saved_domains = load_simple_list(domain_file)
    ai_config = load_ai_config(ai_yaml_file)
    
    st.title("Authorization Manager")
    
    m1, m2, m3 = st.columns(3)
    m1.metric("Device Whitelist", len(saved_devices))
    m2.metric("Domain Whitelist", len(saved_domains))
    m3.metric("AI Policies", len(ai_config.get("ai_signatures", {})))

    st.write("") 

    tab1, tab2, tab3, tab4 = st.tabs(["Device Access", "Domain Whitelist", "AI Policies", "Audit Log"])

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
            st.dataframe(history_df, use_container_width=True, hide_index=True, height=500)
            if st.button("Clear Audit Log", type="secondary"):
                (mac_file.parent / "activity_log.csv").unlink(missing_ok=True)
                st.rerun()
        else:
            st.info("No activity recorded yet.")

if __name__ == "__main__":
    st.set_page_config(page_title="Authorization Manager", layout="wide")
    current_dir = Path(__file__).parent.absolute()
    test_file = current_dir / "authorized_macs.yaml"
    render(test_file)