import streamlit as st
import pandas as pd
import os
import time
from pathlib import Path

# --- VENDOR LOOKUP SETUP ---
try:
    from mac_vendor_lookup import MacLookup
    VENDOR_LIB_AVAILABLE = True
except ImportError:
    VENDOR_LIB_AVAILABLE = False

# --- HELPER FUNCTIONS ---

def get_latest_data(parquet_root):
    """
    Scans for the most recent log file AND known_hosts.parquet.
    """
    try:
        root_path = Path(parquet_root)
        
        if not root_path.exists():
            st.error(f"Directory '{parquet_root}' not found.")
            return None, None, None

        all_parquet_files = list(root_path.rglob("*.parquet"))
        if not all_parquet_files:
            return None, None, None

        # 1. Find known_hosts.parquet specifically
        known_hosts_file = next((f for f in all_parquet_files if "known_hosts" in f.name or "knownhost" in f.name), None)
        known_hosts_df = pd.DataFrame()
        
        if known_hosts_file:
            try:
                known_hosts_df = pd.read_parquet(known_hosts_file)
            except:
                pass

        # 2. Find the active log file (DHCP -> Conn -> DNS)
        traffic_files = [f for f in all_parquet_files if "known_hosts" not in f.name and "knownhost" not in f.name]
        
        dhcp_files = sorted([f for f in traffic_files if "dhcp" in f.name], key=os.path.getmtime, reverse=True)
        conn_files = sorted([f for f in traffic_files if "conn" in f.name], key=os.path.getmtime, reverse=True)
        dns_files  = sorted([f for f in traffic_files if "dns" in f.name],  key=os.path.getmtime, reverse=True)

        target_file = None
        if dhcp_files: target_file = dhcp_files[0]
        elif conn_files: target_file = conn_files[0]
        elif dns_files: target_file = dns_files[0]
        elif traffic_files: target_file = sorted(traffic_files, key=os.path.getmtime, reverse=True)[0]

        df = pd.DataFrame()
        if target_file:
            df = pd.read_parquet(target_file)
            
        return df, target_file, known_hosts_df
            
    except Exception as e:
        st.error(f"Error reading file: {e}")
        return None, None, None

def load_authorized_macs(auth_file):
    """
    Loads allowed MAC addresses into a set.
    Forces lowercase to prevent case-sensitive mismatches.
    """
    allowed = set()
    if os.path.exists(auth_file):
        try:
            with open(auth_file, "r") as f:
                allowed = {line.strip().lower() for line in f if line.strip()}
        except Exception:
            pass
    return allowed

def get_col(df, candidates, default_val):
    """Helper to find columns safely from a list of candidates."""
    for col in candidates:
        if col in df.columns: return df[col]
    return pd.Series([default_val] * len(df), index=df.index)

# --- CACHED VENDOR LOOKUP ---
@st.cache_resource
def get_vendor_lookup_instance():
    """
    Initializes the MacLookup object once. 
    """
    if VENDOR_LIB_AVAILABLE:
        try:
            mac_lookup = MacLookup()
            return mac_lookup
        except Exception as e:
            print(f"Vendor lookup init failed: {e}")
            return None
    return None

# --- MAIN RENDER FUNCTION ---

def render(parquet_root, authorized_macs_file):
    """
    Main function called by app.py.
    """
    
    # --- AUTO REFRESH CONTROLS ---
    col1, col2 = st.columns([0.8, 0.2])
    with col2:
        # User can now toggle this ON/OFF to stop the "constant rendering"
        auto_refresh = st.checkbox("Auto-Refresh", value=True)
    
    REFRESH_RATE = 3 

    # --- DATA LOADING ---
    df, target_file, known_hosts_df = get_latest_data(parquet_root)
    allowed_macs = load_authorized_macs(authorized_macs_file)

    if df is None or df.empty:
        st.warning(f"No traffic logs found in {parquet_root}. Waiting for Zeek data...")
        if auto_refresh:
            time.sleep(REFRESH_RATE)
            st.rerun()
        return

    # --- CLEANING DATA ---
    if not df.empty:
        df = df[~df.astype(str).apply(lambda x: x.str.startswith('#')).any(axis=1)]

    # --- NORMALIZE COLUMNS ---
    df["_final_ts"] = get_col(df, ["ts", "timestamp", "time"], pd.NaT)
    df["_final_mac"] = get_col(df, ["MAC Address", "mac", "orig_l2_addr", "hardware_address"], "Unknown MAC")
    df["_final_ip"] = get_col(df, ["id.orig_h", "IP Address", "src_ip", "source_ip", "ip"], "Unknown IP")
    df["_final_host"] = get_col(df, ["host_name", "Host Name", "computer_name"], "Unknown Host")

    # --- MERGE WITH KNOWN HOSTS ---
    known_macs_map = {} 
    known_vendor_map = {} 

    if not known_hosts_df.empty:
        kh_mac = get_col(known_hosts_df, ["mac", "MAC Address", "host_mac"], None)
        kh_ip  = get_col(known_hosts_df, ["host_ip", "ip", "IP Address"], None)
        kh_vendor_col = get_col(known_hosts_df, ["vendor", "Vendor", "manuf", "manufacturer"], None)

        if kh_mac is not None:
            if kh_ip is not None:
                known_macs_map = dict(zip(kh_mac, kh_ip))
            if kh_vendor_col is not None and not kh_vendor_col.isnull().all():
                known_vendor_map = dict(zip(kh_mac, kh_vendor_col))

    # --- VENDOR RESOLUTION LOGIC ---
    mac_lookup = get_vendor_lookup_instance()

    def resolve_vendor(mac):
        mac = str(mac).strip()
        if mac in known_vendor_map: return known_vendor_map[mac]
        if mac_lookup and len(mac) >= 8: 
            try: return mac_lookup.lookup(mac)
            except: pass
        if not VENDOR_LIB_AVAILABLE: return "Unknown (Install 'mac-vendor-lookup')"
        return "Unknown Vendor"

    def fill_details(row):
        current_ip = str(row["_final_ip"])
        mac = row["_final_mac"]
        if current_ip in ["Unknown IP", "none", "-", "None", "nan", "0.0.0.0"] and mac in known_macs_map:
            row["_final_ip"] = known_macs_map[mac]
        row["_final_vendor"] = resolve_vendor(mac)
        return row

    df = df.apply(fill_details, axis=1)

    # --- PROCESSING ---
    if not df.empty:
        if pd.api.types.is_numeric_dtype(df["_final_ts"]):
            df = df.sort_values("_final_ts")
        unique_df = df.drop_duplicates(subset=["_final_mac"], keep="last").copy()
    else:
        unique_df = df.copy()

    # --- STATUS CHECK ---
    def check_status(row):
        raw_mac = str(row["_final_mac"])
        mac_lower = raw_mac.lower()
        if mac_lower in ["unknown mac", "none", "addr", "-", "nan", "empty"]: return "Unknown"
        if mac_lower in allowed_macs: return "Verified"
        return "Unauthorized"

    unique_df["_final_status"] = unique_df.apply(check_status, axis=1)

    # --- METRICS & ALERTS ---
    unauth_users = unique_df[unique_df["_final_status"] == "Unauthorized"]
    unauth_count = len(unauth_users)
    verifiable_devices = len(unique_df[unique_df["_final_status"] != "Unknown"])

    st.divider()

    if unauth_count > 0:
        st.error(f"SECURITY ALERT: {unauth_count} UNAUTHORIZED DEVICE(S) DETECTED!")
    elif verifiable_devices == 0 and not unique_df.empty:
        st.warning("Data received, but no verifiable MAC addresses found.")
    elif unique_df.empty:
        st.info("Waiting for traffic...")
    else:
        st.success("System Secure. All visible devices verified.")

    # --- TABLE DISPLAY ---
    st.subheader("Live Threat Analysis (Unauthorized)")

    invalid_macs = ["Unknown MAC", "none", "None", "addr", "-", "00:00:00:00:00:00", "nan"]
    
    threats_df = unique_df[
        (unique_df["_final_status"] != "Verified") & 
        (~unique_df["_final_mac"].astype(str).isin(invalid_macs))
    ].copy()

    if threats_df.empty:
        st.info("No unauthorized devices found.")
    else:
        threats_df["_sort_weight"] = 0 
        sorted_df = threats_df.sort_values(by=["_final_ts"], ascending=False)

        # Time Conversion
        try:
            if pd.api.types.is_numeric_dtype(sorted_df["_final_ts"]):
                sorted_df["Display Time"] = pd.to_datetime(sorted_df["_final_ts"], unit='s')
            else:
                sorted_df["Display Time"] = sorted_df["_final_ts"]
        except:
            sorted_df["Display Time"] = sorted_df["_final_ts"]

        display_table = sorted_df[[
            "Display Time", "_final_ip", "_final_mac", "_final_vendor", "_final_host", "_final_status"
        ]].rename(columns={
            "_final_ip": "IP Address", 
            "_final_mac": "MAC Address", 
            "_final_vendor": "Vendor",
            "_final_host": "Host Name", 
            "_final_status": "Status"
        })

        def highlight_security(row):
            return ['background-color: #ff4b4b; color: white; font-weight: bold'] * len(row)

        st.dataframe(
            display_table.style.apply(highlight_security, axis=1),
            use_container_width=True,
            hide_index=True,
            column_config={
                "Display Time": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD HH:mm:ss")
            }
        )

    # --- AUTO REFRESH LOOP ---
    if auto_refresh:
        time.sleep(REFRESH_RATE)
        st.rerun()