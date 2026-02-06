import streamlit as st
import pandas as pd
import os
import time
from pathlib import Path

# --- HELPER FUNCTIONS ---

def get_latest_data(parquet_root):
    """Scans the directory for the most recent log file."""
    try:
        root_path = Path(parquet_root)
        
        if not root_path.exists():
            st.error(f"❌ Directory '{parquet_root}' not found.")
            return None, None

        # Recursive Search for Parquet files
        all_parquet_files = list(root_path.rglob("*.parquet"))

        if not all_parquet_files:
            return None, None

        # Priority: DHCP -> Conn -> DNS (Sort by modification time descending)
        dhcp_files = sorted([f for f in all_parquet_files if "dhcp" in f.name], key=os.path.getmtime, reverse=True)
        conn_files = sorted([f for f in all_parquet_files if "conn" in f.name], key=os.path.getmtime, reverse=True)
        dns_files  = sorted([f for f in all_parquet_files if "dns" in f.name],  key=os.path.getmtime, reverse=True)

        target_file = None
        if dhcp_files: target_file = dhcp_files[0]
        elif conn_files: target_file = conn_files[0]
        elif dns_files: target_file = dns_files[0]
        else: target_file = sorted(all_parquet_files, key=os.path.getmtime, reverse=True)[0]

        if target_file:
            df = pd.read_parquet(target_file)
            return df, target_file
            
    except Exception as e:
        st.error(f"⚠️ Error reading file: {e}")
        return None, None
    
    return None, None

def load_authorized_macs(auth_file):
    """Loads allowed MAC addresses into a set."""
    allowed = set()
    if os.path.exists(auth_file):
        try:
            with open(auth_file, "r") as f:
                allowed = {line.strip() for line in f if line.strip()}
        except Exception:
            pass
    return allowed

def get_col(df, candidates, default_val):
    """Helper to find columns safely from a list of candidates."""
    for col in candidates:
        if col in df.columns: return df[col]
    return pd.Series([default_val] * len(df), index=df.index)

# --- MAIN RENDER FUNCTION ---

def render(parquet_root, authorized_macs_file):
    """
    Main function called by app.py.
    """
    
    # --- SIDEBAR CONTROLS ---
    # We use a unique key for the toggle to avoid state conflicts
    st.sidebar.markdown("---")
    st.sidebar.header("Alerts Settings")
    auto_refresh = st.sidebar.toggle("Enable Live Monitoring", value=True, key="alerts_auto_refresh")
    refresh_rate = st.sidebar.slider("Refresh Interval (s)", 1, 60, 5, key="alerts_refresh_rate")

    # --- HEADER ---
    col_h1, col_h2 = st.columns([3, 1])
    with col_h1:
        st.title(" User Identity & Security Alerts")
    with col_h2:
        if auto_refresh:
            st.markdown(f"#### 🟢 Live: {refresh_rate}s")
        else:
            st.markdown("#### 🔴 Paused")

    # --- DATA LOADING ---
    df, target_file = get_latest_data(parquet_root)
    allowed_macs = load_authorized_macs(authorized_macs_file)

    if df is None:
        st.warning(f"⚠️ No logs found in {parquet_root}. Waiting for Zeek data...")
        if auto_refresh:
            time.sleep(refresh_rate)
            st.rerun()
        return

    # Show file source subtly
    st.caption(f"Source: `{target_file.name}` |  Last Modified: {time.ctime(os.path.getmtime(target_file))}")

    # --- NORMALIZE COLUMNS ---
    df["_final_ts"] = get_col(df, ["ts", "timestamp", "time"], pd.NaT)
    df["_final_mac"] = get_col(df, ["MAC Address", "mac", "orig_l2_addr", "hardware_address"], "Unknown MAC")
    df["_final_ip"] = get_col(df, ["id.orig_h", "IP Address", "src_ip", "source_ip", "ip"], "Unknown IP")
    df["_final_host"] = get_col(df, ["host_name", "Host Name", "computer_name"], "Unknown Host")

    # --- PROCESSING ---
    if not df.empty:
        # Sort by time to ensure 'last' is recent
        if pd.api.types.is_numeric_dtype(df["_final_ts"]):
            df = df.sort_values("_final_ts")
        unique_df = df.drop_duplicates(subset=["_final_mac"], keep="last").copy()
    else:
        unique_df = df.copy()

    # Check Status
    def check_status(row):
        mac = row["_final_mac"]
        if mac == "Unknown MAC": return "Unknown"
        if mac in allowed_macs: return "Verified"
        return "Unauthorized"

    unique_df["_final_status"] = unique_df.apply(check_status, axis=1)

    # --- METRICS & ALERTS ---
    unauth_users = unique_df[unique_df["_final_status"] == "Unauthorized"]
    unauth_count = len(unauth_users)
    
    m1, m2, m3 = st.columns(3)
    m1.metric("Total Devices", len(unique_df))
    m2.metric("Verified Devices", len(unique_df[unique_df["_final_status"] == "Verified"]))
    m3.metric("Unauthorized / Unknown", len(unique_df) - len(unique_df[unique_df["_final_status"] == "Verified"]), delta_color="inverse")

    st.divider()

    if unauth_count > 0:
        st.error(f" SECURITY ALERT: {unauth_count} UNAUTHORIZED DEVICE(S) DETECTED!", icon="⚠️")
    elif unique_df.empty:
        st.info("Waiting for device traffic...")
    else:
        st.success("✅ System Secure. All devices verified.", icon="🛡️")

    # --- TABLE DISPLAY ---
    st.subheader("Live Traffic Analysis")

    # Sort Weight: Unauthorized=0 (Top), Unknown=1, Verified=2
    def get_sort_weight(status):
        if status == "Unauthorized": return 0
        if status == "Unknown": return 1
        return 2
    
    unique_df["_sort_weight"] = unique_df["_final_status"].apply(get_sort_weight)
    sorted_df = unique_df.sort_values(by=["_sort_weight", "_final_ts"], ascending=[True, False])

    # Convert Timestamp for display
    try:
        if pd.api.types.is_numeric_dtype(sorted_df["_final_ts"]):
            sorted_df["Display Time"] = pd.to_datetime(sorted_df["_final_ts"], unit='s')
        else:
            sorted_df["Display Time"] = sorted_df["_final_ts"]
    except:
        sorted_df["Display Time"] = sorted_df["_final_ts"]

    display_table = sorted_df[[
        "Display Time", "_final_ip", "_final_mac", "_final_host", "_final_status"
    ]].rename(columns={
        "_final_ip": "IP Address", "_final_mac": "MAC Address", 
        "_final_host": "Host Name", "_final_status": "Status"
    })

    def highlight_security(row):
        status = row["Status"]
        if status == "Unauthorized":
            return ['background-color: #ff4b4b; color: white; font-weight: bold'] * len(row)
        elif status == "Unknown":
            return ['background-color: #f0f2f6; color: black'] * len(row)
        else: 
            return ['background-color: #d1e7dd; color: black'] * len(row)

    st.dataframe(
        display_table.style.apply(highlight_security, axis=1),
        use_container_width=True,
        hide_index=True,
        column_config={
            "Display Time": st.column_config.DatetimeColumn("Last Seen", format="HH:mm:ss")
        }
    )

    # --- AUTO REFRESH ---
    if auto_refresh:
        time.sleep(refresh_rate)
        st.rerun()