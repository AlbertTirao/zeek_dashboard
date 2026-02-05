import streamlit as st
import pandas as pd

def render(df):
    st.title("🛡️ User Identity & Security Alerts")

    # 1. Validation
    if df is None or df.empty:
        st.info("⏳ Waiting for user activity logs...")
        return

    # --- 2. PRECISE COLUMN MAPPING (Fixed) ---
    # We create a clean display copy.
    display_df = df.copy()

    # Helper function: Tries to find the *best* matching column from a list.
    # It stops as soon as it finds a match.
    def get_col(df, candidates, default_val):
        for col in candidates:
            if col in df.columns:
                return df[col]
        # If no column found, fill with default
        return pd.Series([default_val] * len(df), index=df.index)

    # REVISED PRIORITY: Look for the "Formal" headers from your screenshot first.
    # We moved 'mac' and 'hostname' to the end of the list in case they are corrupted.
    
    # 1. MAC Address
    display_df["_final_mac"] = get_col(
        display_df, 
        ["MAC Address", "mac_address", "ether", "Hardware Address", "mac"], 
        "Unknown MAC"
    )
    
    # 2. IP Address (Try 'IP Address' first, then Zeek standard 'id.orig_h')
    display_df["_final_ip"] = get_col(
        display_df, 
        ["IP Address", "IP", "id.orig_h", "source_ip", "src_ip", "ip"], 
        "Unknown IP"
    )
    
    # 3. Host Name (Prioritize 'Host Name')
    display_df["_final_host"] = get_col(
        display_df, 
        ["Host Name", "hostname", "computer_name", "dhcp_host_name", "host"], 
        "Unknown Host"
    )
    
    # 4. Domain (Prioritize 'Domain')
    display_df["_final_domain"] = get_col(
        display_df, 
        ["Domain", "domain_name", "domain", "qname"], 
        "bns.arpa"
    )

    # --- 3. DEDUPLICATION ---
    # Filter to unique MACs so we don't see the same user 50 times.
    unique_df = display_df.drop_duplicates(subset=["_final_mac"], keep="last").copy()

    # Handle Status (Check if 'status' column exists, otherwise default)
    if "status" in unique_df.columns:
        unique_df["_final_status"] = unique_df["status"]
    else:
        unique_df["_final_status"] = "Unknown"

    # --- 4. METRICS ---
    unauth_users = unique_df[unique_df["_final_status"] == "Unauthorized"]
    
    total_users = len(unique_df)
    unauth_count = len(unauth_users)
    auth_count = total_users - unauth_count

    col1, col2, col3 = st.columns(3)
    col1.metric("👥 Unique Users", total_users)
    col2.metric("✅ Verified", auth_count)
    col3.metric("🚫 Unauthorized", unauth_count, delta_color="inverse")

    st.divider()

    # --- 5. ALERTS BANNER ---
    if not unauth_users.empty:
        st.error(f"🚨 SECURITY ALERT: {unauth_count} Unauthorized User(s) Detected!")
        
        # Optional: Detailed list in expander
        with st.expander("🔍 Quick View: Intruder Details", expanded=False):
            for _, row in unauth_users.iterrows():
                st.markdown(f"🔴 **User:** `{row['_final_host']}` | **IP:** `{row['_final_ip']}` | **MAC:** `{row['_final_mac']}`")
    else:
        st.success("✅ Network Secure: All active users are verified.")

    # --- 6. CREDENTIALS TABLE (Corrected) ---
    st.subheader("User Network Credentials")

    # Build the table using ONLY our cleaner "_final_" columns
    table_data = pd.DataFrame()
    table_data["MAC Address"] = unique_df["_final_mac"]
    table_data["IP Address"]  = unique_df["_final_ip"]
    table_data["Host Name"]   = unique_df["_final_host"]
    table_data["Domain"]      = unique_df["_final_domain"]
    table_data["Status"]      = unique_df["_final_status"]

    # Style the table
    def highlight_unauthorized(row):
        if row["Status"] == "Unauthorized":
            return ['background-color: rgba(255, 75, 75, 0.2)'] * len(row)
        return [''] * len(row)

    st.dataframe(
        table_data.style.apply(highlight_unauthorized, axis=1),
        use_container_width=True,
        height=600,
        hide_index=True
    )

    # --- 7. DEBUGGER (Hidden by default) ---
    # If columns are still wrong, open this to see what your data actually looks like.
    with st.expander("🛠️ Debug: View Raw Column Names"):
        st.write("Available Columns in Data:", df.columns.tolist())
        st.write("First 3 rows of raw data:", df.head(3))