import streamlit as st
import pandas as pd
from datetime import datetime

def render(filtered):
    st.title(" Security Alerts")
    
    # Filter unauthorized devices
    unauth = filtered[filtered["status"]=="Unauthorized"]

    if unauth.empty:
        st.success("✅ System Secure: No unauthorized activity detected.")
        return

    st.error(f"🚨 ALERT: {unauth['mac'].nunique()} Unauthorized Devices Detected")
    
    # New unauthorized devices in last 24h
    new_devices = unauth.groupby("mac")["timestamp"].min()
    recent_new = new_devices[new_devices >= datetime.now() - pd.Timedelta(days=1)]
    
    st.warning(f"New unauthorized devices in last 24h: *{len(recent_new)}*")
    
    st.dataframe(
        unauth.sort_values("timestamp", ascending=False),
        use_container_width=True
    )
