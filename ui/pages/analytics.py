# ui/pages/analytics.py
import streamlit as st
import pandas as pd
from .shadow_apps import render_shadow_apps
from .shadow_uploads import render_shadow_uploads
from .shadow_ai import render_shadow_ai

def render(filtered: pd.DataFrame, http_logs=None, ssl_logs=None, dns_logs=None):
    st.set_page_config(page_title="Network Analytics", layout="wide")
    st.title("Network Analytics")

    if st.button("Refresh Analytics"):
        st.rerun()

    if filtered.empty:
        st.info("No device data available for analytics.")
        return

    tab = st.radio("Select Section", ["Shadow Apps", "Shadow Uploads", "Shadow AI"], horizontal=True)

    if tab == "Shadow Apps":
        render_shadow_apps(http_logs=http_logs, ssl_logs=ssl_logs, dns_logs=dns_logs)
    elif tab == "Shadow Uploads":
        render_shadow_uploads(filtered)
    elif tab == "Shadow AI":
        render_shadow_ai(filtered)
