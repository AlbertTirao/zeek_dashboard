# ui/pages/shadow_ai.py
import streamlit as st
import pandas as pd
import plotly.express as px
from .constants import MAX_ROWS_DISPLAY

def render_shadow_ai(filtered: pd.DataFrame):
    st.subheader("Shadow AI Overview")

    if "application" not in filtered.columns:
        st.info("No AI data available.")
        return

    df_tab = filtered[filtered["application"].str.contains("ai", case=False, na=False)]
    if df_tab.empty:
        st.info("No AI apps detected.")
        return

    count_by_mac = df_tab.groupby("mac").size().reset_index(name="count")
    fig_bar = px.bar(count_by_mac.head(50), x="mac", y="count", title="Top AI App Devices", template="plotly_dark")
    st.plotly_chart(fig_bar, use_container_width=True)

    if "timestamp" in df_tab.columns:
        df_tab["timestamp"] = pd.to_datetime(df_tab["timestamp"], errors="coerce")
        df_line = df_tab.dropna(subset=["timestamp"]).groupby(pd.Grouper(key="timestamp", freq="H")).size().reset_index(name="count")
        fig_line = px.line(df_line, x="timestamp", y="count", title="AI App Events Over Time", template="plotly_dark")
        st.plotly_chart(fig_line, use_container_width=True)

    st.subheader("Device Details - Shadow AI")
    st.dataframe(df_tab.head(MAX_ROWS_DISPLAY), use_container_width=True)
    st.markdown(f"Showing {min(MAX_ROWS_DISPLAY, len(df_tab))} of {len(df_tab)} rows")
