import streamlit as st
import pandas as pd
import plotly.express as px

def render(filtered: pd.DataFrame):
    st.title("Network Analytics")

    # Counts
    total_devices = filtered["mac"].nunique()
    total_auth = filtered[filtered["status"]=="Authorized"]["mac"].nunique()
    total_unauth = filtered[filtered["status"]=="Unauthorized"]["mac"].nunique()

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Devices", total_devices)
    c2.metric("Authorized", total_auth)
    c3.metric("Unauthorized", total_unauth)

    st.markdown("---")
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Device Vendors")
        vendor_counts = filtered.groupby("vendor")["mac"].nunique().sort_values(ascending=False).head(10)
        fig_vendor = px.bar(
            vendor_counts,
            x=vendor_counts.index,
            y=vendor_counts.values,
            labels={"x":"Vendor","y":"Count"},
            template="plotly_dark",
            color_discrete_sequence=['#6366f1']
        )
        st.plotly_chart(fig_vendor, use_container_width=True)

    with col2:
        st.subheader("Unauthorized Risk Distribution")
        devices_df = (
            filtered.groupby("mac")
            .agg(events=("timestamp","count"), status=("status","last"))
            .reset_index()
        )
        devices_df["risk_score"] = devices_df.apply(
            lambda r: r["events"] * (2 if r["status"]=="Unauthorized" else 1),
            axis=1
        )
        devices_df["risk_level"] = pd.cut(
            devices_df["risk_score"],
            bins=[0,5,15,1000],
            labels=["Low","Medium","High"]
        )
        risk_counts = devices_df["risk_level"].value_counts()
        fig_risk = px.pie(
            names=risk_counts.index,
            values=risk_counts.values,
            hole=0.4,
            template="plotly_dark",
            color_discrete_sequence=px.colors.sequential.RdBu
        )
        st.plotly_chart(fig_risk, use_container_width=True)
