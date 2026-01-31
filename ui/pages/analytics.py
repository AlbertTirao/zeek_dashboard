import streamlit as st
import pandas as pd
import plotly.express as px

def render(filtered: pd.DataFrame, get_mac_vendor=None, authorized=None):
    st.title("Network Analytics")

    if authorized is not None:
        st.write(f"Authorized device list length: {len(authorized)}")

    # -----------------------------
    # Ensure vendor column exists
    # -----------------------------
    if "vendor" not in filtered.columns and get_mac_vendor is not None:
        filtered["vendor"] = filtered["mac"].apply(get_mac_vendor)
    elif "vendor" not in filtered.columns:
        filtered["vendor"] = "Unknown"

    # -----------------------------
    # Device counts
    # -----------------------------
    total_devices = filtered["mac"].nunique()
    total_auth = filtered[filtered["status"].str.lower()=="authorized"]["mac"].nunique()
    total_unauth = filtered[filtered["status"].str.lower()=="unauthorized"]["mac"].nunique()

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Devices", total_devices)
    c2.metric("Authorized", total_auth)
    c3.metric("Unauthorized", total_unauth)

    st.markdown("---")
    col1, col2 = st.columns(2)

    # -----------------------------
    # Top Vendors Bar Chart
    # -----------------------------
    with col1:
        st.subheader("Device Vendors")
        vendor_counts = (
            filtered.groupby("vendor")["mac"]
            .nunique()
            .sort_values(ascending=False)
            .head(10)
            .reset_index(name="count")
        )
        if not vendor_counts.empty:
            fig_vendor = px.bar(
                vendor_counts,
                x="vendor",
                y="count",
                labels={"vendor":"Vendor","count":"Count"},
                template="plotly_dark",
                color_discrete_sequence=['#6366f1']
            )
            st.plotly_chart(fig_vendor, use_container_width=True)
        else:
            st.info("No vendor data available.")

    # -----------------------------
    # Unauthorized Risk Distribution Pie Chart
    # -----------------------------
    with col2:
        st.subheader("Unauthorized Risk Distribution")
        if not filtered.empty:
            devices_df = (
                filtered.groupby("mac")
                .agg(events=("timestamp","count"), status=("status","last"))
                .reset_index()
            )
            # Ensure status values are normalized
            devices_df["status"] = devices_df["status"].str.lower()
            # Risk scoring
            devices_df["risk_score"] = devices_df["events"] * devices_df["status"].apply(lambda x: 2 if x=="unauthorized" else 1)
            # Risk level bins
            devices_df["risk_level"] = pd.cut(
                devices_df["risk_score"],
                bins=[0,5,15,float("inf")],
                labels=["Low","Medium","High"]
            )
            risk_counts = devices_df["risk_level"].value_counts().reindex(["Low","Medium","High"], fill_value=0)

            fig_risk = px.pie(
                names=risk_counts.index,
                values=risk_counts.values,
                hole=0.4,
                template="plotly_dark",
                color_discrete_sequence=px.colors.sequential.RdBu
            )
            st.plotly_chart(fig_risk, use_container_width=True)
        else:
            st.info("No devices to analyze.")
