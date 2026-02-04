import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
from .constants import MAX_ROWS_DISPLAY

# Points to the exact same file your Manager App writes to
WHITELIST_FILE = Path("authorized_macs.txt")

def load_authorized_macs() -> set:
    """Helper to load the whitelist into a set for fast lookup."""
    if WHITELIST_FILE.exists():
        with open(WHITELIST_FILE, "r") as f:
            return set(line.strip().lower() for line in f if line.strip())
    return set()

def render_shadow_ai(filtered: pd.DataFrame):
    st.subheader("Shadow AI Overview")

    # 1. Safety Checks
    if "application" not in filtered.columns:
        st.info("No AI data available (missing 'application' column).")
        return

    # Filter for AI applications
    df_tab = filtered[filtered["application"].str.contains("ai", case=False, na=False)].copy()
    
    if df_tab.empty:
        st.info("No AI apps detected in the current filter.")
        return

    # ------------------------------------------------------------------
    # 2. THE CONNECTION BRIDGE (Analytics <--> Whitelist)
    # ------------------------------------------------------------------
    # Load the whitelist from the text file
    authorized_macs = load_authorized_macs()

    # Create a new column "Status" to flag devices
    if "mac" in df_tab.columns:
        df_tab["Status"] = df_tab["mac"].apply(
            lambda x: "✅ Authorized" if str(x).lower() in authorized_macs else "⚠️ Rogue Device"
        )
    else:
        df_tab["Status"] = "Unknown"

    # ------------------------------------------------------------------
    # 3. VISUALIZATION (Updated with Rogue Detection)
    # ------------------------------------------------------------------
    
    # GROUP BY MAC AND STATUS
    # We group by Status too so we can color-code the bars
    count_by_mac = df_tab.groupby(["mac", "Status"]).size().reset_index(name="count")
    
    # Sort so the highest usage is at the top/left
    count_by_mac = count_by_mac.sort_values(by="count", ascending=False)

    st.markdown("### 🚨 Device Threat Detection")
    
    # BAR CHART
    fig_bar = px.bar(
        count_by_mac.head(50), 
        x="mac", 
        y="count", 
        color="Status",  # <--- THIS IS THE KEY CHANGE
        color_discrete_map={
            "✅ Authorized": "#00CC96",  # Green
            "⚠️ Rogue Device": "#EF553B" # Red
        },
        title="Top AI App Usage by Device Status", 
        template="plotly_dark",
        text_auto=True
    )
    st.plotly_chart(fig_bar, use_container_width=True)

    # METRICS ROW
    rogue_count = df_tab[df_tab["Status"] == "⚠️ Rogue Device"]["mac"].nunique()
    total_ai_users = df_tab["mac"].nunique()
    
    m1, m2 = st.columns(2)
    m1.metric("Total Devices using AI", total_ai_users)
    m2.metric("Unauthorized (Rogue) Devices", rogue_count, delta_color="inverse")

    # ------------------------------------------------------------------
    # 4. LINE CHART (Usage over time)
    # ------------------------------------------------------------------
    if "timestamp" in df_tab.columns:
        df_tab["timestamp"] = pd.to_datetime(df_tab["timestamp"], errors="coerce")
        # We drop NaT but keep the Status column for context if needed later
        df_line = df_tab.dropna(subset=["timestamp"]).groupby(pd.Grouper(key="timestamp", freq="H")).size().reset_index(name="count")
        
        fig_line = px.line(
            df_line, 
            x="timestamp", 
            y="count", 
            title="AI App Events Over Time", 
            template="plotly_dark",
            markers=True
        )
        st.plotly_chart(fig_line, use_container_width=True)

    # ------------------------------------------------------------------
    # 5. DETAILED DATA TABLE (With Highlighting)
    # ------------------------------------------------------------------
    st.subheader("Device Details - Shadow AI")

    # Function to color the entire row red if Rogue
    def highlight_rogue(row):
        color = 'background-color: rgba(239, 85, 59, 0.2)' if row.Status == "⚠️ Rogue Device" else ''
        return [color] * len(row)

    # Display table with formatting
    st.dataframe(
        df_tab.head(MAX_ROWS_DISPLAY).style.apply(highlight_rogue, axis=1),
        use_container_width=True,
        column_order=["Status", "mac", "application", "timestamp"] # Reorder to show Status first
    )
    
    st.markdown(f"Showing {min(MAX_ROWS_DISPLAY, len(df_tab))} of {len(df_tab)} rows")