import streamlit as st
from pathlib import Path
import pandas as pd
import re

MAC_REGEX = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')

def render(authorized_macs_file: Path):
    st.set_page_config(page_title="Access Control Dashboard", layout="wide")

    # -----------------------------
    # Header
    # -----------------------------
    st.markdown("""
    <div style="text-align:left; padding-bottom:20px;">
        <h1 style="margin-bottom:5px;">Access Control Dashboard</h1>
        <p style="color:gray; margin-top:0;">
            Manage your MAC whitelist in a clean, interactive table
        </p>
    </div>
    """, unsafe_allow_html=True)


    # -----------------------------
    # Load MACs
    # -----------------------------
    if authorized_macs_file.exists():
        with open(authorized_macs_file, "r") as f:
            saved_macs = [line.strip().lower() for line in f if line.strip()]
    else:
        saved_macs = []

    df = pd.DataFrame({"MAC Address": saved_macs})
    df["Valid"] = df["MAC Address"].apply(lambda x: bool(MAC_REGEX.match(x)))

    # -----------------------------
    # Summary Cards
    # -----------------------------
    total = len(df)
    valid_count = df["Valid"].sum()
    invalid_count = total - valid_count

    col1, col2, col3 = st.columns(3)
    col1.metric("Total MACs", total)
    col2.metric("Valid MACs", valid_count)
    col3.metric("Invalid MACs", invalid_count)

    st.markdown("---")

    # -----------------------------
    # Add / Update MACs (Moved to Top)
    # -----------------------------
    with st.expander("Add / Update MACs", expanded=True):
        with st.form("add_mac_form"):
            new_macs_text = st.text_area("Enter MAC addresses (one per line)", height=120)
            submitted = st.form_submit_button("💾 Save MACs")
            if submitted:
                new_macs = [m.strip().lower() for m in new_macs_text.splitlines() if m.strip()]
                duplicates = set(new_macs).intersection(set(saved_macs))
                added = [m for m in new_macs if m not in saved_macs]
                saved_macs.extend(added)

                # Save to file
                authorized_macs_file.parent.mkdir(exist_ok=True, parents=True)
                with open(authorized_macs_file, "w") as f:
                    f.write("\n".join(sorted(saved_macs)))

                st.success(f"Added {len(added)} new MACs. {len(duplicates)} duplicates ignored.")
                st.session_state["authorized_updated"] = True
                st.experimental_rerun()

    # -----------------------------
    # Search / Filter
    # -----------------------------
    search_query = st.text_input("Search MACs", "")
    df_filtered = df[df["MAC Address"].str.contains(search_query.lower())] if search_query else df

    # -----------------------------
    # Compact Table Display
    # -----------------------------
    st.markdown("### MAC Addresses Table")

    def highlight_invalid(val):
        return 'color: red; font-weight: bold' if not val else 'color: green; font-weight: bold'

    st.dataframe(
        df_filtered.style.applymap(highlight_invalid, subset=["Valid"]),
        use_container_width=True,
        height=400
    )

    # -----------------------------
    # Footer / Notes
    # -----------------------------
    st.markdown("---")
    st.markdown(
        "<div style='font-size:13px; color:gray;'>"
        "Enter MAC addresses in the format <b>00:1A:2B:3C:4D:5E</b>. "
        "Invalid entries are highlighted in red. "
        "Valid entries are green. Changes take effect immediately."
        "</div>", unsafe_allow_html=True
    )
