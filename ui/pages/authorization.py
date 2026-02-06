import streamlit as st
from pathlib import Path
import pandas as pd
import re

# -----------------------------
# Configuration & Constants
# -----------------------------
MAC_REGEX_PATTERN = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
MAC_REGEX = re.compile(MAC_REGEX_PATTERN)

# -----------------------------
# Styling & Assets
# -----------------------------
def inject_custom_css():
    """Injects modern CSS tailored for Dark Mode."""
    st.markdown("""
        <style>
        /* Modern Font Import */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');

        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
        }

        /* Metric Cards Styling - Dark Mode Compatible */
        div[data-testid="stMetric"] {
            background-color: #262730; /* Dark Grey Background */
            border: 1px solid #464b5f; /* Subtle Grey Border */
            border-radius: 8px;
            padding: 15px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3); /* Darker shadow */
        }
        
        /* Ensure text inside metrics is visible */
        div[data-testid="stMetric"] label {
            color: #dcdcdc !important; /* Light Grey for labels */
        }
        
        div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
            color: #ffffff !important; /* White for values */
        }

        /* Expander Styling */
        .streamlit-expanderHeader {
            background-color: #262730;
            border: 1px solid #464b5f;
            border-radius: 8px;
            font-weight: 600;
            color: white;
        }
        
        /* Table Border */
        div[data-testid="stDataEditor"] {
            border: 1px solid #464b5f;
            border-radius: 10px;
            overflow: hidden;
        }
        
        /* Remove standard padding for a tighter look */
        .block-container {
            padding-top: 2rem;
            padding-bottom: 3rem;
        }
        </style>
    """, unsafe_allow_html=True)

# -----------------------------
# Data Logic
# -----------------------------
def load_macs(filepath: Path) -> list[str]:
    """Loads MAC addresses from file, handling deduplication."""
    if not filepath.exists():
        return []
    with open(filepath, "r") as f:
        return sorted(list(set(line.strip().lower() for line in f if line.strip())))

def save_macs(filepath: Path, mac_list: list[str]) -> None:
    """Saves the MAC list to file atomically."""
    filepath.parent.mkdir(exist_ok=True, parents=True)
    clean_list = sorted(list(set(mac_list)))
    with open(filepath, "w") as f:
        f.write("\n".join(clean_list))

def validate_mac(mac: str) -> bool:
    return bool(MAC_REGEX.match(mac))

# -----------------------------
# UI Components
# -----------------------------
def render_metrics(df: pd.DataFrame):
    total = len(df)
    valid_count = df["Valid"].sum() if not df.empty else 0
    invalid_count = total - valid_count

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Devices", total, border=False) # Border handled by CSS
    c2.metric("Authorized", int(valid_count), delta="Active", delta_color="normal", border=False)
    
    if invalid_count > 0:
        c3.metric("Format Errors", int(invalid_count), delta=f"{invalid_count} Invalid", delta_color="inverse", border=False)
    else:
        c3.metric("System Health", "100%", delta="All formats valid", border=False)

def render_add_section(current_macs: list[str], filepath: Path):
    """Renders the input form in the main area."""
    with st.expander("➕ Add New Device", expanded=False):
        st.markdown("Enter MAC addresses below. You can paste multiple entries (one per line).")
        with st.form("bulk_add_main"):
            col_input, col_btn = st.columns([4, 1])
            with col_input:
                new_macs_text = st.text_area(
                    "MAC Address List", 
                    placeholder="00:1a:2b:3c:4d:5e\n11:22:33:44:55:66",
                    height=100,
                    label_visibility="collapsed"
                )
            
            with col_btn:
                st.write("") # Spacer
                st.write("") # Spacer
                submitted = st.form_submit_button("Add Devices", type="primary", use_container_width=True)
            
            if submitted and new_macs_text:
                new_entries = [m.strip().lower() for m in new_macs_text.splitlines() if m.strip()]
                if new_entries:
                    updated_list = current_macs + new_entries
                    save_macs(filepath, updated_list)
                    st.toast(f"✅ Successfully added {len(new_entries)} devices!", icon="🚀")
                    st.rerun()

# -----------------------------
# Main Render Function
# -----------------------------
def render(authorized_macs_file: Path):
    """
    Main entry point for the authorization page.
    Args:
        authorized_macs_file (Path): The file path passed from app.py
    """
    inject_custom_css()
    
    # 1. Load Data
    saved_macs = load_macs(authorized_macs_file)
    
    # 2. Prepare DataFrame
    df = pd.DataFrame({"MAC Address": saved_macs})
    
    if df.empty:
        df["Valid"] = []
        df["_selected"] = []
    else:
        df["Valid"] = df["MAC Address"].apply(validate_mac)
        df["_selected"] = False 

    # 3. Page Header
    st.title("🛡️ Authorization Manager")
    st.markdown("Manage whitelist access for network devices.")
    
    # 4. Metrics & Add Section
    render_metrics(df)
    st.write("") # Vertical spacing
    render_add_section(saved_macs, authorized_macs_file)
    
    st.divider()

    # 5. Search & Filter
    col_title, col_search = st.columns([2, 2])
    with col_title:
        st.subheader("Device Database")
    with col_search:
        search_query = st.text_input("🔍 Search MAC Address", placeholder="Filter list...", label_visibility="collapsed")

    if search_query:
        df_display = df[df["MAC Address"].str.contains(search_query.lower())].copy()
    else:
        df_display = df.copy()

    # 6. Data Editor
    edited_df = st.data_editor(
        df_display,
        column_config={
            "_selected": st.column_config.CheckboxColumn(
                "Select",
                help="Select rows to delete",
                default=False,
                width="small"
            ),
            "MAC Address": st.column_config.TextColumn(
                "MAC Address",
                validate=MAC_REGEX_PATTERN,
                required=True,
                width="large"
            ),
            "Valid": st.column_config.CheckboxColumn(
                "Status",
                disabled=True,
                width="small",
            )
        },
        disabled=["Valid"],
        hide_index=True,
        use_container_width=True,
        key="editor",
        height=400
    )

    # 7. Action Buttons (Save / Delete)
    rows_to_delete = edited_df[edited_df["_selected"] == True]
    
    current_display_macs = set(df_display["MAC Address"])
    new_display_macs = set(edited_df["MAC Address"])
    has_text_changes = current_display_macs != new_display_macs

    col_actions_left, _, col_actions_right = st.columns([1, 2, 1])

    # Delete Button
    with col_actions_left:
        if not rows_to_delete.empty:
            if st.button(f"🗑️ Delete {len(rows_to_delete)} Selected", type="secondary", use_container_width=True):
                macs_to_delete = rows_to_delete["MAC Address"].tolist()
                remaining_macs = [m for m in saved_macs if m not in macs_to_delete]
                save_macs(authorized_macs_file, remaining_macs)
                st.toast("Entries deleted successfully", icon="🗑️")
                st.rerun()

    # Save Button
    with col_actions_right:
        if has_text_changes:
            if st.button("💾 Save Changes", type="primary", use_container_width=True):
                if search_query:
                    hidden_df = df[~df["MAC Address"].str.contains(search_query.lower())]
                    hidden_macs = hidden_df["MAC Address"].tolist()
                else:
                    hidden_macs = []

                final_macs = hidden_macs + edited_df["MAC Address"].tolist()
                save_macs(authorized_macs_file, final_macs)
                st.toast("Database updated!", icon="💾")
                st.rerun()

# -----------------------------
# Standalone Testing
# -----------------------------
if __name__ == "__main__":
    st.set_page_config(page_title="Auth Manager", layout="wide", page_icon="🛡️")
    test_file = Path("authorized_macs_test.txt")
    if not test_file.exists():
        with open(test_file, "w") as f:
            f.write("00:1a:2b:3c:4d:5e")
    render(test_file)