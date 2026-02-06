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
    """Injects modern CSS tailored for Dark Mode and custom metric box."""
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');

        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
        }

        :root {
            --custom-border: 1px solid #464b5f;
            --custom-radius: 8px;
            --card-bg: #262730;
        }

        /* Metric Box Styling from Image */
        .metric-container {
            background-color: #0e1117;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            width: 180px;
            margin-bottom: 25px;
        }
        .metric-label {
            color: #ffffff;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 10px;
        }
        .metric-value {
            color: #ffffff;
            font-size: 48px;
            font-weight: 700;
        }

        .streamlit-expanderHeader {
            background-color: var(--card-bg);
            border: var(--custom-border);
            border-radius: var(--custom-radius);
            font-weight: 600;
            color: white;
        }
        
        div[data-testid="stDataEditor"] {
            border: var(--custom-border);
            border-radius: var(--custom-radius);
            overflow: hidden;
        }

        .stTextInput input, .stTextArea textarea {
            background-color: var(--card-bg);
            border: var(--custom-border);
            border-radius: var(--custom-radius);
            color: white;
        }
        
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
    if not filepath.exists():
        return []
    with open(filepath, "r") as f:
        return sorted(list(set(line.strip().lower() for line in f if line.strip())))

def save_macs(filepath: Path, mac_list: list[str]) -> None:
    filepath.parent.mkdir(exist_ok=True, parents=True)
    clean_list = sorted(list(set(mac_list)))
    with open(filepath, "w") as f:
        f.write("\n".join(clean_list))

# -----------------------------
# UI Components
# -----------------------------
def render_add_section(current_macs: list[str], filepath: Path):
    with st.expander("➕ Add New Device", expanded=False):
        st.markdown("Enter MAC addresses below. You can paste multiple entries.")
        with st.form("bulk_add_main"):
            col_input, col_btn = st.columns([4, 1])
            with col_input:
                new_macs_text = st.text_area(
                    "MAC Address List", 
                    placeholder="00:1a:2b:3c:4d:5e",
                    height=100,
                    label_visibility="collapsed"
                )
            
            with col_btn:
                st.write("") 
                st.write("") 
                submitted = st.form_submit_button("Add Devices", type="primary", use_container_width=True)
            
            if submitted and new_macs_text:
                new_entries = [m.strip().lower() for m in new_macs_text.splitlines() if m.strip()]
                if new_entries:
                    updated_list = current_macs + new_entries
                    save_macs(filepath, updated_list)
                    st.toast(f"✅ Added {len(new_entries)} devices!", icon="🚀")
                    st.rerun()

# -----------------------------
# Main Render Function
# -----------------------------
def render(authorized_macs_file: Path):
    inject_custom_css()
    
    # 1. Load Data
    saved_macs = load_macs(authorized_macs_file)
    total_authorized = len(saved_macs)
    
    # 2. Page Header & New Metric Box
    st.title("Authorization Manager")
    
    # This creates the UI element from your screenshot
    st.markdown(f"""
        <div class="metric-container">
            <div class="metric-label">Authorized</div>
            <div class="metric-value">{total_authorized}</div>
        </div>
    """, unsafe_allow_html=True)

    # 3. Prepare DataFrame
    df = pd.DataFrame({"MAC Address": saved_macs})
    if df.empty:
        df["_selected"] = []
    else:
        df["_selected"] = False 

    # 4. Add Section
    render_add_section(saved_macs, authorized_macs_file)
    st.divider()

    # 5. Search & Filter
    col_title, col_search = st.columns([2, 2])
    with col_title:
        st.subheader("Device Database")
    with col_search:
        search_query = st.text_input("🔍 Search", placeholder="Search list...", label_visibility="collapsed")

    if search_query:
        df_display = df[df["MAC Address"].str.contains(search_query.lower())].copy()
    else:
        df_display = df.copy()

    # 6. Data Editor
    edited_df = st.data_editor(
        df_display,
        column_config={
            "_selected": st.column_config.CheckboxColumn("Delete", default=False, width="small"),
            "MAC Address": st.column_config.TextColumn("AUTHORIZE", validate=MAC_REGEX_PATTERN, required=True, width="large")
        },
        hide_index=True,
        use_container_width=True,
        key="editor",
        height=400
    )

    # 7. Actions
    rows_to_delete = edited_df[edited_df["_selected"] == True]
    current_display_macs = set(df_display["MAC Address"])
    new_display_macs = set(edited_df["MAC Address"])
    has_text_changes = current_display_macs != new_display_macs

    col_actions_left, _, col_actions_right = st.columns([1, 2, 1])

    with col_actions_left:
        if not rows_to_delete.empty:
            if st.button(f"🗑️ Delete {len(rows_to_delete)}", type="secondary", use_container_width=True):
                macs_to_delete = rows_to_delete["MAC Address"].tolist()
                remaining_macs = [m for m in saved_macs if m not in macs_to_delete]
                save_macs(authorized_macs_file, remaining_macs)
                st.rerun()

    with col_actions_right:
        if has_text_changes:
            if st.button("💾 Save Changes", type="primary", use_container_width=True):
                hidden_macs = df[~df["MAC Address"].isin(current_display_macs)]["MAC Address"].tolist() if search_query else []
                final_macs = hidden_macs + edited_df["MAC Address"].tolist()
                save_macs(authorized_macs_file, final_macs)
                st.rerun()

if __name__ == "__main__":
    st.set_page_config(page_title="Auth Manager", layout="wide")
    test_file = Path("authorized_macs_test.txt")
    render(test_file)