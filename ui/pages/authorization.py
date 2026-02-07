import streamlit as st
from pathlib import Path
import pandas as pd
import re

# -----------------------------
# Configuration & Constants
# -----------------------------
# MAC Regex: Standard format XX:XX:XX:XX:XX:XX
MAC_REGEX_PATTERN = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'

# Domain Regex: basic hostname validation (e.g., example.com, sub.site.org)
DOMAIN_REGEX_PATTERN = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'

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

        /* Metric Box Styling */
        .metric-container {
            background-color: #0e1117;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            width: 100%;
            margin-bottom: 25px;
            border: 1px solid #30333d;
        }
        .metric-label {
            color: #b0b3b8;
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 5px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .metric-value {
            color: #ffffff;
            font-size: 42px;
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
# Data Logic (Generic)
# -----------------------------
def load_data(filepath: Path) -> list[str]:
    if not filepath.exists():
        return []
    with open(filepath, "r") as f:
        return sorted(list(set(line.strip().lower() for line in f if line.strip())))

def save_data(filepath: Path, item_list: list[str]) -> None:
    filepath.parent.mkdir(exist_ok=True, parents=True)
    clean_list = sorted(list(set(item_list)))
    with open(filepath, "w") as f:
        f.write("\n".join(clean_list))

# -----------------------------
# Reusable Component: Manager
# -----------------------------
def render_generic_manager(
    data_list: list[str], 
    filepath: Path, 
    item_name: str, 
    column_label: str, 
    regex_pattern: str, 
    placeholder_example: str
):
    """
    A generic function to render the UI for adding, searching, and editing 
    either MACs or Domains.
    """
    
    # --- Add Section ---
    with st.expander(f"➕ Add New {item_name}", expanded=False):
        st.markdown(f"Enter {column_label}s below. You can paste multiple entries.")
        with st.form(f"bulk_add_{item_name.lower()}"):
            col_input, col_btn = st.columns([4, 1])
            with col_input:
                new_text = st.text_area(
                    f"{item_name} List", 
                    placeholder=placeholder_example,
                    height=100,
                    label_visibility="collapsed"
                )
            
            with col_btn:
                st.write("") 
                st.write("") 
                submitted = st.form_submit_button("Add", type="primary", use_container_width=True)
            
            if submitted and new_text:
                new_entries = [m.strip().lower() for m in new_text.splitlines() if m.strip()]
                if new_entries:
                    updated_list = data_list + new_entries
                    save_data(filepath, updated_list)
                    st.toast(f"✅ Added {len(new_entries)} {item_name.lower()}s!", icon="🚀")
                    st.rerun()

    st.divider()

    # --- Search & Filter ---
    col_title, col_search = st.columns([2, 2])
    with col_title:
        st.subheader(f"{item_name} Database")
    with col_search:
        search_query = st.text_input("🔍 Search", placeholder=f"Search {item_name.lower()}...", label_visibility="collapsed", key=f"search_{item_name}")

    # --- Prepare DataFrame (FIXED) ---
    # We explicitly force dtype="str" for the data column.
    df = pd.DataFrame({column_label: pd.Series(data_list, dtype="str")})
    
    # [FIX APPLIED HERE]
    # Initialize _selected with False, then STRICTLY cast to boolean.
    # This prevents Pandas from using 'object' or 'float' (NaN) which crashes Streamlit checkboxes.
    df["_selected"] = False
    df["_selected"] = df["_selected"].astype(bool)

    if search_query:
        # Ensure we are searching string values, handling potential NaN edge cases safely
        df_display = df[df[column_label].astype(str).str.contains(search_query.lower())].copy()
    else:
        df_display = df.copy()

    # --- Data Editor ---
    edited_df = st.data_editor(
        df_display,
        column_config={
            "_selected": st.column_config.CheckboxColumn("Delete", default=False, width="small"),
            column_label: st.column_config.TextColumn(
                "AUTHORIZE", 
                validate=regex_pattern, 
                required=True, 
                width="large"
            )
        },
        hide_index=True,
        use_container_width=True,
        key=f"editor_{item_name}",
        height=400
    )

    # --- Actions (Delete/Save) ---
    # Since we forced boolean types, this comparison is now safe
    rows_to_delete = edited_df[edited_df["_selected"] == True]
    
    current_display_items = set(df_display[column_label])
    new_display_items = set(edited_df[column_label])
    has_text_changes = current_display_items != new_display_items

    col_actions_left, _, col_actions_right = st.columns([1, 2, 1])

    with col_actions_left:
        if not rows_to_delete.empty:
            if st.button(f"🗑️ Delete {len(rows_to_delete)}", type="secondary", use_container_width=True, key=f"del_{item_name}"):
                items_to_delete = rows_to_delete[column_label].tolist()
                remaining_items = [m for m in data_list if m not in items_to_delete]
                save_data(filepath, remaining_items)
                st.rerun()

    with col_actions_right:
        if has_text_changes:
            if st.button("💾 Save Changes", type="primary", use_container_width=True, key=f"save_{item_name}"):
                # If searching, we must preserve hidden items
                hidden_items = df[~df[column_label].isin(current_display_items)][column_label].tolist() if search_query else []
                final_items = hidden_items + edited_df[column_label].tolist()
                save_data(filepath, final_items)
                st.rerun()

# -----------------------------
# Main Render Function
# -----------------------------
def render(mac_file: Path):
    """
    Renders the authorization page.
    Args:
        mac_file (Path): The path to the MAC address file.
    
    NOTE: The Domain file is automatically created in the same directory as the mac_file.
    """
    inject_custom_css()
    
    # Automatically define domain file path relative to the mac file
    domain_file = mac_file.parent / "whitelist_domains.txt"

    # 1. Load Data
    saved_macs = load_data(mac_file)
    saved_domains = load_data(domain_file)
    
    st.title("Authorization Manager")
    
    # 2. Metrics (Side by Side)
    m_col1, m_col2 = st.columns(2)
    
    with m_col1:
        st.markdown(f"""
            <div class="metric-container">
                <div class="metric-label">Authorized Devices</div>
                <div class="metric-value">{len(saved_macs)}</div>
            </div>
        """, unsafe_allow_html=True)
        
    with m_col2:
        st.markdown(f"""
            <div class="metric-container">
                <div class="metric-label">Whitelisted Domains</div>
                <div class="metric-value">{len(saved_domains)}</div>
            </div>
        """, unsafe_allow_html=True)

    # 3. Tabs for separation
    tab_mac, tab_domain = st.tabs([" MAC Addresses", " Whitelisted Domains"])

    with tab_mac:
        render_generic_manager(
            data_list=saved_macs,
            filepath=mac_file,
            item_name="Device",
            column_label="MAC Address",
            regex_pattern=MAC_REGEX_PATTERN,
            placeholder_example="00:1a:2b:3c:4d:5e"
        )

    with tab_domain:
        render_generic_manager(
            data_list=saved_domains,
            filepath=domain_file,
            item_name="Domain",
            column_label="Domain Name",
            regex_pattern=DOMAIN_REGEX_PATTERN,
            placeholder_example="example.com\napi.service.org"
        )

if __name__ == "__main__":
    st.set_page_config(page_title="Auth Manager", layout="wide")
    test_file = Path("authorized_macs_test.txt")
    render(test_file)