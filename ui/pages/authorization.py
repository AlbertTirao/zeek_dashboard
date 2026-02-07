import streamlit as st
from pathlib import Path
import pandas as pd
import datetime

# -----------------------------
# Configuration & Constants
# -----------------------------
MAC_REGEX_PATTERN = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
DOMAIN_REGEX_PATTERN = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'

# -----------------------------
# Styling & Assets
# -----------------------------
def inject_custom_css():
    """Injects modern CSS tailored for Dark Mode with BORDERS REMOVED."""
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');

        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
        }

        :root {
            --custom-border: none; 
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
            border: none; 
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
# History / Logging Logic
# -----------------------------
def log_activity(filepath: Path, action: str, item_type: str, items: list[str]):
    """
    Logs an action to a CSV file.
    """
    if not items:
        return

    log_file = filepath.parent / "activity_log.csv"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    new_rows = []
    for item in items:
        new_rows.append({
            "Timestamp": timestamp,
            "Action": action,
            "Type": item_type,
            "Item": item
        })
    
    df_new = pd.DataFrame(new_rows)
    
    # Append to existing CSV or create new if headers needed
    header_needed = not log_file.exists()
    df_new.to_csv(log_file, mode='a', header=header_needed, index=False)

def load_history(filepath: Path) -> pd.DataFrame:
    """Loads the activity log CSV and removes duplicates."""
    log_file = filepath.parent / "activity_log.csv"
    if not log_file.exists():
        return pd.DataFrame(columns=["Timestamp", "Action", "Type", "Item"])
    
    try:
        df = pd.read_csv(log_file)
        # Ensure no duplicate log entries exist
        df = df.drop_duplicates()
        # Sort by timestamp descending (newest first)
        if "Timestamp" in df.columns:
            df = df.sort_values(by="Timestamp", ascending=False)
        return df
    except Exception:
        return pd.DataFrame(columns=["Timestamp", "Action", "Type", "Item"])

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
    A generic function to render the UI for adding, searching, and editing.
    """
    
    # --- Add Section ---
    # UPDATED: Removed emoji from expander title
    with st.expander(f"Add New {item_name}", expanded=False):
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
                # 1. Parse Input
                entries_to_process = [m.strip().lower() for m in new_text.splitlines() if m.strip()]
                
                # 2. Filter Duplicates (Only add what isn't already there)
                existing_set = set(data_list)
                actually_new_items = [item for item in entries_to_process if item not in existing_set]
                
                if actually_new_items:
                    # Update List
                    updated_list = data_list + actually_new_items
                    save_data(filepath, updated_list)
                    
                    # Log History (Only for truly new items)
                    log_activity(filepath, "Added", item_name, actually_new_items)
                    
                    st.toast(f"Added {len(actually_new_items)} new {item_name.lower()}s!", icon="✅")
                    st.rerun()
                elif entries_to_process:
                    # User entered data, but it all existed already
                    st.warning(f"All entered {item_name.lower()}s already exist.")

    st.divider()

    # --- Search & Filter ---
    col_title, col_search = st.columns([2, 2])
    with col_title:
        st.subheader(f"{item_name} Database")
    with col_search:
        search_query = st.text_input("🔍 Search", placeholder=f"Search {item_name.lower()}...", label_visibility="collapsed", key=f"search_{item_name}")

    # --- Prepare DataFrame ---
    df = pd.DataFrame({column_label: pd.Series(data_list, dtype="str")})
    df["_selected"] = False
    df["_selected"] = df["_selected"].astype(bool)

    if search_query:
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
    rows_to_delete = edited_df[edited_df["_selected"] == True]
    
    current_display_items = set(df_display[column_label])
    new_display_items = set(edited_df[column_label])
    has_text_changes = current_display_items != new_display_items

    col_actions_left, _, col_actions_right = st.columns([1, 2, 1])

    with col_actions_left:
        if not rows_to_delete.empty:
            if st.button(f"Delete {len(rows_to_delete)}", type="secondary", use_container_width=True, key=f"del_{item_name}"):
                items_to_delete = rows_to_delete[column_label].tolist()
                
                # 1. Update List
                remaining_items = [m for m in data_list if m not in items_to_delete]
                save_data(filepath, remaining_items)
                
                # 2. Log History
                log_activity(filepath, "Deleted", item_name, items_to_delete)
                
                st.rerun()

    with col_actions_right:
        if has_text_changes:
            if st.button("Save Changes", type="primary", use_container_width=True, key=f"save_{item_name}"):
                hidden_items = df[~df[column_label].isin(current_display_items)][column_label].tolist() if search_query else []
                final_items = hidden_items + edited_df[column_label].tolist()
                save_data(filepath, final_items)
                # We log a generic bulk update for inline text edits
                log_activity(filepath, "Edited", item_name, ["Bulk Update via Table"])
                st.rerun()

# -----------------------------
# Main Render Function
# -----------------------------
def render(mac_file: Path):
    """
    Renders the authorization page.
    """
    inject_custom_css()
    
    domain_file = mac_file.parent / "whitelist_domains.txt"

    # 1. Load Data
    saved_macs = load_data(mac_file)
    saved_domains = load_data(domain_file)
    
    st.title("Authorization Manager")
    
    # 2. Metrics
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

    # 3. Tabs (UPDATED: Removed emojis)
    tab_mac, tab_domain, tab_history = st.tabs([" MAC Addresses", " Whitelisted Domains", " Activity Log"])

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
        
    with tab_history:
        st.subheader("Action History")
        history_df = load_history(mac_file)
        
        if not history_df.empty:
            # Simple color styling for actions
            def color_action(val):
                if val == 'Added':
                    return 'color: #4CAF50; font-weight: bold'
                elif val == 'Deleted':
                    return 'color: #FF5252; font-weight: bold'
                else:
                    return 'color: #FFC107; font-weight: bold'

            st.dataframe(
                history_df.style.map(color_action, subset=['Action']),
                use_container_width=True,
                hide_index=True,
                height=500
            )
            
            if st.button("Clear History", type="secondary"):
                log_path = mac_file.parent / "activity_log.csv"
                if log_path.exists():
                    log_path.unlink()
                    st.rerun()
        else:
            st.info("No activity recorded yet.")

if __name__ == "__main__":
    st.set_page_config(page_title="Auth Manager", layout="wide")
    test_file = Path("authorized_macs_test.txt")
    render(test_file)