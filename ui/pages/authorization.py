import streamlit as st
from pathlib import Path
import pandas as pd
import re

# Regex Constants
MAC_REGEX = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
DOMAIN_REGEX = re.compile(r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$')

def manage_whitelist(file_path: Path, regex_pattern: re.Pattern, item_name: str, example_text: str):
    """
    Generic function to handle UI and logic for any whitelist type.
    """
    # ------------------------------------------------------------------
    # 1. Load Data
    # ------------------------------------------------------------------
    if file_path.exists():
        with open(file_path, "r") as f:
            saved_items = [line.strip().lower() for line in f if line.strip()]
    else:
        saved_items = []

    # ------------------------------------------------------------------
    # 2. Process Data (Validation)
    # ------------------------------------------------------------------
    df = pd.DataFrame({item_name: saved_items})
    if not df.empty:
        df["Valid"] = df[item_name].apply(lambda x: bool(regex_pattern.match(x)))
    else:
        df["Valid"] = []

    # ------------------------------------------------------------------
    # 3. Metrics
    # ------------------------------------------------------------------
    total = len(df)
    valid = df["Valid"].sum() if not df.empty else 0
    invalid = total - valid

    c1, c2, c3 = st.columns(3)
    c1.metric(f"Total {item_name}s", total)
    c2.metric("Valid", int(valid))
    c3.metric("Invalid", int(invalid))

    st.markdown("---")

    # ------------------------------------------------------------------
    # 4. Management Tools (Add & Remove)
    # ------------------------------------------------------------------
    col_add, col_del = st.columns(2)

    # --- SECTION A: ADD ITEMS ---
    with col_add:
        with st.expander(f"➕ Add {item_name}s", expanded=False):
            with st.form(f"add_{item_name}_form"):
                input_text = st.text_area(f"Enter {item_name}s", height=100, placeholder=example_text)
                prevent_invalid = st.checkbox(f"Discard invalid entries?", value=True)
                submitted_add = st.form_submit_button(f"💾 Save")

                if submitted_add:
                    new_items = [line.strip().lower() for line in input_text.splitlines() if line.strip()]
                    
                    if prevent_invalid:
                        valid_items = [i for i in new_items if regex_pattern.match(i)]
                        new_items = valid_items

                    # Deduplicate
                    added = [i for i in new_items if i not in saved_items]
                    saved_items.extend(added)

                    # Save
                    file_path.parent.mkdir(exist_ok=True, parents=True)
                    with open(file_path, "w") as f:
                        f.write("\n".join(sorted(saved_items)))

                    st.success(f"Added {len(added)} items.")
                    st.rerun()

    # --- SECTION B: REMOVE ITEMS (NEW) ---
    with col_del:
        with st.expander(f"🗑️ Remove {item_name}s", expanded=False):
            # Multiselect allows searching and selecting multiple items
            items_to_remove = st.multiselect(
                f"Select {item_name}s to delete:", 
                options=saved_items,
                placeholder="Type to search..."
            )
            
            if st.button(f"Confirm Delete", key=f"del_btn_{item_name}"):
                if items_to_remove:
                    # Keep only items NOT in the remove list
                    remaining_items = [i for i in saved_items if i not in items_to_remove]
                    
                    # Overwrite file
                    with open(file_path, "w") as f:
                        f.write("\n".join(sorted(remaining_items)))
                    
                    st.warning(f"Deleted {len(items_to_remove)} items.")
                    st.rerun()
                else:
                    st.info("Select items above first.")

    # ------------------------------------------------------------------
    # 5. Table & Search
    # ------------------------------------------------------------------
    st.markdown(f"### Current {item_name} List")
    search_query = st.text_input(f"🔍 Search table", "", key=f"search_{item_name}")
    
    if not df.empty:
        df_filtered = df[df[item_name].str.contains(search_query.lower())] if search_query else df
        
        def highlight_invalid(val):
            return 'color: #ff4b4b; font-weight: bold' if not val else 'color: #09ab3b; font-weight: bold'

        st.dataframe(
            df_filtered.style.map(highlight_invalid, subset=["Valid"]),
            use_container_width=True,
            height=300
        )
    else:
        st.info(f"No {item_name}s found.")

def render(authorized_macs_file: Path, authorized_domains_file: Path):
    st.set_page_config(page_title="Access Control Dashboard", layout="wide")
    
    st.markdown("## Access Control Dashboard")
    
    tab_mac, tab_domain = st.tabs(["🔒 MAC Whitelist", "🌐 Domain Whitelist"])

    with tab_mac:
        manage_whitelist(authorized_macs_file, MAC_REGEX, "MAC Address", "00:1A:2B:3C:4D:5E")

    with tab_domain:
        manage_whitelist(authorized_domains_file, DOMAIN_REGEX, "Domain", "example.com")

if __name__ == "__main__":
    render(Path("authorized_macs.txt"), Path("authorized_domains.txt"))