import streamlit as st
from pathlib import Path
import pandas as pd
import datetime
import yaml

# -----------------------------
# Configuration & Constants
# -----------------------------
MAC_REGEX_PATTERN = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
DOMAIN_REGEX_PATTERN = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'

# -----------------------------
# Styling & Assets
# -----------------------------
def inject_custom_css():
    """Injects strict, professional CSS for Enterprise Dark Mode."""
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');

        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
        }

        /* Metric Styling - Clean & Flat */
        div[data-testid="stMetricValue"] {
            font-size: 28px;
            font-weight: 600;
        }
        div[data-testid="stMetricLabel"] {
            font-size: 14px;
            font-weight: 500;
            color: #888;
        }

        /* Inputs & Tables */
        .stTextInput input, .stTextArea textarea, .stSelectbox, div[data-testid="stDataEditor"] {
            border-radius: 4px !important;
        }
        
        /* Headers */
        h1, h2, h3 {
            font-weight: 600 !important;
            letter-spacing: -0.5px;
        }
        
        /* Remove default padding */
        .block-container {
            padding-top: 2rem;
            padding-bottom: 3rem;
        }
        </style>
    """, unsafe_allow_html=True)

# -----------------------------
# Data Logic
# -----------------------------
def load_data(filepath: Path) -> list[str]:
    """Robustly finds a list of strings in a YAML file."""
    if not filepath.exists():
        return []

    with open(filepath, "r") as f:
        try:
            data = yaml.safe_load(f)
            if data is None: return []
            
            if isinstance(data, list):
                return sorted(list(set(str(x).strip().lower() for x in data if x)))
            
            if isinstance(data, dict):
                target_key = filepath.stem
                if target_key in data and isinstance(data[target_key], list):
                    return sorted(list(set(str(x).strip().lower() for x in data[target_key] if x)))
                
                for key, val in data.items():
                    if isinstance(val, list):
                        return sorted(list(set(str(x).strip().lower() for x in val if x)))
            return []
        except:
            return []

def save_data(filepath: Path, item_list: list[str]) -> None:
    filepath.parent.mkdir(exist_ok=True, parents=True)
    if filepath.suffix != ".yaml":
        filepath = filepath.with_suffix(".yaml")

    key_name = filepath.stem
    clean_list = sorted(list(set(item_list)))
    data_dict = {key_name: clean_list}

    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump(data_dict, f, sort_keys=False)

def load_ai_config(filepath: Path):
    if not filepath.exists():
        return {"authorized_providers": [], "ai_signatures": {}, "local_ai_ports": {}}
    with open(filepath, "r") as f:
        try:
            config = yaml.safe_load(f)
            return config if config else {"authorized_providers": [], "ai_signatures": {}, "local_ai_ports": {}}
        except:
            return {"authorized_providers": [], "ai_signatures": {}, "local_ai_ports": {}}

def save_ai_config(filepath: Path, config_dict: dict):
    filepath.parent.mkdir(exist_ok=True, parents=True)
    with open(filepath, "w") as f:
        yaml.safe_dump(config_dict, f, sort_keys=False)

# -----------------------------
# Logging Logic
# -----------------------------
def log_activity(filepath: Path, action: str, item_type: str, items: list[str]):
    if not items: return

    log_file = filepath.parent / "activity_log.csv"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    new_rows = [{"Timestamp": timestamp, "Action": action, "Type": item_type, "Item": item} for item in items]
    df_new = pd.DataFrame(new_rows)
    
    header_needed = not log_file.exists()
    df_new.to_csv(log_file, mode='a', header=header_needed, index=False)

def load_history(filepath: Path) -> pd.DataFrame:
    log_file = filepath.parent / "activity_log.csv"
    if not log_file.exists():
        return pd.DataFrame(columns=["Timestamp", "Action", "Type", "Item"])
    try:
        df = pd.read_csv(log_file)
        return df.drop_duplicates().sort_values(by="Timestamp", ascending=False)
    except:
        return pd.DataFrame(columns=["Timestamp", "Action", "Type", "Item"])

# -----------------------------
# Generic List Manager (Updated UI)
# -----------------------------
def render_generic_manager(
    data_list: list[str], 
    filepath: Path, 
    item_name: str, 
    column_label: str, 
    regex_pattern: str, 
    placeholder_example: str
):
    # --- Bulk Import Section (No Expander) ---
    st.markdown(f"**Bulk Import {item_name}s**")
    
    col_input, col_btn = st.columns([5, 1])
    with col_input:
        new_text = st.text_input(f"Paste {item_name}s (comma or space separated)", placeholder=placeholder_example, label_visibility="collapsed")
    with col_btn:
        if st.button("Import", key=f"btn_import_{item_name}"):
            if new_text:
                # Split by newline, comma, or space for robust pasting
                import re
                entries = [m.strip().lower() for m in re.split(r'[,\s\n]+', new_text) if m.strip()]
                existing_set = set(data_list)
                new_items = [x for x in entries if x not in existing_set]
                
                if new_items:
                    save_data(filepath, data_list + new_items)
                    log_activity(filepath, "Added", item_name, new_items)
                    st.toast(f"Successfully added {len(new_items)} items")
                    st.rerun()
                else:
                    st.warning("No new items found (duplicates ignored).")

    st.divider()
    
    # --- Search & Filter ---
    col_search, _ = st.columns([2, 2])
    with col_search:
        search_query = st.text_input("Search Database", placeholder=f"Filter {item_name}s...", label_visibility="collapsed")

    # --- Main Editor Table ---
    # Filter Data based on Search
    if search_query:
        filtered_list = [item for item in data_list if search_query.lower() in item.lower()]
    else:
        filtered_list = data_list

    df = pd.DataFrame({column_label: filtered_list})
    
    edited_df = st.data_editor(
        df,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            column_label: st.column_config.TextColumn(
                f"{column_label}", 
                validate=regex_pattern, 
                required=True, 
                width="large"
            )
        },
        key=f"editor_{item_name}",
        height=400
    )

    # --- Save Logic ---
    st.write("") # Spacer
    
    # Calculate changes based on the ORIGINAL full list vs EDITED list
    # Note: If search was active, we need to be careful not to delete hidden items.
    
    if st.button(f"Save Changes", type="primary", key=f"save_{item_name}"):
        current_edited_items = []
        if not edited_df.empty and column_label in edited_df.columns:
             current_edited_items = sorted(list(set(edited_df[column_label].astype(str).str.strip().str.lower().tolist())))
        
        # Logic: 
        # 1. Identify items removed from the CURRENT view (filtered view)
        # 2. Identify new items added
        # 3. Reconstruct the full list preserving items that were hidden by search
        
        original_filtered_set = set(filtered_list)
        new_filtered_set = set(current_edited_items)
        
        # Items that were in the view but are gone now = Deleted
        deleted_from_view = original_filtered_set - new_filtered_set
        
        # Items that are in the view but weren't before = Added
        added_to_view = new_filtered_set - original_filtered_set
        
        # Full List Reconstruction:
        # Start with original full data
        final_set = set(data_list)
        # Remove what was deleted
        final_set = final_set - deleted_from_view
        # Add what was added
        final_set = final_set | added_to_view
        
        final_list = sorted(list(final_set))
        
        if deleted_from_view or added_to_view:
            save_data(filepath, final_list)
            if added_to_view: log_activity(filepath, "Added", item_name, list(added_to_view))
            if deleted_from_view: log_activity(filepath, "Deleted", item_name, list(deleted_from_view))
            st.success("Database updated successfully.")
            st.rerun()
        else:
            st.info("No changes detected.")

# -----------------------------
# AI Signature Manager (Updated UI)
# -----------------------------
def render_ai_signature_manager(yaml_path: Path):
    config = load_ai_config(yaml_path)
    
    st.subheader("Sanctioned AI Providers")
    
    auth_list = config.get("authorized_providers", [])
    sigs_dict = config.get("ai_signatures", {})
    available_providers = list(sigs_dict.keys())
    valid_defaults = [x for x in auth_list if x in available_providers]
    
    new_auth = st.multiselect("Select Authorized Providers", options=available_providers, default=valid_defaults)
    
    if set(new_auth) != set(auth_list):
        if st.button("Update Sanctioned List"):
            config["authorized_providers"] = new_auth
            save_ai_config(yaml_path, config)
            st.toast("Sanctioned list updated")
            st.rerun()

    st.divider()
    
    st.subheader("Detection Signatures")
    
    sig_data = []
    for provider, patterns in sigs_dict.items():
        pat_str = ", ".join(patterns) if isinstance(patterns, list) else str(patterns)
        sig_data.append({"Provider": provider, "Patterns": pat_str})
    
    sig_df = pd.DataFrame(sig_data)
    
    edited_sigs = st.data_editor(
        sig_df,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "Provider": st.column_config.TextColumn("Provider Name", required=True),
            "Patterns": st.column_config.TextColumn("Regex Patterns (Comma Separated)", width="large", required=True)
        },
        key="ai_sig_editor"
    )
    
    if st.button("Save Changes", type="primary", key="save_ai"):
        new_sigs = {}
        for _, row in edited_sigs.iterrows():
            if pd.notna(row.get("Provider")) and pd.notna(row.get("Patterns")):
                p_name = str(row["Provider"]).strip()
                p_pats = [p.strip() for p in str(row["Patterns"]).split(",") if p.strip()]
                if p_name: new_sigs[p_name] = p_pats
        
        config["ai_signatures"] = new_sigs
        save_ai_config(yaml_path, config)
        log_activity(yaml_path, "Edited", "AI Signatures", ["Bulk Configuration Update"])
        st.success("AI policies updated successfully.")

# -----------------------------
# Main Render
# -----------------------------
def render(mac_file: Path):
    inject_custom_css()
    
    if mac_file.suffix != ".yaml":
        mac_file = mac_file.with_suffix(".yaml")

    mac_file = mac_file.resolve()
    domain_file = (mac_file.parent / "whitelist_domains.yaml").resolve()
    ai_yaml_file = (mac_file.parent / "ai_signatures.yaml").resolve()

    saved_macs = load_data(mac_file)
    saved_domains = load_data(domain_file)
    ai_config = load_ai_config(ai_yaml_file)
    
    st.title("Authorization Manager")
    
    # Metrics - Clean & Flat
    m1, m2, m3 = st.columns(3)
    m1.metric("Device Whitelist", len(saved_macs))
    m2.metric("Domain Whitelist", len(saved_domains))
    m3.metric("AI Policies", len(ai_config.get("ai_signatures", {})))

    st.write("") # Spacer

    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs(["Device Access", "Domain Whitelist", "AI Policies", "Audit Log"])

    with tab1:
        render_generic_manager(saved_macs, mac_file, "Device", "MAC Address", MAC_REGEX_PATTERN, "00:1a:2b:3c:4d:5e")

    with tab2:
        render_generic_manager(saved_domains, domain_file, "Domain", "Domain Name", DOMAIN_REGEX_PATTERN, "example.com")
        
    with tab3:
        render_ai_signature_manager(ai_yaml_file)
        
    with tab4:
        st.subheader("System Audit Log")
        history_df = load_history(mac_file)
        if not history_df.empty:
            st.dataframe(
                history_df,
                use_container_width=True,
                hide_index=True,
                height=500
            )
            if st.button("Clear Audit Log", type="secondary"):
                (mac_file.parent / "activity_log.csv").unlink(missing_ok=True)
                st.rerun()
        else:
            st.info("No activity recorded yet.")

if __name__ == "__main__":
    st.set_page_config(page_title="Authorization Manager", layout="wide")
    current_dir = Path(__file__).parent.absolute()
    test_file = current_dir / "authorized_macs.yaml"
    render(test_file)