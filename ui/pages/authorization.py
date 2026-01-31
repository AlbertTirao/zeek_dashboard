import streamlit as st
import time
from pathlib import Path

def render(logs_dir: Path, authorized: set):
    KNOWN_HOSTS_FILE = logs_dir / "known_hosts.log"

    st.title(" Access Control")
    st.info("Manage the whitelist of authorized MAC addresses below.")

    current_macs = "\n".join(sorted(authorized))

    with st.form("auth_form"):
        text = st.text_area(
            "Authorized MAC addresses (one per line)",
            current_macs,
            height=300
        )
        submitted = st.form_submit_button("💾 Save Configuration")
        if submitted:
            macs = {m.strip().lower() for m in text.splitlines() if m.strip()}
            KNOWN_HOSTS_FILE.parent.mkdir(exist_ok=True)
            with open(KNOWN_HOSTS_FILE, "w") as f:
                f.write("\n".join(sorted(macs)))
            st.success("Configuration updated successfully!")
            time.sleep(1)
            st.rerun()  # <- updated for latest Streamlit

