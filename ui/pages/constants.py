# ui/pages/constants.py
from pathlib import Path
import streamlit as st


MAX_ROWS_DISPLAY = 320

# Path to the allowlist file (relative to this file)
ALLOWLIST_FILE = Path(__file__).resolve().parent.parent / "allowlist.txt"

def load_allowlist():
    """Load approved domains from allowlist.txt, ignore empty lines and comments."""
    if not ALLOWLIST_FILE.exists():
        return []

    with open(ALLOWLIST_FILE, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
