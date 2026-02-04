import streamlit as st
import pandas as pd
from pathlib import Path
import requests
from datetime import datetime, timedelta

# =====================================================
# 1. HELPER: MAC VENDOR LOOKUP
# =====================================================
@st.cache_data(show_spinner=False)
def get_mac_vendor(mac: str) -> str:
    """Fetches vendor name from MAC address API."""
    if not mac or mac == "unknown":
        return "Unknown"
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text if r.status_code == 200 else "Unknown"
    except Exception:
        return "Unknown"

# =====================================================
# 2. HELPER: ZEEK LOG PARSER
# =====================================================
def load_zeek_log(path: Path) -> pd.DataFrame:
    """
    Robustly parses Zeek logs (tab-separated).
    """
    headers = None
    rows = []

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    if line.startswith("#fields"):
                        headers = line.split("\t")[1:]
                    continue
                if headers:
                    parts = line.split("\t")
                    rows.append(parts[:len(headers)])

        if not headers or not rows:
            return pd.DataFrame()

        df = pd.DataFrame(rows, columns=headers)

        # Standardize Timestamps
        if "ts" in df.columns:
            df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
            df["ts"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")

        # Standardize MACs (Crucial for merging!)
        if "mac" in df.columns:
            df["mac"] = df["mac"].astype(str).str.strip().str.lower()
        
        # Standardize IPs 
        if "host" in df.columns:
            df["host"] = df["host"].astype(str).str.strip()

        # Drop rows with missing critical keys
        if {"ts", "host", "mac"}.issubset(df.columns):
            df = df.dropna(subset=["ts", "host", "mac"])

        return df

    except Exception as e:
        print(f"Error loading {path}: {e}")
        return pd.DataFrame()

# =====================================================
# 3. HELPER: DHCP NORMALIZATION
# =====================================================
def normalize_dhcp(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extracts MAC and Hostname from DHCP logs to enrich Known Hosts.
    We merge on MAC, not IP, for higher accuracy.
    """
    if df.empty:
        return df
    
    # 1. Standardize MAC for merging
    if "mac" in df.columns:
         df["mac"] = df["mac"].astype(str).str.strip().str.lower()
    
    # 2. Select relevant columns
    cols = ["mac", "host_name", "domain"]
    
    # 3. Filter valid columns
    valid_cols = [c for c in cols if c in df.columns]
    df_clean = df[valid_cols].copy()
    
    # 4. Remove entries with no MAC
    if "mac" in df_clean.columns:
        df_clean = df_clean[df_clean["mac"] != "nan"]
        df_clean = df_clean[df_clean["mac"] != ""]
    
    return df_clean

# =====================================================
# 4. MAIN DATA LOADING & PROCESSING
# =====================================================
def load_and_process_data():
    logs_root = Path("logs")
    
    # --- 1. Load Authorized MACs ---
    authorized_mac_file = Path("authorized_macs.txt")
    authorized_macs = set()
    if authorized_mac_file.exists():
        authorized_macs = {
            line.strip().lower() 
            for line in authorized_mac_file.read_text().splitlines() 
            if line.strip()
        }

    # --- 2. Iterate Log Folders ---
    daily_folders = sorted(
        [f for f in logs_root.iterdir() if f.is_dir() and not f.name.endswith("-CSV")],
        reverse=True
    )

    known_hosts = pd.DataFrame()
    dhcp = pd.DataFrame()

    for folder in daily_folders:
        kh_log = folder / "known_hosts.log"
        dhcp_log = folder / "dhcp.log"

        if kh_log.exists():
            df = load_zeek_log(kh_log)
            known_hosts = pd.concat([known_hosts, df], ignore_index=True)

        if dhcp_log.exists():
            df_dhcp = load_zeek_log(dhcp_log)
            dhcp = pd.concat([dhcp, df_dhcp], ignore_index=True)

    if known_hosts.empty:
        return pd.DataFrame()

    # --- 3. Merge DHCP Data (THE FIX) ---
    # Strategy: Merge based on MAC Address, not IP.
    # Why? IPs change (dynamic). MACs are permanent hardware IDs.
    if not dhcp.empty:
        dhcp_norm = normalize_dhcp(dhcp)
        
        # Deduplicate DHCP: Keep the *last* seen hostname for each MAC
        # (Assuming logs are read in order, last entry is most recent)
        dhcp_unique = dhcp_norm.drop_duplicates(subset=["mac"], keep="last")
        
        # Merge known_hosts (IP/MAC) with dhcp (Hostname/MAC)
        merged = pd.merge(
            known_hosts,
            dhcp_unique,
            how="left",
            on="mac"  # <--- Changed from IP to MAC for accuracy
        )
    else:
        merged = known_hosts.copy()
        merged["host_name"] = "-"
        merged["domain"] = None

    merged["host_name"] = merged.get("host_name", "-").fillna("-")

    # --- 4. Aggregate per MAC ---
    devices = (
        merged
        .groupby("mac", dropna=False)
        .agg(
            ip=("host", "last"),
            host_name=("host_name", "last"),
            domain=("domain", "last"),
            first_seen=("ts", "min"),
            last_seen=("ts", "max"),
        )
        .reset_index()
    )

    # --- 5. Determine Status & Filter ---
    devices["status"] = devices["mac"].apply(
        lambda m: "Authorized" if m in authorized_macs else "Unauthorized"
    )

    # Filter: ONLY Unauthorized
    rogue_devices = devices[devices["status"] == "Unauthorized"].copy()
    
    # --- 6. Add Vendor Info ---
    rogue_devices["vendor"] = rogue_devices["mac"].apply(get_mac_vendor)

    return rogue_devices

# =====================================================
# 5. RENDER DASHBOARD
# =====================================================
def render(df=None): 
    st.title("🚨 Live Security Alerts")
    st.caption(f"Last Scan: {datetime.now().strftime('%H:%M:%S')}")

    # Load fresh data
    rogue_df = load_and_process_data()

    # --- A. Empty State ---
    if rogue_df.empty:
        st.success("✅ System Secure: No unauthorized devices detected.")
        if st.button("Refresh Scan"):
            st.rerun()
        return

    # --- B. Metrics ---
    now = datetime.now()
    cutoff = now - timedelta(days=1)
    
    # Ensure datetime format
    if not pd.api.types.is_datetime64_any_dtype(rogue_df["last_seen"]):
        rogue_df["last_seen"] = pd.to_datetime(rogue_df["last_seen"])

    active_threats = rogue_df[rogue_df["last_seen"] >= cutoff]
    new_count = len(active_threats)
    total_count = len(rogue_df)

    c1, c2 = st.columns(2)
    with c1:
        st.metric("Total Unauthorized", total_count, "All time detected")
    with c2:
        st.metric("Active Threats (24h)", new_count, "Requires Action", delta_color="inverse")

    if new_count > 0:
        st.error(f"⚠️ ACTION REQUIRED: {new_count} unauthorized devices active recently.")

    # --- C. Table ---
    st.subheader("📋 Unauthorized Device Details")
    
    st.dataframe(
        rogue_df.sort_values("last_seen", ascending=False),
        column_config={
            "mac": "MAC Address",
            "ip": "IP Address",
            "host_name": "Host Name",
            "domain": "Domain",
            "vendor": "Vendor",
            "first_seen": st.column_config.DatetimeColumn(
                "First Seen", format="D MMM YYYY, HH:mm"
            ),
            "last_seen": st.column_config.DatetimeColumn(
                "Last Seen", format="D MMM YYYY, HH:mm"
            ),
            # Explicitly showing Access Status
            "status": st.column_config.TextColumn("Access Status"),
        },
        use_container_width=True,
        hide_index=True
    )

    if st.button("Refresh Data"):
        st.rerun()

if __name__ == "__main__":
    render()