import streamlit as st
import pandas as pd
from pathlib import Path
import requests

# =====================================================
# MAC vendor lookup
# =====================================================
@st.cache_data(show_spinner=False)
def get_mac_vendor(mac: str) -> str:
    if not mac or mac == "unknown":
        return "Unknown"
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text if r.status_code == 200 else "Unknown"
    except Exception:
        return "Unknown"

# =====================================================
# Zeek log loader (robust to tabs/spaces)
# =====================================================
def load_zeek_log(path: Path) -> pd.DataFrame:
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
                    rows.append(parts[:len(headers)])  # truncate extra columns

        if not headers or not rows:
            return pd.DataFrame()

        df = pd.DataFrame(rows, columns=headers)

        # Convert ts to datetime (Zeek ts is usually Unix epoch)
        if "ts" in df.columns:
            df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
            df["ts"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")

        # Normalize MAC and other strings
        if "mac" in df.columns:
            df["mac"] = df["mac"].astype(str).str.strip().str.lower()
        if "host" in df.columns:
            df["host"] = df["host"].astype(str).str.strip()

        # Drop rows missing ts/host/mac for known_hosts
        if {"ts", "host", "mac"}.issubset(df.columns):
            df = df.dropna(subset=["ts", "host", "mac"])

        return df

    except Exception as e:
        st.warning(f"Failed to load {path.name}: {e}")
        return pd.DataFrame()


# =====================================================
# Locate latest Zeek LOG folder
# =====================================================
logs_root = Path("logs")

daily_folders = sorted(
    [f for f in logs_root.iterdir() if f.is_dir() and not f.name.endswith("-CSV")],
    reverse=True
)

known_hosts = pd.DataFrame()
dhcp = pd.DataFrame()

for folder in daily_folders:  # load all days
    kh_log = folder / "known_hosts.log"
    dhcp_log = folder / "dhcp.log"

    if kh_log.exists():
        df = load_zeek_log(kh_log)
        known_hosts = pd.concat([known_hosts, df], ignore_index=True)

    if dhcp_log.exists():
        df_dhcp = load_zeek_log(dhcp_log)
        dhcp = pd.concat([dhcp, df_dhcp], ignore_index=True)

if known_hosts.empty:
    st.warning("No known_hosts logs found")

# =====================================================
# Normalize known_hosts
# =====================================================
if not known_hosts.empty:
    required_cols = {"ts", "host", "mac"}
    if not required_cols.issubset(known_hosts.columns):
        st.error(f"known_hosts.log missing required columns: {known_hosts.columns.tolist()}")
        known_hosts = pd.DataFrame()
    else:
        known_hosts["mac"] = known_hosts["mac"].astype(str).str.strip().str.lower()
        # keep ts as datetime (already converted)
        known_hosts = known_hosts.dropna(subset=["ts", "host", "mac"])
        # Add date-only column for filtering
        known_hosts["date_only"] = known_hosts["ts"].dt.date

# =====================================================
# Normalize DHCP (optional enrichment)
# =====================================================
def normalize_dhcp(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    cols = ["client_addr", "host_name", "domain"]
    return df[[c for c in cols if c in df.columns]]

# =====================================================
# Authorized MACs
# =====================================================
authorized_mac_file = Path("authorized_macs.txt")
authorized_macs: set[str] = set()

if authorized_mac_file.exists():
    authorized_macs = {
        line.strip().lower()
        for line in authorized_mac_file.read_text().splitlines()
        if line.strip()
    }
else:
    st.warning("authorized_macs.txt not found — all devices Unauthorized")

# =====================================================
# Devices Page with multi-date filter
# =====================================================
def render(authorized: set[str]):
    st.title("Device Inventory")

    if known_hosts.empty:
        st.info("No devices detected")
        return

    # ------------------------
    # Multi-date selector
    # ------------------------
    available_dates = sorted(known_hosts["date_only"].unique(), reverse=True)
    selected_dates = st.multiselect(
        "Select date(s) to display",
        options=available_dates,
        default=available_dates[:1]  # latest by default
    )

    if selected_dates:
        filtered_hosts = known_hosts[known_hosts["date_only"].isin(selected_dates)]
    else:
        filtered_hosts = known_hosts.copy()

    if filtered_hosts.empty:
        st.info("No devices for the selected date(s)")
        return

    # Merge DHCP info if available
    if not dhcp.empty:
        dhcp_norm = normalize_dhcp(dhcp)
        merged = pd.merge(
            filtered_hosts,
            dhcp_norm,
            how="left",
            left_on="host",
            right_on="client_addr"
        )
    else:
        merged = filtered_hosts.copy()
        merged["host_name"] = "-"
        merged["domain"] = None

    merged["host_name"] = merged.get("host_name", "-").fillna("-")

    # Aggregate per MAC
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

    # Vendor
    devices["vendor"] = devices["mac"].apply(get_mac_vendor)

    # Authorization
    devices["status"] = devices["mac"].apply(
        lambda m: "Authorized" if m in authorized else "Unauthorized"
    )

    # Search
    search = st.text_input("🔍 Search MAC / IP / Host / Domain", "")
    if search:
        devices = devices[
            devices.astype(str)
            .apply(lambda c: c.str.contains(search, case=False, na=False))
            .any(axis=1)
        ]

    # Display
    st.dataframe(
        devices.sort_values("last_seen", ascending=False),
        column_config={
            "mac": "MAC Address",
            "ip": "IP Address",
            "host_name": "Host Name",
            "domain": "Domain",
            "vendor": "Vendor",
            "first_seen": st.column_config.DatetimeColumn(
                "First Seen", format="YYYY-MM-DD HH:mm:ss"
            ),
            "last_seen": st.column_config.DatetimeColumn(
                "Last Seen", format="YYYY-MM-DD HH:mm:ss"
            ),
            "status": "Access Status",
        },
        use_container_width=True,
        hide_index=True
    )
