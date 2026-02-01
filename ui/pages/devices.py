import streamlit as st
import pandas as pd
from pathlib import Path
import requests
from io import StringIO

def folder_date(f: Path):
    try:
        return pd.to_datetime(f.name, errors="coerce")
    except Exception:
        return pd.NaT

# =====================================================
# Helper: read Zeek log file into DataFrame
# =====================================================
def read_zeek_log(path: Path) -> pd.DataFrame:
    fields = None
    data = []

    with open(path, "r") as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.strip().split()[1:]
            elif not line.startswith("#"):
                data.append(line)

    if not fields or not data:
        return pd.DataFrame()

    return pd.read_csv(
        StringIO("".join(data)),
        sep="\t",
        names=fields,
        low_memory=False
    )

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
# Load latest known_hosts.csv and DHCP CSV
# =====================================================
logs_root = Path("logs")
known_hosts_file = None
dhcp_file = None

# daily_folders = sorted(
#     [f for f in logs_root.iterdir() if f.is_dir() and f.name.endswith("-CSV")],
#     reverse=True
# )

# daily_folders = sorted(
#     [f for f in logs_root.iterdir() if f.is_dir()],
#     reverse=True
# )

# if daily_folders:
#     latest_folder = daily_folders[0]
#     # known_hosts_file = latest_folder / "known_hosts.csv"
#     # dhcp_file = latest_folder / "dhcp.csv"  # <-- use DHCP CSV now
#     known_hosts_logs = list(latest_folder.glob("known_hosts*.log"))
#     dhcp_logs = list(latest_folder.glob("dhcp*.log"))

#     known_hosts_file = max(known_hosts_logs, key=lambda f: f.stat().st_mtime) if known_hosts_logs else None
#     dhcp_file = max(dhcp_logs, key=lambda f: f.stat().st_mtime) if dhcp_logs else None

daily_folders = [
    f for f in logs_root.iterdir()
    if f.is_dir() and not pd.isna(folder_date(f))
]

daily_folders.sort(key=folder_date, reverse=True)

latest_folder = daily_folders[0] if daily_folders else None

if latest_folder:
    known_hosts_logs = list(latest_folder.glob("known_hosts*.log"))
    dhcp_logs = list(latest_folder.glob("dhcp*.log"))

    known_hosts_file = max(known_hosts_logs, key=lambda f: f.stat().st_mtime) if known_hosts_logs else None
    dhcp_file = max(dhcp_logs, key=lambda f: f.stat().st_mtime) if dhcp_logs else None
else:
    st.warning("No valid dated log folders found")

st.write("Using folder:", latest_folder)
st.write("known_hosts_file:", known_hosts_file)
st.write("dhcp_file:", dhcp_file)

# -------------------------
# Load known_hosts
# -------------------------
known_hosts = pd.DataFrame()
if known_hosts_file and known_hosts_file.exists():
    # known_hosts = pd.read_csv(known_hosts_file)
    known_hosts = read_zeek_log(known_hosts_file)
    if not {"ts", "host", "mac"}.issubset(known_hosts.columns):
        st.warning(f"known_hosts.csv missing expected columns: {known_hosts.columns}")
        known_hosts = pd.DataFrame()
else:
    st.warning("No known_hosts.csv found")

# -------------------------
# Load DHCP CSV for host_name/domain
# -------------------------
dhcp = pd.DataFrame()
if dhcp_file and dhcp_file.exists():
    # dhcp = pd.read_csv(dhcp_file)
    dhcp = read_zeek_log(dhcp_file)
    if not {"client_addr", "host_name", "domain"}.issubset(dhcp.columns):
        st.warning(f"DHCP CSV missing expected columns: {dhcp.columns}")
        dhcp = pd.DataFrame()
else:
    st.warning("No DHCP CSV found")

# Load authorized MACs from file
authorized_mac_file = Path("authorized_macs.txt")
authorized_macs = set()
if authorized_mac_file.exists():
    with open(authorized_mac_file, "r") as f:
        authorized_macs = set(line.strip().lower() for line in f if line.strip())
else:
    st.warning("authorized_macs.txt not found, all devices will show as Unauthorized")

# =====================================================
# Devices Page Renderer
# =====================================================
def render(authorized: set[str]):
    st.title("Device Inventory")

    if known_hosts.empty:
        st.info("No known hosts to display")
        return
# Normalize MACs in known_hosts
    known_hosts["mac"] = known_hosts["mac"].astype(str).str.strip().str.lower()

    # Merge with DHCP as before
    if not dhcp.empty:
        merged = pd.merge(
            known_hosts,
            dhcp[["client_addr", "host_name", "domain"]],
            how="left",
            left_on="host",
            right_on="client_addr"
        )
    else:
        merged = known_hosts.copy()
        merged["host_name"] = "-"
        merged["domain"] = None

    # Fill missing host_name
    merged["host_name"] = merged["host_name"].fillna("-")
    merged["mac"] = merged["mac"].astype(str).str.strip().str.lower()
    merged["ts"] = pd.to_datetime(merged["ts"], errors="coerce")

    # Group by MAC for devices
    devices = (
        merged.groupby("mac", dropna=False)
        .agg(
            host=("host", "last"),
            host_name=("host_name", "last"),
            domain=("domain", "last"),
            first_seen=("ts", "min"),
            last_seen=("ts", "max")
        )
        .reset_index()
    )

    # Normalize again after groupby
    devices["mac"] = devices["mac"].astype(str).str.strip().str.lower()

    # Authorization check
    devices["status"] = devices["mac"].apply(
        lambda m: "Authorized" if m in authorized_macs else "Unauthorized"
    )

    # Search/filter input
    search = st.text_input("🔍 Search MAC / IP / Host Name / Domain", "")
    if search:
        mask = devices.astype(str).apply(
            lambda x: x.str.contains(search, case=False, na=False)
        ).any(axis=1)
        devices = devices[mask]

    # Display table
    st.dataframe(
        devices.sort_values("last_seen", ascending=False),
        column_config={
            "mac": "MAC Address",
            "host": "IP / Host",
            "host_name": "Host Name",
            "domain": "Domain",
            "vendor": "Vendor",
            "first_seen": st.column_config.DatetimeColumn(
                "First Seen", format="YYYY-MM-DD HH:mm:ss"
            ),
            "last_seen": st.column_config.DatetimeColumn(
                "Last Seen", format="YYYY-MM-DD HH:mm:ss"
            ),
            "status": st.column_config.TextColumn("Access Status"),
        },
        use_container_width=True,
        hide_index=True
    )


# =====================================================
# MAIN
# =====================================================
render(authorized_macs)