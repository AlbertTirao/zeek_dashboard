import requests
from pathlib import Path

# -------------------------------
# MAC vendor lookup
# -------------------------------
def get_mac_vendor(mac: str) -> str:
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text if r.status_code == 200 else "Unknown"
    except:
        return "Unknown"

# -------------------------------
# Normalize MAC addresses
# -------------------------------
def normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    return mac.lower().replace(":", "").replace("-", "").strip()

# -------------------------------
# Load authorized MACs
# -------------------------------
def load_authorized_macs(file_path: str = "authorized_macs.txt") -> set:
    path = Path(file_path)
    if path.exists():
        return set(normalize_mac(line) for line in path.read_text().splitlines() if line.strip())
    return set()

# -------------------------------
# List all logs recursively
# -------------------------------
def list_all_logs(log_dir: Path):
    files = []
    for f in sorted(log_dir.rglob("*.*")):
        if f.is_file():
            files.append(str(f.relative_to(log_dir)))
    return files
