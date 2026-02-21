# ui/pages/shadow_sharings.py
import re
import math
import warnings
import ipaddress
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import duckdb
import pandas as pd
import streamlit as st
import plotly.express as px
import yaml
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode

# -----------------------------------------------------------------------------
# CONFIG
# -----------------------------------------------------------------------------

CACHE_VERSION = "shadow-sharing-cache-v9-hostname-parity"
CACHE_DIRNAME = "_shadow_cache_sharing"
DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WHITELIST_FILE = PROJECT_ROOT / "whitelist_domains.yaml"

try:
    from .constants import MAX_ROWS_DISPLAY
except ImportError:
    MAX_ROWS_DISPLAY = 1000

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#f59e0b",
    "LOW": "#22c55e",
}

# -----------------------------------------------------------------------------
# CACHE HELPERS (same pattern as shadow apps)
# -----------------------------------------------------------------------------

def cache_dir(parquet_root: Path) -> Path:
    return Path(parquet_root) / CACHE_DIRNAME


def cache_events_path(parquet_root: Path, date_str: str) -> Path:
    return cache_dir(parquet_root) / f"date={date_str}" / "shadow_sharing.parquet"


def cache_meta_path(parquet_root: Path, date_str: str) -> Path:
    return cache_dir(parquet_root) / f"date={date_str}" / "meta.yaml"


def read_yaml(path: Path) -> dict:
    try:
        if not path.exists():
            return {}
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def write_yaml(path: Path, data: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, sort_keys=False)
    except Exception:
        pass


def _file_signature(paths: List[Path]) -> List[List[object]]:
    sig: List[List[object]] = []
    for p in paths:
        try:
            st_ = p.stat()
            sig.append([str(p.resolve()), int(st_.st_mtime_ns), int(st_.st_size)])
        except Exception:
            continue
    return sig


def _meta_expected(files_sig: Dict[str, List[List[object]]], whitelist_mtime_ns: int) -> dict:
    return {
        "cache_version": CACHE_VERSION,
        "whitelist_mtime_ns": int(whitelist_mtime_ns),
        "files_sig": files_sig,
    }

# -----------------------------------------------------------------------------
# DuckDB (fast parquet scan)
# -----------------------------------------------------------------------------

@st.cache_resource
def get_duckdb_connection():
    return duckdb.connect(database=":memory:")


def _sql_list(paths: List[Path]) -> str:
    return "[" + ",".join(f"'{p.as_posix()}'" for p in paths) + "]"


def _duck_read_parquet_union(paths: List[Path]) -> pd.DataFrame:
    if not paths:
        return pd.DataFrame()

    con = get_duckdb_connection()
    try:
        arr = _sql_list(paths)
        return con.execute(f"SELECT * FROM read_parquet({arr}, union_by_name=TRUE)").fetchdf()
    except Exception:
        # fallback: per file
        dfs: List[pd.DataFrame] = []
        for p in paths:
            try:
                dfs.append(con.execute(f"SELECT * FROM read_parquet('{p.as_posix()}')").fetchdf())
            except Exception:
                continue
        return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

# -----------------------------------------------------------------------------
# Whitelist loader (basis)
# -----------------------------------------------------------------------------

def _safe_yaml_load(path: Path) -> dict:
    try:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                d = yaml.safe_load(f) or {}
                return d if isinstance(d, dict) else {}
    except Exception:
        pass
    return {}


def _extract_whitelist_domains(y: dict) -> List[str]:
    """
    Supports common shapes:
      - {trusted_domains: [..]}
      - {whitelist_domains: [..]}
      - {domains: [..]}
      - {[..]} (not dict) -> handled in loader by returning {}
    """
    for k in ["trusted_domains", "whitelist_domains", "domains", "allowed_domains", "whitelist", "allowlist"]:
        v = y.get(k)
        if isinstance(v, list):
            return [str(x).strip().lower() for x in v if str(x).strip()]
    # also allow dict form: {domain: true}
    for k in ["trusted_domains", "whitelist_domains", "domains", "allowed_domains", "whitelist", "allowlist"]:
        if k in y and isinstance(y[k], dict):
            return [str(x).strip().lower() for x in y[k].keys()]
    return []


@st.cache_data(ttl=600, show_spinner=False)
def load_whitelist() -> Tuple[List[str], int]:
    y = _safe_yaml_load(WHITELIST_FILE)
    domains = _extract_whitelist_domains(y)
    domains = sorted(set([d for d in domains if d]))
    mtime_ns = int(WHITELIST_FILE.stat().st_mtime_ns) if WHITELIST_FILE.exists() else 0
    return domains, mtime_ns


WHITELIST_DOMAINS, WHITELIST_MTIME_NS = load_whitelist()


def _is_admin_user() -> bool:
    """
    Best-effort admin detection. Works if your auth layer sets either:
      - st.session_state["is_admin"] = True
      - st.session_state["user_role"] = "admin"
    Otherwise defaults to False.
    """
    try:
        if bool(st.session_state.get("is_admin", False)):
            return True
        if str(st.session_state.get("user_role", "")).lower() == "admin":
            return True
    except Exception:
        pass
    return False


def _add_domain_to_whitelist(domain: str) -> Tuple[bool, str]:
    """
    Add a domain/host to whitelist_domains.yaml.

    Returns (ok, message).
    """
    host = _normalize_host(domain)
    if not host:
        return False, "Empty destination"
    if _is_ip_literal(host):
        return False, "Refusing to whitelist a raw IP (use a domain)"

    y = _safe_yaml_load(WHITELIST_FILE)
    if not isinstance(y, dict):
        y = {}

    # pick a list key to use / preserve
    key = None
    for k in ["trusted_domains", "whitelist_domains", "domains", "allowed_domains", "whitelist", "allowlist"]:
        if isinstance(y.get(k), list):
            key = k
            break
    if key is None:
        # If dict form exists, extend it; else default to trusted_domains list
        for k in ["trusted_domains", "whitelist_domains", "domains", "allowed_domains", "whitelist", "allowlist"]:
            if isinstance(y.get(k), dict):
                y[k][host] = True
                try:
                    WHITELIST_FILE.parent.mkdir(parents=True, exist_ok=True)
                    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
                        yaml.safe_dump(y, f, sort_keys=True)
                    return True, f"Added {host} to {k}"
                except Exception as e:
                    return False, f"Failed to write whitelist: {e}"
        key = "trusted_domains"
        y[key] = []

    lst = [str(x).strip().lower() for x in (y.get(key) or []) if str(x).strip()]
    if host in lst:
        return True, f"{host} already present in {key}"
    lst.append(host)
    lst = sorted(set(lst))
    y[key] = lst

    try:
        WHITELIST_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(y, f, sort_keys=True)
        return True, f"Added {host} to {key}"
    except Exception as e:
        return False, f"Failed to write whitelist: {e}"

# -----------------------------------------------------------------------------
# Normalization helpers
# -----------------------------------------------------------------------------

_MAC_HEX_RE = re.compile(r"[^0-9a-fA-F]")
_ISO_LIKE = re.compile(
    r"^\d{4}-\d{2}-\d{2}"
    r"(?:[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)?$"
)


def normalize_mac(value) -> Optional[str]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None

    if isinstance(value, (bytes, bytearray)) and len(value) == 6:
        hx = bytes(value).hex()
    else:
        s = str(value).strip()
        if not s or s == "-" or s.lower() in ("nan", "none"):
            return None
        hx = _MAC_HEX_RE.sub("", s)

    if len(hx) != 12:
        return None
    hx = hx.lower()
    return ":".join(hx[i:i + 2] for i in range(0, 12, 2))


def _clean_str_series(s: pd.Series) -> pd.Series:
    s = s.astype(str).str.strip()
    return s.replace({"": None, "-": None, "nan": None, "None": None})


def _is_ip_literal(value: object) -> bool:
    s = str(value or "").strip()
    if not s:
        return False
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1].strip()
    if s.lower() in {"nan", "none", "unknown", "-"}:
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


def _ensure_ts_datetime(df: pd.DataFrame) -> pd.DataFrame:
    """
    Avoids the common warning "Could not infer format..." by using heuristics.
    """
    if "ts" not in df.columns:
        df["ts"] = pd.NaT
        return df

    s = df["ts"]
    if pd.api.types.is_datetime64_any_dtype(s):
        return df

    if pd.api.types.is_numeric_dtype(s):
        df["ts"] = pd.to_datetime(s, unit="s", errors="coerce")
        return df

    s_str = s.astype(str).str.strip().replace({"": None, "-": None, "nan": None, "None": None})
    num = pd.to_numeric(s_str, errors="coerce")
    if num.notna().mean() >= 0.80:
        df["ts"] = pd.to_datetime(num, unit="s", errors="coerce")
        return df

    non_na = s_str.dropna()
    if len(non_na) > 0 and (non_na.apply(lambda x: bool(_ISO_LIKE.match(x))).mean() >= 0.80):
        df["ts"] = pd.to_datetime(s_str, format="ISO8601", errors="coerce")
        return df

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Could not infer format", category=UserWarning)
        df["ts"] = pd.to_datetime(s_str, errors="coerce")
    return df


def fingerprint_client(ua: str) -> str:
    if pd.isna(ua) or ua in ["-", ""]:
        return "Unknown"
    ua = str(ua).lower()
    if any(x in ua for x in ["python", "curl", "wget", "aiohttp", "requests", "httpx", "postman", "powershell", "go-http-client", "okhttp", "java"]):
        return "Automation / SDK"
    if any(x in ua for x in ["mozilla", "chrome", "safari", "edge", "firefox"]):
        return "Web Browser"
    return "Mobile / App"

# -----------------------------------------------------------------------------
# File discovery
# -----------------------------------------------------------------------------

@st.cache_data(show_spinner=False)
def get_available_dates(parquet_root: Path) -> List[str]:
    parquet_root = Path(parquet_root)
    if not parquet_root.exists():
        return []
    out: List[str] = []
    for p in parquet_root.iterdir():
        if p.is_dir() and DATE_DIR_RE.match(p.name):
            out.append(p.name)
    return sorted(out, reverse=True)


@st.cache_data(show_spinner=False)
def _collect_known_files(parquet_root: Path) -> List[Path]:
    parquet_root = Path(parquet_root)
    known: List[Path] = []
    if not parquet_root.exists():
        return known
    try:
        for f in parquet_root.rglob("*.parquet"):
            n = f.name.lower()
            if ("known_hosts" in n) or ("knownhost" in n) or ("known_devices" in n) or ("knowndevices" in n):
                known.append(f)
    except Exception:
        pass
    return sorted(set(known))


def _collect_date_files(date_dir: Path) -> Dict[str, List[Path]]:
    buckets = {"http": [], "ssl": [], "dns": [], "conn": [], "files": [], "dhcp": []}
    if not date_dir.exists():
        return buckets

    try:
        for f in date_dir.rglob("*.parquet"):
            n = f.name.lower()
            if n.startswith("http"):
                buckets["http"].append(f)
            elif n.startswith("ssl"):
                buckets["ssl"].append(f)
            elif n.startswith("dns"):
                buckets["dns"].append(f)
            elif n.startswith("conn"):
                buckets["conn"].append(f)
            elif n.startswith("files"):
                buckets["files"].append(f)
            elif n.startswith("dhcp"):
                buckets["dhcp"].append(f)
    except Exception:
        pass

    for k in buckets:
        buckets[k] = sorted(set(buckets[k]))
    return buckets

# -----------------------------------------------------------------------------
# Identity enrichment (DHCP + conn + known)
# -----------------------------------------------------------------------------

def _build_identity_maps(dhcp_files: List[Path], conn_files: List[Path], known_files: List[Path]) -> Tuple[Dict[str, Tuple[Optional[str], str]], Dict[str, str]]:
    ip_map: Dict[str, Tuple[Optional[str], str]] = {}
    mac_map: Dict[str, str] = {}

    def ingest(df: pd.DataFrame, source_hint: str) -> None:
        nonlocal ip_map, mac_map
        if df.empty:
            return

        # Some sources may expose duplicate column names; keep first occurrence.
        if df.columns.duplicated().any():
            df = df.loc[:, ~df.columns.duplicated()].copy()

        df = _ensure_ts_datetime(df)
        if "ts" in df.columns:
            df = df.sort_values("ts")

        if source_hint == "dhcp":
            ip_candidates = ["client_addr", "assigned_addr", "requested_addr", "ip", "id.orig_h", "orig_h"]
            mac_candidates = ["mac", "client_chaddr", "hardware_address", "hwaddr", "chaddr", "orig_l2_addr", "l2_addr", "src_mac"]
            host_candidates = ["host_name", "hostname", "client_hostname", "client_fqdn", "client_name", "name", "device_name", "host"]
        elif source_hint == "known":
            ip_candidates = ["host", "ip", "ip_addr", "addr", "id.orig_h", "orig_h", "client_addr", "assigned_addr"]
            mac_candidates = ["mac", "mac_addr", "hwaddr", "client_chaddr", "client_mac", "orig_l2_addr", "l2_addr", "src_mac"]
            host_candidates = ["host_name", "hostname", "name", "device_name", "client_hostname", "client_fqdn", "client_name"]
        else:
            ip_candidates = ["id.orig_h", "orig_h", "src_ip", "ip", "client_addr", "assigned_addr", "addr"]
            mac_candidates = ["orig_l2_addr", "l2_addr", "src_mac", "mac", "orig_mac", "id.orig_mac", "hwaddr", "mac_addr"]
            host_candidates = ["host_name", "hostname", "device_name", "host", "name"]

        ip_col = next((c for c in ip_candidates if c in df.columns), None)
        mac_col = next((c for c in mac_candidates if c in df.columns), None)
        host_col = next((c for c in host_candidates if c in df.columns), None)
        if host_col in {ip_col, mac_col}:
            host_col = None

        if ip_col is None and mac_col is None:
            return

        if ip_col is not None:
            df[ip_col] = _clean_str_series(df[ip_col])
            df[ip_col] = df[ip_col].where(df[ip_col].apply(_is_ip_literal), None)
        if mac_col is not None:
            df[mac_col] = df[mac_col].apply(normalize_mac)
        if host_col is not None:
            df[host_col] = df[host_col].astype(str).replace({"nan": "", "None": "", "-": ""}).str.strip()
            df[host_col] = df[host_col].where(~df[host_col].apply(_is_ip_literal), "")
        else:
            host_col = "__host"
            df[host_col] = ""

        # ip -> (mac, host) last seen
        if ip_col is not None:
            sub_cols = list(dict.fromkeys([ip_col, host_col] + ([mac_col] if mac_col is not None else [])))
            if "ts" in df.columns:
                sub_cols = list(dict.fromkeys(["ts"] + sub_cols))
            sub = df[sub_cols].dropna(subset=[ip_col]).copy()
            if "ts" in sub.columns:
                sub = sub.sort_values("ts")

            def last_non_null_mac(x: pd.Series):
                x = x.dropna()
                return x.iloc[-1] if len(x) else None

            def last_non_empty_host(x: pd.Series):
                x = x.astype(str).replace({"nan": "", "None": "", "-": ""})
                x = x.where(~x.apply(_is_ip_literal), "")
                x = x[x != ""]
                return x.iloc[-1] if len(x) else ""

            if mac_col is not None:
                g = sub.groupby(ip_col, dropna=True).agg(mac=(mac_col, last_non_null_mac), host=(host_col, last_non_empty_host))
            else:
                g = sub.groupby(ip_col, dropna=True).agg(host=(host_col, last_non_empty_host))
                g["mac"] = None

            for ip, r in g.iterrows():
                ip_map[str(ip)] = (r.get("mac", None), r.get("host", "") or "")

        # mac -> host
        if mac_col is not None:
            subm_cols = list(dict.fromkeys([mac_col, host_col] + (["ts"] if "ts" in df.columns else [])))
            subm = df[subm_cols].dropna(subset=[mac_col]).copy()
            subm[host_col] = subm[host_col].astype(str).replace({"nan": "", "None": "", "-": ""})
            subm[host_col] = subm[host_col].where(~subm[host_col].apply(_is_ip_literal), "")
            subm = subm[subm[host_col] != ""]
            if not subm.empty:
                if "ts" in subm.columns:
                    subm = subm.sort_values("ts")
                gm = subm.groupby(mac_col, dropna=True).agg(host=(host_col, lambda x: x.iloc[-1] if len(x) else ""))
                for mac, r in gm.iterrows():
                    if mac and r.get("host", ""):
                        mac_map[str(mac)] = r["host"]

    if dhcp_files:
        ingest(_duck_read_parquet_union(dhcp_files), "dhcp")
    if conn_files:
        ingest(_duck_read_parquet_union(conn_files), "conn")
    if known_files:
        ingest(_duck_read_parquet_union(known_files), "known")

    return ip_map, mac_map


def _enrich_identity(events: pd.DataFrame, ip_map: Dict[str, Tuple[Optional[str], str]], mac_map: Dict[str, str]) -> pd.DataFrame:
    if events.empty:
        return events

    if "mac" not in events.columns:
        events["mac"] = None
    if "host_name" not in events.columns:
        events["host_name"] = None

    def _is_valid_host(value: object) -> bool:
        s = str(value or "").strip()
        if not s:
            return False
        if s.lower() in {"nan", "none", "unknown", "-"}:
            return False
        if _is_ip_literal(s):
            return False
        return True

    for c in ["orig_l2_addr", "l2_addr", "src_mac", "mac", "orig_mac", "id.orig_mac", "mac_addr", "client_chaddr", "hardware_address", "hwaddr", "chaddr"]:
        if c in events.columns:
            tmp = events[c].apply(normalize_mac)
            events["mac"] = events["mac"].where(events["mac"].notna() & (events["mac"] != ""), tmp)
            break

    events["mac"] = events["mac"].apply(normalize_mac)

    if "id.orig_h" in events.columns:
        ips = _clean_str_series(events["id.orig_h"])
        mac_from_ip = ips.map(lambda ip: ip_map.get(ip, (None, ""))[0] if ip else None)
        host_from_ip = ips.map(lambda ip: ip_map.get(ip, (None, ""))[1] if ip else "")

        events["mac"] = events["mac"].where(events["mac"].notna(), mac_from_ip)
        events["host_name"] = events["host_name"].where(
            events["host_name"].apply(_is_valid_host),
            host_from_ip,
        )

    events["mac"] = events["mac"].apply(normalize_mac)
    macs = events["mac"].astype(str).replace({"nan": "", "None": ""})
    host_from_mac = macs.map(lambda m: mac_map.get(m, "") if m else "")
    events["host_name"] = events["host_name"].where(
        events["host_name"].apply(_is_valid_host),
        host_from_mac,
    )

    events["mac"] = events["mac"].astype(str).fillna("").replace({"None": "", "nan": ""})
    events["host_name"] = events["host_name"].astype(str).fillna("").replace({"None": "", "nan": "", "-": ""})
    events["host_name"] = events["host_name"].where(~events["host_name"].apply(_is_ip_literal), "")
    events["host_name"] = events["host_name"].replace({"": "Unknown"})
    events.loc[events["host_name"].str.lower().isin(["nan", "none"]), "host_name"] = "Unknown"
    return events


def _identity_confidence(row: pd.Series) -> str:
    mac = str(row.get("mac", "") or "")
    host = str(row.get("host_name", "") or "")
    ip = str(row.get("id.orig_h", "") or "")
    if mac and host:
        return "High"
    if mac and ip:
        return "Medium"
    if ip:
        return "Low"
    return "Unknown"

# -----------------------------------------------------------------------------
# Action detection + Category tagging
# -----------------------------------------------------------------------------

UPLOAD_URI_RE = re.compile(r"(^|/)(upload|uploads|file|files|attachments|drive|share|send|transfer|content)(/|$)", re.IGNORECASE)
PASTE_URI_RE = re.compile(r"(paste|bin|snippet|gist)", re.IGNORECASE)
REMOTE_URI_RE = re.compile(r"(remote|rdp|vpn|tunnel|teamviewer|anydesk)", re.IGNORECASE)
API_UPLOAD_RE = re.compile(r"(multipart/form-data|application/octet-stream)", re.IGNORECASE)

# category patterns (domain based)
CATEGORY_RULES: List[Tuple[str, List[str]]] = [
    ("Cloud Storage", [
        "drive.google.com", "docs.google.com", "storage.googleapis.com",
        "onedrive.live.com", "sharepoint.com", "1drv.ms",
        "dropbox.com", "dropboxusercontent.com",
        "box.com",
        "mega.nz",
        "wetransfer.com",
        "icloud.com",
        "s3.amazonaws.com", "amazonaws.com",
        "azureedge.net", "blob.core.windows.net"
    ]),
    ("Paste", ["pastebin.com", "dpaste.com", "hastebin.com", "gist.github.com", "ghostbin.com"]),
    ("Messaging", ["slack.com", "discord.com", "telegram.org", "whatsapp.com", "messenger.com"]),
    ("Code Repo", ["github.com", "gitlab.com", "bitbucket.org"]),
    ("Remote Access", ["teamviewer.com", "anydesk.com", "ngrok.io", "ngrok.com", "tailscale.com", "zerotier.com"]),
]


# -----------------------------------------------------------------------------
# Correlation / destination normalization helpers
# -----------------------------------------------------------------------------

# NOTE: We do not have a Public Suffix List in this project, so registrable-domain
# extraction is best-effort. It is used for grouping; allowlist checks are done
# against the *full* normalized host via boundary-safe suffix matching.
_MULTI_LEVEL_SUFFIXES = {
    # common
    "co.uk", "org.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp",
    "com.br", "com.mx",
    "co.in", "com.ph",
}


def _strip_scheme_path(value: str) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    # remove scheme
    if "://" in s:
        s = s.split("://", 1)[1]
    # remove path/query
    s = s.split("/", 1)[0]
    s = s.split("?", 1)[0]
    s = s.split("#", 1)[0]
    return s.strip()


def _split_host_port(hostport: str) -> Tuple[str, Optional[int]]:
    s = str(hostport or "").strip()
    if not s:
        return "", None
    # IPv6 in brackets: [2001:db8::1]:443
    if s.startswith("["):
        if "]" in s:
            host = s[1:s.index("]")]
            rest = s[s.index("]") + 1:]
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except Exception:
                    return host, None
            return host, None
        return s, None
    # plain host:port (avoid treating IPv6 as host:port)
    if s.count(":") == 1:
        h, p = s.rsplit(":", 1)
        if p.isdigit():
            try:
                return h, int(p)
            except Exception:
                return h, None
    return s, None


def _normalize_host(value: str) -> str:
    """
    Normalize any of:
      - 'https://sub.example.com/path'
      - 'sub.example.com:443'
      - '[2001:db8::1]:443'
      - '1.2.3.4:443'
    into a lowercase host/IP without port/path.
    """
    s = _strip_scheme_path(value)
    host, _ = _split_host_port(s)
    host = str(host or "").strip().strip(".").lower()
    if host in {"", "unknown", "nan", "none", "-"}:
        return ""
    return host


def _registrable_domain_best_effort(host: str) -> str:
    h = _normalize_host(host)
    if not h:
        return ""
    if _is_ip_literal(h):
        return h
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2:
        return h
    suffix2 = ".".join(parts[-2:])
    suffix3 = ".".join(parts[-3:])
    # if last two labels are a known multi-level suffix, keep last 3 labels
    if suffix2 in _MULTI_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    if suffix3 in _MULTI_LEVEL_SUFFIXES and len(parts) >= 4:
        return ".".join(parts[-4:])
    return ".".join(parts[-2:])


def _is_internal_ip(value: str) -> bool:
    s = str(value or "").strip()
    if not s:
        return False
    try:
        ip = ipaddress.ip_address(s)
        # Private, ULA, link-local, loopback are treated as internal
        return bool(ip.is_private or ip.is_link_local or ip.is_loopback)
    except Exception:
        return False


def _parse_zeek_list(v: object) -> List[str]:
    """
    Zeek parquet fields can be:
      - list/tuple
      - string like 'a,b,c' or 'a b c'
      - '(empty)' or '-'
    """
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return []
    if isinstance(v, (list, tuple, set)):
        return [str(x).strip() for x in v if str(x).strip() and str(x).strip() not in {"-", "(empty)"}]
    s = str(v).strip()
    if not s or s in {"-", "(empty)", "nan", "None"}:
        return []
    # split on commas or whitespace
    if "," in s:
        parts = [p.strip() for p in s.split(",")]
    else:
        parts = [p.strip() for p in re.split(r"\s+", s)]
    return [p for p in parts if p and p not in {"-", "(empty)"}]


def _build_dns_ip_map(dns_df: pd.DataFrame) -> Dict[str, str]:
    """Best-effort mapping from answer IP -> query domain for the date."""
    if dns_df is None or dns_df.empty:
        return {}
    if "answers" not in dns_df.columns or "query" not in dns_df.columns:
        return {}
    out: Dict[str, str] = {}
    tmp = dns_df[["query", "answers"]].copy()
    tmp["query"] = tmp["query"].astype(str)
    for _, r in tmp.iterrows():
        q = _normalize_host(r.get("query", ""))
        if not q:
            continue
        dom = _registrable_domain_best_effort(q) or q
        for a in _parse_zeek_list(r.get("answers")):
            a = str(a).strip()
            if _is_ip_literal(a):
                out[a] = dom
    return out


def _first_nonempty(series: pd.Series) -> str:
    for x in series.tolist():
        s = str(x or "").strip()
        if s and s.lower() not in {"nan", "none", "(empty)", "-"}:
            return s
    return ""


def _build_ssl_by_uid(ssl_df: pd.DataFrame) -> pd.DataFrame:
    if ssl_df is None or ssl_df.empty or "uid" not in ssl_df.columns:
        return pd.DataFrame(columns=["uid", "server_name", "ja3", "ja3s", "version", "cipher", "curve", "next_protocol"])
    keep = [c for c in ["uid", "ts", "server_name", "ja3", "ja3s", "version", "cipher", "curve", "next_protocol"] if c in ssl_df.columns]
    sdf = ssl_df[keep].copy()
    sdf = _ensure_ts_datetime(sdf)
    sdf = sdf.sort_values("ts", ascending=True)
    g = sdf.groupby("uid", dropna=False)
    out = pd.DataFrame({
        "uid": g.size().index.astype(str),
        "server_name": g["server_name"].apply(_first_nonempty) if "server_name" in sdf.columns else "",
        "ja3": g["ja3"].apply(_first_nonempty) if "ja3" in sdf.columns else "",
        "ja3s": g["ja3s"].apply(_first_nonempty) if "ja3s" in sdf.columns else "",
        "version": g["version"].apply(_first_nonempty) if "version" in sdf.columns else "",
        "cipher": g["cipher"].apply(_first_nonempty) if "cipher" in sdf.columns else "",
        "curve": g["curve"].apply(_first_nonempty) if "curve" in sdf.columns else "",
        "next_protocol": g["next_protocol"].apply(_first_nonempty) if "next_protocol" in sdf.columns else "",
    }).reset_index(drop=True)
    out["uid"] = out["uid"].astype(str)
    return out


def _http_content_type_row(df: pd.DataFrame) -> pd.Series:
    if "content_type" in df.columns:
        return df["content_type"].astype(str)
    if "orig_mime_types" in df.columns:
        return df["orig_mime_types"].apply(lambda v: _parse_zeek_list(v)[0] if _parse_zeek_list(v) else "")
    return pd.Series([""] * len(df))


def _build_http_by_uid(http_df: pd.DataFrame) -> pd.DataFrame:
    if http_df is None or http_df.empty or "uid" not in http_df.columns:
        return pd.DataFrame(columns=[
            "uid", "host", "method", "uri", "user_agent", "content_type",
            "status_code", "request_body_len", "response_body_len",
            "http_any_upload", "http_any_share"
        ])
    keep = [c for c in ["uid", "ts", "host", "method", "uri", "user_agent", "status_code", "request_body_len", "response_body_len", "orig_mime_types", "content_type"] if c in http_df.columns]
    hdf = http_df[keep].copy()
    hdf = _ensure_ts_datetime(hdf)
    hdf = hdf.sort_values("ts", ascending=True)

    # normalize content type
    hdf["content_type_norm"] = _http_content_type_row(hdf).astype(str)

    # flags
    hdf["method_norm"] = hdf.get("method", "").astype(str).str.upper()
    hdf["uri_norm"] = hdf.get("uri", "").astype(str)
    hdf["host_norm"] = hdf.get("host", "").astype(str)

    hdf["http_is_upload"] = hdf["method_norm"].isin(["POST", "PUT", "PATCH"]) & (
        hdf["uri_norm"].str.contains(UPLOAD_URI_RE) | hdf["content_type_norm"].str.contains(API_UPLOAD_RE)
    )
    hdf["http_is_share"] = (
        hdf["uri_norm"].str.contains(PASTE_URI_RE)
        | hdf["uri_norm"].str.contains(re.compile(r"(share|shared|sharing|create_shared|create_shared_link|/s/)", re.IGNORECASE))
    )

    # numeric body lens
    if "request_body_len" in hdf.columns:
        hdf["request_body_len_num"] = pd.to_numeric(hdf["request_body_len"], errors="coerce").fillna(0)
    else:
        hdf["request_body_len_num"] = 0.0
    if "response_body_len" in hdf.columns:
        hdf["response_body_len_num"] = pd.to_numeric(hdf["response_body_len"], errors="coerce").fillna(0)
    else:
        hdf["response_body_len_num"] = 0.0

    g = hdf.groupby("uid", dropna=False)
    out = pd.DataFrame({
        "uid": g.size().index.astype(str),
        "host": g["host_norm"].apply(_first_nonempty),
        "method": g["method_norm"].apply(_first_nonempty),
        "uri": g["uri_norm"].apply(_first_nonempty),
        "user_agent": g["user_agent"].apply(_first_nonempty) if "user_agent" in hdf.columns else "",
        "content_type": g["content_type_norm"].apply(_first_nonempty),
        "status_code": g["status_code"].apply(_first_nonempty) if "status_code" in hdf.columns else "",
        "request_body_len": g["request_body_len_num"].sum(),
        "response_body_len": g["response_body_len_num"].sum(),
        "http_any_upload": g["http_is_upload"].max().astype(bool),
        "http_any_share": g["http_is_share"].max().astype(bool),
    }).reset_index(drop=True)
    out["uid"] = out["uid"].astype(str)
    return out


def _build_files_by_uid(files_df: pd.DataFrame) -> pd.DataFrame:
    """Join files.log to conn via uid or conn_uids (Zeek often uses conn_uids list)."""
    if files_df is None or files_df.empty:
        return pd.DataFrame(columns=["uid", "file_total_bytes", "file_seen_bytes", "file_mime_types", "file_names", "file_sources"])
    f = files_df.copy()
    f = _ensure_ts_datetime(f)
    if "uid" in f.columns:
        f["_uid"] = f["uid"].astype(str)
    elif "conn_uids" in f.columns:
        f["_uid_list"] = f["conn_uids"].apply(_parse_zeek_list)
        f = f.explode("_uid_list")
        f["_uid"] = f["_uid_list"].astype(str)
    else:
        return pd.DataFrame(columns=["uid", "file_total_bytes", "file_seen_bytes", "file_mime_types", "file_names", "file_sources"])

    f["file_total_bytes"] = pd.to_numeric(f.get("total_bytes", 0), errors="coerce").fillna(0)
    f["file_seen_bytes"] = pd.to_numeric(f.get("seen_bytes", 0), errors="coerce").fillna(0)
    f["file_mime"] = f.get("mime_type", "").astype(str)
    f["file_name"] = f.get("filename", "").astype(str)
    f["file_source"] = f.get("source", "").astype(str)

    g = f.groupby("_uid", dropna=False)
    out = pd.DataFrame({
        "uid": g.size().index.astype(str),
        "file_total_bytes": g["file_total_bytes"].sum(),
        "file_seen_bytes": g["file_seen_bytes"].sum(),
        "file_mime_types": g["file_mime"].apply(lambda s: ", ".join([x for x in sorted(set([str(v).strip() for v in s.tolist() if str(v).strip()]))][:6])),
        "file_names": g["file_name"].apply(lambda s: ", ".join([x for x in sorted(set([str(v).strip() for v in s.tolist() if str(v).strip()]))][:6])),
        "file_sources": g["file_source"].apply(lambda s: ", ".join([x for x in sorted(set([str(v).strip() for v in s.tolist() if str(v).strip()]))][:6])),
    }).reset_index(drop=True)
    out["uid"] = out["uid"].astype(str)
    return out


def _detect_action_flow(row: pd.Series) -> Tuple[str, str]:
    """Higher-confidence action inference after correlation."""
    if bool(row.get("http_any_share", False)):
        return ("Share Link", "http uri indicates share/link creation")
    if bool(row.get("http_any_upload", False)):
        return ("Upload", "http method/uri/content-type indicates upload")
    file_bytes = float(row.get("file_total_bytes", 0) or 0)
    if file_bytes >= 1 * 1024 * 1024:
        bout = float(row.get("bytes_out", 0) or 0)
        bin_ = float(row.get("bytes_in", 0) or 0)
        if bout >= bin_:
            return ("File Transfer (Upload)", "files.log total_bytes + conn direction")
        return ("File Transfer (Download)", "files.log total_bytes + conn direction")
    bout = float(row.get("bytes_out", 0) or 0)
    bin_ = float(row.get("bytes_in", 0) or 0)
    ratio = float(row.get("out_in_ratio", 0) or 0)
    if bout >= 10 * 1024 * 1024 and ratio >= 5:
        return ("Upload (TLS)", "conn orig_bytes high and outbound ratio high")
    if bin_ >= 25 * 1024 * 1024 and (bin_ >= 3 * max(bout, 1)):
        return ("Download", "conn resp_bytes high and inbound ratio high")
    return ("Access", "baseline access")


def _build_correlated_flows(
    conn_df: pd.DataFrame,
    ssl_by_uid: pd.DataFrame,
    http_by_uid: pd.DataFrame,
    files_by_uid: pd.DataFrame,
    dns_ip_map: Dict[str, str],
) -> pd.DataFrame:
    if conn_df is None or conn_df.empty:
        return pd.DataFrame()

    c = conn_df.copy()
    c = _ensure_ts_datetime(c)
    c = c.dropna(subset=["ts"])

    for col in ["uid", "id.orig_h", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "orig_ip_bytes", "resp_ip_bytes", "orig_l2_addr"]:
        if col not in c.columns:
            c[col] = None

    c["uid"] = c["uid"].astype(str)
    c["id.orig_h"] = c["id.orig_h"].astype(str).str.strip()
    c["id.resp_h"] = c["id.resp_h"].astype(str).str.strip()
    c["id.resp_p"] = pd.to_numeric(c["id.resp_p"], errors="coerce").fillna(0).astype(int)

    ob = pd.to_numeric(c["orig_bytes"], errors="coerce")
    rb = pd.to_numeric(c["resp_bytes"], errors="coerce")
    if ob.isna().all():
        ob = pd.to_numeric(c["orig_ip_bytes"], errors="coerce")
    if rb.isna().all():
        rb = pd.to_numeric(c["resp_ip_bytes"], errors="coerce")
    c["bytes_out"] = ob.fillna(0)
    c["bytes_in"] = rb.fillna(0)
    c["out_in_ratio"] = c["bytes_out"] / (c["bytes_in"].clip(lower=1))

    # Focus on internal -> external. If orig_h isn't parseable, keep it.
    try:
        c = c[(~c["id.orig_h"].apply(_is_ip_literal)) | (c["id.orig_h"].apply(_is_internal_ip))]
    except Exception:
        pass
    try:
        c = c[~c["id.resp_h"].apply(_is_internal_ip)]
    except Exception:
        pass

    if not ssl_by_uid.empty:
        c = c.merge(ssl_by_uid, on="uid", how="left", suffixes=("", "_ssl"))
    else:
        c["server_name"] = ""

    if not http_by_uid.empty:
        c = c.merge(http_by_uid, on="uid", how="left", suffixes=("", "_http"))
    else:
        for col in ["host", "method", "uri", "user_agent", "content_type", "status_code"]:
            c[col] = ""
        c["request_body_len"] = 0.0
        c["response_body_len"] = 0.0
        c["http_any_upload"] = False
        c["http_any_share"] = False

    if not files_by_uid.empty:
        c = c.merge(files_by_uid, on="uid", how="left", suffixes=("", "_files"))
    else:
        c["file_total_bytes"] = 0.0
        c["file_seen_bytes"] = 0.0
        c["file_mime_types"] = ""
        c["file_names"] = ""
        c["file_sources"] = ""

    c["dest_host_http"] = c.get("host", "").astype(str).apply(_normalize_host)
    c["dest_host_sni"] = c.get("server_name", "").astype(str).apply(_normalize_host)
    c["dest_host_dns"] = c.get("id.resp_h", "").astype(str).map(lambda ip: dns_ip_map.get(str(ip).strip(), ""))
    c["dest_host_dns"] = c["dest_host_dns"].astype(str).apply(_normalize_host)

    def _pick_dest(row):
        if row.get("dest_host_http"):
            return row["dest_host_http"], "http.host"
        if row.get("dest_host_sni"):
            return row["dest_host_sni"], "ssl.server_name"
        if row.get("dest_host_dns"):
            return row["dest_host_dns"], "dns.answers->query"
        return str(row.get("id.resp_h") or "").strip(), "conn.id.resp_h"

    picked = c.apply(_pick_dest, axis=1, result_type="expand")
    c["destination"] = picked[0].replace({"": "Unknown", "nan": "Unknown", "None": "Unknown"}).fillna("Unknown")
    c["Destination_Basis"] = picked[1].fillna("")

    c["dest_domain"] = c["destination"].apply(_registrable_domain_best_effort)
    c.loc[c["dest_domain"].eq(""), "dest_domain"] = c["destination"]

    # Primary byte measure for dashboard = outbound bytes
    c["bytes"] = c["bytes_out"]

    # action inference
    act = c.apply(_detect_action_flow, axis=1)
    c["Action"] = [a for a, _ in act]
    c["Action_Basis"] = [b for _, b in act]

    c["log_source"] = "flow"

    keep_cols = [
        "ts", "uid", "log_source",
        "id.orig_h", "orig_l2_addr",
        "id.resp_h", "id.resp_p", "proto", "service", "duration",
        "destination", "dest_domain", "Destination_Basis",
        "bytes", "bytes_out", "bytes_in", "out_in_ratio",
        "method", "uri", "user_agent", "content_type",
        "server_name", "ja3", "ja3s", "version", "cipher", "curve", "next_protocol",
        "host", "status_code", "request_body_len", "response_body_len", "http_any_upload", "http_any_share",
        "file_total_bytes", "file_seen_bytes", "file_mime_types", "file_names", "file_sources",
        "Action", "Action_Basis",
    ]
    keep_cols = [c0 for c0 in keep_cols if c0 in c.columns]
    return c[keep_cols].copy()
def _domain_in_allowlist(dest: str, allowlist: List[str]) -> Tuple[bool, str]:
    """
    Returns (allowed, basis)

    Boundary-safe suffix match:
      - allow 'example.com' matches 'example.com' and 'a.b.example.com'
      - does NOT match 'example.com.evil.tld'
    """
    host = _normalize_host(dest)
    if not host:
        return (False, "")

    for a in (allowlist or []):
        a0 = str(a or "").strip().lower()
        if not a0:
            continue
        # support wildcard forms like "*.example.com"
        if a0.startswith("*."):
            a0 = a0[2:]
        a0 = _normalize_host(a0) or a0.strip(".")
        if not a0:
            continue
        if host == a0 or host.endswith("." + a0):
            return (True, a0)

    return (False, "")
def _tag_category(dest: str) -> str:
    d = str(dest or "").lower().strip()
    if not d:
        return "Unknown"
    for cat, rules in CATEGORY_RULES:
        if any(r in d for r in rules):
            return cat
    return "Unknown"


def _detect_action(log_source: str, method: str, uri: str, user_agent: str, dest: str, content_type: str = "") -> Tuple[str, str]:
    """
    Returns (Action, Action_Basis)
    """
    ls = (log_source or "").lower()
    m = (method or "").upper()
    u = str(uri or "")
    d = str(dest or "")
    ua = str(user_agent or "")

    # DNS-based exfil is handled separately as "DNS Exfil Suspected"
    if ls == "dns":
        return ("DNS Lookup", "dns query")

    # SSL: only domain (SNI), no method/uri
    if ls == "ssl":
        return ("Encrypted Access", "tls sni")

    # CONN: only ports/bytes, no uri
    if ls == "conn":
        return ("Raw Connection", "conn telemetry")

    # FILES: explicit file transfer metadata from Zeek files.log
    if ls == "files":
        return ("File Transfer", "files telemetry")

    # HTTP:
    # Upload
    if m in ("POST", "PUT", "PATCH"):
        if UPLOAD_URI_RE.search(u):
            return ("Upload", f"http {m} uri contains upload/file/share keyword")
        if API_UPLOAD_RE.search(content_type or ""):
            return ("Upload", f"http {m} content-type suggests upload")
        # generic: any POST could be exfil or chat etc.
        return ("Post Data", f"http {m}")

    # Share/paste indicators
    if PASTE_URI_RE.search(u) or PASTE_URI_RE.search(d):
        return ("Paste/Share", "paste/gist indicator")
    if REMOTE_URI_RE.search(u) or REMOTE_URI_RE.search(d):
        return ("Remote Access", "remote indicator")

    # client type can hint
    if fingerprint_client(ua) == "Automation / SDK":
        return ("Automated Access", "automation user-agent")

    return ("Browse", "http read access")

# -----------------------------------------------------------------------------
# DNS tunneling heuristics
# -----------------------------------------------------------------------------

_BASE32_64_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=_-")

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for k, c in freq.items():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _dns_exfil_score(query: str) -> Tuple[int, str]:
    """
    Returns (score_add, reason)
    Basic signals:
      - long query
      - high entropy
      - many allowed chars (b64-ish)
    """
    q = str(query or "")
    qn = q.replace(".", "")
    if not q:
        return 0, ""

    score = 0
    reasons: List[str] = []

    if len(q) >= 120:
        score += 25
        reasons.append("dns query length >=120")
    elif len(q) >= 80:
        score += 15
        reasons.append("dns query length >=80")

    ent = _shannon_entropy(qn[:200])
    if ent >= 4.2:
        score += 20
        reasons.append(f"high entropy ({ent:.2f})")

    # proportion of base-ish chars
    baseish = sum(1 for ch in qn if ch in _BASE32_64_CHARS)
    if len(qn) >= 40 and (baseish / max(1, len(qn))) >= 0.95:
        score += 10
        reasons.append("b64-like charset")

    return score, "; ".join(reasons)

# -----------------------------------------------------------------------------
# Risk scoring (SOC-style)
# -----------------------------------------------------------------------------

def _severity_label(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _risk_score_row(row: pd.Series) -> Tuple[int, str]:
    """
    Returns (Risk_Score, Risk_Basis)

    Scoring philosophy:
      - Shadow sharing is fundamentally "unapproved egress to sharing-capable services"
      - Strongest evidence comes from correlated HTTP methods/URIs and files.log
      - For TLS-only, we can only infer from volume + directionality (orig_bytes vs resp_bytes)
    """
    score = 10
    basis: List[str] = []

    allowed = bool(row.get("Allowed", False))
    if not allowed:
        score += 15
        basis.append("destination not in whitelist")

    cat = str(row.get("Category", "Unknown"))
    if cat in ("Cloud Storage", "Paste", "Remote Access"):
        score += 10
        basis.append(f"category={cat}")

    action = str(row.get("Action", "") or "")
    if action in {"Upload", "Upload (TLS)", "File Transfer (Upload)"}:
        score += 20
        basis.append(f"action={action}")
    elif action in {"Share Link", "Paste/Share"}:
        score += 12
        basis.append(f"action={action}")
    elif action == "Post Data":
        score += 10
        basis.append("http post")

    if str(row.get("Client_Type", "")) == "Automation / SDK":
        score += 10
        basis.append("automation user-agent")

    # Prefer outbound bytes for flows
    bytes_out = float(row.get("bytes_out", row.get("bytes", 0)) or 0)
    bytes_in = float(row.get("bytes_in", 0) or 0)
    ratio = float(row.get("out_in_ratio", 0) or 0)

    if bytes_out >= 500 * 1024 * 1024:
        score += 35
        basis.append(">=500MB outbound")
    elif bytes_out >= 100 * 1024 * 1024:
        score += 25
        basis.append(">=100MB outbound")
    elif bytes_out >= 10 * 1024 * 1024:
        score += 12
        basis.append(">=10MB outbound")

    if bytes_out >= 10 * 1024 * 1024 and ratio >= 5 and not allowed:
        score += 10
        basis.append("high outbound ratio")

    file_bytes = float(row.get("file_total_bytes", 0) or 0)
    if file_bytes >= 10 * 1024 * 1024:
        score += 10
        basis.append("files.log >=10MB")

    # If HTTP request body is large, treat as stronger upload evidence.
    req_body = float(row.get("request_body_len", 0) or 0)
    if req_body >= 10 * 1024 * 1024:
        score += 10
        basis.append("http request_body_len >=10MB")

    # DNS exfil heuristics (dns rows)
    dns_add = int(row.get("DNS_Exfil_Add", 0) or 0)
    if dns_add > 0:
        score += dns_add
        r = str(row.get("DNS_Exfil_Reason", "") or "")
        basis.append(f"dns exfil: {r}" if r else "dns exfil heuristic")

    score = int(min(100, score))
    if not basis:
        basis = ["baseline"]
    return score, "; ".join(basis)


def _detect_exfil_signal_row(row: pd.Series) -> Tuple[bool, str]:
    """
    Returns (is_exfil_signal, detection_basis) using explicit/strong indicators.
    """
    reasons: List[str] = []

    action = str(row.get("Action", "") or "")
    log_source = str(row.get("log_source", "") or "").lower()
    severity = str(row.get("Severity", "") or "").upper()
    dns_reason = str(row.get("DNS_Exfil_Reason", "") or "").strip()
    allowed = bool(row.get("Allowed", False))

    bytes_out = float(row.get("bytes_out", row.get("bytes", 0)) or 0)
    ratio = float(row.get("out_in_ratio", 0) or 0)
    file_bytes = float(row.get("file_total_bytes", 0) or 0)

    if action in {"Upload", "Upload (TLS)", "File Transfer (Upload)", "Share Link", "Paste/Share", "Post Data"}:
        reasons.append(f"action={action}")

    if dns_reason:
        reasons.append("dns exfil heuristic")

    if not allowed and bytes_out >= 10 * 1024 * 1024 and ratio >= 5:
        reasons.append(">=10MB outbound with high ratio")

    if not allowed and file_bytes >= 10 * 1024 * 1024:
        reasons.append("files.log >=10MB on unapproved dest")

    if not allowed and severity in {"CRITICAL", "HIGH"} and bytes_out >= 50 * 1024 * 1024:
        reasons.append("high-risk large outbound transfer")

    # TLS-only, still suspicious: large raw flow to unapproved destination
    if not allowed and log_source == "flow" and bytes_out >= 100 * 1024 * 1024:
        reasons.append("unapproved flow >=100MB outbound")

    if not reasons:
        return False, ""
    return True, "; ".join(reasons)


# -----------------------------------------------------------------------------
# Builders
# -----------------------------------------------------------------------------

def _destination_from_df(df: pd.DataFrame, log_source: str) -> pd.Series:
    def _first_vector_value(v: object) -> str:
        if isinstance(v, list):
            if not v:
                return ""
            v = v[0]
        try:
            if pd.isna(v):
                return ""
        except Exception:
            pass
        s = str(v).strip()
        if not s or s in {"nan", "None", "[]"}:
            return ""
        if s.startswith("[") and s.endswith("]"):
            s = s[1:-1].strip()
            if "," in s:
                s = s.split(",", 1)[0]
            s = s.strip().strip("'").strip('"').strip()
        return s

    ls = log_source.lower()
    if ls == "http":
        if "host" in df.columns:
            return df["host"].astype(str).fillna("")
        if "id.resp_h" in df.columns:
            return df["id.resp_h"].astype(str).fillna("")
        return pd.Series([""] * len(df))
    if ls == "ssl":
        if "server_name" in df.columns:
            return df["server_name"].astype(str).fillna("")
        return pd.Series([""] * len(df))
    if ls == "dns":
        if "query" in df.columns:
            return df["query"].astype(str).fillna("")
        return pd.Series([""] * len(df))
    if ls == "conn":
        h = df["id.resp_h"].astype(str).fillna("") if "id.resp_h" in df.columns else pd.Series([""] * len(df))
        p = df["id.resp_p"].astype(str).fillna("") if "id.resp_p" in df.columns else pd.Series([""] * len(df))
        out = (h + ":" + p).replace({":": ""})
        return out
    if ls == "files":
        for col in ["rx_hosts", "tx_hosts", "id.resp_h", "host", "server_name", "id.orig_h"]:
            if col not in df.columns:
                continue
            if col in {"rx_hosts", "tx_hosts"}:
                s = df[col].apply(_first_vector_value)
            else:
                s = df[col].astype(str).fillna("").str.strip()
            s = s.replace({"nan": "", "None": "", "[]": ""})
            if (s != "").any():
                return s
        return pd.Series([""] * len(df))
    return pd.Series([""] * len(df))


def _bytes_from_df(df: pd.DataFrame, log_source: str) -> pd.Series:
    ls = log_source.lower()
    if ls == "http":
        if "request_body_len" in df.columns:
            return pd.to_numeric(df["request_body_len"], errors="coerce").fillna(0)
        return pd.Series([0] * len(df))
    if ls == "conn":
        if "orig_ip_bytes" in df.columns:
            return pd.to_numeric(df["orig_ip_bytes"], errors="coerce").fillna(0)
        if "orig_bytes" in df.columns:
            return pd.to_numeric(df["orig_bytes"], errors="coerce").fillna(0)
        return pd.Series([0] * len(df))
    if ls == "files":
        if "total_bytes" in df.columns:
            return pd.to_numeric(df["total_bytes"], errors="coerce").fillna(0)
        if "seen_bytes" in df.columns:
            return pd.to_numeric(df["seen_bytes"], errors="coerce").fillna(0)
        return pd.Series([0] * len(df))
    return pd.Series([0] * len(df))


def _build_one_date(parquet_root: Path, date_str: str, known_files: List[Path]) -> pd.DataFrame:
    """
    Build one day's shadow-sharing dataset.

    New approach:
      - Use conn.log as the primary table (one row per uid / flow)
      - Correlate ssl/http/files onto conn via uid (and files.conn_uids)
      - Use dns.answers->query as a fallback naming source when http.host / ssl.server_name are missing
      - Keep dns.log rows separately for DNS exfil heuristics (tunneling / b64-like labels)
    """
    date_dir = Path(parquet_root) / date_str
    buckets = _collect_date_files(date_dir)

    files_sig = {
        "http": _file_signature(buckets["http"]),
        "ssl": _file_signature(buckets["ssl"]),
        "dns": _file_signature(buckets["dns"]),
        "conn": _file_signature(buckets["conn"]),
        "files": _file_signature(buckets["files"]),
        "dhcp": _file_signature(buckets["dhcp"]),
        "known": _file_signature(known_files),
    }

    cpath = cache_events_path(parquet_root, date_str)
    mpath = cache_meta_path(parquet_root, date_str)

    expected = _meta_expected(files_sig, WHITELIST_MTIME_NS)
    meta = read_yaml(mpath)

    if cpath.exists() and meta == expected:
        try:
            df_cached = pd.read_parquet(cpath)
            if not df_cached.empty:
                df_cached = _ensure_ts_datetime(df_cached)
                return df_cached.sort_values("ts", ascending=False)
        except Exception:
            pass

    # identity maps
    ip_map, mac_map = _build_identity_maps(buckets["dhcp"], buckets["conn"], known_files)

    # read logs
    df_conn = _duck_read_parquet_union(buckets.get("conn") or [])
    df_ssl = _duck_read_parquet_union(buckets.get("ssl") or [])
    df_http = _duck_read_parquet_union(buckets.get("http") or [])
    df_files = _duck_read_parquet_union(buckets.get("files") or [])
    df_dns = _duck_read_parquet_union(buckets.get("dns") or [])

    # correlated flows
    dns_ip_map = _build_dns_ip_map(df_dns) if not df_dns.empty else {}
    ssl_by_uid = _build_ssl_by_uid(df_ssl) if not df_ssl.empty else pd.DataFrame()
    http_by_uid = _build_http_by_uid(df_http) if not df_http.empty else pd.DataFrame()
    files_by_uid = _build_files_by_uid(df_files) if not df_files.empty else pd.DataFrame()
    df_flow = _build_correlated_flows(df_conn, ssl_by_uid, http_by_uid, files_by_uid, dns_ip_map)

    # dns rows (kept for tunneling heuristics / supporting evidence)
    df_dns_events = pd.DataFrame()
    if not df_dns.empty:
        d = df_dns.copy()
        d = _ensure_ts_datetime(d)
        d = d.dropna(subset=["ts"])
        if "id.orig_h" not in d.columns:
            d["id.orig_h"] = ""
        else:
            d["id.orig_h"] = d["id.orig_h"].astype(str).str.strip()
        if "orig_l2_addr" not in d.columns:
            d["orig_l2_addr"] = None

        # destination = query
        if "query" not in d.columns:
            d["query"] = ""
        d["destination"] = d["query"].astype(str).fillna("").replace({"(empty)": "", "-": ""})
        d.loc[d["destination"].eq(""), "destination"] = "Unknown"
        d["bytes"] = 0
        d["log_source"] = "dns"
        d["method"] = ""
        d["uri"] = ""
        d["user_agent"] = ""
        d["content_type"] = ""
        d["Action"] = "DNS Lookup"
        d["Action_Basis"] = "dns query"
        keep = [
            "ts", "log_source", "id.orig_h", "destination", "bytes",
            "method", "uri", "user_agent", "content_type",
            "orig_l2_addr", "query", "answers", "rcode_name", "qtype_name",
            "Action", "Action_Basis",
        ]
        keep = [c for c in keep if c in d.columns]
        df_dns_events = d[keep].copy()

    frames: List[pd.DataFrame] = []
    if df_flow is not None and not df_flow.empty:
        frames.append(df_flow)
    if df_dns_events is not None and not df_dns_events.empty:
        frames.append(df_dns_events)

    if not frames:
        return pd.DataFrame()

    out = pd.concat(frames, ignore_index=True)
    out = _ensure_ts_datetime(out).sort_values("ts", ascending=False)

    # identity enrichment
    out = _enrich_identity(out, ip_map, mac_map)
    out["Identity_Confidence"] = out.apply(_identity_confidence, axis=1)

    # allowlist basis (destination host/domain)
    allowed_basis = out["destination"].apply(lambda d: _domain_in_allowlist(d, WHITELIST_DOMAINS))
    out["Allowed"] = allowed_basis.apply(lambda x: bool(x[0]))
    out["Allow_Basis"] = allowed_basis.apply(lambda x: str(x[1] or ""))

    # category
    out["Category"] = out["destination"].apply(_tag_category)

    # client type
    if "user_agent" not in out.columns:
        out["user_agent"] = ""
    out["Client_Type"] = out["user_agent"].apply(fingerprint_client)

    # Fill missing Action (mostly defensive)
    if "Action" not in out.columns:
        out["Action"] = ""
    if "Action_Basis" not in out.columns:
        out["Action_Basis"] = ""
    missing_action = out["Action"].astype(str).str.strip().eq("")
    if missing_action.any():
        tmp = out.loc[missing_action].apply(
            lambda r: _detect_action(
                str(r.get("log_source", "")),
                str(r.get("method", "")),
                str(r.get("uri", "")),
                str(r.get("user_agent", "")),
                str(r.get("destination", "")),
                str(r.get("content_type", "")),
            ),
            axis=1,
        )
        out.loc[missing_action, "Action"] = tmp.apply(lambda x: x[0])
        out.loc[missing_action, "Action_Basis"] = tmp.apply(lambda x: x[1])

    # DNS exfil heuristics (only on dns rows)
    out["DNS_Exfil_Add"] = 0
    out["DNS_Exfil_Reason"] = ""
    dns_mask = out["log_source"].astype(str).str.lower().eq("dns")
    if dns_mask.any():
        q_series = out.loc[dns_mask, "destination"].astype(str).fillna("")
        scores_reasons = q_series.apply(_dns_exfil_score)
        out.loc[dns_mask, "DNS_Exfil_Add"] = scores_reasons.apply(lambda x: int(x[0]))
        out.loc[dns_mask, "DNS_Exfil_Reason"] = scores_reasons.apply(lambda x: str(x[1] or ""))

    # risk score + severity + basis
    rs = out.apply(_risk_score_row, axis=1)
    out["Risk_Score"] = rs.apply(lambda x: int(x[0]))
    out["Risk_Basis"] = rs.apply(lambda x: str(x[1]))
    out["Severity"] = out["Risk_Score"].apply(_severity_label)

    # explicit exfil signal detector (used by Data Exfiltration Threats tab)
    ex = out.apply(_detect_exfil_signal_row, axis=1)
    out["Exfil_Indicator"] = ex.apply(lambda x: bool(x[0]))
    out["Exfil_Detection_Basis"] = ex.apply(lambda x: str(x[1]))

    # VirusTotal link for domain-like destinations; best-effort.
    vt_target = out["destination"].astype(str).apply(_registrable_domain_best_effort)
    vt_target = vt_target.where(vt_target.astype(str).str.len() > 0, out["destination"].astype(str))
    out["vt_link"] = "https://www.virustotal.com/gui/domain/" + vt_target.astype(str)

    # write cache
    try:
        cpath.parent.mkdir(parents=True, exist_ok=True)
        out.to_parquet(cpath, index=False)
        write_yaml(mpath, expected)
    except Exception:
        pass

    return out


@st.cache_data(show_spinner=False, ttl=300, max_entries=24)
def _load_shadow_sharing_data_cached(
    parquet_root_str: str,
    target_dates: Tuple[str, ...],
    cache_version: str,
    whitelist_mtime_ns: int,
) -> pd.DataFrame:
    # cache_version + whitelist_mtime_ns are explicit cache-busters.
    _ = cache_version
    _ = whitelist_mtime_ns

    parquet_root = Path(parquet_root_str)
    if not parquet_root.exists():
        return pd.DataFrame()

    known_files = _collect_known_files(parquet_root)

    frames: List[pd.DataFrame] = []
    for d in target_dates:
        if not d or not DATE_DIR_RE.match(str(d)):
            continue
        df_d = _build_one_date(parquet_root, str(d), known_files)
        if not df_d.empty:
            frames.append(df_d)

    if not frames:
        return pd.DataFrame()

    out = pd.concat(frames, ignore_index=True)
    out = _ensure_ts_datetime(out)
    return out.sort_values("ts", ascending=False)


def load_shadow_sharing_data(parquet_root: Path, target_dates: List[str]) -> pd.DataFrame:
    parquet_root = Path(parquet_root)
    dates_key = tuple(str(d) for d in (target_dates or []) if d and DATE_DIR_RE.match(str(d)))
    return _load_shadow_sharing_data_cached(
        str(parquet_root),
        dates_key,
        CACHE_VERSION,
        int(WHITELIST_MTIME_NS),
    )


def _is_dark_theme() -> bool:
    try:
        base = st.get_option("theme.base")
        if isinstance(base, str) and base.lower() in {"light", "dark"}:
            return base.lower() == "dark"
    except Exception:
        pass
    return True


def get_aggrid_theme_and_css():
    dark = _is_dark_theme()
    theme = "alpine-dark" if dark else "alpine"

    custom_css = {
        ".ag-root-wrapper": {"background-color": "#050B16", "color": "#EAEAEA", "border": "1px solid #22324E"},
        ".ag-header": {"background-color": "#0A1730", "color": "#EAF2FF", "border-bottom": "1px solid #29406A"},
        ".ag-header-cell, .ag-header-group-cell": {
            "background-color": "#0A1730",
            "color": "#EAF2FF",
            "border-right": "1px solid #20365A",
        },
        ".ag-header-cell-label": {"font-weight": "700", "letter-spacing": "0.02em"},
        ".ag-cell": {"background-color": "#050B16", "color": "#EAEAEA", "border-color": "#13233D"},
        ".ag-row": {"background-color": "#050B16"},
        ".ag-row-odd": {"background-color": "#071224"},
        ".ag-row-even": {"background-color": "#050E1D"},
        ".ag-row-hover": {"background-color": "#0F203D"},
        ".ag-row-selected": {"background-color": "#1E3A5F"},
        ".ag-floating-filter-body input": {
            "background-color": "#0A1730 !important",
            "color": "#EAEAEA !important",
            "border": "1px solid #32517F !important",
            "border-radius": "6px !important",
        },
        ".ag-paging-panel": {"background-color": "#050B16", "color": "#EAEAEA", "border-top": "1px solid #22324E"},
        ".ag-paging-row-summary-panel": {"background-color": "#050B16", "color": "#EAEAEA"},
        ".ag-paging-page-summary-panel": {"background-color": "#050B16", "color": "#EAEAEA"},
        ".ag-pagination": {"background-color": "#050B16", "color": "#EAEAEA"},
        ".ag-paging-page-size": {"background-color": "#0A1730 !important", "color": "#EAEAEA !important"},
        ".ag-paging-panel .ag-page-size": {
            "background-color": "#0A1730 !important",
            "color": "#EAEAEA !important",
            "border": "1px solid #2D456C !important",
            "outline": "none !important",
        },
        ".ag-paging-panel .ag-page-size option": {"background-color": "#0A1730 !important", "color": "#EAEAEA !important"},
        ".ag-paging-panel .ag-select, .ag-paging-panel .ag-picker-field-wrapper": {
            "background-color": "#0A1730 !important",
            "color": "#EAEAEA !important",
            "border": "1px solid #2D456C !important",
        },
        ".ag-paging-panel .ag-picker-field-display": {"background-color": "#0A1730 !important", "color": "#EAEAEA !important"},
    }
    return theme, custom_css


def get_plotly_template() -> str:
    return "plotly_dark" if _is_dark_theme() else "plotly_white"


def style_plotly_figure(fig, *, height: int = 360, show_legend: bool = True):
    fig.update_layout(
        template=get_plotly_template(),
        height=height,
        margin=dict(l=12, r=12, t=40, b=12),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        legend=dict(orientation="h", y=1.02, x=1.0, xanchor="right", yanchor="bottom"),
    )
    if not show_legend:
        fig.update_layout(showlegend=False)
    return fig


def _risk_score_cellstyle() -> JsCode:
    return JsCode(
        """
        function(params) {
            const v = Number(params.value || 0);
            if (v >= 80) return { 'color': '#ef4444', 'fontWeight': '900' };
            if (v >= 60) return { 'color': '#f97316', 'fontWeight': '900' };
            if (v >= 30) return { 'color': '#f59e0b', 'fontWeight': '800' };
            return { 'color': '#22c55e', 'fontWeight': '700' };
        }
        """
    )


def _severity_cellstyle() -> JsCode:
    return JsCode(
        """
        function(params) {
            const v = (params.value || '').toString().toUpperCase();
            if (v === 'CRITICAL') return { 'color': '#ef4444', 'fontWeight': '900' };
            if (v === 'HIGH') return { 'color': '#f97316', 'fontWeight': '900' };
            if (v === 'MEDIUM') return { 'color': '#f59e0b', 'fontWeight': '800' };
            if (v === 'LOW') return { 'color': '#22c55e', 'fontWeight': '700' };
            return {};
        }
        """
    )


def _allowed_cellstyle() -> JsCode:
    return JsCode(
        """
        function(params) {
            const v = params.value;
            const yes = (v === true) || (String(v).toLowerCase() === 'true');
            if (yes) return { 'color': '#22c55e', 'fontWeight': '700' };
            return { 'color': '#ef4444', 'fontWeight': '800' };
        }
        """
    )


def _link_cell_renderer() -> JsCode:
    return JsCode(
        """
        function(params) {
            if (!params.value) return '';
            return `<a href="${params.value}" target="_blank" style="color:#8AB4F8;text-decoration:underline;">Open</a>`;
        }
        """
    )


def render_shadow_aggrid(
    df: pd.DataFrame,
    gb: GridOptionsBuilder,
    *,
    key: str,
    height: int = 430,
    update_mode=GridUpdateMode.SELECTION_CHANGED,
):
    grid_options = gb.build()
    default_col_def = dict(grid_options.get("defaultColDef") or {})
    # Keep sorting available via column menu (three-dot menu).
    default_col_def["sortable"] = True
    default_col_def["filter"] = "agSetColumnFilter"
    default_col_def["floatingFilter"] = False
    default_col_def.setdefault("minWidth", 96)
    default_col_def["menuTabs"] = ["filterMenuTab", "generalMenuTab"]
    filter_params = dict(default_col_def.get("filterParams") or {})
    filter_params.setdefault("excelMode", "windows")
    filter_params.setdefault("buttons", ["apply", "clear", "cancel"])
    filter_params.setdefault("closeOnApply", True)
    filter_params.setdefault("suppressMiniFilter", False)
    default_col_def["filterParams"] = filter_params
    grid_options["defaultColDef"] = default_col_def
    grid_options["suppressMenuHide"] = False
    grid_options["enableCellTextSelection"] = True
    grid_options["ensureDomOrder"] = True
    grid_options["enableRtl"] = False
    grid_options["suppressColumnVirtualisation"] = True

    autofit_js = JsCode(
        """
        function(params) {
            setTimeout(function() {
                if (!params) return;
                if (params.columnApi) {
                    const cols = params.columnApi.getAllColumns ? params.columnApi.getAllColumns() : [];
                    const colIds = cols.map(function(c) { return c.getColId ? c.getColId() : c.colId; }).filter(Boolean);
                    if (colIds.length) {
                        try { params.columnApi.autoSizeColumns(colIds, false); } catch (e) {}
                    }
                }
            }, 0);
        }
        """
    )
    grid_options["onFirstDataRendered"] = autofit_js
    grid_options["onGridSizeChanged"] = autofit_js

    ag_theme, ag_css = get_aggrid_theme_and_css()
    table_css = dict(ag_css)
    table_css.update(
        {
            ".ag-root-wrapper": {"background-color": "#061120", "color": "#EAF2FF", "border": "1px solid #2A466E"},
            ".ag-header": {"background-color": "#10213E", "color": "#EAF2FF", "border-bottom": "1px solid #3A5A8E", "direction": "ltr !important"},
            ".ag-header-cell, .ag-header-group-cell": {
                "background-color": "#10213E",
                "color": "#EAF2FF",
                "border-right": "1px solid #2A466E",
                "direction": "ltr !important",
            },
            ".ag-header-cell-label": {"white-space": "nowrap"},
            ".ag-header-cell-label .ag-header-cell-text": {
                "white-space": "nowrap",
                "overflow": "hidden",
                "text-overflow": "ellipsis",
            },
            ".ag-row-odd": {"background-color": "#07162A"},
            ".ag-row-even": {"background-color": "#0A1C33"},
            ".ag-row-hover": {"background-color": "#13305A"},
            ".ag-row-selected": {"background-color": "#1B3F75"},
        }
    )

    st.markdown("<div class='shadow-table-shell'>", unsafe_allow_html=True)
    grid_response = AgGrid(
        df,
        gridOptions=grid_options,
        update_mode=update_mode,
        data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
        height=height,
        theme=ag_theme,
        custom_css=table_css,
        allow_unsafe_jscode=True,
        enable_enterprise_modules=True,
        fit_columns_on_grid_load=False,
        reload_data=True,
        key=key,
    )
    st.markdown("</div>", unsafe_allow_html=True)
    return grid_response


def inject_shadow_sharing_css():
    st.markdown(
        """
        <style>
        :root {
            --panel-border: rgba(255,255,255,0.12);
            --panel-bg: rgba(255,255,255,0.03);
        }

        .stApp {
            background:
                radial-gradient(1200px 550px at 10% -5%, rgba(0, 247, 255, 0.08), transparent 45%),
                radial-gradient(900px 460px at 90% 8%, rgba(246, 48, 73, 0.08), transparent 42%),
                #040B18;
        }

        .shadow-day-chip {
            border: 1px solid rgba(255,255,255,0.18);
            background: rgba(255,255,255,0.05);
            border-radius: 999px;
            padding: 7px 12px;
            margin-top: 1.72rem;
            font-size: 12px;
            font-weight: 700;
            line-height: 1.2;
            display: inline-flex;
            align-items: center;
        }

        .shadow-callout {
            border: 1px solid var(--panel-border);
            background: var(--panel-bg);
            border-radius: 10px;
            padding: 0.5rem 0.72rem;
            font-size: 0.84rem;
            margin-bottom: 0.45rem;
        }

        .shadow-filter-shell {
            border: 1px solid rgba(148, 163, 184, 0.28);
            background: linear-gradient(135deg, rgba(15,23,42,0.66), rgba(2,6,23,0.62));
            border-radius: 12px;
            padding: 0.72rem 0.85rem 0.55rem 0.85rem;
            margin-bottom: 0.45rem;
        }

        .shadow-filter-hint {
            font-size: 0.76rem;
            color: #9fb1c8;
            margin-top: 0.2rem;
            margin-bottom: 0.3rem;
        }

        .shadow-filter-shell [data-testid="stWidgetLabel"] p {
            font-size: 0.76rem;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            color: #bfd1ea;
            font-weight: 700;
        }

        .shadow-filter-shell [data-testid="stTextInput"] input,
        .shadow-filter-shell [data-testid="stTextArea"] textarea,
        .shadow-filter-shell [data-testid="stNumberInput"] input {
            background: rgba(8, 20, 40, 0.8) !important;
            border: 1px solid #35517d !important;
            color: #e5eefc !important;
        }

        .shadow-filter-shell [data-testid="stSelectbox"] div[data-baseweb="select"] > div,
        .shadow-filter-shell [data-testid="stMultiSelect"] div[data-baseweb="select"] > div {
            background: rgba(8, 20, 40, 0.8) !important;
            border: 1px solid #35517d !important;
            color: #e5eefc !important;
            min-height: 2.42rem;
        }

        .shadow-table-shell {
            border: 1px solid rgba(148, 163, 184, 0.24);
            background: linear-gradient(180deg, rgba(2,6,23,0.5), rgba(2,6,23,0.35));
            border-radius: 12px;
            padding: 0.56rem 0.62rem 0.46rem 0.62rem;
            margin-bottom: 0.75rem;
        }

        [data-testid="stMetric"] {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 12px;
            padding: 0.55rem 0.75rem;
            min-height: 125px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }

        [data-testid="stMetricLabel"] p {
            font-size: 0.75rem;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            font-weight: 600;
            min-height: 2.15em;
        }

        [data-testid="stMetricValue"] {
            line-height: 1.1;
            min-height: 2.5rem;
            display: flex;
            align-items: center;
        }

        [data-testid="stMetricDelta"] {
            min-height: 1.5rem;
        }

        .stTabs [data-baseweb="tab-list"] {
            gap: 0.45rem;
            margin-bottom: 0.35rem;
        }

        .stTabs [data-baseweb="tab"] {
            border: 1px solid var(--panel-border);
            border-radius: 999px;
            background: rgba(255,255,255,0.03);
            padding: 0.38rem 0.88rem;
            font-size: 0.86rem;
            height: auto;
        }

        .stTabs [data-baseweb="tab"][aria-selected="true"] {
            background: rgba(255,255,255,0.08);
            border-color: rgba(255,255,255,0.2);
            font-weight: 700;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

# -----------------------------------------------------------------------------
# UI
# -----------------------------------------------------------------------------


def _close_shadow_sharing_dialog() -> None:
    st.session_state["shadow_sharing_dialog_open"] = False
    st.session_state["shadow_sharing_dialog_mac"] = None
    st.session_state["shadow_sharing_last_selected_mac"] = None
    st.session_state.pop("shadow_sharing_dialog_base_df", None)
    st.session_state.pop("shadow_sharing_dialog_base_key", None)
    st.session_state["shadow_sharing_grid_nonce"] = int(st.session_state.get("shadow_sharing_grid_nonce", 0)) + 1


def _extract_selected_mac(selected_rows) -> Optional[str]:
    selected_mac = None
    if isinstance(selected_rows, pd.DataFrame):
        if not selected_rows.empty and "mac" in selected_rows.columns:
            selected_mac = selected_rows.iloc[0]["mac"]
    elif isinstance(selected_rows, list):
        if len(selected_rows) > 0 and isinstance(selected_rows[0], dict):
            selected_mac = selected_rows[0].get("mac")

    if selected_mac is None:
        return None

    selected_mac = str(selected_mac).strip().lower()
    if not selected_mac:
        return None
    return selected_mac


def _normalized_token_tuple(values, *, upper: bool = False) -> Tuple[str, ...]:
    items = values if isinstance(values, list) else []
    out: List[str] = []
    seen = set()
    for raw in items:
        s = str(raw).strip()
        if not s:
            continue
        s = s.upper() if upper else s.lower()
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    out.sort()
    return tuple(out)


def _build_text_search_blob(df: pd.DataFrame, columns: List[str]) -> pd.Series:
    if df.empty:
        return pd.Series([], index=df.index, dtype="object")
    cols = [c for c in columns if c in df.columns]
    if not cols:
        return pd.Series([""] * len(df), index=df.index, dtype="object")
    blob = df[cols[0]].astype(str).str.lower()
    for c in cols[1:]:
        blob = blob + " | " + df[c].astype(str).str.lower()
    return blob.fillna("")


@st.dialog("Device Forensics Details", width="large")
def show_shadow_sharing_device_dialog(
    filtered: pd.DataFrame,
    *,
    selected_scope_key: str,
):
    target_mac = str(st.session_state.get("shadow_sharing_dialog_mac") or "").strip().lower()
    if not target_mac:
        st.info("No MAC selected.")
        return

    mac_key = re.sub(r"[^0-9A-Za-z_]+", "_", target_mac).strip("_") or "mac"

    st.markdown(
        """
        <style>
        div[data-testid="stDialog"] > div[role="dialog"] {
            width: min(95vw, 1450px) !important;
            max-width: min(95vw, 1450px) !important;
            border: 1px solid rgba(148, 163, 184, 0.35);
            background: linear-gradient(180deg, rgba(3,10,23,0.96), rgba(2,8,20,0.97));
        }
        div[data-testid="stDialog"] div[role="dialog"] .stDialogContent {
            padding-left: 1.05rem !important;
            padding-right: 1.05rem !important;
            padding-bottom: 0.8rem !important;
        }
        div[data-testid="stDialog"] .shadow-dialog-hero {
            border: 1px solid rgba(148, 163, 184, 0.28);
            background: linear-gradient(135deg, rgba(15,23,42,0.66), rgba(2,6,23,0.62));
            border-radius: 12px;
            padding: 0.58rem 0.76rem;
            margin-bottom: 0.4rem;
        }
        div[data-testid="stDialog"] .shadow-dialog-title {
            color: #e7efff;
            font-weight: 800;
            letter-spacing: 0.02em;
            font-size: 1rem;
            line-height: 1.2;
        }
        div[data-testid="stDialog"] .shadow-dialog-subtitle {
            color: #b8cae6;
            font-size: 0.8rem;
            margin-top: 0.22rem;
        }
        div[data-testid="stDialog"] .shadow-dialog-subtitle code {
            border: 1px solid rgba(148, 163, 184, 0.3);
            background: rgba(8, 20, 40, 0.78);
            color: #dbeafe;
            border-radius: 999px;
            padding: 0.12rem 0.52rem;
        }
        div[data-testid="stDialog"] .shadow-dialog-chips {
            display: flex;
            flex-wrap: wrap;
            gap: 0.42rem;
            margin: 0.05rem 0 0.5rem 0;
        }
        div[data-testid="stDialog"] .shadow-dialog-chip {
            border: 1px solid rgba(148, 163, 184, 0.28);
            background: rgba(255,255,255,0.04);
            border-radius: 999px;
            padding: 0.21rem 0.58rem;
            font-size: 0.72rem;
            color: #c7d6eb;
            line-height: 1.1;
        }
        div[data-testid="stDialog"] .stTabs [data-baseweb="tab-list"] {
            gap: 0.42rem;
            margin-bottom: 0.4rem;
        }
        div[data-testid="stDialog"] .stTabs [data-baseweb="tab"] {
            border: 1px solid rgba(148, 163, 184, 0.3);
            background: rgba(255,255,255,0.03);
            border-radius: 999px;
            padding: 0.32rem 0.8rem;
            font-size: 0.82rem;
        }
        div[data-testid="stDialog"] .stTabs [data-baseweb="tab"][aria-selected="true"] {
            background: rgba(255,255,255,0.08);
            border-color: rgba(186, 207, 234, 0.42);
            font-weight: 700;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    if "mac" not in filtered.columns:
        st.warning("MAC column is not available in this dataset.")
        return

    dialog_base_key = f"{selected_scope_key}:{target_mac}:{len(filtered)}"
    cached_base = st.session_state.get("shadow_sharing_dialog_base_df")
    cached_base_key = st.session_state.get("shadow_sharing_dialog_base_key")

    if isinstance(cached_base, pd.DataFrame) and cached_base_key == dialog_base_key:
        scoped = cached_base.copy()
    else:
        mac_norm = filtered["mac"].astype(str).str.strip().str.lower()
        scoped = filtered.loc[mac_norm == target_mac].copy()
        scoped["mac"] = target_mac
        st.session_state["shadow_sharing_dialog_base_df"] = scoped.copy()
        st.session_state["shadow_sharing_dialog_base_key"] = dialog_base_key

    if scoped.empty:
        st.warning("No records found for this MAC with current page filters.")
        return

    scoped["mac"] = target_mac

    top = st.columns([1.0, 5.0])
    with top[0]:
        if st.button("Close", use_container_width=True, type="primary", key=f"shadow_sharing_dlg_close_{selected_scope_key}_{mac_key}"):
            _close_shadow_sharing_dialog()
            st.rerun()
    with top[1]:
        st.markdown(
            f"""
            <div class='shadow-dialog-hero'>
                <div class='shadow-dialog-title'>Device Forensics Drilldown</div>
                <div class='shadow-dialog-subtitle'>Scope locked to MAC <code>{target_mac}</code></div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div class='shadow-filter-shell'>", unsafe_allow_html=True)
    dlg_f1, dlg_f2 = st.columns([2.5, 1.0])
    with dlg_f1:
        dialog_search = st.text_input(
            "Search In Device Scope",
            placeholder="destination, IP, host, action, URI, risk basis...",
            key=f"shadow_sharing_dlg_search_{selected_scope_key}_{mac_key}",
        ).strip()
    with dlg_f2:
        row_options = [5000, 10000, 25000, 50000, 100000]
        default_rows = 10000 if len(scoped) > 10000 else next((n for n in row_options if len(scoped) <= n), row_options[-1])
        dialog_row_limit = st.selectbox(
            "Rows To Analyze",
            options=row_options,
            index=row_options.index(default_rows),
            key=f"shadow_sharing_dlg_rows_{selected_scope_key}_{mac_key}",
        )
    st.markdown("</div>", unsafe_allow_html=True)

    scoped_all = scoped.copy()
    if dialog_search:
        q = dialog_search.lower()
        search_cols = [
            "host_name",
            "id.orig_h",
            "destination",
            "log_source",
            "Category",
            "Action",
            "Allow_Basis",
            "Action_Basis",
            "Risk_Basis",
            "method",
            "uri",
            "DNS_Exfil_Reason",
        ]
        mask = pd.Series(False, index=scoped_all.index)
        for col in search_cols:
            if col in scoped_all.columns:
                mask = mask | scoped_all[col].astype(str).str.lower().str.contains(q, na=False)
        scoped_all = scoped_all[mask].copy()

    if scoped_all.empty:
        st.info("No records match your dialog search.")
        return

    scoped_ts = pd.to_datetime(scoped_all["ts"], errors="coerce")
    first_seen = scoped_ts.min()
    last_seen = scoped_ts.max()
    total_mb = float(scoped_all["bytes"].sum()) / 1024 / 1024
    unapproved = int((scoped_all["Allowed"] == False).sum())  # noqa: E712
    unique_dest = int(scoped_all["destination"].replace({"": None, "Unknown": None}).dropna().nunique())
    high_crit = int(scoped_all["Severity"].isin(["CRITICAL", "HIGH"]).sum())

    scoped = scoped_all.sort_values("ts", ascending=False).copy()
    matched_events = int(len(scoped))
    if len(scoped) > int(dialog_row_limit):
        scoped = scoped.head(int(dialog_row_limit)).copy()
        st.caption(f"Performance mode: loaded latest {len(scoped):,} of {matched_events:,} matched events.")
    else:
        st.caption(f"Loaded {len(scoped):,} matched events.")

    first_seen_txt = first_seen.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(first_seen) else "-"
    last_seen_txt = last_seen.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(last_seen) else "-"
    st.markdown(
        f"""
        <div class='shadow-dialog-chips'>
            <span class='shadow-dialog-chip'>First Seen: <strong>{first_seen_txt}</strong></span>
            <span class='shadow-dialog-chip'>Last Seen: <strong>{last_seen_txt}</strong></span>
            <span class='shadow-dialog-chip'>Unique Destinations: <strong>{unique_dest:,}</strong></span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    dm1, dm2, dm3, dm4 = st.columns(4)
    dm1.metric("Scoped Events", f"{len(scoped):,}")
    dm2.metric("Unapproved", unapproved, delta="Investigate" if unapproved > 0 else "Clear", delta_color="inverse")
    dm3.metric("Critical / High", f"{high_crit:,}", delta="High Risk" if high_crit > 0 else "None", delta_color="inverse")
    dm4.metric("Total Volume", f"{total_mb:.2f} MB")

    tab_dest, tab_bursts, tab_log = st.tabs(["By Destination", "Bursts", "Event Log"])

    with tab_dest:
        st.markdown("#### Destination Forensics")

        dest = scoped.groupby("destination", dropna=False).agg(
            Category=("Category", lambda x: x.value_counts().index[0] if len(x) else "Unknown"),
            Allow_Basis=("Allow_Basis", lambda x: next((v for v in x.astype(str) if v), "")),
            Last_Seen=("ts", "max"),
            Events=("ts", "count"),
            Unique_IPs=("id.orig_h", lambda x: x.astype(str).str.strip().replace({"": None, "nan": None, "None": None, "none": None, "-": None}).dropna().nunique()),
            Total_MB=("bytes", lambda x: float(x.sum()) / 1024 / 1024),
            Max_Risk=("Risk_Score", "max"),
            Top_Action=("Action", lambda x: x.value_counts().index[0] if len(x) else ""),
        ).reset_index().sort_values(["Max_Risk", "Total_MB", "Events"], ascending=False)

        dest_grid = dest.copy()
        dest_grid.insert(0, "#", range(1, len(dest_grid) + 1))
        dest_grid["Last_Seen"] = pd.to_datetime(dest_grid["Last_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M").fillna("")
        dest_grid["Total_MB"] = pd.to_numeric(dest_grid["Total_MB"], errors="coerce").fillna(0).round(2)
        dest_grid["Max_Risk"] = pd.to_numeric(dest_grid["Max_Risk"], errors="coerce").fillna(0).astype(int)
        dest_grid["Max_Risk_Level"] = dest_grid["Max_Risk"].apply(_severity_label)
        dest_grid = dest_grid.drop(columns=["Max_Risk"])

        gb_dest = GridOptionsBuilder.from_dataframe(dest_grid)
        gb_dest.configure_default_column(filter=True, sortable=True, resizable=True, flex=1)
        gb_dest.configure_pagination(paginationAutoPageSize=False, paginationPageSize=15)
        gb_dest.configure_column("#", header_name="#", width=62, pinned="left", suppressMovable=True, resizable=False)
        gb_dest.configure_column("destination", header_name="Destination", minWidth=200)
        gb_dest.configure_column("Category", width=130)
        gb_dest.configure_column("Allow_Basis", header_name="Allow Basis", minWidth=210)
        gb_dest.configure_column("Last_Seen", header_name="Last Seen", width=150)
        gb_dest.configure_column("Events", width=88)
        gb_dest.configure_column("Unique_IPs", header_name="IPs", width=90)
        gb_dest.configure_column("Total_MB", header_name="Total MB", width=116)
        gb_dest.configure_column("Max_Risk_Level", header_name="Risk Level", width=130, cellStyle=_severity_cellstyle())
        gb_dest.configure_column("Top_Action", header_name="Top Action", minWidth=145)

        render_shadow_aggrid(
            dest_grid,
            gb_dest,
            key=f"shadow_sharing_dest_grid_{selected_scope_key}_{mac_key}",
            height=430,
            update_mode=GridUpdateMode.NO_UPDATE,
        )

        st.markdown("#### Authorize Destination (allowlist)")

        # Only offer domains/hosts (not IPs) that are currently unapproved in this scope.
        cand = dest.copy()
        cand["Allow_Basis"] = cand["Allow_Basis"].astype(str).fillna("")
        cand = cand[cand["Allow_Basis"].eq("")]
        cand = cand[~cand["destination"].astype(str).apply(lambda x: _is_ip_literal(_normalize_host(x)))]
        cand = cand[~cand["destination"].astype(str).str.lower().isin(["unknown", "nan", "none", ""])]

        candidates = cand["destination"].astype(str).dropna().unique().tolist()
        candidates = sorted(candidates)[:200]

        if not candidates:
            st.caption("No unapproved domain-like destinations detected for this device in the selected scope.")
        else:
            sel_domain = st.selectbox("Select a destination to add to the whitelist", candidates, key=f"shadow_sharing_auth_select_{selected_scope_key}_{mac_key}")
            is_admin = _is_admin_user()

            if not is_admin:
                st.caption("Admin-only action: set st.session_state['is_admin']=True or st.session_state['user_role']='admin' in your auth layer.")
            if st.button("Authorize selected destination", key=f"shadow_sharing_auth_btn_{selected_scope_key}_{mac_key}", disabled=not is_admin):
                ok, msg = _add_domain_to_whitelist(sel_domain)
                if ok:
                    st.success(msg)
                    st.cache_data.clear()
                    st.rerun()
                else:
                    st.error(msg)


    with tab_bursts:
        st.markdown("#### Burst Detection (5-minute windows)")
        b = scoped.copy()
        b["bucket"] = b["ts"].dt.floor("5min")
        b["mac"] = target_mac
        b["bytes"] = pd.to_numeric(b["bytes"], errors="coerce").fillna(0)
        if "destination" not in b.columns:
            b["destination"] = "Unknown"
        b["destination"] = b["destination"].astype(str).replace({"": "Unknown", "nan": "Unknown", "None": "Unknown"}).fillna("Unknown")

        top_app = (
            b.groupby(["bucket", "mac", "destination"], dropna=False)["bytes"]
            .sum()
            .reset_index(name="top_app_bytes")
            .sort_values(["bucket", "mac", "top_app_bytes", "destination"], ascending=[True, True, False, True])
            .drop_duplicates(["bucket", "mac"], keep="first")
            .rename(columns={"destination": "top_application"})
        )

        bursts = b.groupby(["bucket", "mac"], dropna=False).agg(
            bytes=("bytes", "sum"),
            events=("ts", "count"),
            max_risk=("Risk_Score", "max"),
            host=("host_name", lambda x: next((v for v in x.astype(str) if v), "")),
        ).reset_index()
        bursts = bursts.merge(top_app, on=["bucket", "mac"], how="left")
        bursts["top_application"] = bursts["top_application"].fillna("Unknown").astype(str)
        bursts["top_app_bytes"] = pd.to_numeric(bursts["top_app_bytes"], errors="coerce").fillna(0).astype(int)

        top_bursts = bursts.sort_values(["max_risk", "bytes", "events"], ascending=False).head(200)

        if top_bursts.empty:
            st.info("No burst windows for this MAC.")
        else:
            fig = px.scatter(
                top_bursts,
                x="bucket",
                y="mac",
                size="bytes",
                color="max_risk",
                hover_data=["host", "events", "top_application", "top_app_bytes"],
                template=get_plotly_template(),
                render_mode="webgl" if len(top_bursts) > 2000 else "auto",
                title="Top bursts (size=bytes, color=max risk)",
            )
            style_plotly_figure(fig, height=395, show_legend=False)
            st.plotly_chart(fig, use_container_width=True)

            burst_grid = top_bursts.copy()
            burst_grid.insert(0, "#", range(1, len(burst_grid) + 1))
            burst_grid["bucket"] = pd.to_datetime(burst_grid["bucket"], errors="coerce").dt.strftime("%m-%d %H:%M").fillna("")
            burst_grid["bytes"] = pd.to_numeric(burst_grid["bytes"], errors="coerce").fillna(0).astype(int)
            burst_grid["max_risk"] = pd.to_numeric(burst_grid["max_risk"], errors="coerce").fillna(0).astype(int)
            burst_grid["top_app_bytes"] = pd.to_numeric(burst_grid["top_app_bytes"], errors="coerce").fillna(0).astype(int)
            burst_grid["max_risk_level"] = burst_grid["max_risk"].apply(_severity_label)
            burst_grid = burst_grid.drop(columns=["max_risk"])

            gb_burst = GridOptionsBuilder.from_dataframe(burst_grid)
            gb_burst.configure_default_column(filter=True, sortable=True, resizable=True, flex=1)
            gb_burst.configure_pagination(paginationAutoPageSize=False, paginationPageSize=20)
            gb_burst.configure_column("#", header_name="#", width=62, pinned="left", suppressMovable=True, resizable=False)
            gb_burst.configure_column("bucket", header_name="Window", width=150)
            gb_burst.configure_column("mac", header_name="MAC", minWidth=150)
            gb_burst.configure_column("host", header_name="Host", minWidth=160)
            gb_burst.configure_column("top_application", header_name="Top Application / Software", minWidth=220)
            gb_burst.configure_column("top_app_bytes", header_name="Top App Bytes", width=140)
            gb_burst.configure_column("events", header_name="Events", width=90)
            gb_burst.configure_column("bytes", header_name="Bytes", width=130)
            gb_burst.configure_column("max_risk_level", header_name="Max Risk Level", width=130, cellStyle=_severity_cellstyle())

            render_shadow_aggrid(
                burst_grid,
                gb_burst,
                key=f"shadow_sharing_burst_grid_{selected_scope_key}_{mac_key}",
                height=430,
                update_mode=GridUpdateMode.NO_UPDATE,
            )

    with tab_log:
        head, btn = st.columns([4, 1])
        with head:
            st.markdown("#### Detailed Event Log (export-ready)")
        with btn:
            csv_data = scoped.to_csv(index=False).encode("utf-8")
            st.download_button("Export CSV", csv_data, f"shadow_sharing_log_{mac_key}.csv", "text/csv")

        st.markdown(
            f"<div class='shadow-filter-hint'>Showing up to <strong>{MAX_ROWS_DISPLAY:,}</strong> rows from <strong>{len(scoped):,}</strong> loaded events (<strong>{matched_events:,}</strong> matched) for <strong>{target_mac}</strong>.</div>",
            unsafe_allow_html=True,
        )

        cols = [
            "ts", "host_name", "mac", "Identity_Confidence", "id.orig_h",
            "destination", "vt_link",
            "Allow_Basis",
            "Category", "Action", "Action_Basis",
            "bytes",
            "Client_Type",
            "Risk_Score", "Severity", "Risk_Basis",
            "log_source",
            "method", "uri",
            "DNS_Exfil_Add", "DNS_Exfil_Reason",
        ]

        log_src = scoped.copy()
        for c in cols:
            if c not in log_src.columns:
                log_src[c] = ""

        view = log_src[cols].copy()
        log_grid = view.head(MAX_ROWS_DISPLAY).copy()
        log_grid.insert(0, "#", range(1, len(log_grid) + 1))
        log_grid["ts"] = pd.to_datetime(log_grid["ts"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
        log_grid["bytes"] = pd.to_numeric(log_grid["bytes"], errors="coerce").fillna(0).astype(int)
        log_grid["Risk_Score"] = pd.to_numeric(log_grid["Risk_Score"], errors="coerce").fillna(0).astype(int)

        gb_log = GridOptionsBuilder.from_dataframe(log_grid)
        gb_log.configure_default_column(filter=True, sortable=True, resizable=True, flex=1)
        gb_log.configure_pagination(paginationAutoPageSize=False, paginationPageSize=20)
        gb_log.configure_column("#", header_name="#", width=62, pinned="left", suppressMovable=True, resizable=False)
        gb_log.configure_column("ts", header_name="Time", minWidth=150, flex=1.1)
        gb_log.configure_column("host_name", header_name="Host", minWidth=140, flex=1.2)
        gb_log.configure_column("mac", header_name="MAC", minWidth=145, flex=1.15)
        gb_log.configure_column("Identity_Confidence", header_name="Identity", minWidth=120, flex=1.0)
        gb_log.configure_column("id.orig_h", header_name="IP", minWidth=125, flex=1.0)
        gb_log.configure_column("destination", header_name="Destination", minWidth=180, flex=1.6)
        gb_log.configure_column("vt_link", header_name="VirusTotal", minWidth=105, flex=0.9, cellRenderer=_link_cell_renderer())
        gb_log.configure_column("Allow_Basis", header_name="Allow Basis", minWidth=200, flex=1.8)
        gb_log.configure_column("Category", minWidth=120, flex=1.0)
        gb_log.configure_column("Action", minWidth=130, flex=1.1)
        gb_log.configure_column("bytes", header_name="Bytes", minWidth=110, flex=1.0)
        gb_log.configure_column("Client_Type", header_name="Client", minWidth=120, flex=1.0)
        gb_log.configure_column("Risk_Score", header_name="Risk Score", minWidth=95, flex=0.85, cellStyle=_risk_score_cellstyle())
        gb_log.configure_column("Severity", header_name="Risk Level", minWidth=105, flex=0.95, cellStyle=_severity_cellstyle())
        gb_log.configure_column("log_source", header_name="Source", minWidth=95, flex=0.9)
        gb_log.configure_column("method", header_name="Method", minWidth=90, flex=0.9)
        gb_log.configure_column("uri", header_name="URI", minWidth=220, flex=2.0)
        gb_log.configure_column("Risk_Basis", header_name="Risk Basis", minWidth=220, flex=2.0)
        gb_log.configure_column("Action_Basis", header_name="Action Basis", minWidth=210, flex=1.9)
        gb_log.configure_column("DNS_Exfil_Reason", header_name="DNS Exfil Reason", minWidth=220, flex=2.0)

        render_shadow_aggrid(
            log_grid,
            gb_log,
            key=f"shadow_sharing_log_grid_{selected_scope_key}_{mac_key}",
            height=520,
            update_mode=GridUpdateMode.NO_UPDATE,
        )


def render_shadow_sharing(parquet_root: Path):
    inject_shadow_sharing_css()

    parquet_root = Path(parquet_root)
    if not parquet_root.exists():
        st.error("Data directory not found.")
        return

    available_dates = get_available_dates(parquet_root)
    if not available_dates:
        st.warning("No logs found.")
        return

    def _on_scope_change():
        _close_shadow_sharing_dialog()

    selected_date = st.selectbox(
        "Dataset Scope",
        available_dates,
        index=0,
        key="shadow_sharing_date",
        on_change=_on_scope_change,
    )
    selected_scope_key = re.sub(r"[^A-Za-z0-9_]+", "_", str(selected_date))
    st.session_state.setdefault("shadow_sharing_dialog_open", False)
    st.session_state.setdefault("shadow_sharing_dialog_mac", None)
    st.session_state.setdefault("shadow_sharing_last_selected_mac", None)
    st.session_state.setdefault("shadow_sharing_dialog_base_df", None)
    st.session_state.setdefault("shadow_sharing_dialog_base_key", None)
    st.session_state.setdefault("shadow_sharing_grid_nonce", 0)
    st.session_state.setdefault("shadow_sharing_threat_base_df", None)
    st.session_state.setdefault("shadow_sharing_threat_cache_key", None)
    st.session_state.setdefault("shadow_sharing_threat_summary", None)

    search_q = st.text_input("Search (MAC, Host, IP, Destination, Basis)", placeholder="e.g., 192.168.1.14",)

    c1, c2, c3 = st.columns([1.8, 1.4, 1.2])
    with c1:
        action_filter = st.multiselect(
            "Action",
            ["Upload", "Post Data", "Paste/Share", "File Transfer", "Remote Access", "Automated Access", "Browse", "Encrypted Access", "Raw Connection", "DNS Lookup"],
            default=[],
            placeholder="All actions",
        )
    with c2:
        category_filter = st.multiselect(
            "Category",
            ["Cloud Storage", "Paste", "Messaging", "Code Repo", "Remote Access", "Unknown"],
            default=[],
            placeholder="All categories",
        )
    with c3:
        min_bytes_mb = st.number_input("Min Bytes (MB)", min_value=0, value=0, step=10)

    c4, c5 = st.columns([1.55, 2.0])
    with c4:
        selected_risk_levels = st.multiselect("Risk Level", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with c5:
        selected_sources = st.multiselect("Source Logs", ["http", "ssl", "dns", "conn", "files"], default=["http", "ssl", "dns", "files"])

    # Date scope
    target_dates = [selected_date] if selected_date else []

    df = load_shadow_sharing_data(parquet_root, target_dates)

    if df.empty:
        st.info("No data detected for the selected timeframe.")
        return

    # Apply filters
    filtered = df.copy()

    if selected_sources:
        filtered = filtered[filtered["log_source"].isin(selected_sources)]

    if selected_risk_levels:
        filtered = filtered[filtered["Severity"].isin(selected_risk_levels)]

    if min_bytes_mb > 0:
        filtered = filtered[filtered["bytes"] >= float(min_bytes_mb) * 1024 * 1024]

    if action_filter:
        filtered = filtered[filtered["Action"].isin(action_filter)]

    if category_filter:
        filtered = filtered[filtered["Category"].isin(category_filter)]

    if search_q:
        q = search_q.lower().strip()
        if q:
            filtered = filtered[
                filtered["mac"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                | filtered["host_name"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                | filtered["id.orig_h"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                | filtered["destination"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                | filtered["Risk_Basis"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                | filtered["Action_Basis"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                | filtered["Allow_Basis"].astype(str).str.lower().str.contains(q, na=False, regex=False)
            ]

    if filtered.empty:
        st.warning("No data matches your filters.")
        return

    main_filter_cache_key = (
        selected_scope_key,
        _normalized_token_tuple(selected_sources),
        _normalized_token_tuple(selected_risk_levels, upper=True),
        int(min_bytes_mb),
        _normalized_token_tuple(action_filter),
        _normalized_token_tuple(category_filter),
        str(search_q or "").strip().lower(),
        int(len(filtered)),
    )

    # Metrics
    st.divider()
    m1, m2, m3, m4, m5 = st.columns(5)

    total_b = float(filtered["bytes"].sum())
    total_mb = total_b / 1024 / 1024
    unapproved = int((filtered["Allowed"] == False).sum())  # noqa: E712
    critical = int((filtered["Severity"] == "CRITICAL").sum())
    autom = int((filtered["Client_Type"] == "Automation / SDK").sum())

    metric_mac = filtered["mac"].astype(str).str.strip().str.lower().replace({"nan": "", "none": "", "-": ""})
    metric_ip = filtered["id.orig_h"].astype(str).str.strip().replace({"nan": "", "None": "", "none": "", "-": ""})
    metric_device = metric_mac.where(metric_mac != "", "ip:" + metric_ip)
    metric_device = metric_device.where(metric_device != "ip:", None)
    uniq_dev = int(metric_device.dropna().nunique())

    m1.metric("Selected Events", f"{len(filtered):,}")
    m2.metric("Unapproved Events", unapproved, delta="Risk" if unapproved > 0 else "Clear", delta_color="inverse")
    m3.metric("Total Volume", f"{total_mb:.2f} MB")
    m4.metric("Critical", critical, delta="Investigate" if critical > 0 else "Clear", delta_color="inverse")
    m5.metric("Automation / SDK", f"{autom:,}")
    st.markdown(
        f"<div class='shadow-filter-hint'>Unique devices in scope: <strong>{uniq_dev:,}</strong></div>",
        unsafe_allow_html=True,
    )

    # Tabs (main page)
    tab_overview, tab_device, tab_threat = st.tabs(["Overview", "By Device", "Data Exfiltration Threats"])

    # -------------------------------------------------------------------------
    # Overview
    # -------------------------------------------------------------------------
    with tab_overview:
        left, right = st.columns([1.1, 1.1])

        with left:
            st.markdown("#### Category Breakdown (bytes)")
            cat_df = filtered.groupby("Category", dropna=False).agg(bytes=("bytes", "sum"), events=("ts", "count")).reset_index()
            fig_cat = px.bar(
                cat_df.sort_values("bytes", ascending=False),
                x="Category",
                y="bytes",
                hover_data=["events"],
                color="Category",
                color_discrete_sequence=px.colors.qualitative.Bold,
                template=get_plotly_template(),
            )
            style_plotly_figure(fig_cat, height=345, show_legend=False)
            fig_cat.update_yaxes(title="Bytes")
            st.plotly_chart(fig_cat, use_container_width=True)

        with right:
            st.markdown("#### Action Breakdown (events)")
            act_df = filtered.groupby("Action", dropna=False).agg(events=("ts", "count"), bytes=("bytes", "sum")).reset_index()
            fig_act = px.bar(
                act_df.sort_values("events", ascending=False),
                x="Action",
                y="events",
                hover_data=["bytes"],
                color="Action",
                color_discrete_sequence=px.colors.qualitative.Prism,
                template=get_plotly_template(),
            )
            style_plotly_figure(fig_act, height=345, show_legend=False)
            fig_act.update_yaxes(title="Events")
            st.plotly_chart(fig_act, use_container_width=True)

        st.markdown("#### Timeline (Risk Trend)")
        if len(filtered) >= 8000:
            bucket = "1h"
        elif len(filtered) >= 2500:
            bucket = "30min"
        else:
            bucket = "15min"

        trend_src = filtered.copy()
        trend_src["time_bucket"] = trend_src["ts"].dt.floor(bucket)
        risk_timeline = (
            trend_src.groupby(["time_bucket", "Severity"], dropna=False)
            .agg(events=("ts", "count"), avg_risk=("Risk_Score", "mean"))
            .reset_index()
            .sort_values("time_bucket")
        )
        risk_timeline["Severity"] = pd.Categorical(
            risk_timeline["Severity"],
            categories=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            ordered=True,
        )

        tl_left, tl_right = st.columns([1.55, 1.0])
        with tl_left:
            fig_timeline = px.area(
                risk_timeline,
                x="time_bucket",
                y="events",
                color="Severity",
                color_discrete_map=SEVERITY_COLORS,
                category_orders={"Severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                template=get_plotly_template(),
                hover_data={"events": True, "avg_risk": ":.1f"},
            )
            style_plotly_figure(fig_timeline, height=395)
            fig_timeline.update_layout(legend_title_text="Risk Level")
            fig_timeline.update_xaxes(title=f"Time ({bucket} buckets)")
            fig_timeline.update_yaxes(title="Events")
            st.plotly_chart(fig_timeline, use_container_width=True)

        with tl_right:
            risk_line = (
                trend_src.groupby("time_bucket", dropna=False)
                .agg(avg_risk=("Risk_Score", "mean"), high_crit=("Severity", lambda s: int(s.isin(["CRITICAL", "HIGH"]).sum())))
                .reset_index()
                .sort_values("time_bucket")
            )
            fig_risk = px.line(
                risk_line,
                x="time_bucket",
                y=["avg_risk", "high_crit"],
                template=get_plotly_template(),
                markers=True,
            )
            style_plotly_figure(fig_risk, height=395)
            fig_risk.update_traces(line=dict(width=2.5))
            fig_risk.update_layout(legend_title_text=None)
            fig_risk.update_xaxes(title="Time")
            fig_risk.update_yaxes(title="Trend")
            st.plotly_chart(fig_risk, use_container_width=True)

    # -------------------------------------------------------------------------
    # By Device
    # -------------------------------------------------------------------------
    with tab_device:
        st.markdown("#### Device Forensics (MAC preferred)")
        st.markdown(
            "<div class='shadow-callout'>Click a MAC row to open Destination, Bursts, and Event Log for that specific MAC only.</div>",
            unsafe_allow_html=True,
        )

        def _first_valid_mac(vals: pd.Series) -> str:
            for raw in vals.astype(str):
                v = raw.strip().lower()
                if v and v not in {"nan", "none"} and v != "-":
                    return v
            return ""

        def _first_valid_ip(vals: pd.Series) -> str:
            for raw in vals.astype(str):
                v = raw.strip()
                if v and v.lower() not in {"nan", "none"} and v != "-":
                    return v
            return ""

        def _first_device_name(vals: pd.Series) -> str:
            for raw in vals.astype(str):
                v = raw.strip()
                if v and v.lower() not in {"nan", "none", "unknown"} and v != "-" and not _is_ip_literal(v):
                    return v
            return "Unknown"

        dev_src = filtered.copy()
        dev_src["__mac"] = dev_src["mac"].astype(str).str.strip().str.lower().replace({"nan": "", "none": "", "-": ""})
        dev_src["__ip"] = dev_src["id.orig_h"].astype(str).str.strip().replace({"nan": "", "None": "", "none": "", "-": ""})
        dev_src = dev_src[(dev_src["__mac"] != "") | (dev_src["__ip"] != "")].copy()

        if dev_src.empty:
            st.info("No identifiable MAC/IP rows are available in this scope.")
            st.session_state["shadow_sharing_last_selected_mac"] = None
        else:
            dev_src["bytes"] = pd.to_numeric(dev_src["bytes"], errors="coerce").fillna(0)
            dev_src["Risk_Score"] = pd.to_numeric(dev_src["Risk_Score"], errors="coerce").fillna(0)
            dev_src["__device_key"] = dev_src["__mac"].where(dev_src["__mac"] != "", "ip:" + dev_src["__ip"])

            top_dest = (
                dev_src.groupby(["__device_key", "destination"], dropna=False)
                .agg(
                    dest_events=("ts", "count"),
                    dest_bytes=("bytes", "sum"),
                    Top_Dest_Max_Risk=("Risk_Score", "max"),
                )
                .reset_index()
                .sort_values(
                    ["__device_key", "dest_events", "dest_bytes", "Top_Dest_Max_Risk", "destination"],
                    ascending=[True, False, False, False, True],
                )
                .drop_duplicates("__device_key", keep="first")
                .rename(columns={"destination": "Top_Dest"})
            )

            dev = dev_src.groupby("__device_key", dropna=False).agg(
                mac=("__mac", _first_valid_mac),
                IP=("__ip", _first_valid_ip),
                Hostname=("host_name", _first_device_name),
                Last_Seen=("ts", "max"),
                Events=("ts", "count"),
                Unapproved=("Allowed", lambda x: int((x == False).sum())),  # noqa: E712
                Total_MB=("bytes", lambda x: float(x.sum()) / 1024 / 1024),
                Top_Action=("Action", lambda x: x.value_counts().index[0] if len(x) else ""),
                Max_Risk=("Risk_Score", "max"),
            ).reset_index()

            dev = dev.merge(top_dest[["__device_key", "Top_Dest", "Top_Dest_Max_Risk"]], on="__device_key", how="left")
            dev["Top_Dest"] = dev["Top_Dest"].astype(str).replace({"nan": "Unknown", "None": "Unknown"}).fillna("Unknown")
            dev["Top_Dest_Max_Risk"] = pd.to_numeric(dev["Top_Dest_Max_Risk"], errors="coerce").fillna(0).astype(int)
            dev = dev.sort_values(["Max_Risk", "Total_MB", "Events"], ascending=False).drop(columns=["__device_key"])

            dev_grid = dev.copy()
            dev_grid.insert(0, "#", range(1, len(dev_grid) + 1))
            dev_grid["Last_Seen"] = pd.to_datetime(dev_grid["Last_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M").fillna("")
            dev_grid["Total_MB"] = pd.to_numeric(dev_grid["Total_MB"], errors="coerce").fillna(0).round(2)
            dev_grid["Max_Risk"] = pd.to_numeric(dev_grid["Max_Risk"], errors="coerce").fillna(0).astype(int)
            dev_grid["Top_Dest_Max_Risk"] = pd.to_numeric(dev_grid["Top_Dest_Max_Risk"], errors="coerce").fillna(0).astype(int)
            dev_grid["Max_Risk_Level"] = dev_grid["Max_Risk"].apply(_severity_label)
            dev_grid["Top_Dest_Risk_Level"] = dev_grid["Top_Dest_Max_Risk"].apply(_severity_label)
            dev_grid = dev_grid.drop(columns=["Max_Risk"])
            dev_grid = dev_grid.drop(columns=["Top_Dest_Max_Risk"])

            gb_dev = GridOptionsBuilder.from_dataframe(dev_grid)
            gb_dev.configure_default_column(filter=True, sortable=True, resizable=True, flex=1)
            gb_dev.configure_pagination(paginationAutoPageSize=False, paginationPageSize=15)
            gb_dev.configure_selection(selection_mode="single", use_checkbox=False)
            gb_dev.configure_column("#", header_name="#", width=62, pinned="left", suppressMovable=True, resizable=False)
            clickable_mac_style = JsCode(
                """
                function(params) {
                    const v = String(params.value || '').trim();
                    if (!v) return { 'color': '#93A6BF' };
                    return {
                        'color': '#8AB4F8',
                        'fontWeight': '700',
                        'cursor': 'pointer',
                        'textDecoration': 'underline'
                    };
                }
                """
            )
            gb_dev.configure_column("mac", header_name="MAC (Click)", minWidth=160, cellStyle=clickable_mac_style)
            gb_dev.configure_column("IP", header_name="IP", minWidth=140)
            gb_dev.configure_column("Hostname", minWidth=170)
            gb_dev.configure_column("Last_Seen", header_name="Last Seen", width=150)
            gb_dev.configure_column("Events", width=90)
            gb_dev.configure_column("Unapproved", width=108)
            gb_dev.configure_column("Total_MB", header_name="Total MB", width=116)
            gb_dev.configure_column("Top_Action", header_name="Top Action", minWidth=145)
            gb_dev.configure_column("Top_Dest", header_name="Top Destination", minWidth=180)
            gb_dev.configure_column("Top_Dest_Risk_Level", header_name="Top Dest Risk Level", width=150, cellStyle=_severity_cellstyle())
            gb_dev.configure_column("Max_Risk_Level", header_name="Device Max Risk Level", width=170, cellStyle=_severity_cellstyle())

            dev_response = render_shadow_aggrid(
                dev_grid,
                gb_dev,
                key=f"shadow_sharing_device_grid_{selected_scope_key}_{int(st.session_state.get('shadow_sharing_grid_nonce', 0))}",
                height=430,
            )

            selected_mac = _extract_selected_mac(dev_response.get("selected_rows", None))
            if selected_mac:
                prev = st.session_state.get("shadow_sharing_last_selected_mac")
                if selected_mac != prev:
                    mac_norm = filtered["mac"].astype(str).str.strip().str.lower()
                    dialog_base = filtered.loc[mac_norm == selected_mac].copy()
                    dialog_base["mac"] = selected_mac
                    st.session_state["shadow_sharing_dialog_base_df"] = dialog_base
                    st.session_state["shadow_sharing_dialog_base_key"] = f"{selected_scope_key}:{selected_mac}:{len(filtered)}"
                    st.session_state["shadow_sharing_last_selected_mac"] = selected_mac
                    st.session_state["shadow_sharing_dialog_mac"] = selected_mac
                    st.session_state["shadow_sharing_dialog_open"] = True
                    st.rerun()
            else:
                st.session_state["shadow_sharing_last_selected_mac"] = None
                st.session_state.pop("shadow_sharing_dialog_base_df", None)
                st.session_state.pop("shadow_sharing_dialog_base_key", None)

            has_mac_rows = dev_grid["mac"].astype(str).str.strip().replace({"": None, "nan": None, "none": None}).dropna().nunique() > 0
            if not has_mac_rows:
                st.info("MAC values are not available in this scope, so MAC drilldown dialog is disabled.")

    # -------------------------------------------------------------------------
    # Data Exfiltration Threats (moved from shadow_apps)
    # -------------------------------------------------------------------------
    with tab_threat:
        st.markdown("#### Data Exfiltration Threats")
        st.markdown(
            "<div class='shadow-callout'>Focused view of logs/events that triggered explicit exfiltration detection signals.</div>",
            unsafe_allow_html=True,
        )

        threat_cache_key = ("threat-base",) + main_filter_cache_key
        cached_threat_base = st.session_state.get("shadow_sharing_threat_base_df")
        cached_threat_key = st.session_state.get("shadow_sharing_threat_cache_key")
        cached_threat_summary = st.session_state.get("shadow_sharing_threat_summary")

        if (
            cached_threat_key == threat_cache_key
            and isinstance(cached_threat_base, pd.DataFrame)
            and isinstance(cached_threat_summary, dict)
        ):
            threat_base = cached_threat_base
            threat_summary = cached_threat_summary
        else:
            threat_base = filtered
            if "Exfil_Indicator" not in threat_base.columns:
                threat_base = threat_base.copy()
                ex = threat_base.apply(_detect_exfil_signal_row, axis=1)
                threat_base["Exfil_Indicator"] = ex.apply(lambda x: bool(x[0]))
                threat_base["Exfil_Detection_Basis"] = ex.apply(lambda x: str(x[1]))
            elif "Exfil_Detection_Basis" not in threat_base.columns:
                threat_base = threat_base.copy()
                threat_base["Exfil_Detection_Basis"] = ""

            threat_base = threat_base[
                (threat_base["Allowed"] == False) & (threat_base["Exfil_Indicator"] == True)  # noqa: E712
            ].copy()

            threat_summary = {}
            if not threat_base.empty:
                threat_base["bytes"] = pd.to_numeric(threat_base["bytes"], errors="coerce").fillna(0)
                threat_base = threat_base.sort_values("ts", ascending=False)
                threat_base["__search_blob"] = _build_text_search_blob(
                    threat_base,
                    ["mac", "host_name", "id.orig_h", "destination", "Exfil_Detection_Basis", "Risk_Basis", "Action_Basis"],
                )

                action_options = sorted(
                    threat_base["Action"]
                    .dropna()
                    .astype(str)
                    .str.strip()
                    .replace("", pd.NA)
                    .dropna()
                    .unique()
                    .tolist()
                )
                detail_sources = sorted(
                    threat_base["log_source"]
                    .dropna()
                    .astype(str)
                    .str.strip()
                    .replace("", pd.NA)
                    .dropna()
                    .unique()
                    .tolist()
                )

                mac_norm = threat_base["mac"].astype(str).str.strip().str.lower().replace({"nan": "", "none": "", "-": ""})
                ip_norm = threat_base["id.orig_h"].astype(str).str.strip().replace({"nan": "", "None": "", "none": "", "-": ""})
                offender_id = mac_norm.where(mac_norm != "", ip_norm)
                offender_type = pd.Series("Unknown", index=threat_base.index, dtype="object")
                offender_type.loc[mac_norm != ""] = "MAC"
                offender_type.loc[(mac_norm == "") & (ip_norm != "")] = "IP"
                offender_src = pd.DataFrame({"__offender_id": offender_id, "__offender_type": offender_type})
                offender_src = offender_src[offender_src["__offender_id"] != ""]

                top_off = (
                    offender_src.groupby(["__offender_id", "__offender_type"], dropna=False)
                    .size()
                    .reset_index(name="events")
                    .sort_values("events", ascending=False)
                    .head(1)
                )
                top_offender = (
                    str(top_off.iloc[0]["__offender_id"])
                    if not top_off.empty and str(top_off.iloc[0]["__offender_id"]).strip()
                    else "Unknown"
                )
                top_offender_type = str(top_off.iloc[0]["__offender_type"]) if not top_off.empty else "Unknown"
                top_offender_cnt = int(top_off.iloc[0]["events"]) if not top_off.empty else 0

                top_unauth = (
                    threat_base.groupby("destination", dropna=False)
                    .size()
                    .reset_index(name="Hits")
                    .sort_values("Hits", ascending=False)
                    .head(10)
                    .rename(columns={"destination": "Domain"})
                )

                risk_counts = (
                    threat_base.groupby("Severity", dropna=False)
                    .size()
                    .reset_index(name="Count")
                    .rename(columns={"Severity": "Risk"})
                    .sort_values("Count", ascending=False)
                )

                threat_summary = {
                    "action_options": action_options,
                    "detail_sources": detail_sources,
                    "top_offender": top_offender,
                    "top_offender_type": top_offender_type,
                    "top_offender_cnt": top_offender_cnt,
                    "detected_destinations": int(
                        threat_base["destination"].replace({"": None, "Unknown": None}).dropna().nunique()
                    ),
                    "high_crit_count": int(threat_base["Severity"].isin(["CRITICAL", "HIGH"]).sum()),
                    "top_unauth": top_unauth,
                    "risk_counts": risk_counts,
                }

            st.session_state["shadow_sharing_threat_base_df"] = threat_base
            st.session_state["shadow_sharing_threat_cache_key"] = threat_cache_key
            st.session_state["shadow_sharing_threat_summary"] = threat_summary

        if threat_base.empty:
            st.success("No exfiltration signals detected in current scope.")
        else:
            action_options = threat_summary.get("action_options", [])
            detail_sources = threat_summary.get("detail_sources", [])
            top_offender = str(threat_summary.get("top_offender", "Unknown"))
            top_offender_type = str(threat_summary.get("top_offender_type", "Unknown"))
            top_offender_cnt = int(threat_summary.get("top_offender_cnt", 0))
            detected_destinations = int(threat_summary.get("detected_destinations", 0))
            high_crit_count = int(threat_summary.get("high_crit_count", 0))
            top_unauth = threat_summary.get("top_unauth", pd.DataFrame(columns=["Domain", "Hits"]))
            risk_counts = threat_summary.get("risk_counts", pd.DataFrame(columns=["Risk", "Count"]))

            tm1, tm2, tm3 = st.columns(3)
            tm1.metric("Detected Exfil Destinations", f"{detected_destinations:,}")
            tm2.metric(
                f"Top Offender ({top_offender_type})",
                top_offender,
                delta=f"{top_offender_cnt:,} events",
                delta_color="inverse",
            )
            tm3.metric(
                "Critical / High Risks",
                f"{high_crit_count:,}",
                delta="Requires attention",
                delta_color="inverse",
            )

            st.divider()

            with st.expander("Data Exfiltration Monitor (High Volume Traffic)", expanded=True):
                st.caption("Scope uses logs/events flagged by exfiltration detection signals only.")
                st.markdown("<div class='shadow-filter-shell'>", unsafe_allow_html=True)
                exf_top_1, exf_top_2, exf_top_3 = st.columns([1.4, 1.8, 2.2])
                with exf_top_1:
                    exfil_risk_filter = st.multiselect(
                        "Exfiltration Risk",
                        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        key=f"sharing_exfil_risk_{selected_scope_key}",
                    )
                with exf_top_2:
                    exfil_action_filter = st.multiselect(
                        "Action",
                        action_options,
                        default=action_options,
                        key=f"sharing_exfil_action_{selected_scope_key}",
                    )
                with exf_top_3:
                    exfil_search = st.text_input(
                        "Search Exfiltration (MAC/IP/Host/Destination/Basis)",
                        placeholder="e.g., suspicious.com or 192.168.1.44",
                        key=f"sharing_exfil_search_{selected_scope_key}",
                    ).strip()

                max_bytes = int(threat_base["bytes"].max()) if not threat_base.empty else 0
                max_mb = int(max(10, min(5000, math.ceil(max_bytes / (1024 * 1024)) if max_bytes > 0 else 10)))

                exf_bottom_1, exf_bottom_2 = st.columns([1.4, 2.0])
                with exf_bottom_1:
                    exfil_min_mb = st.slider(
                        "Min Transfer (MB)",
                        0,
                        max_mb,
                        min(5, max_mb),
                        key=f"sharing_exfil_min_mb_{selected_scope_key}",
                    )
                with exf_bottom_2:
                    exfil_chart_mode = st.radio(
                        "Graph Type",
                        ["Bubble by Destination", "Hourly Transfer Trend"],
                        horizontal=True,
                        key=f"sharing_exfil_chart_mode_{selected_scope_key}",
                    )
                st.markdown("</div>", unsafe_allow_html=True)

                exfil_points = threat_base.copy()
                if exfil_risk_filter:
                    exfil_points = exfil_points[exfil_points["Severity"].isin(exfil_risk_filter)]
                if exfil_action_filter:
                    exfil_points = exfil_points[exfil_points["Action"].isin(exfil_action_filter)]
                if exfil_search:
                    q = exfil_search.lower()
                    if "__search_blob" in exfil_points.columns:
                        exfil_points = exfil_points[exfil_points["__search_blob"].str.contains(q, na=False, regex=False)]
                    else:
                        exfil_points = exfil_points[
                            exfil_points["mac"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                            | exfil_points["host_name"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                            | exfil_points["id.orig_h"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                            | exfil_points["destination"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                            | exfil_points["Exfil_Detection_Basis"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                            | exfil_points["Risk_Basis"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                            | exfil_points["Action_Basis"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                        ]
                min_upload_bytes = int(exfil_min_mb * 1024 * 1024)
                if min_upload_bytes > 0:
                    exfil_points = exfil_points[exfil_points["bytes"] >= min_upload_bytes]
                else:
                    exfil_points = exfil_points[exfil_points["bytes"] > 0]
                if len(exfil_points) > 5000:
                    exfil_points = exfil_points.nlargest(5000, "bytes")
                else:
                    exfil_points = exfil_points.sort_values("bytes", ascending=False)

                st.markdown(
                    f"<div class='shadow-filter-hint'>Risk: <strong>{', '.join(exfil_risk_filter) if exfil_risk_filter else 'None'}</strong> | Action: <strong>{len(exfil_action_filter)} selected</strong> | Search: <strong>{'On' if exfil_search else 'Off'}</strong> | Min Transfer: <strong>{exfil_min_mb} MB</strong></div>",
                    unsafe_allow_html=True,
                )

                exfil_c1, exfil_c2 = st.columns([1, 2])
                with exfil_c1:
                    filtered_mb = float(exfil_points["bytes"].sum()) / 1024 / 1024 if not exfil_points.empty else 0.0
                    exfil_c1.metric("Filtered Transfer", f"{filtered_mb:,.2f} MB", delta="Potential leak", delta_color="inverse")
                    exfil_c1.metric("Filtered Events", f"{len(exfil_points):,}")
                    exfil_c1.metric(
                        "Detected Exfil Destinations",
                        f"{int(exfil_points['destination'].replace({'': None, 'Unknown': None}).dropna().nunique()):,}" if not exfil_points.empty else "0",
                    )

                with exfil_c2:
                    if not exfil_points.empty:
                        if exfil_chart_mode == "Bubble by Destination":
                            bubble_df = exfil_points.head(400)
                            fig_exfil = px.scatter(
                                bubble_df,
                                x="destination",
                                y="bytes",
                                size="bytes",
                                color="Severity",
                                color_discrete_map=SEVERITY_COLORS,
                                hover_data=["mac", "host_name", "id.orig_h", "Action"],
                                title="Outbound Transfer by Destination",
                            )
                            style_plotly_figure(fig_exfil, height=360)
                            fig_exfil.update_xaxes(title="Destination")
                            fig_exfil.update_yaxes(title="Bytes")
                        else:
                            trend = exfil_points.copy()
                            trend = trend.dropna(subset=["ts"])
                            if trend.empty:
                                fig_exfil = None
                            else:
                                trend["hour"] = trend["ts"].dt.floor("1H")
                                trend = trend.groupby("hour", as_index=False)["bytes"].sum()
                                fig_exfil = px.line(
                                    trend,
                                    x="hour",
                                    y="bytes",
                                    markers=True,
                                    color_discrete_sequence=["#38bdf8"],
                                    title="Hourly Outbound Transfer Volume",
                                )
                                style_plotly_figure(fig_exfil, height=360, show_legend=False)
                                fig_exfil.update_xaxes(title=None)
                                fig_exfil.update_yaxes(title="Bytes")

                        if fig_exfil is None:
                            st.info("No timestamped events available for trend graph.")
                        else:
                            st.plotly_chart(fig_exfil, use_container_width=True)
                    else:
                        st.info("No significant outbound traffic detected with current filters.")

            st.divider()

            st.markdown("#### Risk Distribution")
            if not risk_counts.empty:
                fig_u2 = px.pie(
                    risk_counts,
                    values="Count",
                    names="Risk",
                    color="Risk",
                    color_discrete_map=SEVERITY_COLORS,
                    hole=0.6,
                )
                style_plotly_figure(fig_u2, height=360)
                st.plotly_chart(fig_u2, use_container_width=True)
            else:
                st.info("No risk distribution data.")

            st.divider()

            st.markdown("#### Threat Details")
            st.markdown("<div class='shadow-filter-shell'>", unsafe_allow_html=True)
            af_top_1, af_top_2 = st.columns([1.25, 1.75])
            af_bottom_1, _ = st.columns([3, 1])

            with af_top_1:
                detail_risk = st.multiselect(
                    "Filter by Risk",
                    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    key=f"sharing_threat_risk_{selected_scope_key}",
                )

            with af_top_2:
                detail_source_filter = st.multiselect(
                    "Filter by Log Source",
                    detail_sources,
                    default=detail_sources,
                    key=f"sharing_threat_src_{selected_scope_key}",
                )

            with af_bottom_1:
                detail_search = st.text_input(
                    "Search (IP, MAC, Destination, Host, Detection Basis)",
                    placeholder="e.g., be:18:78:9d:3f:b1 or suspicious-domain.com",
                    key=f"sharing_threat_search_{selected_scope_key}",
                ).strip()
            st.markdown("</div>", unsafe_allow_html=True)

            detail_df = threat_base.copy()
            if detail_risk:
                detail_df = detail_df[detail_df["Severity"].isin(detail_risk)]
            if detail_source_filter:
                detail_df = detail_df[detail_df["log_source"].isin(detail_source_filter)]
            if detail_search:
                q = detail_search.lower()
                if "__search_blob" in detail_df.columns:
                    detail_df = detail_df[detail_df["__search_blob"].str.contains(q, na=False, regex=False)]
                else:
                    detail_df = detail_df[
                        detail_df["mac"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                        | detail_df["host_name"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                        | detail_df["id.orig_h"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                        | detail_df["destination"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                        | detail_df["Exfil_Detection_Basis"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                        | detail_df["Risk_Basis"].astype(str).str.lower().str.contains(q, na=False, regex=False)
                    ]
            detail_df = detail_df.head(MAX_ROWS_DISPLAY).copy()

            detail_risk_summary = ", ".join(detail_risk) if detail_risk else "None"
            detail_source_summary = f"{len(detail_source_filter)} selected" if detail_source_filter else "None"
            detail_search_summary = "On" if detail_search else "Off"
            st.markdown(
                f"<div class='shadow-filter-hint'>Risk: <strong>{detail_risk_summary}</strong> | Sources: <strong>{detail_source_summary}</strong> | Search: <strong>{detail_search_summary}</strong></div>",
                unsafe_allow_html=True,
            )

            if detail_df.empty:
                st.info("No rows match your filters.")
            else:
                detail_df["ts"] = pd.to_datetime(detail_df["ts"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S").fillna("")
                detail_df["bytes"] = pd.to_numeric(detail_df["bytes"], errors="coerce").fillna(0).astype(int)

                detail_cols = [
                    "ts",
                    "mac",
                    "host_name",
                    "id.orig_h",
                    "destination",
                    "log_source",
                    "Action",
                    "Category",
                    "bytes",
                    "Severity",
                    "Exfil_Detection_Basis",
                    "Risk_Basis",
                    "DNS_Exfil_Reason",
                ]
                detail_cols = [c for c in detail_cols if c in detail_df.columns]
                detail_grid = detail_df[detail_cols].copy()
                detail_grid.insert(0, "#", range(1, len(detail_grid) + 1))

                bytes_style = JsCode(
                    """
                    function(params) {
                        const v = Number(params.value || 0);
                        if (v > 100000000) return {color: '#fb7185', fontWeight: '700'};
                        if (v > 10000000) return {color: '#f59e0b', fontWeight: '700'};
                        return {color: '#93c5fd'};
                    }
                    """
                )

                gb_threat = GridOptionsBuilder.from_dataframe(detail_grid)
                gb_threat.configure_default_column(filter=True, sortable=True, resizable=True, flex=1)
                gb_threat.configure_pagination(paginationAutoPageSize=False, paginationPageSize=20)
                gb_threat.configure_column("#", header_name="#", width=62, pinned="left", suppressMovable=True, resizable=False)
                if "ts" in detail_grid.columns:
                    gb_threat.configure_column("ts", header_name="Timestamp", minWidth=160, flex=1.1)
                if "destination" in detail_grid.columns:
                    gb_threat.configure_column("destination", header_name="Destination", minWidth=200, flex=1.5)
                if "bytes" in detail_grid.columns:
                    gb_threat.configure_column("bytes", header_name="Transfer (Bytes)", minWidth=130, flex=1.0, cellStyle=bytes_style)
                if "Severity" in detail_grid.columns:
                    gb_threat.configure_column("Severity", header_name="Risk Level", minWidth=110, flex=0.9, cellStyle=_severity_cellstyle())
                if "Exfil_Detection_Basis" in detail_grid.columns:
                    gb_threat.configure_column("Exfil_Detection_Basis", header_name="Detection Basis", minWidth=240, flex=1.8)
                if "Risk_Basis" in detail_grid.columns:
                    gb_threat.configure_column("Risk_Basis", header_name="Risk Basis", minWidth=220, flex=1.8)
                if "DNS_Exfil_Reason" in detail_grid.columns:
                    gb_threat.configure_column("DNS_Exfil_Reason", header_name="DNS Exfil Reason", minWidth=220, flex=1.8)

                render_shadow_aggrid(
                    detail_grid,
                    gb_threat,
                    key=f"shadow_sharing_threat_grid_{selected_scope_key}",
                    height=460,
                    update_mode=GridUpdateMode.NO_UPDATE,
                )
                st.caption(f"{len(detail_grid):,} detected exfil events shown (limited to {MAX_ROWS_DISPLAY:,}).")

    with st.expander("Detection basis (what this page detects)", expanded=False):
        st.write(
            "This page correlates Zeek telemetry (HTTP/SSL/DNS/CONN/FILES) and flags potential Shadow Sharing / Exfiltration.\n"
            "- Allowed/Unapproved is based on whitelist_domains.yaml (Allow_Basis shows which entry matched).\n"
            "- Action is inferred from HTTP method/URI patterns, client type, and files telemetry.\n"
            "- DNS exfil heuristics flag tunneling-like query patterns.\n"
            "- Risk_Score/Risk Level is computed with an explainable Risk_Basis string."
        )

    if st.session_state.get("shadow_sharing_dialog_open") and st.session_state.get("shadow_sharing_dialog_mac"):
        show_shadow_sharing_device_dialog(filtered, selected_scope_key=selected_scope_key)


# Backward compatibility if your app imports render_shadow_uploads
def render_shadow_uploads(parquet_root: Path):
    return render_shadow_sharing(parquet_root)
