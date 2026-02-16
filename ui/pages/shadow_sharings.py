# ui/pages/shadow_sharings.py
import re
import math
import warnings
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

CACHE_VERSION = "shadow-sharing-cache-v5"
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
      - {whitelist_domains: [..]}
      - {domains: [..]}
      - {[..]} (not dict) -> handled in loader by returning {}
    """
    for k in ["whitelist_domains", "domains", "allowed_domains", "whitelist", "allowlist"]:
        v = y.get(k)
        if isinstance(v, list):
            return [str(x).strip().lower() for x in v if str(x).strip()]
    # also allow dict form: {domain: true}
    if "whitelist_domains" in y and isinstance(y["whitelist_domains"], dict):
        return [str(x).strip().lower() for x in y["whitelist_domains"].keys()]
    return []


@st.cache_data(ttl=600, show_spinner=False)
def load_whitelist() -> Tuple[List[str], int]:
    y = _safe_yaml_load(WHITELIST_FILE)
    domains = _extract_whitelist_domains(y)
    domains = sorted(set([d for d in domains if d]))
    mtime_ns = int(WHITELIST_FILE.stat().st_mtime_ns) if WHITELIST_FILE.exists() else 0
    return domains, mtime_ns


WHITELIST_DOMAINS, WHITELIST_MTIME_NS = load_whitelist()

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
    buckets = {"http": [], "ssl": [], "dns": [], "conn": [], "dhcp": []}
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

    def ingest(df: pd.DataFrame) -> None:
        nonlocal ip_map, mac_map
        if df.empty:
            return

        df = _ensure_ts_datetime(df)
        if "ts" in df.columns:
            df = df.sort_values("ts")

        ip_col = next((c for c in ["assigned_addr", "client_addr", "id.orig_h", "addr", "ip"] if c in df.columns), None)
        mac_col = next((c for c in ["mac", "orig_l2_addr", "l2_addr", "src_mac", "hwaddr"] if c in df.columns), None)
        host_col = next((c for c in ["host_name", "hostname", "device_name", "host"] if c in df.columns), None)

        if ip_col is None and mac_col is None:
            return

        if ip_col is not None:
            df[ip_col] = _clean_str_series(df[ip_col])
        if mac_col is not None:
            df[mac_col] = df[mac_col].apply(normalize_mac)
        if host_col is not None:
            df[host_col] = df[host_col].astype(str).replace({"nan": "", "None": "", "-": ""}).str.strip()
        else:
            host_col = "__host"
            df[host_col] = ""

        # ip -> (mac, host) last seen
        if ip_col is not None:
            sub_cols = [ip_col, host_col] + ([mac_col] if mac_col is not None else [])
            if "ts" in df.columns:
                sub_cols = ["ts"] + sub_cols
            sub = df[sub_cols].dropna(subset=[ip_col]).copy()
            if "ts" in sub.columns:
                sub = sub.sort_values("ts")

            def last_non_null_mac(x: pd.Series):
                x = x.dropna()
                return x.iloc[-1] if len(x) else None

            def last_non_empty_host(x: pd.Series):
                x = x.astype(str).replace({"nan": "", "None": "", "-": ""})
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
            subm_cols = [mac_col, host_col] + (["ts"] if "ts" in df.columns else [])
            subm = df[subm_cols].dropna(subset=[mac_col]).copy()
            subm[host_col] = subm[host_col].astype(str).replace({"nan": "", "None": "", "-": ""})
            subm = subm[subm[host_col] != ""]
            if not subm.empty:
                if "ts" in subm.columns:
                    subm = subm.sort_values("ts")
                gm = subm.groupby(mac_col, dropna=True).agg(host=(host_col, lambda x: x.iloc[-1] if len(x) else ""))
                for mac, r in gm.iterrows():
                    if mac and r.get("host", ""):
                        mac_map[str(mac)] = r["host"]

    if dhcp_files:
        ingest(_duck_read_parquet_union(dhcp_files))
    if conn_files:
        ingest(_duck_read_parquet_union(conn_files))
    if known_files:
        ingest(_duck_read_parquet_union(known_files))

    return ip_map, mac_map


def _enrich_identity(events: pd.DataFrame, ip_map: Dict[str, Tuple[Optional[str], str]], mac_map: Dict[str, str]) -> pd.DataFrame:
    if events.empty:
        return events

    if "mac" not in events.columns:
        events["mac"] = None
    if "host_name" not in events.columns:
        events["host_name"] = None

    for c in ["orig_l2_addr", "l2_addr", "src_mac"]:
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
            events["host_name"].notna() & (events["host_name"] != ""),
            host_from_ip,
        )

    events["mac"] = events["mac"].apply(normalize_mac)
    macs = events["mac"].astype(str).replace({"nan": "", "None": ""})
    host_from_mac = macs.map(lambda m: mac_map.get(m, "") if m else "")
    events["host_name"] = events["host_name"].where(
        events["host_name"].notna() & (events["host_name"] != ""),
        host_from_mac,
    )

    # don't force "Unknown" (leave empty if truly unresolved)
    events["mac"] = events["mac"].astype(str).fillna("").replace({"None": "", "nan": ""})
    events["host_name"] = events["host_name"].astype(str).fillna("").replace({"None": "", "nan": ""})
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

def _domain_in_allowlist(dest: str, allowlist: List[str]) -> Tuple[bool, str]:
    """
    Returns (allowed, basis)
    basis is the matched allowlist domain, or ""
    """
    d = str(dest or "").lower().strip()
    if not d or d in ("unknown", "nan", "none", "-"):
        return (False, "")
    for a in allowlist:
        if a and a in d:
            return (True, a)
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
    """
    score = 10
    basis: List[str] = []

    # Allowlist / unapproved
    if not bool(row.get("Allowed", False)):
        score += 15
        basis.append("destination not in whitelist")

    # Category
    cat = str(row.get("Category", "Unknown"))
    if cat in ("Cloud Storage", "Paste", "Remote Access"):
        score += 10
        basis.append(f"category={cat}")

    # Action
    action = str(row.get("Action", ""))
    if action == "Upload":
        score += 20
        basis.append("upload action")
    elif action == "Post Data":
        score += 10
        basis.append("http post")
    elif action == "Paste/Share":
        score += 12
        basis.append("paste/share action")
    elif action == "Automated Access":
        score += 10
        basis.append("automation access")

    # Client type
    if str(row.get("Client_Type", "")) == "Automation / SDK":
        score += 10
        basis.append("automation user-agent")

    # Bytes
    b = float(row.get("bytes", 0) or 0)
    if b >= 500 * 1024 * 1024:
        score += 35
        basis.append(">=500MB")
    elif b >= 100 * 1024 * 1024:
        score += 25
        basis.append(">=100MB")
    elif b >= 10 * 1024 * 1024:
        score += 12
        basis.append(">=10MB")

    # DNS exfil
    dns_add = int(row.get("DNS_Exfil_Add", 0) or 0)
    if dns_add > 0:
        score += dns_add
        r = str(row.get("DNS_Exfil_Reason", "") or "")
        basis.append(f"dns exfil: {r}" if r else "dns exfil heuristic")

    # cap
    score = int(min(100, score))
    if not basis:
        basis = ["baseline"]
    return score, "; ".join(basis)

# -----------------------------------------------------------------------------
# Builders
# -----------------------------------------------------------------------------

def _destination_from_df(df: pd.DataFrame, log_source: str) -> pd.Series:
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
    return pd.Series([0] * len(df))


def _build_one_date(parquet_root: Path, date_str: str, known_files: List[Path]) -> pd.DataFrame:
    date_dir = Path(parquet_root) / date_str
    buckets = _collect_date_files(date_dir)

    files_sig = {
        "http": _file_signature(buckets["http"]),
        "ssl": _file_signature(buckets["ssl"]),
        "dns": _file_signature(buckets["dns"]),
        "conn": _file_signature(buckets["conn"]),
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

    frames: List[pd.DataFrame] = []
    for src in ["http", "ssl", "dns", "conn"]:
        paths = buckets.get(src, [])
        if not paths:
            continue

        df = _duck_read_parquet_union(paths)
        if df.empty:
            continue

        df["log_source"] = src
        df = _ensure_ts_datetime(df)
        df = df.dropna(subset=["ts"])

        # ensure fields
        if "id.orig_h" not in df.columns:
            df["id.orig_h"] = ""
        else:
            df["id.orig_h"] = df["id.orig_h"].astype(str).str.strip()

        if "orig_l2_addr" not in df.columns:
            df["orig_l2_addr"] = None
        if "user_agent" not in df.columns:
            df["user_agent"] = ""
        if "method" not in df.columns:
            df["method"] = ""
        if "uri" not in df.columns:
            df["uri"] = ""
        # optional content-type (if Zeek HTTP header logging is present)
        if "content_type" not in df.columns:
            df["content_type"] = ""

        df["destination"] = _destination_from_df(df, src).replace({"": "Unknown", "nan": "Unknown", "None": "Unknown"}).fillna("Unknown")
        df["bytes"] = _bytes_from_df(df, src)

        keep = [
            "ts", "log_source", "id.orig_h", "destination", "bytes",
            "method", "uri", "user_agent", "content_type",
            "orig_l2_addr",
            "host", "server_name", "query",
        ]
        keep = [c for c in keep if c in df.columns]
        frames.append(df[keep].copy())

    if not frames:
        return pd.DataFrame()

    out = pd.concat(frames, ignore_index=True)
    out = _ensure_ts_datetime(out).sort_values("ts", ascending=False)

    # identity enrichment
    out = _enrich_identity(out, ip_map, mac_map)
    out["Identity_Confidence"] = out.apply(_identity_confidence, axis=1)

    # allowlist basis
    allowed_basis = out["destination"].apply(lambda d: _domain_in_allowlist(d, WHITELIST_DOMAINS))
    out["Allowed"] = allowed_basis.apply(lambda x: bool(x[0]))
    out["Allow_Basis"] = allowed_basis.apply(lambda x: str(x[1] or ""))

    # category
    out["Category"] = out["destination"].apply(_tag_category)

    # client type
    out["Client_Type"] = out["user_agent"].apply(fingerprint_client)

    # action detection
    out["Action"], out["Action_Basis"] = zip(*out.apply(
        lambda r: _detect_action(
            str(r.get("log_source", "")),
            str(r.get("method", "")),
            str(r.get("uri", "")),
            str(r.get("user_agent", "")),
            str(r.get("destination", "")),
            str(r.get("content_type", "")),
        ),
        axis=1
    ))

    # DNS exfil heuristics (only on dns rows)
    out["DNS_Exfil_Add"] = 0
    out["DNS_Exfil_Reason"] = ""
    dns_mask = out["log_source"].astype(str).str.lower().eq("dns")
    if dns_mask.any() and "query" in out.columns:
        q_series = out.loc[dns_mask, "destination"].astype(str).fillna("")
        scores_reasons = q_series.apply(_dns_exfil_score)
        out.loc[dns_mask, "DNS_Exfil_Add"] = scores_reasons.apply(lambda x: int(x[0]))
        out.loc[dns_mask, "DNS_Exfil_Reason"] = scores_reasons.apply(lambda x: str(x[1] or ""))

    # risk score + severity + basis
    rs = out.apply(_risk_score_row, axis=1)
    out["Risk_Score"] = rs.apply(lambda x: int(x[0]))
    out["Risk_Basis"] = rs.apply(lambda x: str(x[1]))
    out["Severity"] = out["Risk_Score"].apply(_severity_label)

    # VirusTotal link for domain/SNI/query
    out["vt_link"] = "https://www.virustotal.com/gui/domain/" + out["destination"].astype(str)

    # write cache
    try:
        cpath.parent.mkdir(parents=True, exist_ok=True)
        out.to_parquet(cpath, index=False)
        write_yaml(mpath, expected)
    except Exception:
        pass

    return out


def load_shadow_sharing_data(parquet_root: Path, target_dates: List[str]) -> pd.DataFrame:
    parquet_root = Path(parquet_root)
    if not parquet_root.exists():
        return pd.DataFrame()

    known_files = _collect_known_files(parquet_root)

    frames: List[pd.DataFrame] = []
    for d in (target_dates or []):
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
    autofit_js = JsCode(
        """
        function(params) {
            setTimeout(function() {
                if (params && params.api) {
                    params.api.sizeColumnsToFit();
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
            ".ag-header": {"background-color": "#10213E", "color": "#EAF2FF", "border-bottom": "1px solid #3A5A8E"},
            ".ag-header-cell, .ag-header-group-cell": {"background-color": "#10213E", "color": "#EAF2FF", "border-right": "1px solid #2A466E"},
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
        fit_columns_on_grid_load=True,
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
        }

        [data-testid="stMetricLabel"] p {
            font-size: 0.75rem;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            font-weight: 600;
        }

        [data-testid="stMetricValue"] {
            line-height: 1.1;
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

def render_shadow_sharing(parquet_root: Path):
    inject_shadow_sharing_css()
    st.markdown("### Data Exfiltration Monitoring")
    st.markdown(
        "<div class='shadow-callout'>Correlates HTTP/SSL/DNS/CONN telemetry to surface potential shadow sharing and exfiltration paths.</div>",
        unsafe_allow_html=True,
    )

    parquet_root = Path(parquet_root)
    if not parquet_root.exists():
        st.error("Data directory not found.")
        return

    available_dates = get_available_dates(parquet_root)
    if not available_dates:
        st.warning("No logs found.")
        return

    top1, top2, top3 = st.columns([1.5, 2.3, 0.8])
    with top1:
        selected_date = st.selectbox(
            "Dataset Scope",
            available_dates,
            index=0,
            key="shadow_sharing_date",
        )
    selected_scope_key = re.sub(r"[^A-Za-z0-9_]+", "_", str(selected_date))
    with top2:
        scope_label = selected_date
        st.markdown(
            f"<div class='shadow-day-chip'>Active scope: &nbsp; <strong>{scope_label}</strong></div>",
            unsafe_allow_html=True,
        )
    with top3:
        st.write("")
        st.write("")
        if st.button("Refresh", key="shadow_sharing_refresh"):
            st.cache_data.clear()
            st.cache_resource.clear()
            st.rerun()

    with st.expander("Detection basis (what this page detects)", expanded=False):
        st.write(
            "This page correlates Zeek telemetry (HTTP/SSL/DNS/CONN) and flags potential Shadow Sharing / Exfiltration.\n"
            "- Allowed/Unapproved is based on whitelist_domains.yaml (Allow_Basis shows which entry matched).\n"
            "- Action is inferred from HTTP method/URI patterns and client type.\n"
            "- DNS exfil heuristics flag tunneling-like query patterns.\n"
            "- Risk_Score/Severity is computed with an explainable Risk_Basis string."
        )

    st.markdown("<div class='shadow-filter-shell'>", unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns([2.0, 1.35, 1.55, 1.2])
    with c1:
        selected_sources = st.multiselect("Protocols", ["http", "ssl", "dns", "conn"], default=["http", "ssl", "dns"])
    with c2:
        show_only_unapproved = st.checkbox("Only Unapproved", value=False)
    with c3:
        min_sev = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with c4:
        min_bytes_mb = st.number_input("Min Bytes (MB)", min_value=0, value=0, step=10)

    c5, c6, c7 = st.columns([1.8, 1.4, 2.6])
    with c5:
        action_filter = st.multiselect(
            "Action",
            ["Upload", "Post Data", "Paste/Share", "Remote Access", "Automated Access", "Browse", "Encrypted Access", "Raw Connection", "DNS Lookup"],
            default=[],
            placeholder="All actions",
        )
    with c6:
        category_filter = st.multiselect(
            "Category",
            ["Cloud Storage", "Paste", "Messaging", "Code Repo", "Remote Access", "Unknown"],
            default=[],
            placeholder="All categories",
        )
    with c7:
        search_q = st.text_input("Search (MAC, Host, IP, Destination, Basis)", placeholder="Enter keywords...")
    st.markdown("</div>", unsafe_allow_html=True)

    source_summary = ", ".join(selected_sources) if selected_sources else "None"
    sev_summary = ", ".join(min_sev) if min_sev else "None"
    search_summary = "On" if (search_q or "").strip() else "Off"
    st.markdown(
        f"<div class='shadow-filter-hint'>Protocols: <strong>{source_summary}</strong> | Severity: <strong>{sev_summary}</strong> | Only Unapproved: <strong>{'Yes' if show_only_unapproved else 'No'}</strong> | Search: <strong>{search_summary}</strong></div>",
        unsafe_allow_html=True,
    )

    # Date scope
    target_dates = [selected_date] if selected_date else []

    with st.spinner("Analyzing telemetry (fast cache + DuckDB)..."):
        df = load_shadow_sharing_data(parquet_root, target_dates)

    if df.empty:
        st.info("No data detected for the selected timeframe.")
        return

    # Apply filters
    filtered = df.copy()

    if selected_sources:
        filtered = filtered[filtered["log_source"].isin(selected_sources)]

    if show_only_unapproved:
        filtered = filtered[filtered["Allowed"] == False]  # noqa: E712

    if min_sev:
        filtered = filtered[filtered["Severity"].isin(min_sev)]

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
                filtered["mac"].astype(str).str.lower().str.contains(q, na=False)
                | filtered["host_name"].astype(str).str.lower().str.contains(q, na=False)
                | filtered["id.orig_h"].astype(str).str.lower().str.contains(q, na=False)
                | filtered["destination"].astype(str).str.lower().str.contains(q, na=False)
                | filtered["Risk_Basis"].astype(str).str.lower().str.contains(q, na=False)
                | filtered["Action_Basis"].astype(str).str.lower().str.contains(q, na=False)
                | filtered["Allow_Basis"].astype(str).str.lower().str.contains(q, na=False)
            ]

    if filtered.empty:
        st.warning("No data matches your filters.")
        return

    # Metrics
    st.divider()
    m1, m2, m3, m4, m5 = st.columns(5)

    total_b = float(filtered["bytes"].sum())
    total_mb = total_b / 1024 / 1024
    unapproved = int((filtered["Allowed"] == False).sum())  # noqa: E712
    critical = int((filtered["Severity"] == "CRITICAL").sum())
    autom = int((filtered["Client_Type"] == "Automation / SDK").sum())

    uniq_mac = filtered["mac"].replace({"": None}).dropna().nunique()
    uniq_ip = filtered["id.orig_h"].replace({"": None}).dropna().nunique()
    uniq_dev = int(uniq_mac if uniq_mac > 0 else uniq_ip)

    m1.metric("Selected Events", f"{len(filtered):,}")
    m2.metric("Unapproved Events", unapproved, delta="Risk" if unapproved > 0 else "Clear", delta_color="inverse")
    m3.metric("Total Volume", f"{total_mb:.2f} MB")
    m4.metric("Critical", critical, delta="Investigate" if critical > 0 else "Clear", delta_color="inverse")
    m5.metric("Automation / SDK", f"{autom:,}")
    st.markdown(
        f"<div class='shadow-filter-hint'>Unique devices in scope: <strong>{uniq_dev:,}</strong></div>",
        unsafe_allow_html=True,
    )

    # Tabs
    tab_overview, tab_device, tab_dest, tab_bursts, tab_log = st.tabs(
        ["Overview", "By Device", "By Destination", "Bursts", "Event Log"]
    )

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

        use_mac = filtered["mac"].replace({"": None}).dropna().nunique() > 0
        key = "mac" if use_mac else "id.orig_h"

        dev = filtered.groupby(key, dropna=False).agg(
            Host=("host_name", lambda x: next((v for v in x.astype(str) if v), "")),
            Last_Seen=("ts", "max"),
            Events=("ts", "count"),
            Unapproved=("Allowed", lambda x: int((x == False).sum())),  # noqa: E712
            Total_MB=("bytes", lambda x: float(x.sum()) / 1024 / 1024),
            Top_Action=("Action", lambda x: x.value_counts().index[0] if len(x) else ""),
            Top_Dest=("destination", lambda x: x.value_counts().index[0] if len(x) else ""),
            Max_Risk=("Risk_Score", "max"),
        ).reset_index().sort_values(["Max_Risk", "Total_MB", "Events"], ascending=False)

        dev_grid = dev.copy()
        dev_grid.insert(0, "#", range(1, len(dev_grid) + 1))
        dev_grid["Last_Seen"] = pd.to_datetime(dev_grid["Last_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M").fillna("")
        dev_grid["Total_MB"] = pd.to_numeric(dev_grid["Total_MB"], errors="coerce").fillna(0).round(2)

        gb_dev = GridOptionsBuilder.from_dataframe(dev_grid)
        gb_dev.configure_default_column(filter=True, sortable=True, resizable=True, flex=1)
        gb_dev.configure_pagination(paginationAutoPageSize=False, paginationPageSize=15)
        gb_dev.configure_column("#", header_name="#", width=62, pinned="left", suppressMovable=True, resizable=False)
        gb_dev.configure_column(key, header_name="MAC" if key == "mac" else "IP", minWidth=140)
        gb_dev.configure_column("Host", minWidth=160)
        gb_dev.configure_column("Last_Seen", header_name="Last Seen", width=150)
        gb_dev.configure_column("Events", width=90)
        gb_dev.configure_column("Unapproved", width=108)
        gb_dev.configure_column("Total_MB", header_name="Total MB", width=116)
        gb_dev.configure_column("Top_Action", header_name="Top Action", minWidth=145)
        gb_dev.configure_column("Top_Dest", header_name="Top Destination", minWidth=180)
        gb_dev.configure_column("Max_Risk", header_name="Max Risk", width=96, cellStyle=_risk_score_cellstyle())

        render_shadow_aggrid(
            dev_grid,
            gb_dev,
            key=f"shadow_sharing_device_grid_{selected_scope_key}",
            height=430,
        )

    # -------------------------------------------------------------------------
    # By Destination
    # -------------------------------------------------------------------------
    with tab_dest:
        st.markdown("#### Destination Forensics")

        dest = filtered.groupby("destination", dropna=False).agg(
            Category=("Category", lambda x: x.value_counts().index[0] if len(x) else "Unknown"),
            Allowed=("Allowed", lambda x: bool(x.value_counts().index[0]) if len(x) else False),
            Allow_Basis=("Allow_Basis", lambda x: next((v for v in x.astype(str) if v), "")),
            Last_Seen=("ts", "max"),
            Events=("ts", "count"),
            Unique_Devices=("mac", lambda x: x.replace({"": None}).dropna().nunique()),
            Total_MB=("bytes", lambda x: float(x.sum()) / 1024 / 1024),
            Max_Risk=("Risk_Score", "max"),
            Top_Action=("Action", lambda x: x.value_counts().index[0] if len(x) else ""),
        ).reset_index().sort_values(["Max_Risk", "Total_MB", "Events"], ascending=False)

        dest_grid = dest.copy()
        dest_grid.insert(0, "#", range(1, len(dest_grid) + 1))
        dest_grid["Last_Seen"] = pd.to_datetime(dest_grid["Last_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M").fillna("")
        dest_grid["Total_MB"] = pd.to_numeric(dest_grid["Total_MB"], errors="coerce").fillna(0).round(2)

        gb_dest = GridOptionsBuilder.from_dataframe(dest_grid)
        gb_dest.configure_default_column(filter=True, sortable=True, resizable=True, flex=1)
        gb_dest.configure_pagination(paginationAutoPageSize=False, paginationPageSize=15)
        gb_dest.configure_column("#", header_name="#", width=62, pinned="left", suppressMovable=True, resizable=False)
        gb_dest.configure_column("destination", header_name="Destination", minWidth=200)
        gb_dest.configure_column("Category", width=130)
        gb_dest.configure_column("Allowed", width=98, cellStyle=_allowed_cellstyle())
        gb_dest.configure_column("Allow_Basis", header_name="Allow Basis", minWidth=210)
        gb_dest.configure_column("Last_Seen", header_name="Last Seen", width=150)
        gb_dest.configure_column("Events", width=88)
        gb_dest.configure_column("Unique_Devices", header_name="Devices", width=90)
        gb_dest.configure_column("Total_MB", header_name="Total MB", width=116)
        gb_dest.configure_column("Max_Risk", header_name="Max Risk", width=96, cellStyle=_risk_score_cellstyle())
        gb_dest.configure_column("Top_Action", header_name="Top Action", minWidth=145)

        render_shadow_aggrid(
            dest_grid,
            gb_dest,
            key=f"shadow_sharing_dest_grid_{selected_scope_key}",
            height=430,
        )

    # -------------------------------------------------------------------------
    # Bursts
    # -------------------------------------------------------------------------
    with tab_bursts:
        st.markdown("#### Burst Detection (5-minute windows)")
        # bucket time to 5 minutes
        b = filtered.copy()
        b["bucket"] = b["ts"].dt.floor("5min")
        use_mac = b["mac"].replace({"": None}).dropna().nunique() > 0
        dev_key = "mac" if use_mac else "id.orig_h"

        bursts = b.groupby(["bucket", dev_key], dropna=False).agg(
            bytes=("bytes", "sum"),
            events=("ts", "count"),
            max_risk=("Risk_Score", "max"),
            host=("host_name", lambda x: next((v for v in x.astype(str) if v), "")),
        ).reset_index()

        # show top bursts
        top_bursts = bursts.sort_values(["max_risk", "bytes", "events"], ascending=False).head(200)

        fig = px.scatter(
            top_bursts,
            x="bucket",
            y=dev_key,
            size="bytes",
            color="max_risk",
            hover_data=["host", "events"],
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

        gb_burst = GridOptionsBuilder.from_dataframe(burst_grid)
        gb_burst.configure_default_column(filter=True, sortable=True, resizable=True, flex=1)
        gb_burst.configure_pagination(paginationAutoPageSize=False, paginationPageSize=20)
        gb_burst.configure_column("#", header_name="#", width=62, pinned="left", suppressMovable=True, resizable=False)
        gb_burst.configure_column("bucket", header_name="Window", width=150)
        gb_burst.configure_column(dev_key, header_name="MAC" if dev_key == "mac" else "IP", minWidth=150)
        gb_burst.configure_column("host", header_name="Host", minWidth=160)
        gb_burst.configure_column("events", header_name="Events", width=90)
        gb_burst.configure_column("bytes", header_name="Bytes", width=130)
        gb_burst.configure_column("max_risk", header_name="Max Risk", width=100, cellStyle=_risk_score_cellstyle())

        render_shadow_aggrid(
            burst_grid,
            gb_burst,
            key=f"shadow_sharing_burst_grid_{selected_scope_key}",
            height=430,
        )

    # -------------------------------------------------------------------------
    # Event Log
    # -------------------------------------------------------------------------
    with tab_log:
        head, btn = st.columns([4, 1])
        with head:
            st.markdown("#### Detailed Event Log (export-ready)")
        with btn:
            csv_data = filtered.to_csv(index=False).encode("utf-8")
            st.download_button("Export CSV", csv_data, "shadow_sharing_log.csv", "text/csv")

        st.markdown(
            f"<div class='shadow-filter-hint'>Showing up to <strong>{MAX_ROWS_DISPLAY:,}</strong> rows from <strong>{len(filtered):,}</strong> matched events.</div>",
            unsafe_allow_html=True,
        )

        cols = [
            "ts", "host_name", "mac", "Identity_Confidence", "id.orig_h",
            "destination", "vt_link",
            "Allowed", "Allow_Basis",
            "Category", "Action", "Action_Basis",
            "bytes",
            "Client_Type",
            "Risk_Score", "Severity", "Risk_Basis",
            "log_source",
            "method", "uri",
            "DNS_Exfil_Add", "DNS_Exfil_Reason",
        ]
        for c in cols:
            if c not in filtered.columns:
                filtered[c] = ""

        view = filtered[cols].copy()
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
        gb_log.configure_column(
            "destination",
            header_name="Destination",
            minWidth=180,
            flex=1.6,
        )
        gb_log.configure_column("vt_link", header_name="VirusTotal", minWidth=105, flex=0.9, cellRenderer=_link_cell_renderer())
        gb_log.configure_column("Allowed", minWidth=95, flex=0.8, cellStyle=_allowed_cellstyle())
        gb_log.configure_column(
            "Allow_Basis",
            header_name="Allow Basis",
            minWidth=200,
            flex=1.8,
        )
        gb_log.configure_column("Category", minWidth=120, flex=1.0)
        gb_log.configure_column("Action", minWidth=130, flex=1.1)
        gb_log.configure_column("bytes", header_name="Bytes", minWidth=110, flex=1.0)
        gb_log.configure_column("Client_Type", header_name="Client", minWidth=120, flex=1.0)
        gb_log.configure_column("Risk_Score", header_name="Risk", minWidth=85, flex=0.8, cellStyle=_risk_score_cellstyle())
        gb_log.configure_column("Severity", minWidth=95, flex=0.9, cellStyle=_severity_cellstyle())
        gb_log.configure_column("log_source", header_name="Source", minWidth=95, flex=0.9)
        gb_log.configure_column("method", header_name="Method", minWidth=90, flex=0.9)
        gb_log.configure_column("uri", header_name="URI", minWidth=220, flex=2.0)
        gb_log.configure_column("Risk_Basis", header_name="Risk Basis", minWidth=220, flex=2.0)
        gb_log.configure_column("Action_Basis", header_name="Action Basis", minWidth=210, flex=1.9)
        gb_log.configure_column("DNS_Exfil_Reason", header_name="DNS Exfil Reason", minWidth=220, flex=2.0)

        render_shadow_aggrid(
            log_grid,
            gb_log,
            key=f"shadow_sharing_log_grid_{selected_scope_key}",
            height=520,
        )


# Backward compatibility if your app imports render_shadow_uploads
def render_shadow_uploads(parquet_root: Path):
    return render_shadow_sharing(parquet_root)
