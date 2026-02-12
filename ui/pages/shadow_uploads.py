# ui/pages/shadow_sharing.py
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

# -----------------------------------------------------------------------------
# UI
# -----------------------------------------------------------------------------

def render_shadow_sharing(parquet_root: Path):
    st.markdown("#### Shadow IT & Data Exfiltration Monitor")

    parquet_root = Path(parquet_root)
    if not parquet_root.exists():
        st.error("Data directory not found.")
        return

    available_dates = get_available_dates(parquet_root)
    if not available_dates:
        st.warning("No logs found.")
        return

    with st.expander("Detection basis (what this page detects)", expanded=False):
        st.write(
            "This page correlates Zeek telemetry (HTTP/SSL/DNS/CONN) and flags potential Shadow Sharing / Exfiltration.\n"
            "- Allowed/Unapproved is based on whitelist_domains.yaml (Allow_Basis shows which entry matched).\n"
            "- Action is inferred from HTTP method/URI patterns and client type.\n"
            "- DNS exfil heuristics flag tunneling-like query patterns.\n"
            "- Risk_Score/Severity is computed with an explainable Risk_Basis string."
        )

    # Controls
    top1, top2 = st.columns([5, 1])
    with top1:
        date_options = ["All Available Dates"] + available_dates
        selected_date = st.selectbox("Timeframe", date_options, index=1 if len(available_dates) > 0 else 0)
    with top2:
        st.write("")
        st.write("")
        if st.button("Refresh"):
            st.cache_data.clear()
            st.cache_resource.clear()
            st.rerun()

    c1, c2, c3, c4 = st.columns([2.5, 2, 2, 2])
    with c1:
        selected_sources = st.multiselect("Protocols", ["http", "ssl", "dns", "conn"], default=["http", "ssl", "dns"])
    with c2:
        show_only_unapproved = st.checkbox("Only Unapproved", value=False)
    with c3:
        min_sev = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with c4:
        min_bytes_mb = st.number_input("Min Bytes (MB)", min_value=0, value=0, step=10)

    c5, c6, c7 = st.columns([2, 2, 4])
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

    st.divider()

    # Date scope
    target_dates = available_dates if selected_date == "All Available Dates" else ([selected_date] if selected_date else [])

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
    st.markdown("---")
    m1, m2, m3, m4, m5 = st.columns(5)

    total_b = float(filtered["bytes"].sum())
    total_mb = total_b / 1024 / 1024
    unapproved = int((filtered["Allowed"] == False).sum())  # noqa: E712
    critical = int((filtered["Severity"] == "CRITICAL").sum())
    autom = int((filtered["Client_Type"] == "Automation / SDK").sum())

    uniq_mac = filtered["mac"].replace({"": None}).dropna().nunique()
    uniq_ip = filtered["id.orig_h"].replace({"": None}).dropna().nunique()
    uniq_dev = int(uniq_mac if uniq_mac > 0 else uniq_ip)

    m1.metric("Selected Events", len(filtered))
    m2.metric("Unapproved Events", unapproved, delta="Risk" if unapproved > 0 else "Clear", delta_color="inverse")
    m3.metric("Total Volume", f"{total_mb:.2f} MB")
    m4.metric("Critical", critical, delta="Investigate" if critical > 0 else "Clear", delta_color="inverse")
    m5.metric("Automation", autom)

    # Tabs
    tab_overview, tab_device, tab_dest, tab_bursts, tab_log = st.tabs(
        ["Overview", "By Device", "By Destination", "Bursts", "Event Log"]
    )

    # -------------------------------------------------------------------------
    # Overview
    # -------------------------------------------------------------------------
    with tab_overview:
        left, right = st.columns(2)

        with left:
            st.markdown("#### Category Breakdown (bytes)")
            cat_df = filtered.groupby("Category", dropna=False).agg(bytes=("bytes", "sum"), events=("ts", "count")).reset_index()
            fig_cat = px.bar(cat_df.sort_values("bytes", ascending=False), x="Category", y="bytes", hover_data=["events"], template="plotly_dark")
            st.plotly_chart(fig_cat, use_container_width=True)

        with right:
            st.markdown("#### Action Breakdown (events)")
            act_df = filtered.groupby("Action", dropna=False).agg(events=("ts", "count"), bytes=("bytes", "sum")).reset_index()
            fig_act = px.bar(act_df.sort_values("events", ascending=False), x="Action", y="events", hover_data=["bytes"], template="plotly_dark")
            st.plotly_chart(fig_act, use_container_width=True)

        st.markdown("#### Timeline (Risk)")
        fig_scatter = px.scatter(
            filtered,
            x="ts",
            y="destination",
            color="Severity",
            size="Risk_Score",
            hover_data=["mac", "host_name", "id.orig_h", "Action", "Category", "bytes", "Risk_Basis", "Allow_Basis"],
            template="plotly_dark",
            render_mode="webgl" if len(filtered) > 2000 else "auto",
        )
        st.plotly_chart(fig_scatter, use_container_width=True)

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

        st.dataframe(
            dev,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Last_Seen": st.column_config.DatetimeColumn("Last Seen", format="MM-DD HH:mm"),
                "Total_MB": st.column_config.NumberColumn("Total (MB)", format="%.2f"),
            },
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

        st.dataframe(
            dest,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Last_Seen": st.column_config.DatetimeColumn("Last Seen", format="MM-DD HH:mm"),
                "Total_MB": st.column_config.NumberColumn("Total (MB)", format="%.2f"),
            },
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
            template="plotly_dark",
            render_mode="webgl" if len(top_bursts) > 2000 else "auto",
            title="Top bursts (size=bytes, color=max risk)",
        )
        st.plotly_chart(fig, use_container_width=True)

        st.dataframe(
            top_bursts,
            use_container_width=True,
            hide_index=True,
            column_config={
                "bucket": st.column_config.DatetimeColumn("Window", format="MM-DD HH:mm"),
                "bytes": st.column_config.NumberColumn("Bytes", format="%d"),
            },
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

        st.dataframe(
            view.head(MAX_ROWS_DISPLAY),
            use_container_width=True,
            hide_index=True,
            column_config={
                "ts": st.column_config.DatetimeColumn("Time", format="MM-DD HH:mm:ss"),
                "vt_link": st.column_config.LinkColumn("VirusTotal", display_text=r".*domain/(.*)"),
                "bytes": st.column_config.NumberColumn("Bytes", format="%d"),
                "Risk_Score": st.column_config.NumberColumn("Risk", format="%d"),
            },
            column_order=[
                "ts", "host_name", "mac", "Identity_Confidence", "id.orig_h",
                "destination", "vt_link",
                "Allowed", "Allow_Basis",
                "Category", "Action",
                "bytes", "Client_Type",
                "Risk_Score", "Severity",
                "log_source", "method", "uri",
                "Risk_Basis",
                "Action_Basis",
                "DNS_Exfil_Reason",
            ],
        )


# Backward compatibility if your app imports render_shadow_uploads
def render_shadow_uploads(parquet_root: Path):
    return render_shadow_sharing(parquet_root)
