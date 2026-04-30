# ui/pages/shadow_sharings_backend.py
import re
import math
import warnings
import ipaddress
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import duckdb
import pandas as pd
import streamlit as st
import yaml

# -----------------------------------------------------------------------------
# CONFIG
# -----------------------------------------------------------------------------

CACHE_VERSION = "shadow-sharing-cache-v19-logstamp-runtime-policy"
CACHE_DIRNAME = "_shadow_cache_sharing"
DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WHITELIST_FILE = PROJECT_ROOT / "whitelist_domains.yaml"

# Sharing/service signatures (algorithm #6)
# Optional override file. If missing, built-in defaults are used.
SIGNATURES_FILE = PROJECT_ROOT / "shadow_sharing_signatures.yaml"
CATEGORY_RULES_FILE = None  # categories disabled
# Incident model (algorithm #2/#4/#5)
INCIDENT_WINDOW_MINUTES = 5
BIG_OUT_BYTES = 10 * 1024 * 1024          # 10 MB
LONG_DURATION_SEC = 60                    # 60 seconds
CHUNK_CONN_COUNT = 5
RATIO_HIGH = 5.0

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


def _meta_expected(
    files_sig: Dict[str, List[List[object]]],
) -> dict:
    return {
        "cache_version": CACHE_VERSION,
        "files_sig": files_sig,
    }

# -----------------------------------------------------------------------------
# DuckDB (fast parquet scan)
# -----------------------------------------------------------------------------

@st.cache_resource
def get_duckdb_connection():
    con = duckdb.connect(database=":memory:")
    try:
        con.execute("SET memory_limit='4GB'")
    except Exception:
        pass
    try:
        con.execute("SET threads TO 4")
    except Exception:
        pass
    try:
        con.execute("PRAGMA enable_object_cache")
    except Exception:
        pass
    try:
        con.execute("PRAGMA enable_progress_bar=false")
    except Exception:
        pass
    try:
        tmp = PROJECT_ROOT / ".duckdb_temp"
        tmp.mkdir(parents=True, exist_ok=True)
        con.execute(f"SET temp_directory='{tmp.as_posix()}'")
    except Exception:
        pass
    return con


def _sql_list(paths: List[Path]) -> str:
    escaped = []
    for p in paths:
        p0 = p.resolve().as_posix().replace("'", "''")
        escaped.append("'" + p0 + "'")
    return "[" + ",".join(escaped) + "]"


def _duck_read_parquet_union(paths: List[Path]) -> pd.DataFrame:
    if not paths:
        return pd.DataFrame()

    con = get_duckdb_connection()
    try:
        arr = _sql_list(paths)
        return con.execute(f"SELECT * FROM read_parquet({arr}, union_by_name=TRUE)").fetchdf()
    except Exception as e:
        print(f"⚠️ DuckDB Bulk Union Failed: {e}") # print logs
        # fallback: per file
        dfs: List[pd.DataFrame] = []
        for p in paths:
            try:
                dfs.append(con.execute(f"SELECT * FROM read_parquet('{p.as_posix()}')").fetchdf())
            except Exception as e2:
                print(f"🚨 DuckDB skipped file {p.name} due to error: {e2}") # <-- Add this print
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
            out: List[str] = []
            seen: set[str] = set()
            for item in v:
                domain = _extract_whitelist_domain_item(item)
                if domain and domain not in seen:
                    seen.add(domain)
                    out.append(domain)
            return out
    # also allow dict form: {domain: true}
    for k in ["trusted_domains", "whitelist_domains", "domains", "allowed_domains", "whitelist", "allowlist"]:
        if k in y and isinstance(y[k], dict):
            return [str(x).strip().lower() for x in y[k].keys()]
    return []


def _normalize_whitelist_host_early(value: object) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    s = s.split("?", 1)[0]
    s = s.split("#", 1)[0]
    if s.startswith("[") and "]" in s:
        s = s[1 : s.index("]")]
    elif s.count(":") == 1:
        host, port = s.rsplit(":", 1)
        if port.isdigit():
            s = host
    s = str(s or "").strip().strip(".").lower()
    s = s.split("%", 1)[0]
    if s in {"", "unknown", "nan", "none", "-", "(empty)", "*"}:
        return ""
    return s


def _extract_whitelist_domain_item(item: object) -> str:
    if isinstance(item, dict):
        for key in ("domain", "domain_name", "host", "name", "value"):
            value = item.get(key)
            host = _normalize_whitelist_host_early(value)
            if host:
                return host
        return ""
    return _normalize_whitelist_host_early(item)


def _normalize_whitelist_list_entries(entries: list, *, preserve_dict_rows: bool) -> list:
    normalized_rows = []
    seen: set[str] = set()
    for item in entries or []:
        domain = _extract_whitelist_domain_item(item)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        if preserve_dict_rows:
            row = {"domain": domain}
            if isinstance(item, dict):
                stamp = str(item.get("date_modified", "") or "").strip()
                if stamp:
                    row["date_modified"] = stamp
            normalized_rows.append(row)
        else:
            normalized_rows.append(domain)
    return normalized_rows


@st.cache_data(ttl=600, show_spinner=False)
def load_whitelist() -> Tuple[List[str], int]:
    y = _safe_yaml_load(WHITELIST_FILE)
    domains = _extract_whitelist_domains(y)
    domains = sorted(set([d for d in domains if d]))
    mtime_ns = int(WHITELIST_FILE.stat().st_mtime_ns) if WHITELIST_FILE.exists() else 0
    return domains, mtime_ns


WHITELIST_DOMAINS, WHITELIST_MTIME_NS = load_whitelist()


# -----------------------------------------------------------------------------
# Host/Domain Normalization (must be defined early; used during module import)
# -----------------------------------------------------------------------------
def _strip_scheme_path(value: str) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    # remove scheme
    if "://" in s:
        s = s.split("://", 1)[1]
    # remove path/query/fragment
    s = s.split("/", 1)[0]
    s = s.split("?", 1)[0]
    s = s.split("#", 1)[0]
    return s.strip()


def _split_host_port(hostport: str):
    s = str(hostport or "").strip()
    if not s:
        return "", None
    # IPv6 in brackets: [2001:db8::1]:443
    if s.startswith("[") and "]" in s:
        host = s[1 : s.index("]")]
        rest = s[s.index("]") + 1 :]
        if rest.startswith(":"):
            try:
                return host, int(rest[1:])
            except Exception:
                return host, None
        return host, None
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
    """Normalize URL/hostport/host into lowercase host without port/path."""
    s = _strip_scheme_path(value)
    host, _ = _split_host_port(s)
    host = str(host or "").strip().strip(".").lower()
    # strip IPv6 zone index like "%eth0" if present
    host = host.split("%", 1)[0]
    if host in {"", "unknown", "nan", "none", "-", "(empty)", "*"}:
        return ""
    return host

# -----------------------------------------------------------------------------
# SIGNATURES (algorithm #6)
# -----------------------------------------------------------------------------

_DEFAULT_SHARING_SIGNATURES: Dict[str, List[str]] = {
    "Google Drive": ["drive.google.com", "drive.usercontent.google.com", "googleusercontent.com"],
    "Dropbox": ["dropbox.com", "dropboxapi.com", "dropboxusercontent.com"],
    "Microsoft OneDrive/SharePoint": ["onedrive.live.com", "1drv.ms", "sharepoint.com", "sharepointonline.com", "microsoftonline.com"],
    "Box": ["box.com", "boxcdn.net"],
    "WeTransfer": ["wetransfer.com", "we.tl"],
    "MEGA": ["mega.nz", "mega.co.nz"],
    "Telegram": ["telegram.org", "t.me", "telegram.me", "telegram-cdn.org"],
    "Discord": ["discord.com", "discord.gg", "discordapp.com", "discordapp.net"],
    "Pastebin/Gist": ["pastebin.com", "gist.github.com", "raw.githubusercontent.com"],
}

def _extract_signature_map(y: dict) -> Dict[str, List[str]]:
    if not isinstance(y, dict):
        return {}
    for k in ["services", "sharing_signatures", "signatures"]:
        v = y.get(k)
        if isinstance(v, dict):
            out: Dict[str, List[str]] = {}
            for svc, doms in v.items():
                if isinstance(doms, list):
                    out[str(svc).strip() or "Uncategorized"] = [str(d).strip().lower() for d in doms if str(d).strip()]
            return out
        if isinstance(v, list):
            return {"Uncategorized": [str(d).strip().lower() for d in v if str(d).strip()]}
    if "domains" in y and isinstance(y["domains"], list):
        return {"Uncategorized": [str(d).strip().lower() for d in y["domains"] if str(d).strip()]}
    out2: Dict[str, List[str]] = {}
    for svc, doms in y.items():
        if isinstance(doms, list):
            out2[str(svc).strip() or "Uncategorized"] = [str(d).strip().lower() for d in doms if str(d).strip()]
    return out2

@st.cache_data(ttl=600, show_spinner=False)
def load_sharing_signatures() -> Tuple[Dict[str, List[str]], int]:
    y = _safe_yaml_load(SIGNATURES_FILE)
    m = _extract_signature_map(y)
    if not m:
        m = dict(_DEFAULT_SHARING_SIGNATURES)
    norm: Dict[str, List[str]] = {}
    for svc, doms in (m or {}).items():
        svc0 = str(svc).strip() or "Uncategorized"
        dom_list: List[str] = []
        for d in doms or []:
            d0 = _normalize_host(str(d))
            if d0:
                dom_list.append(d0)
        if dom_list:
            norm[svc0] = sorted(set(dom_list))
    mtime_ns = int(SIGNATURES_FILE.stat().st_mtime_ns) if SIGNATURES_FILE.exists() else 0
    return norm, mtime_ns

SIGNATURES_MAP, SIGNATURES_MTIME_NS = load_sharing_signatures()


def _extract_category_rule_map(y: dict) -> Dict[str, List[str]]:
    if not isinstance(y, dict):
        return {}

    raw = None
    for k in ["categories", "category_rules", "rules"]:
        v = y.get(k)
        if isinstance(v, dict):
            raw = v
            break
    if raw is None and all(isinstance(v, list) for v in y.values()):
        raw = y
    if not isinstance(raw, dict):
        return {}

    out: Dict[str, List[str]] = {}
    for cat, vals in raw.items():
        if not isinstance(vals, list):
            continue
        cat_name = str(cat or "").strip() or "Unknown"
        rules: List[str] = []
        for v in vals:
            d = _normalize_host(str(v))
            if d:
                rules.append(d)
        if rules:
            out[cat_name] = sorted(set(rules))
    return out


@st.cache_data(ttl=600, show_spinner=False)
def load_category_rules() -> Tuple[List[Tuple[str, List[str]]], int]:
    """Categories are disabled for Shadow Sharing (always returns empty rules)."""
    return [], 0


CATEGORY_RULES, CATEGORY_RULES_MTIME_NS = load_category_rules()


def _domain_in_signatures(dest: str, sig_map: Dict[str, List[str]]) -> Tuple[bool, str, str]:
    host = _normalize_host(dest)
    if not host:
        return (False, "", "")
    for svc, doms in (sig_map or {}).items():
        for d in (doms or []):
            d0 = str(d or "").strip().lower()
            if not d0:
                continue
            if d0.startswith("*."):
                d0 = d0[2:]
            d0 = _normalize_host(d0) or d0.strip(".")
            if not d0:
                continue
            if host == d0 or host.endswith("." + d0):
                return (True, str(svc), d0)
    return (False, "", "")


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
        key = WHITELIST_FILE.stem
        y[key] = []

    existing_list = y.get(key) or []
    preserve_dict_rows = any(isinstance(item, dict) for item in existing_list)
    normalized_rows = _normalize_whitelist_list_entries(existing_list, preserve_dict_rows=preserve_dict_rows)
    existing_domains = {
        (row.get("domain") if isinstance(row, dict) else row)
        for row in normalized_rows
        if (row.get("domain") if isinstance(row, dict) else row)
    }
    if host in existing_domains:
        return True, f"{host} already present in {key}"
    if preserve_dict_rows:
        normalized_rows.append({"domain": host, "date_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    else:
        normalized_rows.append(host)
    y[key] = normalized_rows

    try:
        WHITELIST_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(y, f, sort_keys=True)
        return True, f"Added {host} to {key}"
    except Exception as e:
        return False, f"Failed to write whitelist: {e}"


def _remove_domain_from_whitelist(domain: str) -> Tuple[bool, str]:
    """
    Remove a domain/host from whitelist_domains.yaml.

    Returns (ok, message).
    """
    host = _normalize_host(domain)
    if not host:
        return False, "Empty destination"

    y = _safe_yaml_load(WHITELIST_FILE)
    if not isinstance(y, dict):
        y = {}

    removed_from = ""
    changed = False
    keys = ["trusted_domains", "whitelist_domains", "domains", "allowed_domains", "whitelist", "allowlist"]
    for k in keys:
        v = y.get(k)
        if isinstance(v, list):
            preserve_dict_rows = any(isinstance(item, dict) for item in v)
            normalized_rows = _normalize_whitelist_list_entries(v, preserve_dict_rows=preserve_dict_rows)
            kept = []
            removed_here = False
            for item in normalized_rows:
                domain = item.get("domain") if isinstance(item, dict) else item
                if domain == host:
                    removed_here = True
                    continue
                kept.append(item)
            if removed_here:
                y[k] = kept
                removed_from = k
                changed = True
                break
        elif isinstance(v, dict):
            if host in v:
                del v[host]
                y[k] = v
                removed_from = k
                changed = True
                break

    if not changed:
        return True, f"{host} not present in whitelist"

    try:
        WHITELIST_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(y, f, sort_keys=True)
        return True, f"Removed {host} from {removed_from}"
    except Exception as e:
        return False, f"Failed to write whitelist: {e}"


def refresh_shadow_sharing_runtime_state() -> None:
    """
    Refresh in-memory whitelist/signature metadata and clear shadow-sharing caches.
    Call after mutating whitelist/signature files.
    """
    global WHITELIST_DOMAINS, WHITELIST_MTIME_NS
    global SIGNATURES_MAP, SIGNATURES_MTIME_NS
    global CATEGORY_RULES, CATEGORY_RULES_MTIME_NS

    try:
        load_whitelist.clear()
    except Exception:
        pass
    try:
        WHITELIST_DOMAINS, WHITELIST_MTIME_NS = load_whitelist()
    except Exception:
        WHITELIST_DOMAINS, WHITELIST_MTIME_NS = ([], 0)

    try:
        load_sharing_signatures.clear()
    except Exception:
        pass
    try:
        SIGNATURES_MAP, SIGNATURES_MTIME_NS = load_sharing_signatures()
    except Exception:
        SIGNATURES_MAP, SIGNATURES_MTIME_NS = ({}, 0)

    try:
        load_category_rules.clear()
    except Exception:
        pass
    try:
        CATEGORY_RULES, CATEGORY_RULES_MTIME_NS = load_category_rules()
    except Exception:
        CATEGORY_RULES, CATEGORY_RULES_MTIME_NS = ([], 0)

    for fn_name in [
        "_load_shadow_sharing_data_cached",
        "_load_shadow_sharing_bundle_cached",
        "load_shadow_sharing_incidents_data",
    ]:
        try:
            fn = globals().get(fn_name)
            if fn is not None and hasattr(fn, "clear"):
                fn.clear()
        except Exception:
            pass

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

def _extract_date_token(value: str) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw:
        return None
    if DATE_DIR_RE.match(raw):
        return raw
    if raw.startswith("date="):
        tail = raw.split("date=", 1)[1].strip()
        if DATE_DIR_RE.match(tail):
            return tail
    return None


@st.cache_data(show_spinner=False)
def get_available_dates(parquet_root: Path) -> List[str]:
    parquet_root = Path(parquet_root)
    if not parquet_root.exists():
        return []
    return sorted(_date_dir_map(parquet_root).keys(), reverse=True)


@st.cache_data(show_spinner=False)
def _date_dir_map(parquet_root: Path) -> Dict[str, str]:
    parquet_root = Path(parquet_root)
    out: Dict[str, str] = {}
    if not parquet_root.exists():
        return out
    try:
        for p in parquet_root.iterdir():
            if not p.is_dir():
                continue
            d = _extract_date_token(p.name)
            if not d:
                continue
            out.setdefault(str(d), str(p))
    except Exception:
        return out
    return out


def _resolve_date_dir(parquet_root: Path, date_str: str) -> Optional[Path]:
    root = Path(parquet_root)
    d = str(date_str or "").strip()
    if not d:
        return None

    mapped = _date_dir_map(root).get(d)
    if mapped:
        p = Path(mapped)
        if p.exists() and p.is_dir():
            return p

    direct = root / d
    if direct.exists() and direct.is_dir():
        return direct

    alt = root / f"date={d}"
    if alt.exists() and alt.is_dir():
        return alt
    return None


def _collect_known_files_uncached(parquet_root: Path) -> List[Path]:
    parquet_root = Path(parquet_root)
    known: List[Path] = []
    if not parquet_root.exists():
        return known

    def _is_cache_derived_path(p: Path) -> bool:
        for part in p.parts:
            pl = str(part).strip().lower()
            if pl.startswith("_shadow_cache"):
                return True
            if pl.startswith("_cache_"):
                return True
            if pl == ".duckdb_temp":
                return True
        return False

    try:
        for f in parquet_root.rglob("*.parquet"):
            if _is_cache_derived_path(f):
                continue
            n = f.name.lower()
            if n == "known_hosts_norm.parquet":
                continue
            if ("known_hosts" in n) or ("knownhost" in n) or ("known_devices" in n) or ("knowndevices" in n):
                known.append(f)
    except Exception:
        pass
    return sorted(set(known))


@st.cache_data(show_spinner=False)
def _collect_known_files(parquet_root: Path) -> List[Path]:
    return _collect_known_files_uncached(parquet_root)


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


def _files_signature_digest(paths: List[Path]) -> str:
    if not paths:
        return "none"
    rows: List[str] = []
    for p in sorted(set(paths)):
        try:
            st_ = p.stat()
            rows.append(f"{p.resolve().as_posix()}|{int(st_.st_mtime_ns)}|{int(st_.st_size)}")
        except Exception:
            rows.append(f"{p.resolve().as_posix()}|0|0")
    blob = "\n".join(rows).encode("utf-8")
    return hashlib.sha1(blob).hexdigest()


@st.cache_data(show_spinner=False, ttl=20)
def _target_logs_signature_cached(parquet_root_str: str, target_dates: Tuple[str, ...]) -> str:
    root = Path(parquet_root_str)
    if not root.exists():
        return "missing-root"

    scan_paths: List[Path] = []
    for d in target_dates or ():
        if not d or not DATE_DIR_RE.match(str(d)):
            continue
        date_dir = _resolve_date_dir(root, str(d))
        if date_dir is None:
            continue
        buckets = _collect_date_files(date_dir)
        for key in ["http", "ssl", "dns", "conn", "files", "dhcp"]:
            scan_paths.extend(buckets.get(key) or [])

    # identity attribution can depend on known_hosts/known_devices outside the selected date folder.
    scan_paths.extend(_collect_known_files_uncached(root))
    return _files_signature_digest(scan_paths)


def shadow_sharing_logs_signature(parquet_root: Path, target_dates: List[str]) -> str:
    root = str(Path(parquet_root).resolve())
    dates_key = _normalize_target_dates_key(target_dates)
    return _target_logs_signature_cached(root, dates_key)

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
# Action detection
# -----------------------------------------------------------------------------

UPLOAD_URI_RE = re.compile(r"(^|/)(upload|uploads|file|files|attachments|drive|share|send|transfer|content)(/|$)", re.IGNORECASE)
# Keep share-link indicators boundary-aware to avoid false positives
# such as "/molbin/.../events.json" matching on the "bin" substring.
PASTE_URI_RE = re.compile(r"(?:^|[/?._-])(paste(?:bin)?|snippet|gist)(?:$|[/?._-])", re.IGNORECASE)
REMOTE_URI_RE = re.compile(r"(remote|rdp|vpn|tunnel|teamviewer|anydesk)", re.IGNORECASE)
API_UPLOAD_RE = re.compile(r"(multipart/form-data|application/octet-stream)", re.IGNORECASE)

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
    # strip IPv6 zone index like "%eth0" if present
    host = host.split("%", 1)[0]
    if host in {"", "unknown", "nan", "none", "-", "(empty)", "*"}:
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
    # Normalize any host/IP forms and strip IPv6 zone index if present.
    s_norm = _normalize_host(s)
    s_norm = (s_norm or s).split("%", 1)[0].strip()
    if not s_norm:
        return False
    try:
        ip = ipaddress.ip_address(s_norm)
        # Treat local-only / non-routable categories as "internal/non-external" for this dashboard.
        return bool(ip.is_private or ip.is_link_local or ip.is_loopback or ip.is_multicast)
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
) -> pd.DataFrame:
    if conn_df is None or conn_df.empty:
        return pd.DataFrame()

    c = conn_df.copy()
    c = _ensure_ts_datetime(c)
    c = c.dropna(subset=["ts"])

    for col in ["uid", "id.orig_h", "id.resp_h", "id.resp_p", "proto", "service", "duration",
        "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "conn_state", "history", "orig_bytes", "resp_bytes", "orig_ip_bytes", "resp_ip_bytes", "orig_l2_addr"]:
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
    c["out_in_ratio"] = (c["bytes_out"] / (c["bytes_in"].clip(lower=1))).round(3)

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
    def _pick_dest(row):
        if row.get("dest_host_http"):
            return row["dest_host_http"], "http.host"
        if row.get("dest_host_sni"):
            return row["dest_host_sni"], "ssl.server_name"
        return _normalize_host(str(row.get("id.resp_h") or "")), "conn.id.resp_h"

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

    def _is_meaningful_text(v: object) -> bool:
        s = str(v or "").strip().lower()
        return s not in {"", "nan", "none", "-", "unknown", "(empty)"}

    def _to_boolish(v: object) -> bool:
        if isinstance(v, bool):
            return v
        s = str(v or "").strip().lower()
        return s in {"1", "true", "t", "yes", "y"}

    def _flow_source_types(row: pd.Series) -> str:
        sources: List[str] = ["conn"]

        http_present = (
            _is_meaningful_text(row.get("method", ""))
            or _is_meaningful_text(row.get("uri", ""))
            or _is_meaningful_text(row.get("user_agent", ""))
            or _is_meaningful_text(row.get("content_type", ""))
            or _is_meaningful_text(row.get("host", ""))
            or float(pd.to_numeric(row.get("request_body_len", 0), errors="coerce") or 0) > 0
            or float(pd.to_numeric(row.get("response_body_len", 0), errors="coerce") or 0) > 0
            or _to_boolish(row.get("http_any_upload", False))
            or _to_boolish(row.get("http_any_share", False))
        )
        if http_present:
            sources.append("http")

        ssl_present = (
            _is_meaningful_text(row.get("server_name", ""))
            or _is_meaningful_text(row.get("ja3", ""))
            or _is_meaningful_text(row.get("ja3s", ""))
            or _is_meaningful_text(row.get("version", ""))
            or _is_meaningful_text(row.get("cipher", ""))
            or _is_meaningful_text(row.get("curve", ""))
            or _is_meaningful_text(row.get("next_protocol", ""))
        )
        if ssl_present:
            sources.append("ssl")

        files_present = (
            float(pd.to_numeric(row.get("file_total_bytes", 0), errors="coerce") or 0) > 0
            or float(pd.to_numeric(row.get("file_seen_bytes", 0), errors="coerce") or 0) > 0
            or _is_meaningful_text(row.get("file_mime_types", ""))
            or _is_meaningful_text(row.get("file_names", ""))
            or _is_meaningful_text(row.get("file_sources", ""))
        )
        if files_present:
            sources.append("files")

        return ", ".join(sources)

    c["source_types"] = c.apply(_flow_source_types, axis=1)

    c["log_source"] = "flow"

    keep_cols = [
        "ts", "uid", "log_source",
        "id.orig_h", "id.orig_p", "orig_l2_addr",
        "id.resp_h", "id.resp_p", "proto", "service", "duration",
        "destination", "dest_domain", "Destination_Basis",
        "bytes", "bytes_out", "bytes_in", "out_in_ratio", "is_long", "is_big_out",
        "method", "uri", "user_agent", "content_type",
        "server_name", "ja3", "ja3s", "version", "cipher", "curve", "next_protocol",
        "host", "status_code", "request_body_len", "response_body_len", "http_any_upload", "http_any_share",
        "file_total_bytes", "file_seen_bytes", "file_mime_types", "file_names", "file_sources",
        "source_types",
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

    # Derived fields (algorithm #2)
    c["duration"] = pd.to_numeric(c.get("duration", 0), errors="coerce").fillna(0)
    c["is_long"] = c["duration"] >= LONG_DURATION_SEC
    c["is_big_out"] = pd.to_numeric(c.get("bytes_out", 0), errors="coerce").fillna(0) >= BIG_OUT_BYTES


def _detect_action(log_source: str, method: str, uri: str, user_agent: str, dest: str, content_type: str = "") -> Tuple[str, str]:
    """
    Returns (Action, Action_Basis)
    """
    ls = (log_source or "").lower()
    m = (method or "").upper()
    u = str(uri or "")
    d = str(dest or "")
    ua = str(user_agent or "")

    # DNS handling is represented as lookup activity
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
        # generic: any POST could be transfer or API/chat traffic.
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
    dest_raw = str(row.get("destination", "") or "").strip().lower()
    dest_unknown = dest_raw in {"", "unknown", "nan", "none", "(empty)", "*"}
    # If destination is unknown/placeholder, don't treat it as "unapproved" (avoid false penalties).
    unapproved = (not allowed) and (not dest_unknown)
    if unapproved:
        score += 15
        basis.append("destination not in whitelist")

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

    if bytes_out >= 10 * 1024 * 1024 and ratio >= 5 and unapproved:
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

    score = int(min(100, score))
    if not basis:
        basis = ["baseline"]
    return score, "; ".join(basis)


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
      - Destination naming uses http.host -> ssl.server_name -> conn.id.resp_h (no DNS answer fallback)
      - Keep dns.log rows separately for lookup visibility and context
    """
    date_dir = _resolve_date_dir(Path(parquet_root), date_str)
    if date_dir is None:
        return pd.DataFrame()
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

    expected = _meta_expected(files_sig)
    meta = read_yaml(mpath)

    if cpath.exists() and meta == expected:
        try:
            df_cached = pd.read_parquet(cpath)
            if not df_cached.empty:
                df_cached = _ensure_ts_datetime(df_cached)
                return df_cached
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
    ssl_by_uid = _build_ssl_by_uid(df_ssl) if not df_ssl.empty else pd.DataFrame()
    http_by_uid = _build_http_by_uid(df_http) if not df_http.empty else pd.DataFrame()
    files_by_uid = _build_files_by_uid(df_files) if not df_files.empty else pd.DataFrame()
    df_flow = _build_correlated_flows(df_conn, ssl_by_uid, http_by_uid, files_by_uid)

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
        d["destination"] = d["query"].astype(str).fillna("").replace({"(empty)": "", "-": "", "*": ""})
        d.loc[d["destination"].eq(""), "destination"] = "Unknown"
        d["bytes"] = 0
        d["log_source"] = "dns"
        d["source_types"] = "dns"
        d["method"] = ""
        d["uri"] = ""
        d["user_agent"] = ""
        d["content_type"] = ""
        d["Action"] = "DNS Lookup"
        d["Action_Basis"] = "dns query"
        keep = [
            "ts", "log_source", "source_types", "id.orig_h", "destination", "bytes",
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

    # Stable event identifier for unique counting.
    # - Prefer Zeek conn UID when present (correlated flow rows).
    # - Fallback to a composite key for rows that do not have uid (e.g., dns rows).
    if "event_id" not in out.columns:
        uid_norm = out["uid"].astype(str).str.strip() if "uid" in out.columns else pd.Series("", index=out.index)
        uid_ok = ~uid_norm.isin(["", "-", "(empty)", "nan", "none", "None"])
        ts_str = pd.to_datetime(out["ts"], errors="coerce").dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
        ts_str = ts_str.fillna("")
        log_src = out.get("log_source", pd.Series("", index=out.index)).astype(str).str.strip().str.lower().fillna("")
        orig_h = out.get("id.orig_h", pd.Series("", index=out.index)).astype(str).str.strip().fillna("")
        resp_h = out.get("id.resp_h", pd.Series("", index=out.index)).astype(str).str.strip().fillna("") if "id.resp_h" in out.columns else pd.Series("", index=out.index)
        dest = out.get("destination", pd.Series("", index=out.index)).astype(str).str.strip().fillna("")
        method = out.get("method", pd.Series("", index=out.index)).astype(str).str.strip().fillna("")
        uri = out.get("uri", pd.Series("", index=out.index)).astype(str).str.strip().fillna("")
        fallback = (
            "row:" + log_src + "|" + ts_str + "|" + orig_h + "|" + resp_h + "|" + dest + "|" + method + "|" + uri
        )
        out["event_id"] = ("uid:" + uid_norm).where(uid_ok, fallback)

    # identity enrichment
    out = _enrich_identity(out, ip_map, mac_map)
    out["Identity_Confidence"] = out.apply(_identity_confidence, axis=1)

    # allowlist basis (destination host/domain)
    allowed_basis = out["destination"].apply(lambda d: _domain_in_allowlist(d, WHITELIST_DOMAINS))
    out["Allowed"] = allowed_basis.apply(lambda x: bool(x[0]))
    out["Allow_Basis"] = allowed_basis.apply(lambda x: str(x[1] or ""))


    # Make Allow_Basis explicit for operator clarity.
    # If not allowed and no whitelist match, show 'no match'.
    # If destination is unknown/placeholder, show 'n/a (unknown destination)'.
    _dest_norm = out["destination"].astype(str).str.strip().str.lower()
    _dest_unknown = _dest_norm.isin({"", "unknown", "nan", "none", "(empty)", "*"})
    out.loc[_dest_unknown & (out["Allowed"] == False), "Allow_Basis"] = "n/a (unknown destination)"  # noqa: E712
    out.loc[(~_dest_unknown) & (out["Allowed"] == False) & (out["Allow_Basis"].astype(str).str.strip() == ""), "Allow_Basis"] = "no match"

    # Sharing signature match (algorithm #6)
    sig_target = out.get("dest_domain", out["destination"]).astype(str)
    sig = sig_target.apply(lambda d: _domain_in_signatures(d, SIGNATURES_MAP))
    out["Signature_Match"] = sig.apply(lambda x: bool(x[0]))
    out["Signature_Service"] = sig.apply(lambda x: str(x[1] or ""))
    out["Signature_Basis"] = sig.apply(lambda x: str(x[2] or ""))  # noqa: E712

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

    # risk score + severity + basis
    rs = out.apply(_risk_score_row, axis=1)
    out["Risk_Score"] = rs.apply(lambda x: int(x[0]))
    out["Risk_Basis"] = rs.apply(lambda x: str(x[1]))
    out["Severity"] = out["Risk_Score"].apply(_severity_label)

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


def _apply_runtime_policy_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Re-apply policy columns from in-memory whitelist/signatures.
    This keeps dashboard refreshes fast because we can reuse cached day parquet rows and
    recompute policy fields without rescanning raw logs.
    """
    if df is None or df.empty:
        return df

    out = df.copy()
    if "destination" not in out.columns:
        out["destination"] = ""

    def _normalize_host_series(series: pd.Series) -> pd.Series:
        s = series.fillna("").astype(str).str.strip().str.lower()
        s = s.str.replace(r"^[a-z][a-z0-9+.\-]*://", "", regex=True)
        s = s.str.replace(r"^//", "", regex=True)
        s = s.str.split("/").str[0].str.split("?").str[0].str.split("#").str[0]
        s = s.str.replace(r"^\[([^\]]+)\](?::\d+)?$", r"\1", regex=True)
        s = s.str.replace(r"^([^:\s]+):\d+$", r"\1", regex=True)
        s = s.str.strip().str.strip(".")
        s = s.replace({"nan": "", "none": "", "-": "", "(empty)": "", "*": ""})
        return s

    dest_raw = out["destination"].fillna("").astype(str)
    dest_host = _normalize_host_series(dest_raw)
    dest_unknown = dest_host.isin({"", "unknown"})

    # --- Allowlist matching (boundary-safe suffix match) ---
    allow_domains: List[str] = []
    for a in (WHITELIST_DOMAINS or []):
        a0 = _normalize_host(str(a or "").strip().lower())
        if a0:
            allow_domains.append(a0)
    allow_domains = sorted(set(allow_domains), key=len, reverse=True)

    allowed = pd.Series(False, index=out.index, dtype=bool)
    allow_basis = pd.Series("", index=out.index, dtype="object")
    for dom in allow_domains:
        m = (~allowed) & (dest_host.eq(dom) | dest_host.str.endswith("." + dom))
        if bool(m.any()):
            allowed.loc[m] = True
            allow_basis.loc[m] = dom

    out["Allowed"] = allowed
    out["Allow_Basis"] = allow_basis.astype(str)
    out.loc[dest_unknown & (~out["Allowed"]), "Allow_Basis"] = "n/a (unknown destination)"
    out.loc[(~dest_unknown) & (~out["Allowed"]) & (out["Allow_Basis"].astype(str).str.strip() == ""), "Allow_Basis"] = "no match"

    # --- Signature matching (first match wins, boundary-safe) ---
    sig_target_raw = out["destination"] if "dest_domain" not in out.columns else out["dest_domain"]
    sig_host = _normalize_host_series(sig_target_raw.astype(str))
    sig_match = pd.Series(False, index=out.index, dtype=bool)
    sig_service = pd.Series("", index=out.index, dtype="object")
    sig_basis = pd.Series("", index=out.index, dtype="object")
    sig_rules: List[Tuple[str, str]] = []
    for svc, doms in (SIGNATURES_MAP or {}).items():
        for d in (doms or []):
            d0 = _normalize_host(str(d or "").strip().lower())
            if d0:
                sig_rules.append((str(svc), d0))
    for svc, dom in sig_rules:
        m = (~sig_match) & (sig_host.eq(dom) | sig_host.str.endswith("." + dom))
        if bool(m.any()):
            sig_match.loc[m] = True
            sig_service.loc[m] = svc
            sig_basis.loc[m] = dom

    out["Signature_Match"] = sig_match
    out["Signature_Service"] = sig_service.astype(str)
    out["Signature_Basis"] = sig_basis.astype(str)

    # --- Client type ---
    ua = out.get("user_agent", pd.Series("", index=out.index)).fillna("").astype(str)
    ua_l = ua.str.lower()
    auto_mask = ua_l.str.contains(
        r"python|curl|wget|aiohttp|requests|httpx|postman|powershell|go-http-client|okhttp|java",
        regex=True,
        na=False,
    )
    browser_mask = ua_l.str.contains(r"mozilla|chrome|safari|edge|firefox", regex=True, na=False)
    client_type = pd.Series("Mobile / App", index=out.index, dtype="object")
    client_type.loc[browser_mask] = "Web Browser"
    client_type.loc[auto_mask] = "Automation / SDK"
    client_type.loc[ua_l.isin({"", "-"})] = "Unknown"
    out["Client_Type"] = client_type

    # --- Risk scoring (vectorized equivalent of _risk_score_row) ---
    action = out.get("Action", pd.Series("", index=out.index)).fillna("").astype(str)
    bytes_out = pd.to_numeric(out.get("bytes_out", out.get("bytes", 0)), errors="coerce").fillna(0.0)
    bytes_in = pd.to_numeric(out.get("bytes_in", 0), errors="coerce").fillna(0.0)
    ratio = pd.to_numeric(out.get("out_in_ratio", 0), errors="coerce").fillna(0.0)
    file_bytes = pd.to_numeric(out.get("file_total_bytes", 0), errors="coerce").fillna(0.0)
    req_body = pd.to_numeric(out.get("request_body_len", 0), errors="coerce").fillna(0.0)

    unapproved = (~out["Allowed"]) & (~dest_unknown)
    m_action_upload = action.isin({"Upload", "Upload (TLS)", "File Transfer (Upload)"})
    m_action_share = action.isin({"Share Link", "Paste/Share"})
    m_action_post = action.eq("Post Data")
    m_auto = out["Client_Type"].eq("Automation / SDK")

    m_out_500 = bytes_out >= (500 * 1024 * 1024)
    m_out_100 = (~m_out_500) & (bytes_out >= (100 * 1024 * 1024))
    m_out_10 = (~m_out_500) & (~m_out_100) & (bytes_out >= (10 * 1024 * 1024))
    m_high_ratio = (bytes_out >= (10 * 1024 * 1024)) & (ratio >= 5) & unapproved
    m_file_10 = file_bytes >= (10 * 1024 * 1024)
    m_req_10 = req_body >= (10 * 1024 * 1024)

    score = pd.Series(10, index=out.index, dtype="int32")
    score = (
        score
        + (unapproved.astype("int32") * 15)
        + (m_action_upload.astype("int32") * 20)
        + (m_action_share.astype("int32") * 12)
        + (m_action_post.astype("int32") * 10)
        + (m_auto.astype("int32") * 10)
        + (m_out_500.astype("int32") * 35)
        + (m_out_100.astype("int32") * 25)
        + (m_out_10.astype("int32") * 12)
        + (m_high_ratio.astype("int32") * 10)
        + (m_file_10.astype("int32") * 10)
        + (m_req_10.astype("int32") * 10)
    ).clip(lower=0, upper=100)
    out["Risk_Score"] = score.astype(int)

    reasons = pd.concat(
        [
            pd.Series("destination not in whitelist; ", index=out.index).where(unapproved, ""),
            ("action=" + action + "; ").where(m_action_upload | m_action_share, ""),
            pd.Series("http post; ", index=out.index).where(m_action_post, ""),
            pd.Series("automation user-agent; ", index=out.index).where(m_auto, ""),
            pd.Series(">=500MB outbound; ", index=out.index).where(m_out_500, ""),
            pd.Series(">=100MB outbound; ", index=out.index).where(m_out_100, ""),
            pd.Series(">=10MB outbound; ", index=out.index).where(m_out_10, ""),
            pd.Series("high outbound ratio; ", index=out.index).where(m_high_ratio, ""),
            pd.Series("files.log >=10MB; ", index=out.index).where(m_file_10, ""),
            pd.Series("http request_body_len >=10MB; ", index=out.index).where(m_req_10, ""),
        ],
        axis=1,
    ).sum(axis=1).str.rstrip("; ").str.strip()
    out["Risk_Basis"] = reasons.where(reasons.ne(""), "baseline")
    out["Severity"] = out["Risk_Score"].astype(int).apply(_severity_label)
    return out


@st.cache_resource(show_spinner=False)
def _load_shadow_sharing_data_cached(
    parquet_root_str: str,
    target_dates: Tuple[str, ...],
    cache_version: str,
    logs_signature: str,
) -> pd.DataFrame:
    # cache_version + logs_signature are explicit cache-busters.
    _ = cache_version
    _ = logs_signature

    parquet_root = Path(parquet_root_str)
    if not parquet_root.exists():
        return pd.DataFrame()

    known_files = _collect_known_files_uncached(parquet_root)

    frames: List[pd.DataFrame] = []
    for d in target_dates:
        if not d or not DATE_DIR_RE.match(str(d)):
            continue
        df_d = _build_one_date(parquet_root, str(d), known_files)
        if not df_d.empty:
            df_d["_folder_date"] = str(d)
            frames.append(df_d)

    if not frames:
        return pd.DataFrame()

    out = pd.concat(frames, ignore_index=True)
    out = _ensure_ts_datetime(out)
    out = _apply_runtime_policy_columns(out)
    return out.sort_values("ts", ascending=False)


def _normalize_target_dates_key(target_dates: List[str]) -> Tuple[str, ...]:
    return tuple(
        sorted(
            {str(d) for d in (target_dates or []) if d and DATE_DIR_RE.match(str(d))},
            reverse=True,
        )
    )


def load_shadow_sharing_data(parquet_root: Path, target_dates: List[str]) -> pd.DataFrame:
    parquet_root = Path(parquet_root).resolve()
    dates_key = _normalize_target_dates_key(target_dates)
    logs_sig = shadow_sharing_logs_signature(parquet_root, list(dates_key))
    return _load_shadow_sharing_data_cached(
        str(parquet_root),
        dates_key,
        CACHE_VERSION,
        str(logs_sig),
    )



# -----------------------------------------------------------------------------
# INCIDENT ROLLUP (algorithm #5) + CONFIDENCE MODEL (algorithm #4)
# -----------------------------------------------------------------------------

def _confidence_label(score: int) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "PROBABLE"
    return "WEAK"

def build_shadow_sharing_incidents(events_df: pd.DataFrame, window_minutes: int = INCIDENT_WINDOW_MINUTES) -> pd.DataFrame:
    if events_df is None or events_df.empty:
        return pd.DataFrame()

    df = events_df.copy()
    df = _ensure_ts_datetime(df)
    log_src = df.get("log_source", pd.Series("", index=df.index)).astype(str).str.strip().str.lower()
    df = df[log_src.eq("flow")].copy()
    if df.empty:
        return pd.DataFrame()

    if "event_id" in df.columns:
        df = df.drop_duplicates(subset=["event_id"], keep="last")
    else:
        dedupe_cols = [c for c in ["uid", "ts", "id.orig_h", "destination", "bytes_out", "bytes_in", "duration"] if c in df.columns]
        if dedupe_cols:
            df = df.drop_duplicates(subset=dedupe_cols, keep="last")
        else:
            df = df.drop_duplicates()

    def _clean_text(col_name: str, *, lower: bool = False) -> pd.Series:
        raw = df.get(col_name, pd.Series("", index=df.index))
        s = raw.astype(str).str.strip()
        if lower:
            s = s.str.lower()
        s = s.replace({"nan": "", "none": "", "None": "", "-": "", "(empty)": "", "unknown": ""})
        return s.mask(s.eq(""), pd.NA)

    def _coerce_bool_series(raw_series: pd.Series) -> pd.Series:
        if pd.api.types.is_bool_dtype(raw_series):
            return raw_series.fillna(False).astype(bool)
        t = raw_series.astype(str).str.strip().str.lower()
        return t.isin(["1", "true", "t", "yes", "y"])

    mac = _clean_text("orig_l2_addr", lower=True).fillna("")
    ip = _clean_text("id.orig_h").fillna("")
    df["device_id"] = mac.where(mac.ne(""), "ip:" + ip)

    dom = _clean_text("dest_domain", lower=True)
    dest_for_dom = _clean_text("destination", lower=True)
    df["domain"] = dom.fillna(dest_for_dom).fillna("")

    if "source_types" in df.columns:
        src_text = df["source_types"].astype(str).str.lower()
    else:
        src_text = pd.Series("conn", index=df.index, dtype="object")

    def _has_text_columns(cols: List[str]) -> pd.Series:
        m = pd.Series(False, index=df.index)
        for c in cols:
            if c in df.columns:
                t = df[c].astype(str).str.strip().str.lower()
                m = m | ~t.isin(["", "nan", "none", "-", "unknown", "(empty)"])
        return m

    df["_src_conn"] = True
    src_http = src_text.str.contains(r"\bhttp\b", regex=True, na=False)
    src_ssl = src_text.str.contains(r"\bssl\b", regex=True, na=False)
    src_dns = src_text.str.contains(r"\bdns\b", regex=True, na=False)
    src_files = src_text.str.contains(r"\bfiles\b", regex=True, na=False)

    http_infer = _has_text_columns(["method", "uri", "user_agent", "content_type", "host"])
    for c in ["request_body_len", "response_body_len"]:
        if c in df.columns:
            http_infer = http_infer | (pd.to_numeric(df[c], errors="coerce").fillna(0) > 0)
    for c in ["http_any_upload", "http_any_share"]:
        if c in df.columns:
            http_infer = http_infer | _coerce_bool_series(pd.Series(df[c], index=df.index))

    ssl_infer = _has_text_columns(["server_name", "ja3", "ja3s", "version", "cipher", "curve", "next_protocol"])

    files_infer = pd.Series(False, index=df.index)
    for c in ["file_total_bytes", "file_seen_bytes"]:
        if c in df.columns:
            files_infer = files_infer | (pd.to_numeric(df[c], errors="coerce").fillna(0) > 0)
    files_infer = files_infer | _has_text_columns(["file_mime_types", "file_names", "file_sources"])

    df["_src_http"] = src_http | http_infer
    df["_src_ssl"] = src_ssl | ssl_infer
    df["_src_dns"] = src_dns
    df["_src_files"] = src_files | files_infer

    df["bytes_out"] = pd.to_numeric(df.get("bytes_out", pd.Series(0, index=df.index)), errors="coerce").fillna(0)
    df["bytes_in"] = pd.to_numeric(df.get("bytes_in", pd.Series(0, index=df.index)), errors="coerce").fillna(0)
    df["duration"] = pd.to_numeric(df.get("duration", pd.Series(0, index=df.index)), errors="coerce").fillna(0)
    df["is_long"] = df["duration"] >= LONG_DURATION_SEC
    df["is_big_out"] = df["bytes_out"] >= BIG_OUT_BYTES
    # Share-link evidence:
    # Only from explicit http_any_share markers (do not infer from Action/Action_Basis).
    _http_any_share = _coerce_bool_series(pd.Series(df.get("http_any_share", False), index=df.index))
    df["http_share_evidence"] = _http_any_share
    df["sig_match_b"] = _coerce_bool_series(pd.Series(df.get("Signature_Match", False), index=df.index))
    df["allowed_b"] = _coerce_bool_series(pd.Series(df.get("Allowed", False), index=df.index))

    df["day"] = df["ts"].dt.date
    rep = (
        df.groupby(["device_id", "domain"], dropna=False)["day"]
        .nunique()
        .reset_index()
        .rename(columns={"day": "active_days"})
    )
    df = df.merge(rep, on=["device_id", "domain"], how="left")

    w = max(1, int(window_minutes))
    df["time_window"] = df["ts"].dt.floor(f"{w}min")

    # Clean text fields once, then use groupby.last (fast + stable).
    text_map = {
        "mac": _clean_text("orig_l2_addr", lower=True),
        "host_name": _clean_text("host_name"),
        "orig_ip": _clean_text("id.orig_h"),
        "destination": _clean_text("destination"),
        "sig_service": _clean_text("Signature_Service"),
        "allow_basis": _clean_text("Allow_Basis"),
        "action": _clean_text("Action"),
        "action_basis": _clean_text("Action_Basis"),
        "method": _clean_text("method"),
        "uri": _clean_text("uri"),
        "user_agent": _clean_text("user_agent"),
        "file_names": _clean_text("file_names"),
        "file_mime_types": _clean_text("file_mime_types"),
        "uid_clean": _clean_text("uid"),
    }
    for k, s in text_map.items():
        df[f"__{k}"] = s

    group_keys = ["device_id", "domain", "time_window"]
    gb = df.groupby(group_keys, dropna=False)

    agg_num = gb.agg(
        first_ts=("ts", "min"),
        last_ts=("ts", "max"),
        bytes_out_total=("bytes_out", "sum"),
        bytes_in_total=("bytes_in", "sum"),
        total_duration=("duration", "sum"),
        conn_count=("__uid_clean", "nunique"),
        sig_match=("sig_match_b", "max"),
        allowed=("allowed_b", "max"),
        http_share=("http_share_evidence", "max"),
        any_long=("is_long", "max"),
        any_big_out=("is_big_out", "max"),
        active_days=("active_days", "max"),
        src_conn=("_src_conn", "max"),
        src_http=("_src_http", "max"),
        src_ssl=("_src_ssl", "max"),
        src_dns=("_src_dns", "max"),
        src_files=("_src_files", "max"),
    ).reset_index()

    # Fallback when uid is unavailable.
    event_counts = gb.size().reset_index(name="event_count")
    agg = agg_num.merge(event_counts, on=group_keys, how="left")
    agg["conn_count"] = pd.to_numeric(agg.get("conn_count", 0), errors="coerce").fillna(0)
    agg["event_count"] = pd.to_numeric(agg.get("event_count", 0), errors="coerce").fillna(0)
    agg.loc[agg["conn_count"] <= 0, "conn_count"] = agg.loc[agg["conn_count"] <= 0, "event_count"]
    agg["conn_count"] = agg["conn_count"].astype(int)
    agg = agg.drop(columns=["event_count"], errors="ignore")

    text_cols = [
        "__mac",
        "__host_name",
        "__orig_ip",
        "__destination",
        "__sig_service",
        "__allow_basis",
        "__action",
        "__action_basis",
                "__method",
        "__uri",
        "__user_agent",
        "__file_names",
        "__file_mime_types",
    ]
    last_txt = gb[text_cols].last().reset_index()
    agg = agg.merge(last_txt, on=group_keys, how="left")
    agg = agg.rename(
        columns={
            "__mac": "mac",
            "__host_name": "host_name",
            "__orig_ip": "orig_ip",
            "__destination": "destination",
            "__sig_service": "sig_service",
            "__allow_basis": "allow_basis",
            "__action": "action",
            "__action_basis": "action_basis",
                        "__method": "method",
            "__uri": "uri",
            "__user_agent": "user_agent",
            "__file_names": "file_names",
            "__file_mime_types": "file_mime_types",
        }
    )

    # Capture an example HTTP share URI/method from rows where http_any_share was true in this window.
    if "http_share_evidence" in df.columns:
        share_rows = df[df["http_share_evidence"].fillna(False).astype(bool)].copy()
        if not share_rows.empty:
            share_txt = (
                share_rows.groupby(group_keys, dropna=False)[["__method", "__uri"]]
                .last()
                .reset_index()
                .rename(columns={"__method": "share_method", "__uri": "share_uri"})
            )
            agg = agg.merge(share_txt, on=group_keys, how="left")

    src_cols = ["conn", "http", "ssl", "dns", "files"]
    src_flags = ["src_conn", "src_http", "src_ssl", "src_dns", "src_files"]

    def _compose_sources(row) -> str:
        out: List[str] = []
        for c_name, f_name in zip(src_cols, src_flags):
            if bool(row.get(f_name, False)):
                out.append(c_name)
        return ", ".join(out) if out else "conn"

    agg["source_types"] = agg.apply(_compose_sources, axis=1)
    agg = agg.drop(columns=src_flags, errors="ignore")

    agg["bytes_out_total"] = pd.to_numeric(agg.get("bytes_out_total", 0), errors="coerce").fillna(0)
    agg["bytes_in_total"] = pd.to_numeric(agg.get("bytes_in_total", 0), errors="coerce").fillna(0)
    agg = agg[agg["bytes_out_total"] > 0].copy()
    if agg.empty:
        return pd.DataFrame()

    agg["out_in_ratio_total"] = (
        agg["bytes_out_total"] / agg["bytes_in_total"].clip(lower=1)
    ).replace([math.inf, -math.inf], 0).fillna(0).round(3)
    cond_sig = agg["sig_match"].fillna(False).astype(bool)
    cond_not_allowed = ~agg["allowed"].fillna(False).astype(bool)
    cond_upload = (agg["bytes_out_total"] >= BIG_OUT_BYTES) & (agg["out_in_ratio_total"] >= RATIO_HIGH)
    cond_chunking = agg["conn_count"] >= CHUNK_CONN_COUNT
    cond_share = agg["http_share"].fillna(False).astype(bool)
    cond_repeat = (pd.to_numeric(agg.get("active_days", 0), errors="coerce").fillna(0) >= 2) & cond_not_allowed

    agg["confidence_score"] = (
        cond_sig.astype(int) * 40
        + cond_not_allowed.astype(int) * 30
        + cond_upload.astype(int) * 30
        + cond_chunking.astype(int) * 15
        + cond_share.astype(int) * 40
        + cond_repeat.astype(int) * 20
    ).clip(upper=100).astype(int)
    agg["confidence"] = agg["confidence_score"].apply(_confidence_label)
    reason_chunks: List[pd.Series] = []
    reason_chunks.append(pd.Series("signature: known sharing service; ", index=agg.index).where(cond_sig, ""))
    reason_chunks.append(pd.Series("policy: not allowlisted; ", index=agg.index).where(cond_not_allowed, ""))
    reason_chunks.append(pd.Series("upload: >=10MB and high out/in ratio; ", index=agg.index).where(cond_upload, ""))
    reason_chunks.append(pd.Series("chunking: many conns in window; ", index=agg.index).where(cond_chunking, ""))
    # HTTP share-link evidence details (derived from correlated http.log markers)
    _m_share = agg.get("share_method", pd.Series("", index=agg.index)).astype(str).str.strip()
    _u_share = agg.get("share_uri", pd.Series("", index=agg.index)).astype(str).str.strip()
    _m_fallback = agg.get("method", pd.Series("", index=agg.index)).astype(str).str.strip()
    _u_fallback = agg.get("uri", pd.Series("", index=agg.index)).astype(str).str.strip()
    _m = _m_share.where(_m_share.ne(""), _m_fallback).str.upper()
    _u = _u_share.where(_u_share.ne(""), _u_fallback)
    _detail = (_m + " " + _u).str.strip()
    _detail = _detail.where(_detail.ne(""), "http_any_share=True")
    _detail = _detail.where(_detail.str.len() <= 220, _detail.str.slice(0, 217) + "...")
    http_share_reason = ("http_any_share evidence: " + _detail + "; ")
    reason_chunks.append(http_share_reason.where(cond_share, ""))
    reason_chunks.append(pd.Series("repeat: seen across >=2 days; ", index=agg.index).where(cond_repeat, ""))
    agg["confidence_reasons"] = pd.concat(reason_chunks, axis=1).sum(axis=1).str.rstrip("; ").str.strip()
    agg["is_shadow_sharing"] = (agg["sig_match"] == True) & (agg["allowed"] == False) & (agg["confidence_score"] >= 50)  # noqa: E712
    agg["incident_id"] = agg["device_id"].astype(str) + "|" + agg["domain"].astype(str) + "|" + agg["time_window"].astype(str)

    cols = [
        "incident_id",
        "first_ts", "last_ts",
        "mac", "host_name", "orig_ip",
        "source_types",
        "destination", "domain",
        "action", "action_basis",
        "sig_service",
        "allowed", "allow_basis",
        "bytes_out_total", "bytes_in_total", "out_in_ratio_total",
        "conn_count", "total_duration",
        "method", "uri", "user_agent",
        "file_names", "file_mime_types",
        "any_long", "any_big_out",
        "active_days",
        "confidence_score", "confidence", "confidence_reasons",
        "is_shadow_sharing",
    ]
    cols = [c for c in cols if c in agg.columns]
    out = agg[cols].drop_duplicates(subset=["incident_id"], keep="last")
    return out.sort_values(["confidence_score", "bytes_out_total", "conn_count", "last_ts"], ascending=[False, False, False, False])

@st.cache_resource(show_spinner=False)
def _load_shadow_sharing_bundle_cached(
    parquet_root_str: str,
    target_dates: Tuple[str, ...],
    cache_version: str,
    logs_signature: str,
    incident_window_minutes: int,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    # Keep these in the cache key for safe invalidation.
    _ = cache_version
    _ = logs_signature

    events = _load_shadow_sharing_data_cached(
        parquet_root_str,
        target_dates,
        cache_version,
        logs_signature,
    )
    if events is None or events.empty:
        return pd.DataFrame(), pd.DataFrame()
    incidents = build_shadow_sharing_incidents(events, max(1, int(incident_window_minutes or INCIDENT_WINDOW_MINUTES)))
    return events, incidents


def load_shadow_sharing_bundle(parquet_root: Path, target_dates: List[str]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    root = Path(parquet_root).resolve()
    dates_key = _normalize_target_dates_key(target_dates)
    logs_sig = shadow_sharing_logs_signature(root, list(dates_key))
    return _load_shadow_sharing_bundle_cached(
        str(root),
        dates_key,
        CACHE_VERSION,
        str(logs_sig),
        int(INCIDENT_WINDOW_MINUTES),
    )


@st.cache_resource(show_spinner=False)
def load_shadow_sharing_incidents_data(parquet_root: Path, target_dates: List[str]) -> pd.DataFrame:
    _, incidents = load_shadow_sharing_bundle(parquet_root, target_dates)
    return incidents
