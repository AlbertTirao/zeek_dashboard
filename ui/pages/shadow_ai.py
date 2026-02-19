# ui/pages/shadow_ai.py
# Shadow AI SOC dashboard (fast per-date cache, strong identity enrichment, and full analytics views)

import re
import warnings
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import pandas as pd
import streamlit as st
import plotly.express as px
import yaml
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode

# =============================================================================
# FAST LOAD / CACHE CONFIG (MATCH SHADOW APPS DIRECTORY PATTERN)
# =============================================================================

CACHE_VERSION = "shadow-ai-cache-v7"
CACHE_DIRNAME = "_shadow_cache_ai"
DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
AI_SIGNATURES_FILE = PROJECT_ROOT / "ai_signatures.yaml"


# =============================================================================
# CACHE HELPERS (MATCH SHADOW APPS)
# =============================================================================

def cache_dir(parquet_root: Path) -> Path:
    # IMPORTANT: cache lives under the parquet_root (same style as shadow apps)
    # data/parquet/_shadow_cache_ai/date=YYYY-MM-DD/...
    return Path(parquet_root) / CACHE_DIRNAME


def cache_ai_events_path(parquet_root: Path, date_str: str) -> Path:
    return cache_dir(parquet_root) / f"date={date_str}" / "shadow_ai.parquet"


def cache_ai_meta_path(parquet_root: Path, date_str: str) -> Path:
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


# =============================================================================
# YAML LOADER
# =============================================================================

def _safe_yaml_load(path: Path) -> dict:
    try:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _harden_pattern(p: str) -> str:
    """
    YAML uses regex fragments. Harden to reduce false positives.
    """
    if not p:
        return p
    if any(tok in p for tok in ["^", "$", "(?=", "(?<", "(?:^", r"\b"]):
        return p
    return rf"(?:^|[^a-z0-9_-])(?:{p})(?:$|[^a-z0-9_-])"


@st.cache_data(ttl=600, show_spinner=False)
def load_ai_signatures() -> Tuple[List[str], Dict[str, List[str]], Dict[str, List[str]], Dict[int, str], int]:
    """
    Reads ai_signatures.yaml:
      - ai_signatures: provider -> [regex fragments]
      - local_ai_ports: port -> label
      - authorized_providers: [provider names]
    """
    y = _safe_yaml_load(AI_SIGNATURES_FILE)

    authorized = y.get("authorized_providers", []) or []
    ai_sigs = y.get("ai_signatures", {}) or {}
    local_ports = y.get("local_ai_ports", {}) or {}

    authorized = [str(x).strip() for x in authorized if str(x).strip()]

    raw_ai: Dict[str, List[str]] = {}
    hardened_ai: Dict[str, List[str]] = {}
    for prov, pats in ai_sigs.items():
        prov = str(prov).strip()
        if not prov:
            continue
        pats = pats or []
        raw_list: List[str] = []
        hard_list: List[str] = []
        for p in pats:
            p = str(p).strip()
            if not p:
                continue
            raw_list.append(p)
            hard_list.append(_harden_pattern(p))
        if raw_list:
            raw_ai[prov] = raw_list
            hardened_ai[prov] = hard_list

    fixed_ports: Dict[int, str] = {}
    for k, v in local_ports.items():
        try:
            fixed_ports[int(k)] = str(v).strip() if str(v).strip() else f"Port {k}"
        except Exception:
            continue

    mtime_ns = int(AI_SIGNATURES_FILE.stat().st_mtime_ns) if AI_SIGNATURES_FILE.exists() else 0
    return authorized, raw_ai, hardened_ai, fixed_ports, mtime_ns


AUTHORIZED_PROVIDERS, RAW_AI_SIGNATURES, AI_SIGNATURES, LOCAL_AI_PORTS, SIG_MTIME_NS = load_ai_signatures()
AUTHORIZED_SET = {x.lower() for x in AUTHORIZED_PROVIDERS}


def _build_master_pattern(hardened_ai: Dict[str, List[str]]) -> str:
    pats: List[str] = []
    for _, lst in (hardened_ai or {}).items():
        pats.extend([p for p in (lst or []) if p])
    if not pats:
        return r"$^"
    return "(?:" + "|".join(sorted(set(pats))) + ")"


MASTER_PATTERN = _build_master_pattern(AI_SIGNATURES)


# =============================================================================
# NORMALIZATION + IDENTITY HELPERS
# =============================================================================

_MAC_HEX_RE = re.compile(r"[^0-9a-fA-F]")
_ISO_LIKE = re.compile(
    r"^\d{4}-\d{2}-\d{2}"
    r"(?:[ T]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2})?)?$"
)


def normalize_mac(value) -> Optional[str]:
    """Normalize MAC to 'aa:bb:cc:dd:ee:ff'. Return None if invalid."""
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


def _ensure_ts_datetime(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize ts to datetime.
    Avoids pandas warning and reduces NaT when ts is epoch seconds.
    """
    if "ts" not in df.columns:
        df["ts"] = pd.NaT
        return df

    s = df["ts"]
    if pd.api.types.is_datetime64_any_dtype(s):
        return df

    # numeric epoch seconds
    if pd.api.types.is_numeric_dtype(s):
        df["ts"] = pd.to_datetime(s, unit="s", errors="coerce")
        return df

    # string/object
    s_str = s.astype(str).str.strip()
    s_str = s_str.replace({"": None, "-": None, "nan": None, "None": None})

    # numeric strings -> epoch seconds
    num = pd.to_numeric(s_str, errors="coerce")
    if num.notna().mean() >= 0.80:
        df["ts"] = pd.to_datetime(num, unit="s", errors="coerce")
        return df

    # mostly ISO-like
    non_na = s_str.dropna()
    if len(non_na) > 0 and (non_na.apply(lambda x: bool(_ISO_LIKE.match(x))).mean() >= 0.80):
        df["ts"] = pd.to_datetime(s_str, format="ISO8601", errors="coerce")
        return df

    # last resort (slow): suppress only this warning
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Could not infer format", category=UserWarning)
        df["ts"] = pd.to_datetime(s_str, errors="coerce")

    return df


def _clean_ip_series(s: pd.Series) -> pd.Series:
    s = s.astype(str).str.strip()
    return s.replace({"": None, "-": None, "nan": None, "None": None})


def fingerprint_client(ua: str) -> str:
    """Identify if actor is Browser, Automation SDK, or App."""
    if pd.isna(ua) or ua in ["-", ""]:
        return "Unknown"
    ua = str(ua).lower()
    if any(x in ua for x in ["python", "curl", "wget", "aiohttp", "requests", "httpx", "langchain", "openai-python"]):
        return "Automation / SDK"
    if any(x in ua for x in ["mozilla", "chrome", "safari", "edge", "firefox"]):
        return "Web Browser"
    return "Mobile / App"


def _read_parquet_columns(path: Path, desired_cols: List[str]) -> pd.DataFrame:
    """
    Robust parquet read:
      - Try reading only desired columns
      - If it fails (missing columns), read full file then subset
    """
    try:
        return pd.read_parquet(path, columns=desired_cols)
    except Exception:
        try:
            df = pd.read_parquet(path)
            if df.empty:
                return df
            cols = [c for c in desired_cols if c in df.columns]
            return df[cols] if cols else df
        except Exception:
            return pd.DataFrame()


def _assign_provider_and_signature(text_series: pd.Series) -> Tuple[pd.Series, pd.Series]:
    """
    First matching provider wins; Signature_Match stores the raw fragment.
    """
    provider = pd.Series(index=text_series.index, dtype="object")
    sig = pd.Series(index=text_series.index, dtype="object")
    remaining = provider.isna()

    for prov, raw_list in (RAW_AI_SIGNATURES or {}).items():
        hard_list = AI_SIGNATURES.get(prov, [])
        for raw_frag, hard_pat in zip(raw_list, hard_list):
            if not remaining.any():
                break
            try:
                m = remaining & text_series.str.contains(hard_pat, case=False, na=False, regex=True)
            except Exception:
                continue
            if m.any():
                provider[m] = prov
                sig[m] = raw_frag
                remaining = provider.isna()

    return provider.fillna("Unknown"), sig.fillna("-")


def _build_identity_maps(dhcp_files: List[Path], known_files: List[Path]) -> Tuple[Dict[str, Tuple[Optional[str], str]], Dict[str, str]]:
    """
    Build:
      ip_map: ip -> (mac, host_name)
      mac_map: mac -> host_name
    """
    ip_map: Dict[str, Tuple[Optional[str], str]] = {}
    mac_map: Dict[str, str] = {}

    def ingest(df: pd.DataFrame) -> None:
        nonlocal ip_map, mac_map
        if df.empty:
            return

        df = _ensure_ts_datetime(df)

        ip_col = next((c for c in ["client_addr", "assigned_addr", "addr", "ip", "ip_addr", "host_ip", "id.orig_h"] if c in df.columns), None)
        mac_col = next((c for c in ["mac", "l2_addr", "orig_l2_addr", "hwaddr", "src_mac"] if c in df.columns), None)
        host_col = next((c for c in ["host_name", "hostname", "device_name", "host"] if c in df.columns), None)

        if ip_col is None and mac_col is None:
            return

        if ip_col is not None:
            df[ip_col] = _clean_ip_series(df[ip_col])

        if mac_col is not None:
            df[mac_col] = df[mac_col].apply(normalize_mac)

        if host_col is not None:
            df[host_col] = df[host_col].astype(str).str.strip().replace({"nan": "", "None": "", "-": ""})
        else:
            host_col = "__host"
            df[host_col] = ""

        # Sort by ts so "last" is most recent
        if "ts" in df.columns:
            df = df.sort_values("ts")

        # ip -> (mac, host)
        if ip_col is not None:
            sub_cols = ["ts", ip_col, host_col] + ([mac_col] if mac_col is not None else [])
            sub = df[sub_cols].copy()
            sub = sub.dropna(subset=[ip_col])

            def last_non_null_mac(x: pd.Series):
                x = x.dropna()
                return x.iloc[-1] if len(x) else None

            def last_non_empty_host(x: pd.Series):
                x = x.astype(str).replace({"nan": "", "None": "", "-": ""})
                x = x[x != ""]
                return x.iloc[-1] if len(x) else ""

            if mac_col is not None:
                g = sub.groupby(ip_col, dropna=True).agg(
                    mac=(mac_col, last_non_null_mac),
                    host=(host_col, last_non_empty_host),
                )
            else:
                g = sub.groupby(ip_col, dropna=True).agg(host=(host_col, last_non_empty_host))
                g["mac"] = None

            for ip, r in g.iterrows():
                ip_map[str(ip)] = (r.get("mac", None), r.get("host", "") or "")

        # mac -> host
        if mac_col is not None:
            subm = df[[mac_col, host_col] + (["ts"] if "ts" in df.columns else [])].copy()
            subm = subm.dropna(subset=[mac_col])
            subm[host_col] = subm[host_col].astype(str).replace({"nan": "", "None": "", "-": ""})
            subm = subm[subm[host_col] != ""]
            if not subm.empty:
                if "ts" in subm.columns:
                    subm = subm.sort_values("ts")
                gm = subm.groupby(mac_col, dropna=True).agg(host=(host_col, lambda x: x.iloc[-1] if len(x) else ""))
                for mac, r in gm.iterrows():
                    if mac and r.get("host", ""):
                        mac_map[str(mac)] = r["host"]

    # DHCP
    for f in dhcp_files:
        df = _read_parquet_columns(f, ["ts", "mac", "client_addr", "assigned_addr", "host_name", "hostname", "id.orig_h", "orig_l2_addr"])
        ingest(df)

    # known_hosts / known_devices
    for f in known_files:
        df = _read_parquet_columns(f, ["ts", "mac", "l2_addr", "orig_l2_addr", "addr", "ip", "host_name", "hostname", "device_name", "id.orig_h"])
        ingest(df)

    return ip_map, mac_map


def _enrich_identity(events: pd.DataFrame, ip_map: Dict[str, Tuple[Optional[str], str]], mac_map: Dict[str, str]) -> pd.DataFrame:
    """
    Enrich mac/host_name.
    Priority:
      1) orig_l2_addr/l2_addr/src_mac in events
      2) id.orig_h -> ip_map
      3) mac -> mac_map
    """
    if events.empty:
        return events

    if "mac" not in events.columns:
        events["mac"] = None
    if "host_name" not in events.columns:
        events["host_name"] = None

    # 1) L2 fields in event
    for c in ["orig_l2_addr", "l2_addr", "src_mac"]:
        if c in events.columns:
            tmp = events[c].apply(normalize_mac)
            events["mac"] = events["mac"].where(events["mac"].notna() & (events["mac"] != ""), tmp)
            break

    events["mac"] = events["mac"].apply(normalize_mac)

    # 2) IP map
    if "id.orig_h" in events.columns:
        ips = _clean_ip_series(events["id.orig_h"])
        mac_from_ip = ips.map(lambda ip: ip_map.get(ip, (None, ""))[0] if ip else None)
        host_from_ip = ips.map(lambda ip: ip_map.get(ip, (None, ""))[1] if ip else "")

        events["mac"] = events["mac"].where(events["mac"].notna(), mac_from_ip)
        events["host_name"] = events["host_name"].where(
            events["host_name"].notna() & (events["host_name"] != ""),
            host_from_ip,
        )

    # 3) mac map
    events["mac"] = events["mac"].apply(normalize_mac)
    macs = events["mac"].astype(str).replace({"nan": "", "None": ""})
    host_from_mac = macs.map(lambda m: mac_map.get(m, "") if m else "")
    events["host_name"] = events["host_name"].where(
        events["host_name"].notna() & (events["host_name"] != ""),
        host_from_mac,
    )

    # final clean (no forced "Unknown")
    events["mac"] = events["mac"].astype(str).fillna("").replace({"None": "", "nan": ""})
    events["host_name"] = events["host_name"].astype(str).fillna("").replace({"None": "", "nan": ""})
    return events


# =============================================================================
# SCORING / POLICY
# =============================================================================

def calculate_severity(row: pd.Series) -> int:
    """
    SOC-grade scoring (0-100)
    """
    score = 10
    source = str(row.get("Detection_Source", "DNS")).upper()

    if source == "HTTP":
        score += 20
        if str(row.get("method", "")).upper() == "POST":
            score += 20

        bytes_out = float(row.get("Upload_Bytes", 0) or 0)
        if bytes_out > 5 * 1024 * 1024:
            score += 40
        elif bytes_out > 1 * 1024 * 1024:
            score += 20
        elif bytes_out > 10 * 1024:
            score += 10

        uri = str(row.get("Detail", "")).lower()
        if any(x in uri for x in ["/upload", "/files", "/embeddings", "/fine-tune", "/v1/files", "v1/embeddings", "v1/chat/completions"]):
            score += 15

    elif source == "SSL":
        score += 15
    elif source.startswith("DNS"):
        score += 8
    elif source.startswith("CONN"):
        score += 12

    if row.get("Client_Type") == "Automation / SDK":
        score += 15

    return int(min(100, score))


def normalize_severity_label(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _policy_verdict(provider: str) -> str:
    return "Allowed" if str(provider).lower() in AUTHORIZED_SET else "Shadow AI"


def _policy_basis(provider: str) -> str:
    if not AUTHORIZED_PROVIDERS:
        return "authorized_providers is empty (default deny)"
    if str(provider).lower() in AUTHORIZED_SET:
        return "Provider is on allowlist"
    return "Provider is not on allowlist"


def _evidence_type(row: pd.Series) -> str:
    src = str(row.get("Detection_Source", "")).upper()
    if src == "HTTP":
        m = str(row.get("method", "")).upper()
        return f"HTTP+{m}" if m else "HTTP"
    if src == "SSL":
        return "TLS SNI"
    if src == "DNS":
        return "DNS query"
    if src.startswith("CONN"):
        return "Local Port"
    return src or "Unknown"


def _confidence(src: str) -> str:
    # Simple confidence grading
    s = str(src).upper()
    if s in ("HTTP", "SSL"):
        return "High"
    return "Medium"


def _to_domain_from_destination(dest: str) -> str:
    """
    Destination could be:
      - "api.openai.com:443"
      - "api.openai.com"
      - "SNI: api.openai.com"
      - "chatgpt.com"
    Produce a domain-like key for aggregation.
    """
    if dest is None:
        return ""
    s = str(dest).strip()
    if not s or s.lower() in ("nan", "none", "-"):
        return ""
    s = s.replace("SNI:", "").strip()
    # strip port if any
    if ":" in s:
        # keep IPv6? For this dashboard, we want host part (best effort)
        # If it's IPv6, it contains multiple ':', so only strip last ":port" if last part numeric.
        parts = s.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            s = parts[0]
    return s.lower()


# =============================================================================
# FILE DISCOVERY
# =============================================================================

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
    """
    Scan root once for known_hosts/known_devices parquets.
    Cached by Streamlit.
    """
    parquet_root = Path(parquet_root)
    known: List[Path] = []
    if not parquet_root.exists():
        return known
    try:
        for f in parquet_root.rglob("*.parquet"):
            name = f.name.lower()
            if ("known_hosts" in name) or ("knownhost" in name) or ("known_devices" in name) or ("knowndevices" in name):
                known.append(f)
    except Exception:
        pass
    return sorted(set(known))


def _collect_date_logs(date_dir: Path) -> Dict[str, List[Path]]:
    buckets = {"http": [], "ssl": [], "dns": [], "conn": [], "dhcp": []}
    if not date_dir.exists():
        return buckets
    try:
        for f in date_dir.rglob("*.parquet"):
            name = f.name.lower()
            if name.startswith("http"):
                buckets["http"].append(f)
            elif name.startswith("ssl"):
                buckets["ssl"].append(f)
            elif name.startswith("dns"):
                buckets["dns"].append(f)
            elif name.startswith("conn"):
                buckets["conn"].append(f)
            elif name.startswith("dhcp"):
                buckets["dhcp"].append(f)
    except Exception:
        pass

    for k in buckets:
        buckets[k] = sorted(set(buckets[k]))
    return buckets


def _file_signature(paths: List[Path]) -> List[List[object]]:
    """
    IMPORTANT: list-of-lists so YAML roundtrips and meta==expected works.
    """
    sig: List[List[object]] = []
    for p in paths:
        try:
            st_ = p.stat()
            sig.append([str(p.resolve()), int(st_.st_mtime_ns), int(st_.st_size)])
        except Exception:
            continue
    return sig


def _meta_expected(files_sig: Dict[str, List[List[object]]]) -> dict:
    return {
        "cache_version": CACHE_VERSION,
        "sig_mtime_ns": int(SIG_MTIME_NS),
        "files_sig": files_sig,
    }


# =============================================================================
# CORE LOADER (PER-DATE CACHE LIKE SHADOW APPS)
# =============================================================================

def _build_one_date(parquet_root: Path, date_str: str, known_files: List[Path]) -> pd.DataFrame:
    date_dir = Path(parquet_root) / date_str
    buckets = _collect_date_logs(date_dir)

    files_sig = {
        "http": _file_signature(buckets["http"]),
        "ssl": _file_signature(buckets["ssl"]),
        "dns": _file_signature(buckets["dns"]),
        "conn": _file_signature(buckets["conn"]),
        "dhcp": _file_signature(buckets["dhcp"]),
        "known": _file_signature(known_files),
    }

    cpath = cache_ai_events_path(parquet_root, date_str)
    mpath = cache_ai_meta_path(parquet_root, date_str)
    expected = _meta_expected(files_sig)

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
    ip_map, mac_map = _build_identity_maps(buckets["dhcp"], known_files)

    events: List[pd.DataFrame] = []

    # --- HTTP ---
    http_cols = [
        "ts", "id.orig_h", "id.resp_h", "id.resp_p",
        "host", "uri", "user_agent", "method", "request_body_len",
        "orig_l2_addr", "l2_addr", "src_mac",
    ]
    for f in buckets["http"]:
        df = _read_parquet_columns(f, http_cols)
        if df.empty:
            continue
        df = _ensure_ts_datetime(df)

        host_col = "host" if "host" in df.columns else ("id.resp_h" if "id.resp_h" in df.columns else None)
        if host_col is None:
            continue

        host_s = df[host_col].astype(str).fillna("")
        uri_s = df["uri"].astype(str).fillna("") if "uri" in df.columns else ""
        combined = (host_s + " " + uri_s).astype(str)

        mask = combined.str.contains(MASTER_PATTERN, case=False, na=False, regex=True)
        if not mask.any():
            continue

        hit = df.loc[mask].copy()
        hit = _ensure_ts_datetime(hit)

        host_s_hit = hit[host_col].astype(str).fillna("")
        uri_s_hit = hit["uri"].astype(str).fillna("") if "uri" in hit.columns else ""
        combined_hit = (host_s_hit + " " + uri_s_hit)

        prov, sig = _assign_provider_and_signature(combined_hit)

        hit["AI_Provider"] = prov
        hit["Signature_Match"] = sig
        hit["Detection_Source"] = "HTTP"
        hit["Match_Field"] = "HTTP host/uri"

        if "user_agent" in hit.columns:
            hit["Client_Type"] = hit["user_agent"].apply(fingerprint_client)
        else:
            hit["user_agent"] = "-"
            hit["Client_Type"] = "Unknown"

        hit["Upload_Bytes"] = pd.to_numeric(hit.get("request_body_len", 0), errors="coerce").fillna(0)

        method_s = hit["method"].astype(str).fillna("-") if "method" in hit.columns else "-"
        uri_s2 = hit["uri"].astype(str).fillna("-") if "uri" in hit.columns else "-"
        hit["Detail"] = method_s + " " + uri_s2

        if "id.resp_p" in hit.columns:
            p = pd.to_numeric(hit["id.resp_p"], errors="coerce").fillna(-1).astype(int)
            hit["Destination"] = host_s_hit + ":" + p.astype(str)
        else:
            hit["Destination"] = host_s_hit

        # Show exact matched value for evidence
        hit["Matched_Value"] = (host_s_hit + " " + uri_s_hit).astype(str)

        hit["Detection_Basis"] = hit["Match_Field"] + " matched '" + hit["Signature_Match"].astype(str) + "'"
        events.append(hit)

    # --- SSL ---
    ssl_cols = ["ts", "id.orig_h", "id.resp_h", "server_name", "orig_l2_addr", "l2_addr", "src_mac"]
    for f in buckets["ssl"]:
        df = _read_parquet_columns(f, ssl_cols)
        if df.empty:
            continue
        df = _ensure_ts_datetime(df)

        if "server_name" not in df.columns:
            continue

        sni = df["server_name"].astype(str).fillna("")
        mask = sni.str.contains(MASTER_PATTERN, case=False, na=False, regex=True)
        if not mask.any():
            continue

        hit = df.loc[mask].copy()
        hit = _ensure_ts_datetime(hit)

        sni_hit = hit["server_name"].astype(str).fillna("")
        prov, sig = _assign_provider_and_signature(sni_hit)

        hit["AI_Provider"] = prov
        hit["Signature_Match"] = sig
        hit["Detection_Source"] = "SSL"
        hit["Match_Field"] = "TLS SNI"
        hit["Client_Type"] = "Encrypted (TLS)"
        hit["Upload_Bytes"] = 0
        hit["Detail"] = "SNI: " + sni_hit
        hit["Destination"] = sni_hit
        hit["user_agent"] = "-"
        hit["Matched_Value"] = sni_hit.astype(str)

        hit["Detection_Basis"] = hit["Match_Field"] + " matched '" + hit["Signature_Match"].astype(str) + "'"
        events.append(hit)

    # --- DNS ---
    dns_cols = ["ts", "id.orig_h", "id.resp_h", "query", "qtype_name", "rcode_name", "orig_l2_addr", "l2_addr", "src_mac"]
    for f in buckets["dns"]:
        df = _read_parquet_columns(f, dns_cols)
        if df.empty:
            continue
        df = _ensure_ts_datetime(df)

        if "query" not in df.columns:
            continue

        q = df["query"].astype(str).fillna("")
        mask = q.str.contains(MASTER_PATTERN, case=False, na=False, regex=True)
        if not mask.any():
            continue

        hit = df.loc[mask].copy()
        hit = _ensure_ts_datetime(hit)

        q_hit = hit["query"].astype(str).fillna("")
        prov, sig = _assign_provider_and_signature(q_hit)

        hit["AI_Provider"] = prov
        hit["Signature_Match"] = sig
        hit["Detection_Source"] = "DNS"
        hit["Match_Field"] = "DNS query"
        hit["Client_Type"] = "DNS Resolver"
        hit["Upload_Bytes"] = 0

        qtype = hit.get("qtype_name", "-").astype(str).fillna("-")
        rcode = hit.get("rcode_name", "-").astype(str).fillna("-")
        hit["Detail"] = "DNS " + qtype + " " + rcode
        hit["Destination"] = q_hit
        hit["user_agent"] = "-"
        hit["Matched_Value"] = q_hit.astype(str)

        hit["Detection_Basis"] = hit["Match_Field"] + " matched '" + hit["Signature_Match"].astype(str) + "'"
        events.append(hit)

    # --- CONN (local AI ports) ---
    conn_cols = ["ts", "id.orig_h", "id.resp_h", "id.resp_p", "orig_ip_bytes", "orig_l2_addr", "l2_addr", "src_mac"]
    ports = sorted(LOCAL_AI_PORTS.keys())
    if ports:
        for f in buckets["conn"]:
            df = _read_parquet_columns(f, conn_cols)
            if df.empty or "id.resp_p" not in df.columns:
                continue
            df = _ensure_ts_datetime(df)

            rp = pd.to_numeric(df["id.resp_p"], errors="coerce")
            mask = rp.isin(ports)
            if not mask.any():
                continue

            hit = df.loc[mask].copy()
            hit = _ensure_ts_datetime(hit)

            hit["id.resp_p"] = pd.to_numeric(hit["id.resp_p"], errors="coerce").fillna(-1).astype(int)
            hit["AI_Provider"] = hit["id.resp_p"].map(LOCAL_AI_PORTS).fillna("Local/Custom AI")
            hit["Signature_Match"] = hit["id.resp_p"].apply(lambda p: f"port {p}")
            hit["Detection_Source"] = "CONN (Port)"
            hit["Match_Field"] = "conn id.resp_p"
            hit["Client_Type"] = "Local Tool"
            hit["Upload_Bytes"] = pd.to_numeric(hit.get("orig_ip_bytes", 0), errors="coerce").fillna(0)

            resp_h = hit.get("id.resp_h", "").astype(str).fillna("")
            hit["Detail"] = "Port " + hit["id.resp_p"].astype(str) + " traffic"
            hit["Destination"] = resp_h + ":" + hit["id.resp_p"].astype(str)
            hit["user_agent"] = "-"
            hit["Matched_Value"] = hit["Destination"].astype(str)

            hit["Detection_Basis"] = "Local port match (" + hit["Signature_Match"].astype(str) + ")"
            events.append(hit)

    if not events:
        return pd.DataFrame()

    final_df = pd.concat(events, ignore_index=True)
    final_df = _ensure_ts_datetime(final_df)

    # Required columns
    required = [
        "ts", "id.orig_h", "mac", "host_name", "AI_Provider", "Policy_Verdict",
        "Client_Type", "Detection_Source", "Match_Field", "Signature_Match",
        "Matched_Value", "Detection_Basis", "Policy_Basis",
        "Upload_Bytes", "Risk_Score", "Severity", "Confidence",
        "Detail", "Destination", "user_agent",
    ]
    for c in required:
        if c not in final_df.columns:
            final_df[c] = ""

    # identity enrichment
    final_df = _enrich_identity(final_df, ip_map, mac_map)

    # normalize sizes
    final_df["Upload_Bytes"] = pd.to_numeric(final_df.get("Upload_Bytes", 0), errors="coerce").fillna(0)

    # evidence + policy + scoring
    final_df["Evidence_Type"] = final_df.apply(_evidence_type, axis=1)

    final_df["Risk_Score"] = final_df.apply(calculate_severity, axis=1)
    final_df["Severity"] = final_df["Risk_Score"].apply(normalize_severity_label)
    final_df["Policy_Verdict"] = final_df["AI_Provider"].apply(_policy_verdict)
    final_df["Policy_Basis"] = final_df["AI_Provider"].apply(_policy_basis)
    final_df["Confidence"] = final_df["Detection_Source"].apply(_confidence)

    # derived domain
    final_df["Domain"] = final_df["Destination"].apply(_to_domain_from_destination)

    final_df = final_df.sort_values("ts", ascending=False)

    # write cache
    try:
        cpath.parent.mkdir(parents=True, exist_ok=True)
        final_df.to_parquet(cpath, index=False)
        write_yaml(mpath, expected)
    except Exception:
        pass

    return final_df


def load_shadow_ai_data(parquet_root: Path, target_dates: List[str]) -> pd.DataFrame:
    """
    Multi-date loader that reuses per-day caches (fast).
    """
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


# =============================================================================
# ANALYTICS HELPERS (SOC VIEWS)
# =============================================================================

def _bucket_transfer(bytes_out: float) -> str:
    if bytes_out >= 5 * 1024 * 1024:
        return ">5MB"
    if bytes_out >= 1 * 1024 * 1024:
        return "1-5MB"
    if bytes_out >= 10 * 1024:
        return "10KB-1MB"
    if bytes_out > 0:
        return "0-10KB"
    return "0"


def _day_key(ts: pd.Series) -> pd.Series:
    # robust day column
    t = pd.to_datetime(ts, errors="coerce")
    return t.dt.floor("D")


def _safe_value_counts_top(s: pd.Series) -> str:
    if s is None:
        return ""
    s = s.astype(str).replace({"nan": "", "None": "", "-": ""})
    s = s[s != ""]
    if len(s) == 0:
        return ""
    vc = s.value_counts()
    return str(vc.index[0]) if len(vc) else ""


# =============================================================================
# UI HELPERS
# =============================================================================

MAX_ROWS_DISPLAY = 10000
SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#f59e0b",
    "LOW": "#22c55e",
}
POLICY_COLORS = {
    "Shadow AI": "#ef4444",
    "Allowed": "#22c55e",
}


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


def _policy_cellstyle() -> JsCode:
    return JsCode(
        """
        function(params) {
            const v = (params.value || '').toString();
            if (v === 'Shadow AI') return { 'color': '#ef4444', 'fontWeight': '900' };
            if (v === 'Allowed') return { 'color': '#22c55e', 'fontWeight': '800' };
            return {};
        }
        """
    )


def render_shadow_aggrid(
    df: pd.DataFrame,
    gb: GridOptionsBuilder,
    *,
    key: str,
    height: int = 430,
    update_mode=GridUpdateMode.NO_UPDATE,
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
        reload_data=False,
        key=key,
    )
    st.markdown("</div>", unsafe_allow_html=True)
    return grid_response


def _new_grid_builder(df_grid: pd.DataFrame, page_size: int = 15) -> GridOptionsBuilder:
    gb = GridOptionsBuilder.from_dataframe(df_grid)
    gb.configure_default_column(filter=True, sortable=True, resizable=True, flex=1)
    gb.configure_pagination(paginationAutoPageSize=False, paginationPageSize=page_size)
    if "#" in df_grid.columns:
        gb.configure_column("#", header_name="#", width=62, pinned="left", suppressMovable=True, resizable=False, flex=0)
    return gb


def inject_shadow_ai_css():
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


# =============================================================================
# UI RENDERER
# =============================================================================

def render_shadow_ai(parquet_root: Path):
    inject_shadow_ai_css()
    st.markdown("### Shadow AI & Data Leakage Monitor")
    st.markdown(
        "<div class='shadow-callout'>Correlates HTTP/SSL/DNS/CONN telemetry with signature and policy context to surface potential Shadow AI usage and leakage risk.</div>",
        unsafe_allow_html=True,
    )

    parquet_root = Path(parquet_root)
    if not parquet_root.exists():
        st.error(f"Parquet root not found: {parquet_root}")
        return

    available_dates = get_available_dates(parquet_root)
    if not available_dates:
        st.warning("No logs found.")
        return

    date_options = ["All Available Dates"] + available_dates
    top1, top2, top3 = st.columns([1.5, 2.3, 0.8])
    with top1:
        selected_date = st.selectbox(
            "Dataset Scope",
            date_options,
            index=1 if len(available_dates) > 0 else 0,
            key="shadow_ai_date_v2",
        )
    selected_scope_key = re.sub(r"[^A-Za-z0-9_]+", "_", str(selected_date))
    with top2:
        scope_label = selected_date if selected_date != "All Available Dates" else f"All Available Dates ({len(available_dates)})"
        st.markdown(
            f"<div class='shadow-day-chip'>Active scope:&nbsp;<strong>{scope_label}</strong></div>",
            unsafe_allow_html=True,
        )
    with top3:
        st.write("")
        st.write("")
        if st.button("Refresh", key="shadow_ai_refresh_v2"):
            st.cache_data.clear()
            st.cache_resource.clear()
            st.rerun()

    with st.expander("Detection basis (how Shadow AI is decided)", expanded=False):
        st.write(
            "Events are generated when Zeek telemetry matches `ai_signatures.yaml` (HTTP host/uri, TLS SNI, DNS query) "
            "or a configured local AI port (`conn id.resp_p`). Policy verdict is based on `authorized_providers`."
        )
        st.write(
            "Evidence columns include Match_Field, Signature_Match, Matched_Value, Detection_Basis, "
            "Policy_Basis, Evidence_Type, and Confidence."
        )

    provider_values = sorted(list((RAW_AI_SIGNATURES or {}).keys()))
    signature_values = sorted({frag for _, frags in (RAW_AI_SIGNATURES or {}).items() for frag in (frags or [])})
    match_field_values = ["HTTP host/uri", "TLS SNI", "DNS query", "conn id.resp_p"]
    evidence_values = ["HTTP+POST", "HTTP+GET", "TLS SNI", "DNS query", "Local Port", "HTTP"]

    st.markdown("<div class='shadow-filter-shell'>", unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns([1.6, 1.45, 1.8, 1.1])
    with c1:
        selected_verdict = st.multiselect(
            "Policy Verdict",
            ["Shadow AI", "Allowed"],
            default=["Shadow AI", "Allowed"],
            key="shadow_ai_filter_verdict_v2",
        )
    with c2:
        selected_severity = st.multiselect(
            "Severity",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            key="shadow_ai_filter_severity_v2",
        )
    with c3:
        provider_filter = st.multiselect(
            "Provider",
            provider_values,
            default=[],
            placeholder="All providers",
            key="shadow_ai_filter_provider_v2",
        )
    with c4:
        min_upload_kb = st.number_input("Min Upload (KB)", min_value=0, value=0, step=10, key="shadow_ai_filter_min_upload_v2")

    c5, c6, c7 = st.columns([1.6, 1.6, 2.2])
    with c5:
        basis_field = st.multiselect(
            "Match Field",
            match_field_values,
            default=match_field_values,
            key="shadow_ai_filter_field_v2",
        )
    with c6:
        basis_sig = st.multiselect(
            "Signature Match",
            signature_values,
            default=[],
            placeholder="All signatures",
            key="shadow_ai_filter_signature_v2",
        )
    with c7:
        search_q = st.text_input(
            "Search (MAC, Host, Provider, IP, Detail, Basis)",
            placeholder="Enter keywords...",
            key="shadow_ai_filter_search_v2",
        )

    c8, c9, c10 = st.columns([1.45, 1.35, 2.2])
    with c8:
        evidence_filter = st.multiselect(
            "Evidence Type",
            evidence_values,
            default=[],
            placeholder="All evidence",
            key="shadow_ai_filter_evidence_v2",
        )
    with c9:
        only_resolved_mac = st.checkbox("Only resolved MAC", value=False, key="shadow_ai_filter_resolved_v2")
    with c10:
        ignore_dns_only = st.checkbox("Ignore DNS-only events", value=False, key="shadow_ai_filter_ignore_dns_v2")
    st.markdown("</div>", unsafe_allow_html=True)

    verdict_summary = ", ".join(selected_verdict) if selected_verdict else "None"
    severity_summary = ", ".join(selected_severity) if selected_severity else "None"
    provider_summary = f"{len(provider_filter)} selected" if provider_filter else "All"
    search_summary = "On" if (search_q or "").strip() else "Off"
    st.markdown(
        f"<div class='shadow-filter-hint'>Verdict: <strong>{verdict_summary}</strong> | Severity: <strong>{severity_summary}</strong> | Providers: <strong>{provider_summary}</strong> | Search: <strong>{search_summary}</strong></div>",
        unsafe_allow_html=True,
    )

    target_dates = available_dates if selected_date == "All Available Dates" else ([selected_date] if selected_date else [])
    with st.spinner("Analyzing telemetry (fast cache)..."):
        df = load_shadow_ai_data(parquet_root, target_dates)

    if df.empty:
        st.info("No AI signatures detected in the selected range.")
        return

    filtered = df.copy()

    # apply filters
    if selected_verdict:
        filtered = filtered[filtered["Policy_Verdict"].isin(selected_verdict)]
    if selected_severity:
        filtered = filtered[filtered["Severity"].isin(selected_severity)]
    if provider_filter:
        filtered = filtered[filtered["AI_Provider"].isin(provider_filter)]
    if basis_field:
        filtered = filtered[filtered["Match_Field"].isin(basis_field)]
    if basis_sig:
        filtered = filtered[filtered["Signature_Match"].isin(basis_sig)]
    if evidence_filter:
        filtered = filtered[filtered["Evidence_Type"].isin(evidence_filter)]
    if min_upload_kb > 0:
        filtered = filtered[filtered["Upload_Bytes"] >= (float(min_upload_kb) * 1024)]
    if only_resolved_mac:
        filtered = filtered[filtered["mac"].astype(str).str.contains(":", na=False)]
    if ignore_dns_only:
        filtered = filtered[filtered["Detection_Source"].isin(["HTTP", "SSL", "CONN (Port)"])]

    # search
    if search_q:
        q = search_q.lower().strip()
        if q:
            filtered = filtered[
                filtered["mac"].astype(str).str.lower().str.contains(q, na=False)
                | filtered["host_name"].astype(str).str.lower().str.contains(q, na=False)
                | filtered["AI_Provider"].astype(str).str.lower().str.contains(q, na=False)
                | filtered["Detail"].astype(str).str.lower().str.contains(q, na=False)
                | filtered["Destination"].astype(str).str.lower().str.contains(q, na=False)
                | filtered["Domain"].astype(str).str.lower().str.contains(q, na=False)
                | filtered["id.orig_h"].astype(str).str.lower().str.contains(q, na=False)
                | filtered["Detection_Basis"].astype(str).str.lower().str.contains(q, na=False)
                | filtered["Policy_Basis"].astype(str).str.lower().str.contains(q, na=False)
                | filtered["Matched_Value"].astype(str).str.lower().str.contains(q, na=False)
            ]

    if filtered.empty:
        st.warning("No data matches your filters.")
        return

    st.divider()
    m1, m2, m3, m4, m5, m6 = st.columns(6)

    total_leakage_mb = float(filtered["Upload_Bytes"].sum()) / 1024 / 1024
    shadow_count = int((filtered["Policy_Verdict"] == "Shadow AI").sum())
    critical_events = int((filtered["Severity"] == "CRITICAL").sum())
    unique_macs = int(filtered["mac"].astype(str).replace({"": None}).dropna().nunique()) if "mac" in filtered.columns else 0
    unique_hosts = int(filtered["host_name"].astype(str).replace({"": None}).dropna().nunique()) if "host_name" in filtered.columns else 0
    unique_ips = int(filtered["id.orig_h"].astype(str).replace({"": None, "nan": None}).dropna().nunique()) if "id.orig_h" in filtered.columns else 0

    m1.metric("Selected Events", f"{len(filtered):,}")
    m2.metric("Shadow AI Events", f"{shadow_count:,}", delta="Risk" if shadow_count > 0 else "Clear", delta_color="inverse")
    m3.metric("Critical Incidents", f"{critical_events:,}", delta="Investigate" if critical_events > 0 else "Clear", delta_color="inverse")
    m4.metric("Unique MACs", f"{unique_macs:,}")
    m5.metric("Unique Hosts", f"{unique_hosts:,}")
    m6.metric("Data Leakage", f"{total_leakage_mb:.2f} MB")
    st.markdown(
        f"<div class='shadow-filter-hint'>Unique source IPs in scope: <strong>{unique_ips:,}</strong></div>",
        unsafe_allow_html=True,
    )

    # -----------------------------------------------------------------------------
    # TABS: SOC dashboards
    # -----------------------------------------------------------------------------
    tabs = st.tabs([
        "Overview",
        "Trends",
        "Top Destinations",
        "Shadow AI by MAC",
        "Big Transfers",
        "Forensics",
        "Policy / Noise Control",
    ])

    # =============================================================================
    # TAB: OVERVIEW
    # =============================================================================
    with tabs[0]:
        st.markdown("### Posture Analysis")

        g1, g2 = st.columns([2, 1])
        with g1:
            render_mode = "webgl" if len(filtered) > 2000 else "auto"
            fig_scatter = px.scatter(
                filtered,
                x="ts",
                y="AI_Provider",
                size="Risk_Score",
                color="Severity",
                color_discrete_map=SEVERITY_COLORS,
                hover_data=["mac", "host_name", "Detail", "Destination", "Evidence_Type", "Confidence", "Detection_Basis", "Policy_Basis", "id.orig_h"],
                title=f"Incident Timeline ({selected_date})",
                template=get_plotly_template(),
                render_mode=render_mode,
            )
            style_plotly_figure(fig_scatter, height=370)
            fig_scatter.update_xaxes(title="Time")
            fig_scatter.update_yaxes(title="Provider")
            st.plotly_chart(fig_scatter, use_container_width=True)

        with g2:
            if "Client_Type" in filtered.columns and not filtered.empty:
                risk_vectors = filtered.groupby("Client_Type")["Risk_Score"].mean().reset_index()
            else:
                risk_vectors = pd.DataFrame(columns=["Client_Type", "Risk_Score"])

            fig_bar = px.bar(
                risk_vectors,
                x="Risk_Score",
                y="Client_Type",
                orientation="h",
                title="Avg Risk by Client",
                template=get_plotly_template(),
            )
            style_plotly_figure(fig_bar, height=370, show_legend=False)
            fig_bar.update_xaxes(title="Average Risk Score")
            fig_bar.update_yaxes(title=None)
            st.plotly_chart(fig_bar, use_container_width=True)

        # Provider summary
        st.markdown("### Providers in View")
        prov_sum = filtered.groupby(["AI_Provider", "Policy_Verdict"]).agg(
            Events=("ts", "count"),
            Unique_MACs=("mac", lambda x: x.astype(str).replace({"": None}).dropna().nunique()),
            Last_Seen=("ts", "max"),
            Total_Upload_MB=("Upload_Bytes", lambda x: float(x.sum()) / 1024 / 1024),
            Avg_Risk=("Risk_Score", "mean"),
        ).reset_index().sort_values(["Events", "Total_Upload_MB"], ascending=False)

        prov_grid = prov_sum.copy()
        prov_grid.insert(0, "#", range(1, len(prov_grid) + 1))
        prov_grid["Last_Seen"] = pd.to_datetime(prov_grid["Last_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
        prov_grid["Total_Upload_MB"] = pd.to_numeric(prov_grid["Total_Upload_MB"], errors="coerce").fillna(0).round(2)
        prov_grid["Avg_Risk"] = pd.to_numeric(prov_grid["Avg_Risk"], errors="coerce").fillna(0).round(1)

        gb_prov = _new_grid_builder(prov_grid, page_size=15)
        gb_prov.configure_column("AI_Provider", header_name="Provider", minWidth=160, flex=1.3)
        gb_prov.configure_column("Policy_Verdict", header_name="Verdict", minWidth=120, cellStyle=_policy_cellstyle())
        gb_prov.configure_column("Events", width=92, flex=0.8)
        gb_prov.configure_column("Unique_MACs", header_name="Unique MACs", minWidth=110)
        gb_prov.configure_column("Last_Seen", header_name="Last Seen", minWidth=150)
        gb_prov.configure_column("Total_Upload_MB", header_name="Upload MB", minWidth=105)
        gb_prov.configure_column("Avg_Risk", header_name="Avg Risk", minWidth=95, cellStyle=_risk_score_cellstyle())
        render_shadow_aggrid(prov_grid, gb_prov, key=f"shadow_ai_provider_grid_{selected_scope_key}", height=390)

    # =============================================================================
    # TAB: TRENDS
    # =============================================================================
    with tabs[1]:
        st.markdown("### Trend over time")
        tdf = filtered.copy()
        tdf["day"] = _day_key(tdf["ts"])

        # Events per day (all + shadow)
        daily = tdf.groupby(["day", "Policy_Verdict"]).agg(
            Events=("ts", "count"),
            Unique_MACs=("mac", lambda x: x.astype(str).replace({"": None}).dropna().nunique()),
            Upload_MB=("Upload_Bytes", lambda x: float(x.sum()) / 1024 / 1024),
        ).reset_index()

        if daily.empty:
            st.info("No trend data.")
        else:
            c_left, c_right = st.columns([1.2, 1.2])
            with c_left:
                fig1 = px.line(
                    daily,
                    x="day",
                    y="Events",
                    color="Policy_Verdict",
                    color_discrete_map=POLICY_COLORS,
                    title="Events per day",
                    template=get_plotly_template(),
                    markers=True,
                )
                style_plotly_figure(fig1, height=360)
                fig1.update_xaxes(title="Day")
                fig1.update_yaxes(title="Events")
                st.plotly_chart(fig1, use_container_width=True)

            with c_right:
                fig2 = px.line(
                    daily,
                    x="day",
                    y="Unique_MACs",
                    color="Policy_Verdict",
                    color_discrete_map=POLICY_COLORS,
                    title="Unique MACs per day",
                    template=get_plotly_template(),
                    markers=True,
                )
                style_plotly_figure(fig2, height=360)
                fig2.update_xaxes(title="Day")
                fig2.update_yaxes(title="Unique MACs")
                st.plotly_chart(fig2, use_container_width=True)

            fig3 = px.bar(
                daily,
                x="day",
                y="Upload_MB",
                color="Policy_Verdict",
                color_discrete_map=POLICY_COLORS,
                title="Upload (MB) per day",
                template=get_plotly_template(),
            )
            style_plotly_figure(fig3, height=360)
            fig3.update_xaxes(title="Day")
            fig3.update_yaxes(title="Upload MB")
            st.plotly_chart(fig3, use_container_width=True)

    # =============================================================================
    # TAB: TOP DESTINATIONS
    # =============================================================================
    with tabs[2]:
        st.markdown("### Top destinations/domains")
        ddf = filtered.copy()
        ddf["Domain"] = ddf["Domain"].astype(str).fillna("")

        top_dest = ddf.groupby(["AI_Provider", "Policy_Verdict", "Domain"]).agg(
            Events=("ts", "count"),
            Unique_MACs=("mac", lambda x: x.astype(str).replace({"": None}).dropna().nunique()),
            Last_Seen=("ts", "max"),
            Total_Upload_MB=("Upload_Bytes", lambda x: float(x.sum()) / 1024 / 1024),
            Evidence=("Evidence_Type", _safe_value_counts_top),
        ).reset_index().sort_values(["Events", "Total_Upload_MB"], ascending=False)

        dest_grid = top_dest.copy()
        dest_grid.insert(0, "#", range(1, len(dest_grid) + 1))
        dest_grid["Last_Seen"] = pd.to_datetime(dest_grid["Last_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
        dest_grid["Total_Upload_MB"] = pd.to_numeric(dest_grid["Total_Upload_MB"], errors="coerce").fillna(0).round(2)

        gb_dest = _new_grid_builder(dest_grid, page_size=20)
        gb_dest.configure_column("AI_Provider", header_name="Provider", minWidth=150)
        gb_dest.configure_column("Policy_Verdict", header_name="Verdict", minWidth=120, cellStyle=_policy_cellstyle())
        gb_dest.configure_column("Domain", minWidth=220, flex=1.6)
        gb_dest.configure_column("Events", width=95, flex=0.8)
        gb_dest.configure_column("Unique_MACs", header_name="Unique MACs", minWidth=110)
        gb_dest.configure_column("Last_Seen", header_name="Last Seen", minWidth=145)
        gb_dest.configure_column("Total_Upload_MB", header_name="Upload MB", minWidth=105)
        gb_dest.configure_column("Evidence", minWidth=130)
        render_shadow_aggrid(dest_grid, gb_dest, key=f"shadow_ai_dest_grid_{selected_scope_key}", height=455)

        st.markdown("### POST/Upload focus (HTTP evidence)")
        http_only = filtered[(filtered["Detection_Source"] == "HTTP")].copy()
        if http_only.empty:
            st.info("No HTTP events in this view.")
        else:
            http_only["is_post"] = http_only["method"].astype(str).str.upper().eq("POST") if "method" in http_only.columns else False
            post = http_only[http_only["is_post"]].copy()

            post_kpi1, post_kpi2 = st.columns(2)
            post_upload_mb = float(post["Upload_Bytes"].sum()) / 1024 / 1024 if not post.empty else 0.0
            post_kpi1.metric("POST Events", int(len(post)))
            post_kpi2.metric("POST Upload (MB)", f"{post_upload_mb:.2f}")

            # top endpoints
            post["endpoint"] = post["uri"].astype(str).fillna("").str.split("?").str[0] if "uri" in post.columns else ""
            top_end = post.groupby(["AI_Provider", "endpoint"]).agg(
                Events=("ts", "count"),
                Total_Upload_MB=("Upload_Bytes", lambda x: float(x.sum()) / 1024 / 1024),
                Last_Seen=("ts", "max"),
            ).reset_index().sort_values(["Total_Upload_MB", "Events"], ascending=False)

            top_end_grid = top_end.copy()
            top_end_grid.insert(0, "#", range(1, len(top_end_grid) + 1))
            top_end_grid["Last_Seen"] = pd.to_datetime(top_end_grid["Last_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
            top_end_grid["Total_Upload_MB"] = pd.to_numeric(top_end_grid["Total_Upload_MB"], errors="coerce").fillna(0).round(2)

            gb_end = _new_grid_builder(top_end_grid, page_size=15)
            gb_end.configure_column("AI_Provider", header_name="Provider", minWidth=150)
            gb_end.configure_column("endpoint", header_name="Endpoint", minWidth=260, flex=1.8)
            gb_end.configure_column("Events", width=95, flex=0.8)
            gb_end.configure_column("Total_Upload_MB", header_name="Upload MB", minWidth=105)
            gb_end.configure_column("Last_Seen", header_name="Last Seen", minWidth=145)
            render_shadow_aggrid(top_end_grid, gb_end, key=f"shadow_ai_top_end_grid_{selected_scope_key}", height=390)

    # =============================================================================
    # TAB: SHADOW AI BY MAC (with drilldown)
    # =============================================================================
    with tabs[3]:
        st.markdown("### Device exposure (Shadow AI by MAC)")

        mac_view = filtered[filtered["Policy_Verdict"] == "Shadow AI"].copy()
        mac_view["mac"] = mac_view["mac"].astype(str).fillna("")
        mac_view = mac_view[mac_view["mac"].str.contains(":", na=False)]

        if mac_view.empty:
            st.info("No Shadow AI events with resolved MAC in the current view.")
        else:
            mac_view["transfer_bucket"] = mac_view["Upload_Bytes"].apply(lambda b: _bucket_transfer(float(b or 0)))
            mac_summary = mac_view.groupby("mac").agg(
                Host=("host_name", _safe_value_counts_top),
                Last_Seen=("ts", "max"),
                First_Seen=("ts", "min"),
                Events=("ts", "count"),
                Unique_Providers=("AI_Provider", lambda x: x.nunique()),
                Total_Upload_MB=("Upload_Bytes", lambda x: float(x.sum()) / 1024 / 1024),
                Top_Provider=("AI_Provider", _safe_value_counts_top),
                Top_Domain=("Domain", _safe_value_counts_top),
                Source_IP=("id.orig_h", _safe_value_counts_top),
                Top_Evidence=("Evidence_Type", _safe_value_counts_top),
                Max_Severity=("Severity", lambda x: "CRITICAL" if (x == "CRITICAL").any()
                             else ("HIGH" if (x == "HIGH").any()
                                   else ("MEDIUM" if (x == "MEDIUM").any() else "LOW"))),
            ).reset_index().sort_values(["Events", "Total_Upload_MB"], ascending=False)
            mac_grid = mac_summary.copy()
            mac_grid.insert(0, "#", range(1, len(mac_grid) + 1))
            mac_grid["Last_Seen"] = pd.to_datetime(mac_grid["Last_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
            mac_grid["First_Seen"] = pd.to_datetime(mac_grid["First_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
            mac_grid["Total_Upload_MB"] = pd.to_numeric(mac_grid["Total_Upload_MB"], errors="coerce").fillna(0).round(2)

            gb_mac = _new_grid_builder(mac_grid, page_size=15)
            gb_mac.configure_column("mac", header_name="MAC", minWidth=150)
            gb_mac.configure_column("Host", minWidth=140)
            gb_mac.configure_column("Last_Seen", header_name="Last Seen", minWidth=150)
            gb_mac.configure_column("First_Seen", header_name="First Seen", minWidth=150)
            gb_mac.configure_column("Events", width=90, flex=0.8)
            gb_mac.configure_column("Unique_Providers", header_name="Providers", minWidth=95)
            gb_mac.configure_column("Total_Upload_MB", header_name="Upload MB", minWidth=110)
            gb_mac.configure_column("Top_Provider", header_name="Top Provider", minWidth=140)
            gb_mac.configure_column("Top_Domain", header_name="Top Domain", minWidth=170)
            gb_mac.configure_column("Source_IP", header_name="IP", minWidth=120)
            gb_mac.configure_column("Top_Evidence", header_name="Top Evidence", minWidth=130)
            gb_mac.configure_column("Max_Severity", header_name="Max Severity", minWidth=110, cellStyle=_severity_cellstyle())
            render_shadow_aggrid(mac_grid, gb_mac, key=f"shadow_ai_mac_summary_grid_{selected_scope_key}", height=430)

            st.markdown("### Drilldown (select MAC)")
            mac_list = mac_summary["mac"].tolist()
            selected_mac = st.selectbox("MAC", mac_list, index=0, key=f"shadow_ai_mac_select_{selected_scope_key}")

            mac_events = mac_view[mac_view["mac"] == selected_mac].copy().sort_values("ts", ascending=False)

            # per-mac metrics
            d1, d2, d3, d4 = st.columns(4)
            d1.metric("Events", len(mac_events))
            d2.metric("Providers", mac_events["AI_Provider"].nunique())
            d3.metric("Domains", mac_events["Domain"].astype(str).replace({"": None}).dropna().nunique())
            d4.metric("Upload (MB)", f"{float(mac_events['Upload_Bytes'].sum())/1024/1024:.2f}")

            # charts
            cA, cB = st.columns([2, 1])
            with cA:
                figm = px.scatter(
                    mac_events,
                    x="ts",
                    y="AI_Provider",
                    size="Risk_Score",
                    color="Severity",
                    color_discrete_map=SEVERITY_COLORS,
                    hover_data=["Domain", "Detail", "Evidence_Type", "Matched_Value", "Detection_Basis"],
                    title="MAC timeline (provider events)",
                    template=get_plotly_template(),
                    render_mode="webgl" if len(mac_events) > 1500 else "auto",
                )
                style_plotly_figure(figm, height=360)
                figm.update_xaxes(title="Time")
                figm.update_yaxes(title="Provider")
                st.plotly_chart(figm, use_container_width=True)

            with cB:
                byprov = mac_events.groupby("AI_Provider").agg(
                    Events=("ts", "count"),
                    Upload_MB=("Upload_Bytes", lambda x: float(x.sum())/1024/1024),
                ).reset_index().sort_values("Events", ascending=False)
                figp = px.bar(
                    byprov,
                    x="Events",
                    y="AI_Provider",
                    orientation="h",
                    title="Providers (this MAC)",
                    template=get_plotly_template(),
                )
                style_plotly_figure(figp, height=360, show_legend=False)
                figp.update_xaxes(title="Events")
                figp.update_yaxes(title=None)
                st.plotly_chart(figp, use_container_width=True)

            mac_event_cols = [
                "ts", "Severity", "AI_Provider", "Domain", "Evidence_Type",
                "Detail", "Upload_Bytes", "Destination", "Matched_Value",
                "Match_Field", "Signature_Match", "Detection_Basis", "Policy_Basis",
                "id.orig_h", "host_name", "user_agent",
            ]
            for c in mac_event_cols:
                if c not in mac_events.columns:
                    mac_events[c] = ""
            mac_event_grid = mac_events[mac_event_cols].head(MAX_ROWS_DISPLAY).copy()
            mac_event_grid.insert(0, "#", range(1, len(mac_event_grid) + 1))
            mac_event_grid["ts"] = pd.to_datetime(mac_event_grid["ts"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
            mac_event_grid["Upload_Bytes"] = pd.to_numeric(mac_event_grid["Upload_Bytes"], errors="coerce").fillna(0).astype(int)

            gb_events = _new_grid_builder(mac_event_grid, page_size=20)
            gb_events.configure_column("ts", header_name="Time", minWidth=150, flex=1.1)
            gb_events.configure_column("Severity", minWidth=90, flex=0.8, cellStyle=_severity_cellstyle())
            gb_events.configure_column("AI_Provider", header_name="Provider", minWidth=140, flex=1.2)
            gb_events.configure_column("Domain", minWidth=160, flex=1.2)
            gb_events.configure_column("Evidence_Type", header_name="Evidence", minWidth=120, flex=1.0)
            gb_events.configure_column("Detail", minWidth=180, flex=1.7)
            gb_events.configure_column("Upload_Bytes", header_name="Bytes", minWidth=100, flex=0.9)
            gb_events.configure_column("Destination", minWidth=170, flex=1.5)
            gb_events.configure_column("Matched_Value", header_name="Matched", minWidth=180, flex=1.6)
            gb_events.configure_column("Match_Field", header_name="Field", minWidth=120, flex=1.0)
            gb_events.configure_column("Signature_Match", header_name="Signature", minWidth=130, flex=1.1)
            gb_events.configure_column("Detection_Basis", header_name="Detection Basis", minWidth=180, flex=1.7)
            gb_events.configure_column("Policy_Basis", header_name="Policy Basis", minWidth=160, flex=1.5)
            gb_events.configure_column("id.orig_h", header_name="IP", minWidth=125, flex=1.0)
            gb_events.configure_column("host_name", header_name="Host", minWidth=130, flex=1.1)
            gb_events.configure_column("user_agent", header_name="User Agent", minWidth=220, flex=2.0)
            render_shadow_aggrid(mac_event_grid, gb_events, key=f"shadow_ai_mac_events_grid_{selected_scope_key}", height=540)

    # =============================================================================
    # TAB: BIG TRANSFERS
    # =============================================================================
    with tabs[4]:
        st.markdown("### Large transfer alerts")
        bdf = filtered.copy()
        bdf["transfer_bucket"] = bdf["Upload_Bytes"].apply(lambda b: _bucket_transfer(float(b or 0)))

        st.markdown("<div class='shadow-filter-shell'>", unsafe_allow_html=True)
        cA, cB, cC = st.columns(3)
        with cA:
            thresh_kb = st.number_input("Alert threshold (KB)", min_value=1, value=1024, step=256, key="shadow_ai_alert_thresh_v2")
        with cB:
            only_shadow = st.checkbox("Only Shadow AI", value=True, key="shadow_ai_alert_only_shadow_v2")
        with cC:
            only_http_post = st.checkbox("Only HTTP POST", value=False, key="shadow_ai_alert_only_post_v2")
        st.markdown("</div>", unsafe_allow_html=True)

        alert_df = bdf.copy()
        if only_shadow:
            alert_df = alert_df[alert_df["Policy_Verdict"] == "Shadow AI"]
        alert_df = alert_df[alert_df["Upload_Bytes"] >= float(thresh_kb) * 1024]

        if only_http_post:
            if "method" in alert_df.columns:
                alert_df = alert_df[(alert_df["Detection_Source"] == "HTTP") & (alert_df["method"].astype(str).str.upper() == "POST")]
            else:
                alert_df = alert_df.iloc[0:0]

        if alert_df.empty:
            st.info("No events above the threshold in the current view.")
        else:
            alert_cols = [
                "ts", "Severity", "mac", "host_name", "id.orig_h",
                "AI_Provider", "Domain", "Evidence_Type",
                "Upload_Bytes", "Detail", "Destination",
                "Matched_Value", "Detection_Basis",
            ]
            for c in alert_cols:
                if c not in alert_df.columns:
                    alert_df[c] = ""
            alert_grid = alert_df[alert_cols].head(MAX_ROWS_DISPLAY).copy()
            alert_grid.insert(0, "#", range(1, len(alert_grid) + 1))
            alert_grid["ts"] = pd.to_datetime(alert_grid["ts"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
            alert_grid["Upload_Bytes"] = pd.to_numeric(alert_grid["Upload_Bytes"], errors="coerce").fillna(0).astype(int)

            gb_alert = _new_grid_builder(alert_grid, page_size=20)
            gb_alert.configure_column("ts", header_name="Time", minWidth=150, flex=1.1)
            gb_alert.configure_column("Severity", minWidth=90, flex=0.8, cellStyle=_severity_cellstyle())
            gb_alert.configure_column("mac", header_name="MAC", minWidth=150, flex=1.2)
            gb_alert.configure_column("host_name", header_name="Host", minWidth=130, flex=1.1)
            gb_alert.configure_column("id.orig_h", header_name="IP", minWidth=125, flex=1.0)
            gb_alert.configure_column("AI_Provider", header_name="Provider", minWidth=140, flex=1.2)
            gb_alert.configure_column("Domain", minWidth=165, flex=1.3)
            gb_alert.configure_column("Evidence_Type", header_name="Evidence", minWidth=120, flex=1.0)
            gb_alert.configure_column("Upload_Bytes", header_name="Bytes", minWidth=100, flex=0.9)
            gb_alert.configure_column("Detail", minWidth=180, flex=1.7)
            gb_alert.configure_column("Destination", minWidth=170, flex=1.5)
            gb_alert.configure_column("Matched_Value", header_name="Matched", minWidth=180, flex=1.6)
            gb_alert.configure_column("Detection_Basis", header_name="Detection Basis", minWidth=180, flex=1.7)
            render_shadow_aggrid(alert_grid, gb_alert, key=f"shadow_ai_alert_grid_{selected_scope_key}", height=560)

    # =============================================================================
    # TAB: FORENSICS
    # =============================================================================
    with tabs[5]:
        st.markdown("### Incident forensics")

        ftab = st.tabs(["Priority Alerts", "Full Traffic Log", "Top Exfiltrators"])

        with ftab[0]:
            hi = filtered[filtered["Severity"].isin(["CRITICAL", "HIGH"])].copy()
            if hi.empty:
                st.success("No high severity incidents in the current view.")
            else:
                hi_cols = [
                    "ts", "Severity", "Policy_Verdict",
                    "mac", "host_name", "id.orig_h",
                    "AI_Provider", "Domain", "Evidence_Type",
                    "Upload_Bytes", "Detail", "Destination",
                    "Match_Field", "Signature_Match", "Matched_Value",
                    "Detection_Basis", "Policy_Basis", "Confidence",
                ]
                for c in hi_cols:
                    if c not in hi.columns:
                        hi[c] = ""
                hi_grid = hi[hi_cols].head(MAX_ROWS_DISPLAY).copy()
                hi_grid.insert(0, "#", range(1, len(hi_grid) + 1))
                hi_grid["ts"] = pd.to_datetime(hi_grid["ts"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
                hi_grid["Upload_Bytes"] = pd.to_numeric(hi_grid["Upload_Bytes"], errors="coerce").fillna(0).astype(int)

                gb_hi = _new_grid_builder(hi_grid, page_size=20)
                gb_hi.configure_column("ts", header_name="Time", minWidth=150, flex=1.1)
                gb_hi.configure_column("Severity", minWidth=90, flex=0.8, cellStyle=_severity_cellstyle())
                gb_hi.configure_column("Policy_Verdict", header_name="Verdict", minWidth=105, flex=0.9, cellStyle=_policy_cellstyle())
                gb_hi.configure_column("mac", header_name="MAC", minWidth=145, flex=1.1)
                gb_hi.configure_column("host_name", header_name="Host", minWidth=130, flex=1.0)
                gb_hi.configure_column("id.orig_h", header_name="IP", minWidth=125, flex=1.0)
                gb_hi.configure_column("AI_Provider", header_name="Provider", minWidth=140, flex=1.2)
                gb_hi.configure_column("Domain", minWidth=165, flex=1.3)
                gb_hi.configure_column("Evidence_Type", header_name="Evidence", minWidth=120, flex=1.0)
                gb_hi.configure_column("Upload_Bytes", header_name="Bytes", minWidth=100, flex=0.9)
                gb_hi.configure_column("Detail", minWidth=170, flex=1.6)
                gb_hi.configure_column("Destination", minWidth=160, flex=1.4)
                gb_hi.configure_column("Match_Field", header_name="Field", minWidth=110, flex=1.0)
                gb_hi.configure_column("Signature_Match", header_name="Signature", minWidth=130, flex=1.1)
                gb_hi.configure_column("Matched_Value", header_name="Matched", minWidth=170, flex=1.5)
                gb_hi.configure_column("Detection_Basis", header_name="Detection Basis", minWidth=180, flex=1.7)
                gb_hi.configure_column("Policy_Basis", header_name="Policy Basis", minWidth=170, flex=1.6)
                gb_hi.configure_column("Confidence", minWidth=95, flex=0.8)
                render_shadow_aggrid(hi_grid, gb_hi, key=f"shadow_ai_hi_grid_{selected_scope_key}", height=560)

        with ftab[1]:
            cols = [
                "ts", "mac", "host_name", "id.orig_h",
                "Severity", "Risk_Score",
                "AI_Provider", "Policy_Verdict", "Policy_Basis",
                "Evidence_Type", "Confidence",
                "Client_Type", "Detection_Source",
                "Domain", "Destination", "Detail",
                "Match_Field", "Signature_Match", "Matched_Value",
                "Detection_Basis", "user_agent",
            ]
            for c in cols:
                if c not in filtered.columns:
                    filtered[c] = ""

            log_grid = filtered[cols].head(MAX_ROWS_DISPLAY).copy()
            log_grid.insert(0, "#", range(1, len(log_grid) + 1))
            log_grid["ts"] = pd.to_datetime(log_grid["ts"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
            log_grid["Risk_Score"] = pd.to_numeric(log_grid["Risk_Score"], errors="coerce").fillna(0).astype(int)

            gb_log = _new_grid_builder(log_grid, page_size=20)
            gb_log.configure_column("ts", header_name="Time", minWidth=150, flex=1.1)
            gb_log.configure_column("mac", header_name="MAC", minWidth=145, flex=1.1)
            gb_log.configure_column("host_name", header_name="Host", minWidth=130, flex=1.0)
            gb_log.configure_column("id.orig_h", header_name="IP", minWidth=125, flex=1.0)
            gb_log.configure_column("Severity", minWidth=90, flex=0.8, cellStyle=_severity_cellstyle())
            gb_log.configure_column("Risk_Score", header_name="Risk", minWidth=85, flex=0.8, cellStyle=_risk_score_cellstyle())
            gb_log.configure_column("AI_Provider", header_name="Provider", minWidth=140, flex=1.2)
            gb_log.configure_column("Policy_Verdict", header_name="Verdict", minWidth=105, flex=0.9, cellStyle=_policy_cellstyle())
            gb_log.configure_column("Policy_Basis", header_name="Policy Basis", minWidth=160, flex=1.5)
            gb_log.configure_column("Evidence_Type", header_name="Evidence", minWidth=120, flex=1.0)
            gb_log.configure_column("Confidence", minWidth=95, flex=0.8)
            gb_log.configure_column("Client_Type", header_name="Client", minWidth=120, flex=1.0)
            gb_log.configure_column("Detection_Source", header_name="Source", minWidth=110, flex=0.9)
            gb_log.configure_column("Domain", minWidth=160, flex=1.3)
            gb_log.configure_column("Destination", minWidth=170, flex=1.5)
            gb_log.configure_column("Detail", minWidth=180, flex=1.7)
            gb_log.configure_column("Match_Field", header_name="Field", minWidth=120, flex=1.0)
            gb_log.configure_column("Signature_Match", header_name="Signature", minWidth=130, flex=1.1)
            gb_log.configure_column("Matched_Value", header_name="Matched", minWidth=180, flex=1.6)
            gb_log.configure_column("Detection_Basis", header_name="Detection Basis", minWidth=180, flex=1.7)
            gb_log.configure_column("user_agent", header_name="User Agent", minWidth=220, flex=2.0)
            render_shadow_aggrid(log_grid, gb_log, key=f"shadow_ai_log_grid_{selected_scope_key}", height=650)

        with ftab[2]:
            leakers = filtered.groupby(["Policy_Verdict", "host_name", "mac", "AI_Provider"]).agg(
                Total_Upload_MB=("Upload_Bytes", lambda x: float(x.sum()) / 1024 / 1024),
                Event_Count=("ts", "count"),
                Last_Seen=("ts", "max"),
                Top_Domain=("Domain", _safe_value_counts_top),
                Top_Evidence=("Evidence_Type", _safe_value_counts_top),
            ).reset_index().sort_values("Total_Upload_MB", ascending=False)

            if leakers.empty:
                st.info("No upload activity in the current view.")
            else:
                leak_grid = leakers.copy()
                leak_grid.insert(0, "#", range(1, len(leak_grid) + 1))
                leak_grid["Last_Seen"] = pd.to_datetime(leak_grid["Last_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
                leak_grid["Total_Upload_MB"] = pd.to_numeric(leak_grid["Total_Upload_MB"], errors="coerce").fillna(0).round(2)

                gb_leak = _new_grid_builder(leak_grid, page_size=15)
                gb_leak.configure_column("Policy_Verdict", header_name="Verdict", minWidth=110, cellStyle=_policy_cellstyle())
                gb_leak.configure_column("host_name", header_name="Host", minWidth=145)
                gb_leak.configure_column("mac", header_name="MAC", minWidth=150)
                gb_leak.configure_column("AI_Provider", header_name="Provider", minWidth=145)
                gb_leak.configure_column("Total_Upload_MB", header_name="Upload MB", minWidth=110)
                gb_leak.configure_column("Event_Count", header_name="Events", minWidth=90)
                gb_leak.configure_column("Last_Seen", header_name="Last Seen", minWidth=150)
                gb_leak.configure_column("Top_Domain", header_name="Top Domain", minWidth=180)
                gb_leak.configure_column("Top_Evidence", header_name="Top Evidence", minWidth=130)
                render_shadow_aggrid(leak_grid, gb_leak, key=f"shadow_ai_leak_grid_{selected_scope_key}", height=450)

    # =============================================================================
    # TAB: POLICY / NOISE CONTROL
    # =============================================================================
    with tabs[6]:
        st.markdown("### Policy posture / noise controls")

        st.write("Allowlist behavior: if `authorized_providers` is empty, the system defaults to deny and everything is Shadow AI.")
        st.write("To allow specific providers, add provider names (exact keys) to `authorized_providers` in `ai_signatures.yaml`.")

        # show allowlist content
        st.markdown("#### Current allowlist (authorized_providers)")
        if AUTHORIZED_PROVIDERS:
            st.code("\n".join(AUTHORIZED_PROVIDERS))
        else:
            st.info("authorized_providers is empty (default deny).")

        # show detection sources distribution
        st.markdown("#### Detection sources distribution")
        dist = filtered.groupby(["Policy_Verdict", "Detection_Source"]).size().reset_index(name="Events")
        dist_grid = dist.copy()
        dist_grid.insert(0, "#", range(1, len(dist_grid) + 1))
        gb_dist = _new_grid_builder(dist_grid, page_size=10)
        gb_dist.configure_column("Policy_Verdict", header_name="Verdict", minWidth=120, cellStyle=_policy_cellstyle())
        gb_dist.configure_column("Detection_Source", header_name="Source", minWidth=130)
        gb_dist.configure_column("Events", minWidth=90)
        render_shadow_aggrid(dist_grid, gb_dist, key=f"shadow_ai_dist_grid_{selected_scope_key}", height=290)

        st.markdown("#### Signature fragments causing matches (top)")
        sig_top = filtered.groupby(["Policy_Verdict", "Signature_Match"]).size().reset_index(name="Events")
        sig_top = sig_top.sort_values("Events", ascending=False).head(50)
        sig_grid = sig_top.copy()
        sig_grid.insert(0, "#", range(1, len(sig_grid) + 1))
        gb_sig = _new_grid_builder(sig_grid, page_size=15)
        gb_sig.configure_column("Policy_Verdict", header_name="Verdict", minWidth=120, cellStyle=_policy_cellstyle())
        gb_sig.configure_column("Signature_Match", header_name="Signature", minWidth=220, flex=1.8)
        gb_sig.configure_column("Events", minWidth=90)
        render_shadow_aggrid(sig_grid, gb_sig, key=f"shadow_ai_sig_grid_{selected_scope_key}", height=360)

        st.markdown("#### Suggested tuning (if noisy)")
        st.write("- If many hits are DNS-only, enable `Ignore DNS-only events` and focus on HTTP/SSL evidence.")
        st.write("- If one signature fragment dominates false positives, narrow or anchor it in `ai_signatures.yaml`.")
        st.write("- Prefer HTTP host/uri and TLS SNI for stronger attribution; DNS is weaker evidence.")
