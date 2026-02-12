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
# UI RENDERER
# =============================================================================

def render_shadow_ai(parquet_root: Path):
    st.markdown("#### Shadow AI & Data Leakage")

    parquet_root = Path(parquet_root)
    if not parquet_root.exists():
        st.error(f"Parquet root not found: {parquet_root}")
        return

    with st.expander("Detection basis (how Shadow AI is decided)", expanded=False):
        st.write(
            "Events are generated when Zeek telemetry matches a signature from ai_signatures.yaml "
            "(HTTP host/uri, TLS SNI, DNS query) or a configured local AI port (conn id.resp_p). "
            "Policy Verdict uses authorized_providers as an allowlist."
        )
        st.write("Evidence fields: Match_Field, Signature_Match, Matched_Value, Detection_Basis, Policy_Basis, Evidence_Type, Confidence.")

    available_dates = get_available_dates(parquet_root)
    date_options = ["All Available Dates"] + available_dates

    provider_values = sorted(list((RAW_AI_SIGNATURES or {}).keys()))
    signature_values = sorted({frag for _, frags in (RAW_AI_SIGNATURES or {}).items() for frag in (frags or [])})
    match_field_values = ["HTTP host/uri", "TLS SNI", "DNS query", "conn id.resp_p"]
    evidence_values = ["HTTP+POST", "HTTP+GET", "TLS SNI", "DNS query", "Local Port", "HTTP"]

    with st.container(border=True):
        c1, c2, c3 = st.columns([2, 2, 2])
        with c1:
            selected_date = st.selectbox(
                "Select Date Range",
                date_options,
                index=1 if len(date_options) > 1 else 0,
            )
        with c2:
            selected_verdict = st.multiselect(
                "Policy Verdict",
                ["Shadow AI", "Allowed"],
                default=["Shadow AI", "Allowed"],
            )
        with c3:
            selected_severity = st.multiselect(
                "Severity",
                ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            )

        c4, c5, c6 = st.columns([2, 2, 2])
        with c4:
            provider_filter = st.multiselect(
                "Provider",
                provider_values,
                default=[],
                placeholder="All providers",
            )
        with c5:
            basis_field = st.multiselect(
                "Match Field (basis)",
                match_field_values,
                default=match_field_values,
            )
        with c6:
            basis_sig = st.multiselect(
                "Signature Match (basis)",
                signature_values,
                default=[],
                placeholder="All signatures",
            )

        c7, c8, c9 = st.columns([2, 2, 2])
        with c7:
            evidence_filter = st.multiselect(
                "Evidence Type",
                evidence_values,
                default=[],
                placeholder="All evidence types",
            )
        with c8:
            only_resolved_mac = st.checkbox("Only resolved MAC", value=False)
        with c9:
            ignore_dns_only = st.checkbox("Ignore DNS-only events", value=False)

        c10, c11 = st.columns([3, 3])
        with c10:
            search_q = st.text_input("Search (MAC, Host, Provider, IP, Detail, Basis)", placeholder="Enter keywords...")
        with c11:
            min_upload_kb = st.number_input("Min Upload (KB)", min_value=0, value=0, step=10)

    # date scoping
    target_dates = available_dates if selected_date == "All Available Dates" else ([selected_date] if selected_date else [])

    with st.spinner("Loading and correlating telemetry..."):
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
        filtered = filtered[filtered["Upload_Bytes"] >= (min_upload_kb * 1024)]
    if only_resolved_mac:
        filtered = filtered[filtered["mac"].astype(str).fillna("").str.len() > 0
                            & filtered["mac"].astype(str).str.contains(":", na=False)]
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

    # -----------------------------------------------------------------------------
    # KPI / Exposure summary
    # -----------------------------------------------------------------------------
    st.markdown("---")
    m1, m2, m3, m4, m5, m6 = st.columns(6)

    total_leakage_mb = float(filtered["Upload_Bytes"].sum()) / 1024 / 1024 if not filtered.empty else 0.0
    shadow_count = int((filtered["Policy_Verdict"] == "Shadow AI").sum()) if not filtered.empty else 0
    critical_events = int((filtered["Severity"] == "CRITICAL").sum()) if not filtered.empty else 0
    unique_macs = int(filtered["mac"].astype(str).replace({"": None}).dropna().nunique()) if "mac" in filtered.columns else 0
    unique_hosts = int(filtered["host_name"].astype(str).replace({"": None}).dropna().nunique()) if "host_name" in filtered.columns else 0
    unique_ips = int(filtered["id.orig_h"].astype(str).replace({"": None, "nan": None}).dropna().nunique()) if "id.orig_h" in filtered.columns else 0

    m1.metric("Selected Events", len(filtered))
    m2.metric("Shadow AI Events", shadow_count, delta="Risk" if shadow_count > 0 else "Clear", delta_color="inverse")
    m3.metric("Critical Incidents", critical_events, delta="Investigate" if critical_events > 0 else "Clear", delta_color="inverse")
    m4.metric("Unique MACs", unique_macs)
    m5.metric("Unique Hosts", unique_hosts)
    m6.metric("Data Leakage", f"{total_leakage_mb:.2f} MB")

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
                hover_data=["mac", "host_name", "Detail", "Destination", "Evidence_Type", "Confidence", "Detection_Basis", "Policy_Basis", "id.orig_h"],
                title=f"Incident Timeline ({selected_date})",
                template="plotly_dark",
                render_mode=render_mode,
            )
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
                template="plotly_dark",
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        # Provider summary
        st.markdown("### Providers in View")
        prov_sum = filtered.groupby(["AI_Provider", "Policy_Verdict"]).agg(
            Events=("ts", "count"),
            Unique_MACs=("mac", lambda x: x.astype(str).replace({"": None}).dropna().nunique()),
            Last_Seen=("ts", "max"),
            Total_Upload_MB=("Upload_Bytes", lambda x: float(x.sum()) / 1024 / 1024),
        ).reset_index().sort_values(["Policy_Verdict", "Events"], ascending=[True, False])

        st.dataframe(
            prov_sum,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Last_Seen": st.column_config.DatetimeColumn("Last Seen", format="MM-DD HH:mm"),
                "Total_Upload_MB": st.column_config.NumberColumn("Upload (MB)", format="%.2f"),
            },
        )

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
            fig1 = px.line(
                daily,
                x="day",
                y="Events",
                color="Policy_Verdict",
                title="Events per day",
                template="plotly_dark",
            )
            st.plotly_chart(fig1, use_container_width=True)

            fig2 = px.line(
                daily,
                x="day",
                y="Unique_MACs",
                color="Policy_Verdict",
                title="Unique MACs per day",
                template="plotly_dark",
            )
            st.plotly_chart(fig2, use_container_width=True)

            fig3 = px.bar(
                daily,
                x="day",
                y="Upload_MB",
                color="Policy_Verdict",
                title="Upload (MB) per day",
                template="plotly_dark",
            )
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
        ).reset_index().sort_values(["Policy_Verdict", "Events"], ascending=[True, False])

        st.dataframe(
            top_dest,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Last_Seen": st.column_config.DatetimeColumn("Last Seen", format="MM-DD HH:mm"),
                "Total_Upload_MB": st.column_config.NumberColumn("Upload (MB)", format="%.2f"),
            },
        )

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
            post["endpoint"] = post.get("uri", "").astype(str).fillna("").str.split("?").str[0]
            top_end = post.groupby(["AI_Provider", "endpoint"]).agg(
                Events=("ts", "count"),
                Total_Upload_MB=("Upload_Bytes", lambda x: float(x.sum()) / 1024 / 1024),
                Last_Seen=("ts", "max"),
            ).reset_index().sort_values(["Total_Upload_MB", "Events"], ascending=False)

            st.dataframe(
                top_end,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Last_Seen": st.column_config.DatetimeColumn("Last Seen", format="MM-DD HH:mm"),
                    "Total_Upload_MB": st.column_config.NumberColumn("Upload (MB)", format="%.2f"),
                },
            )

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

            st.dataframe(
                mac_summary,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Last_Seen": st.column_config.DatetimeColumn("Last Seen", format="MM-DD HH:mm"),
                    "First_Seen": st.column_config.DatetimeColumn("First Seen", format="MM-DD HH:mm"),
                    "Total_Upload_MB": st.column_config.NumberColumn("Upload (MB)", format="%.2f"),
                },
            )

            st.markdown("### Drilldown (select MAC)")
            mac_list = mac_summary["mac"].tolist()
            selected_mac = st.selectbox("MAC", mac_list, index=0)

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
                    hover_data=["Domain", "Detail", "Evidence_Type", "Matched_Value", "Detection_Basis"],
                    title="MAC timeline (provider events)",
                    template="plotly_dark",
                    render_mode="webgl" if len(mac_events) > 1500 else "auto",
                )
                st.plotly_chart(figm, use_container_width=True)

            with cB:
                byprov = mac_events.groupby("AI_Provider").agg(
                    Events=("ts", "count"),
                    Upload_MB=("Upload_Bytes", lambda x: float(x.sum())/1024/1024),
                ).reset_index().sort_values("Events", ascending=False)
                figp = px.bar(byprov, x="Events", y="AI_Provider", orientation="h", title="Providers (this MAC)", template="plotly_dark")
                st.plotly_chart(figp, use_container_width=True)

            st.dataframe(
                mac_events[
                    [
                        "ts", "Severity", "AI_Provider", "Domain", "Evidence_Type",
                        "Detail", "Upload_Bytes", "Destination", "Matched_Value",
                        "Match_Field", "Signature_Match", "Detection_Basis", "Policy_Basis",
                        "id.orig_h", "host_name", "user_agent",
                    ]
                ],
                use_container_width=True,
                hide_index=True,
                height=520,
                column_config={
                    "ts": st.column_config.DatetimeColumn("Time", format="MM-DD HH:mm"),
                    "Upload_Bytes": st.column_config.NumberColumn("Upload Bytes", format="%d"),
                },
            )

    # =============================================================================
    # TAB: BIG TRANSFERS
    # =============================================================================
    with tabs[4]:
        st.markdown("### Large transfer alerts")
        bdf = filtered.copy()
        bdf["transfer_bucket"] = bdf["Upload_Bytes"].apply(lambda b: _bucket_transfer(float(b or 0)))

        # thresholds (SOC)
        cA, cB, cC = st.columns(3)
        with cA:
            thresh_kb = st.number_input("Alert threshold (KB)", min_value=1, value=1024, step=256)  # default 1MB
        with cB:
            only_shadow = st.checkbox("Only Shadow AI", value=True)
        with cC:
            only_http_post = st.checkbox("Only HTTP POST", value=False)

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
            st.dataframe(
                alert_df[
                    [
                        "ts", "Severity", "mac", "host_name", "id.orig_h",
                        "AI_Provider", "Domain", "Evidence_Type",
                        "Upload_Bytes", "Detail", "Destination",
                        "Matched_Value", "Detection_Basis",
                    ]
                ],
                use_container_width=True,
                hide_index=True,
                height=560,
                column_config={
                    "ts": st.column_config.DatetimeColumn("Time", format="MM-DD HH:mm"),
                    "Upload_Bytes": st.column_config.NumberColumn("Upload Bytes", format="%d"),
                },
            )

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
                st.dataframe(
                    hi[
                        [
                            "ts", "Severity", "Policy_Verdict",
                            "mac", "host_name", "id.orig_h",
                            "AI_Provider", "Domain", "Evidence_Type",
                            "Upload_Bytes", "Detail", "Destination",
                            "Match_Field", "Signature_Match", "Matched_Value",
                            "Detection_Basis", "Policy_Basis", "Confidence",
                        ]
                    ],
                    use_container_width=True,
                    hide_index=True,
                    height=560,
                    column_config={
                        "ts": st.column_config.DatetimeColumn("Time", format="MM-DD HH:mm"),
                        "Upload_Bytes": st.column_config.NumberColumn("Upload Bytes", format="%d"),
                    },
                )

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
            st.dataframe(
                filtered[cols],
                use_container_width=True,
                hide_index=True,
                height=650,
                column_config={"ts": st.column_config.DatetimeColumn("Time", format="MM-DD HH:mm")},
            )

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
                max_val = float(leakers["Total_Upload_MB"].max())
                max_val = max(1.0, max_val)
                st.dataframe(
                    leakers,
                    use_container_width=True,
                    hide_index=True,
                    column_config={
                        "Last_Seen": st.column_config.DatetimeColumn("Last Seen", format="MM-DD HH:mm"),
                        "Total_Upload_MB": st.column_config.ProgressColumn(
                            "Data Exfiltrated (MB)",
                            format="%.2f MB",
                            min_value=0.0,
                            max_value=max_val,
                        )
                    },
                )

    # =============================================================================
    # TAB: POLICY / NOISE CONTROL
    # =============================================================================
    with tabs[6]:
        st.markdown("### Policy posture / noise controls")

        st.write("**Allowlist behavior:** if `authorized_providers` is empty, the system defaults to deny → everything is Shadow AI.")
        st.write("To allow specific providers, add provider names (exact keys) to `authorized_providers` in ai_signatures.yaml.")

        # show allowlist content
        st.markdown("#### Current allowlist (authorized_providers)")
        if AUTHORIZED_PROVIDERS:
            st.code("\n".join(AUTHORIZED_PROVIDERS))
        else:
            st.info("authorized_providers is empty (default deny).")

        # show detection sources distribution
        st.markdown("#### Detection sources distribution")
        dist = filtered.groupby(["Policy_Verdict", "Detection_Source"]).size().reset_index(name="Events")
        st.dataframe(dist, use_container_width=True, hide_index=True)

        st.markdown("#### Signature fragments causing matches (top)")
        sig_top = filtered.groupby(["Policy_Verdict", "Signature_Match"]).size().reset_index(name="Events")
        sig_top = sig_top.sort_values("Events", ascending=False).head(50)
        st.dataframe(sig_top, use_container_width=True, hide_index=True)

        st.markdown("#### Suggested tuning (if noisy)")
        st.write("- If many hits are **DNS-only**, enable 'Ignore DNS-only events' and focus on HTTP/SSL evidence.")
        st.write("- If one signature fragment dominates false positives, narrow it (anchor it) in ai_signatures.yaml.")
        st.write("- Prefer HTTP host/uri and TLS SNI for stronger attribution; DNS is weaker evidence.")
