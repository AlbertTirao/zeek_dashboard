# ui/pages/shadow_ai.py
# Shadow AI SOC dashboard (fast per-date cache, strong identity enrichment, and full analytics views)

import re
import warnings
from datetime import date, datetime, timedelta
from difflib import SequenceMatcher
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

CACHE_VERSION = "shadow-ai-cache-v18-dialog-reopen-mac-ui-polish"
CACHE_DIRNAME = "_shadow_cache_ai"
DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
AI_SIGNATURES_FILE = PROJECT_ROOT / "ai_signatures.yaml"

try:
    from fuzzywuzzy import fuzz, process

    HAS_FUZZYWUZZY = True
except Exception:
    fuzz = None
    process = None
    HAS_FUZZYWUZZY = False


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


DEFAULT_GENERIC_NAME_PATTERNS = [
    r"\bgpt\b",
    r"\bcopilot\b",
    r"\bagent\b",
    r"\bllm\b",
    r"\bgenai\b",
    r"\bai\b",
]
DEFAULT_FILE_UPLOAD_EXTENSIONS = ["csv", "xlsx", "xls", "pdf", "zip", "json"]
DEFAULT_DETECTION_SETTINGS = {
    "baseline_days": 30,
    "large_https_post_threshold_mb": 5.0,
    "medium_https_post_threshold_mb": 1.0,
    "high_frequency_calls_per_hour": 50,
    "json_post_calls_per_hour": 20,
    "small_request_max_kb": 64,
    "smb_window_minutes": 5,
}


@st.cache_data(ttl=600, show_spinner=False)
def load_ai_signatures() -> Tuple[
    List[str],
    Dict[str, List[str]],
    Dict[str, List[str]],
    Dict[int, str],
    List[str],
    List[str],
    Dict[str, float],
    List[str],
    int,
]:
    """
    Reads ai_signatures.yaml:
      - ai_signatures: provider -> [regex fragments]
      - local_ai_ports: port -> label
      - authorized_providers: [provider names]
      - generic_name_patterns: [regex fragments]
      - saas_allowlist_domains: [domain suffixes]
      - detection_settings: threshold and baseline tuning
      - file_upload_extensions: [ext without dot]
    """
    y = _safe_yaml_load(AI_SIGNATURES_FILE)

    authorized = y.get("authorized_providers", []) or []
    ai_sigs = y.get("ai_signatures", {}) or {}
    local_ports = y.get("local_ai_ports", {}) or {}
    generic_name_patterns = y.get("generic_name_patterns", []) or DEFAULT_GENERIC_NAME_PATTERNS
    saas_allowlist_domains = y.get("saas_allowlist_domains", []) or []
    file_upload_extensions = y.get("file_upload_extensions", []) or DEFAULT_FILE_UPLOAD_EXTENSIONS
    det_raw = y.get("detection_settings", {}) or {}

    authorized = [str(x).strip() for x in authorized if str(x).strip()]
    generic_name_patterns = [str(x).strip() for x in generic_name_patterns if str(x).strip()]
    saas_allowlist_domains = [
        str(x).strip().lower().lstrip("*.").strip(".")
        for x in saas_allowlist_domains
        if str(x).strip()
    ]
    file_upload_extensions = [str(x).strip().lower().lstrip(".") for x in file_upload_extensions if str(x).strip()]

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

    def _to_int(v, default: int) -> int:
        try:
            return int(v)
        except Exception:
            return int(default)

    def _to_float(v, default: float) -> float:
        try:
            return float(v)
        except Exception:
            return float(default)

    detection_settings: Dict[str, float] = dict(DEFAULT_DETECTION_SETTINGS)
    detection_settings["baseline_days"] = _to_int(det_raw.get("baseline_days"), int(DEFAULT_DETECTION_SETTINGS["baseline_days"]))
    detection_settings["large_https_post_threshold_mb"] = _to_float(
        det_raw.get("large_https_post_threshold_mb"),
        float(DEFAULT_DETECTION_SETTINGS["large_https_post_threshold_mb"]),
    )
    detection_settings["medium_https_post_threshold_mb"] = _to_float(
        det_raw.get("medium_https_post_threshold_mb"),
        float(DEFAULT_DETECTION_SETTINGS["medium_https_post_threshold_mb"]),
    )
    detection_settings["high_frequency_calls_per_hour"] = _to_int(
        det_raw.get("high_frequency_calls_per_hour"),
        int(DEFAULT_DETECTION_SETTINGS["high_frequency_calls_per_hour"]),
    )
    detection_settings["json_post_calls_per_hour"] = _to_int(
        det_raw.get("json_post_calls_per_hour"),
        int(DEFAULT_DETECTION_SETTINGS["json_post_calls_per_hour"]),
    )
    detection_settings["small_request_max_kb"] = _to_int(
        det_raw.get("small_request_max_kb"),
        int(DEFAULT_DETECTION_SETTINGS["small_request_max_kb"]),
    )
    detection_settings["smb_window_minutes"] = _to_int(
        det_raw.get("smb_window_minutes"),
        int(DEFAULT_DETECTION_SETTINGS["smb_window_minutes"]),
    )

    # clamp invalid values
    detection_settings["baseline_days"] = max(1, int(detection_settings["baseline_days"]))
    detection_settings["large_https_post_threshold_mb"] = max(0.1, float(detection_settings["large_https_post_threshold_mb"]))
    detection_settings["medium_https_post_threshold_mb"] = max(0.05, float(detection_settings["medium_https_post_threshold_mb"]))
    detection_settings["high_frequency_calls_per_hour"] = max(1, int(detection_settings["high_frequency_calls_per_hour"]))
    detection_settings["json_post_calls_per_hour"] = max(1, int(detection_settings["json_post_calls_per_hour"]))
    detection_settings["small_request_max_kb"] = max(1, int(detection_settings["small_request_max_kb"]))
    detection_settings["smb_window_minutes"] = max(1, int(detection_settings["smb_window_minutes"]))

    mtime_ns = int(AI_SIGNATURES_FILE.stat().st_mtime_ns) if AI_SIGNATURES_FILE.exists() else 0
    return (
        authorized,
        raw_ai,
        hardened_ai,
        fixed_ports,
        generic_name_patterns,
        saas_allowlist_domains,
        detection_settings,
        file_upload_extensions,
        mtime_ns,
    )


(
    AUTHORIZED_PROVIDERS,
    RAW_AI_SIGNATURES,
    AI_SIGNATURES,
    LOCAL_AI_PORTS,
    GENERIC_NAME_PATTERNS,
    SAAS_ALLOWLIST_DOMAINS,
    DETECTION_SETTINGS,
    FILE_UPLOAD_EXTENSIONS,
    SIG_MTIME_NS,
) = load_ai_signatures()
AUTHORIZED_SET = {x.lower() for x in AUTHORIZED_PROVIDERS}

BASELINE_DAYS = int(DETECTION_SETTINGS.get("baseline_days", 30))
LARGE_UPLOAD_THRESHOLD_BYTES = int(float(DETECTION_SETTINGS.get("large_https_post_threshold_mb", 5.0)) * 1024 * 1024)
MEDIUM_UPLOAD_THRESHOLD_BYTES = int(float(DETECTION_SETTINGS.get("medium_https_post_threshold_mb", 1.0)) * 1024 * 1024)
HIGH_FREQUENCY_CALLS_PER_HOUR = int(DETECTION_SETTINGS.get("high_frequency_calls_per_hour", 50))
JSON_POST_CALLS_PER_HOUR = int(DETECTION_SETTINGS.get("json_post_calls_per_hour", 20))
SMALL_REQUEST_MAX_BYTES = int(DETECTION_SETTINGS.get("small_request_max_kb", 64) * 1024)
SMB_WINDOW_MINUTES = int(DETECTION_SETTINGS.get("smb_window_minutes", 5))
IDENTITY_TOLERANCE_DAYS = 2  # attribution guard: IP->MAC mapping must be within this lookback window



def _build_master_pattern(hardened_ai: Dict[str, List[str]]) -> str:
    pats: List[str] = []
    for _, lst in (hardened_ai or {}).items():
        pats.extend([p for p in (lst or []) if p])
    if not pats:
        return r"$^"
    return "(?:" + "|".join(sorted(set(pats))) + ")"


MASTER_PATTERN = _build_master_pattern(AI_SIGNATURES)


def _build_provider_hint_pattern(patterns: List[str]) -> re.Pattern:
    compiled_parts: List[str] = []
    for raw in patterns or []:
        p = str(raw).strip()
        if not p:
            continue
        try:
            re.compile(p, re.IGNORECASE)
            compiled_parts.append(f"(?:{p})")
        except Exception:
            compiled_parts.append(re.escape(p))

    if not compiled_parts:
        return re.compile(r"$^")
    return re.compile("|".join(compiled_parts), re.IGNORECASE)


GENERIC_PROVIDER_HINT_PATTERN = _build_provider_hint_pattern(GENERIC_NAME_PATTERNS)

FUZZY_MIN_SCORE = 88
FUZZY_TOKEN_STOPWORDS = {
    "com",
    "net",
    "org",
    "www",
    "http",
    "https",
    "api",
    "app",
    "cloud",
    "service",
    "services",
    "localhost",
    "local",
    "ai",
    "v1",
    "completion",
    "completions",
    "embedding",
    "embeddings",
    "upload",
    "uploads",
    "file",
    "files",
}
FUZZY_PROVIDER_SEEDS: Dict[str, List[str]] = {
    "OpenAI / ChatGPT": ["chat gpt", "chat-gpt", "open ai"],
    "Ollama (Local/Cloud)": ["ollama ai", "ollama local"],
    "Meta Llama": ["llama", "llama 2", "llama2", "llama 3", "llama3", "llama cpp", "meta llama"],
}


def _normalize_fuzzy_text(value: str) -> str:
    s = str(value or "").lower().strip()
    if not s or s in {"nan", "none", "-"}:
        return ""
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def _regex_fragment_to_fuzzy_text(fragment: str) -> str:
    s = str(fragment or "").lower()
    if not s:
        return ""
    s = s.replace(r"\.", ".").replace(r"\/", "/").replace(r"\-", "-")
    s = re.sub(r"\\[dDsSwWbBAZ]", " ", s)
    s = re.sub(r"\[[^\]]*\]", " ", s)
    s = re.sub(r"\([^\)]*\)", " ", s)
    s = re.sub(r"[{}^$*+?|]", " ", s)
    s = s.replace("\\", " ")
    return _normalize_fuzzy_text(s)


def _expand_alias_variants(raw_alias: str) -> List[str]:
    norm = _normalize_fuzzy_text(raw_alias)
    if not norm:
        return []

    out = {norm}
    tokens = [t for t in norm.split() if t and t not in FUZZY_TOKEN_STOPWORDS]
    for t in tokens:
        if len(t) >= 5:
            out.add(t)

    if tokens:
        compact = "".join(tokens)
        if len(compact) >= 6:
            out.add(compact)

    if "chatgpt" in out:
        out.update({"chat gpt", "chat-gpt"})
    if "openai" in out:
        out.update({"open ai"})
    if any(t == "llama" or t.startswith("llama") for t in tokens):
        out.update({"llama", "llama 2", "llama2", "llama 3", "llama3", "llama cpp"})

    return sorted({x for x in out if len(x) >= 4})


def _build_fuzzy_provider_aliases(raw_ai: Dict[str, List[str]]) -> Dict[str, List[str]]:
    provider_aliases: Dict[str, List[str]] = {}

    for provider, fragments in (raw_ai or {}).items():
        bucket = set()
        for alias in _expand_alias_variants(provider):
            bucket.add(alias)
        for frag in (fragments or []):
            cleaned = _regex_fragment_to_fuzzy_text(frag)
            for alias in _expand_alias_variants(cleaned):
                bucket.add(alias)
        if bucket:
            provider_aliases[provider] = sorted(bucket)

    for provider, aliases in FUZZY_PROVIDER_SEEDS.items():
        bucket = set(provider_aliases.get(provider, []))
        for alias in _expand_alias_variants(provider):
            bucket.add(alias)
        for alias in aliases:
            for variant in _expand_alias_variants(alias):
                bucket.add(variant)
        if bucket:
            provider_aliases[provider] = sorted(bucket)

    return provider_aliases


def _build_fuzzy_alias_lookup(provider_aliases: Dict[str, List[str]]) -> Dict[str, str]:
    lookup: Dict[str, str] = {}
    for provider, aliases in provider_aliases.items():
        for alias in aliases:
            if alias and alias not in lookup:
                lookup[alias] = provider
    return lookup


FUZZY_PROVIDER_ALIASES = _build_fuzzy_provider_aliases(RAW_AI_SIGNATURES)
FUZZY_ALIAS_TO_PROVIDER = _build_fuzzy_alias_lookup(FUZZY_PROVIDER_ALIASES)
FUZZY_ALIAS_CHOICES = sorted(FUZZY_ALIAS_TO_PROVIDER.keys())


def _build_fuzzy_hint_pattern(alias_choices: List[str]) -> re.Pattern:
    # Build a lightweight keyword gate to avoid expensive fuzzy checks on clearly unrelated text.
    toks = set()
    for alias in alias_choices or []:
        for tok in str(alias).split():
            tok = tok.strip().lower()
            if len(tok) >= 4 and tok not in FUZZY_TOKEN_STOPWORDS:
                toks.add(tok)
    if not toks:
        return re.compile(r"$^")
    parts = [re.escape(t) for t in sorted(toks, key=len, reverse=True)]
    return re.compile("|".join(parts), re.IGNORECASE)


FUZZY_HINT_PATTERN = _build_fuzzy_hint_pattern(FUZZY_ALIAS_CHOICES)


def _fuzzy_candidates_from_text(raw_text: str) -> List[str]:
    norm = _normalize_fuzzy_text(raw_text)
    if not norm:
        return []

    tokens = [t for t in norm.split() if t not in FUZZY_TOKEN_STOPWORDS]
    candidates: List[str] = [norm]
    candidates.extend([t for t in tokens if len(t) >= 4])

    if len(tokens) >= 2:
        for i in range(len(tokens) - 1):
            pair = f"{tokens[i]} {tokens[i + 1]}".strip()
            if len(pair) >= 6:
                candidates.append(pair)

    compact = "".join(tokens)
    if len(compact) >= 6:
        candidates.append(compact)

    dedup: List[str] = []
    seen = set()
    for item in sorted(candidates, key=len, reverse=True):
        if not item or item in seen:
            continue
        seen.add(item)
        dedup.append(item)
        if len(dedup) >= 12:
            break
    return dedup


def _extract_best_fuzzy_alias(candidate: str) -> Tuple[str, int]:
    if not candidate or not FUZZY_ALIAS_CHOICES:
        return "", 0

    if HAS_FUZZYWUZZY and process is not None and fuzz is not None:
        try:
            match = process.extractOne(candidate, FUZZY_ALIAS_CHOICES, scorer=fuzz.token_set_ratio)
        except Exception:
            match = None
        if not match:
            return "", 0
        return str(match[0]), int(match[1])

    best_alias = ""
    best_score = 0
    for alias in FUZZY_ALIAS_CHOICES:
        score = int(100 * SequenceMatcher(None, candidate, alias).ratio())
        if score > best_score:
            best_alias = alias
            best_score = score
    return best_alias, best_score


def _fuzzy_provider_match(raw_text: str, *, min_score: int = FUZZY_MIN_SCORE) -> Tuple[str, str]:
    best_provider = "Unknown"
    best_alias = ""
    best_score = 0

    for candidate in _fuzzy_candidates_from_text(raw_text):
        alias, score = _extract_best_fuzzy_alias(candidate)
        if score > best_score:
            best_alias = alias
            best_score = score
            best_provider = FUZZY_ALIAS_TO_PROVIDER.get(alias, "Unknown")
            if best_score >= 100:
                break

    if best_provider != "Unknown" and best_score >= int(min_score):
        return best_provider, f"fuzzy:{best_alias} ({best_score})"

    return "Unknown", "-"


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

# Zeek ts is epoch seconds (UTC). Convert to local for correct per-day scoping + identity joins.
LOCAL_TZ = "Asia/Manila"


def normalize_mac(value) -> Optional[str]:
    """Normalize MAC to 'aa:bb:cc:dd:ee:ff'. Return None if invalid."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None

    # 6-byte raw address
    if isinstance(value, (bytes, bytearray)) and len(value) == 6:
        hx = bytes(value).hex()
    else:
        s = str(value).strip()
        if not s or s == "-" or s.lower() in ("nan", "none"):
            return None
        # Strip separators and any non-hex characters.
        hx = _MAC_HEX_RE.sub("", s)

    if len(hx) != 12:
        return None

    hx = hx.lower()
    return ":".join(hx[i : i + 2] for i in range(0, 12, 2))




def _is_private_ip_series(ip_series: pd.Series) -> pd.Series:
    """
    Fast RFC1918/loopback/link-local check for IPv4/IPv6 text.
    Used to gate LOCAL_AI_PORTS detections so they only trigger for internal/local services.
    """
    s = ip_series.astype(str).fillna("")
    # IPv4 common private/loopback/link-local
    m = (
        s.str.startswith(("10.", "192.168.", "127.", "169.254."))
        | s.str.match(r"^172\.(1[6-9]|2\d|3[0-1])\.", na=False)
    )
    # IPv6 common local ranges: fc00::/7, fe80::/10, ::1
    m = m | s.str.startswith(("fc", "fd", "fe80", "::1"))
    return m
def _to_local_naive(ts_series: pd.Series) -> pd.Series:
    """
    Convert a datetime-like Series to Asia/Manila *naive* timestamps.

    - If tz-naive: assume UTC (typical when converting Zeek epoch seconds without tz)
    - If tz-aware: convert to Asia/Manila
    - Output: tz-naive local time for consistent display + merge_asof joins + day scoping
    """
    if ts_series is None:
        return ts_series
    t = pd.to_datetime(ts_series, errors="coerce")
    try:
        tz = getattr(t.dt, "tz", None)
        if tz is None:
            t = t.dt.tz_localize("UTC")
        t = t.dt.tz_convert(LOCAL_TZ).dt.tz_localize(None)
    except Exception:
        # best-effort fallback
        t = pd.to_datetime(t, errors="coerce")
    return t


def _ensure_ts_datetime(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize df['ts'] to a tz-naive datetime for downstream joins/sorts.

    Design goals:
      - Preserve correctness across common ingestion variants:
          * Zeek epoch seconds (float/int) -> UTC datetime (naive)
          * epoch milliseconds -> UTC datetime (naive)
          * ISO strings (tz-aware) -> UTC datetime (naive)
          * ISO strings (tz-naive) -> keep as-is (assumed already local/consistent)
          * datetime64 tz-aware -> UTC datetime (naive)
          * datetime64 tz-naive -> keep as-is
      - Never drop data silently (avoid turning everything into NaT unless truly unparseable).
    """
    if df is None:
        return pd.DataFrame()
    if df.empty:
        return df
    if "ts" not in df.columns:
        df["ts"] = pd.NaT
        return df

    s = df["ts"]

    # datetime dtype
    if pd.api.types.is_datetime64_any_dtype(s):
        try:
            # tz-aware -> convert to UTC naive
            if getattr(s.dt, "tz", None) is not None:
                df["ts"] = s.dt.tz_convert("UTC").dt.tz_localize(None)
            else:
                df["ts"] = s
        except Exception:
            df["ts"] = s
        return df

    # numeric epoch seconds/milliseconds
    if pd.api.types.is_numeric_dtype(s):
        try:
            # Heuristic: epoch ms is ~1e12, epoch seconds ~1e9
            med = float(pd.to_numeric(s, errors="coerce").median())
        except Exception:
            med = 0.0
        unit = "ms" if med > 1e11 else "s"
        dt = pd.to_datetime(s, unit=unit, errors="coerce", utc=True)
        df["ts"] = dt.dt.tz_localize(None)
        return df

    # string/object
    s_str = s.astype(str).str.strip()
    s_str = s_str.replace({"": None, "-": None, "nan": None, "None": None})

    # numeric strings -> epoch seconds/milliseconds
    num = pd.to_numeric(s_str, errors="coerce")
    if num.notna().mean() >= 0.80:
        try:
            med = float(num.median())
        except Exception:
            med = 0.0
        unit = "ms" if med > 1e11 else "s"
        dt = pd.to_datetime(num, unit=unit, errors="coerce", utc=True)
        df["ts"] = dt.dt.tz_localize(None)
        return df

    # parse timestamps (no forced utc; preserve tz if present)
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Could not infer format", category=UserWarning)
        dt = pd.to_datetime(s_str, errors="coerce")

    try:
        if getattr(dt.dt, "tz", None) is not None:
            df["ts"] = dt.dt.tz_convert("UTC").dt.tz_localize(None)
        else:
            df["ts"] = dt
    except Exception:
        df["ts"] = dt
    return df

def _apply_date_scope(df: pd.DataFrame, date_str: str, *, mode: str = "local_auto") -> Tuple[pd.DataFrame, str]:
    """
    Apply a *display* date scope for a local day (Asia/Manila) without breaking ingestion variants.

    This function is used in the UI layer (after caches are loaded). It can:
      - Convert UTC-naive timestamps to local for charts/tables
      - Filter rows to the selected local day

    mode:
      - "folder": no filtering; only best-effort local conversion
      - "local": assume df['ts'] is already local-naive; filter by local day
      - "utc": assume df['ts'] is UTC-naive; convert->local and filter by local day
      - "local_auto" (default): try both local/utc interpretations, choose the one that yields more rows in the local day
    Returns: (scoped_df, decision_string)
    """
    if df is None:
        return pd.DataFrame(), "empty"
    if df.empty:
        return df, "empty"
    if "ts" not in df.columns:
        return df, "no_ts"

    df = _ensure_ts_datetime(df)

    try:
        day_start_local = datetime.strptime(str(date_str), "%Y-%m-%d")
    except Exception:
        return df, "bad_date"

    day_end_local = day_start_local + timedelta(days=1)

    # Candidate A: ts already local-naive
    ts_a = df["ts"]

    # Candidate B: ts is UTC-naive -> convert to local-naive
    try:
        ts_b = pd.to_datetime(df["ts"], errors="coerce").dt.tz_localize("UTC").dt.tz_convert(LOCAL_TZ).dt.tz_localize(None)
    except Exception:
        ts_b = ts_a

    def _mask(ts_series: pd.Series) -> pd.Series:
        try:
            return (ts_series >= day_start_local) & (ts_series < day_end_local)
        except Exception:
            return pd.Series([True] * len(df), index=df.index)

    m_a = _mask(ts_a)
    m_b = _mask(ts_b)

    # Decide interpretation
    decision = mode
    if mode == "folder":
        # still prefer local display if it doesn't destroy ts
        df = df.copy()
        df["ts"] = ts_b
        return df, "folder"
    if mode == "local":
        df = df.copy()
        df["ts"] = ts_a
        return df.loc[m_a].copy(), "local"
    if mode == "utc":
        df = df.copy()
        df["ts"] = ts_b
        return df.loc[m_b].copy(), "utc"

    # local_auto: choose the mask with more hits; tie-break to utc (typical Zeek case)
    ca = int(m_a.sum()) if hasattr(m_a, "sum") else 0
    cb = int(m_b.sum()) if hasattr(m_b, "sum") else 0
    if cb > ca:
        df = df.copy()
        df["ts"] = ts_b
        return df.loc[m_b].copy(), "utc_auto"
    if ca > cb:
        df = df.copy()
        df["ts"] = ts_a
        return df.loc[m_a].copy(), "local_auto"

    # Tie or both zero -> prefer utc conversion but do not silently drop everything if both are zero
    df = df.copy()
    df["ts"] = ts_b
    if cb == 0 and ca == 0:
        return df, "auto_no_in_day"
    return df.loc[m_b].copy(), "utc_auto_tie"

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
      - If it fails (missing columns), probe parquet schema (fast) and retry with existing cols
      - Fallback: read full file then subset
    """
    try:
        return pd.read_parquet(path, columns=desired_cols)
    except Exception:
        # Fast retry: intersect desired columns with parquet schema (avoid full read on missing columns)
        try:
            import pyarrow.parquet as pq  # type: ignore

            pf = pq.ParquetFile(path)
            available = set(pf.schema.names)
            cols = [c for c in desired_cols if c in available]
            if cols:
                return pd.read_parquet(path, columns=cols)
        except Exception:
            pass

        # Last resort (slower): read full file then subset
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
    First matching provider wins via regex; remaining rows get fuzzy fallback.

    IMPORTANT (AI-only mode):
      - We do NOT label "generic" SaaS as AI. If a row does not match a known AI signature
        (or a known provider via fuzzy alias), it stays "Unknown" and is excluded upstream.
    """
    text_series = text_series.astype(str).replace({"nan": "", "None": ""}).fillna("")
    provider = pd.Series(index=text_series.index, dtype="object")
    sig = pd.Series(index=text_series.index, dtype="object")
    remaining = provider.isna()

    # 1) strict signature match
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

    # 2) fuzzy alias fallback (only for texts that contain known AI alias tokens)
    if remaining.any():
        rem = text_series[remaining]
        if not rem.empty:
            try:
                rem_hint = rem[rem.str.contains(FUZZY_HINT_PATTERN, na=False, regex=True)]
            except Exception:
                rem_hint = pd.Series([], dtype="object")
            if not rem_hint.empty:
                # Guard: only apply fuzzy to host-ish values (no whitespace, has dot/colon)
                try:
                    rem_hint = rem_hint[
                        (~rem_hint.astype(str).str.contains(r"\s", regex=True, na=False))
                        & (rem_hint.astype(str).str.contains(r"[\.:]", regex=True, na=False))
                    ]
                except Exception:
                    pass
                fuzzy_map: Dict[str, Tuple[str, str]] = {}
                for raw_text in rem_hint.drop_duplicates().tolist():
                    prov, fuzzy_sig = _fuzzy_provider_match(raw_text, min_score=FUZZY_MIN_SCORE)
                    if prov != "Unknown":
                        fuzzy_map[raw_text] = (prov, fuzzy_sig)

                if fuzzy_map:
                    for raw_text, (prov, fuzzy_sig) in fuzzy_map.items():
                        m = remaining & text_series.eq(raw_text)
                        if m.any():
                            provider[m] = prov
                            sig[m] = fuzzy_sig
                            remaining = provider.isna()

    return provider.fillna("Unknown"), sig.fillna("-")


def _build_identity_maps(dhcp_files: List[Path], known_files: List[Path]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Build time-aware identity observations.

    Why:
      A simple "last seen" IP->MAC map can mis-attribute events when IPs are re-used.
      This returns observation tables so enrichment can use a backward asof join (ts-aware),
      avoiding future mappings and reducing false attribution.

    Returns:
      ip_hist:  columns [ts, ip, mac, host_name]
      mac_hist: columns [ts, mac, host_name]
    """
    ip_rows: List[pd.DataFrame] = []
    mac_rows: List[pd.DataFrame] = []

    def ingest(df: pd.DataFrame) -> None:
        nonlocal ip_rows, mac_rows
        if df is None or df.empty:
            return

        df = _ensure_ts_datetime(df)

        ip_col = next((c for c in ["client_addr", "assigned_addr", "addr", "ip", "ip_addr", "host_ip", "id.orig_h"] if c in df.columns), None)
        mac_col = next((c for c in ["mac", "l2_addr", "orig_l2_addr", "hwaddr", "src_mac"] if c in df.columns), None)
        host_col = next((c for c in ["host_name", "hostname", "device_name", "host"] if c in df.columns), None)

        if "ts" not in df.columns:
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

        # ip observations
        if ip_col is not None:
            cols = ["ts", ip_col, host_col] + ([mac_col] if mac_col is not None else [])
            sub = df[cols].copy()
            sub = sub.rename(columns={ip_col: "ip", host_col: "host_name"})
            sub["ip"] = sub["ip"].astype(str).str.strip().replace({"nan": "", "None": "", "-": ""})
            if mac_col is not None:
                sub = sub.rename(columns={mac_col: "mac"})
            else:
                sub["mac"] = None
            sub["mac"] = sub["mac"].apply(normalize_mac)
            sub["host_name"] = sub["host_name"].astype(str).replace({"nan": "", "None": "", "-": ""})
            sub = sub.dropna(subset=["ip"])
            sub = sub[sub["ip"] != ""]
            if not sub.empty:
                ip_rows.append(sub[["ts", "ip", "mac", "host_name"]])

        # mac observations (for host backfill)
        if mac_col is not None:
            subm = df[["ts", mac_col, host_col]].copy()
            subm = subm.rename(columns={mac_col: "mac", host_col: "host_name"})
            subm["mac"] = subm["mac"].apply(normalize_mac)
            subm["host_name"] = subm["host_name"].astype(str).replace({"nan": "", "None": "", "-": ""})
            subm = subm.dropna(subset=["mac"])
            subm = subm[subm["mac"].astype(str) != ""]
            subm = subm[subm["host_name"] != ""]
            if not subm.empty:
                mac_rows.append(subm[["ts", "mac", "host_name"]])

    # DHCP
    for f in dhcp_files or []:
        df = _read_parquet_columns(f, ["ts", "mac", "client_addr", "assigned_addr", "host_name", "hostname", "id.orig_h", "orig_l2_addr"])
        ingest(df)

    # known_hosts / known_devices
    for f in known_files or []:
        df = _read_parquet_columns(f, ["ts", "mac", "l2_addr", "orig_l2_addr", "addr", "ip", "host_name", "hostname", "device_name", "id.orig_h"])
        ingest(df)

    ip_hist = pd.concat(ip_rows, ignore_index=True) if ip_rows else pd.DataFrame(columns=["ts", "ip", "mac", "host_name"])
    mac_hist = pd.concat(mac_rows, ignore_index=True) if mac_rows else pd.DataFrame(columns=["ts", "mac", "host_name"])

    ip_hist = _ensure_ts_datetime(ip_hist)
    mac_hist = _ensure_ts_datetime(mac_hist)

    # stable sort for merge_asof
    if not ip_hist.empty:
        ip_hist["ip"] = ip_hist["ip"].astype(str).str.strip()
        ip_hist["mac"] = ip_hist["mac"].apply(normalize_mac)
        ip_hist["host_name"] = ip_hist["host_name"].astype(str).replace({"nan": "", "None": "", "-": ""})
        ip_hist = ip_hist.dropna(subset=["ts", "ip"])
        ip_hist = ip_hist[ip_hist["ip"] != ""]
        ip_hist = ip_hist.sort_values(["ip", "ts"]).drop_duplicates(subset=["ip", "ts", "mac", "host_name"], keep="last")

    if not mac_hist.empty:
        mac_hist["mac"] = mac_hist["mac"].apply(normalize_mac)
        mac_hist["host_name"] = mac_hist["host_name"].astype(str).replace({"nan": "", "None": "", "-": ""})
        mac_hist = mac_hist.dropna(subset=["ts", "mac"])
        mac_hist = mac_hist[mac_hist["mac"].astype(str) != ""]
        mac_hist = mac_hist.sort_values(["mac", "ts"]).drop_duplicates(subset=["mac", "ts", "host_name"], keep="last")

    return ip_hist, mac_hist



def _enrich_identity(events: pd.DataFrame, ip_hist: pd.DataFrame, mac_hist: pd.DataFrame) -> pd.DataFrame:
    """
    Enrich mac/host_name with ts-aware attribution.

    Priority:
      1) L2 fields present on the event row (orig_l2_addr/l2_addr/src_mac)
      2) Backward asof join: (id.orig_h, ts) -> last known (ip, mac, host) within IDENTITY_TOLERANCE_DAYS
      3) Backward asof join: (mac, ts) -> last known host_name within IDENTITY_TOLERANCE_DAYS
    """
    if events is None or events.empty:
        return events

    events = events.copy()
    events = _ensure_ts_datetime(events)

    if "mac" not in events.columns:
        events["mac"] = None
    if "host_name" not in events.columns:
        events["host_name"] = None

    # 1) L2 fields in event (most trustworthy)
    for c in ["orig_l2_addr", "l2_addr", "src_mac"]:
        if c in events.columns:
            tmp = events[c].apply(normalize_mac)
            cur = events["mac"].apply(normalize_mac)
            events["mac"] = cur.where(cur.notna() & (cur != ""), tmp)
            break

    events["mac"] = events["mac"].apply(normalize_mac)
    tol = pd.Timedelta(days=int(IDENTITY_TOLERANCE_DAYS or 7))

    # 2) IP -> (mac, host) via backward asof join
    if (
        isinstance(ip_hist, pd.DataFrame)
        and not ip_hist.empty
        and "id.orig_h" in events.columns
        and "ts" in events.columns
    ):
        right = ip_hist.copy()
        right = _ensure_ts_datetime(right)
        for c in ["ip", "mac", "host_name"]:
            if c not in right.columns:
                right[c] = None
        right["ip"] = right["ip"].astype(str).str.strip().replace({"nan": "", "None": "", "-": ""})
        right["mac"] = right["mac"].apply(normalize_mac)
        right["host_name"] = right["host_name"].astype(str).replace({"nan": "", "None": "", "-": ""})
        right = right.dropna(subset=["ts", "ip"])
        right = right[right["ip"] != ""]

        if not right.empty:
            left = events[["ts", "id.orig_h"]].copy()
            left["ip"] = _clean_ip_series(left["id.orig_h"]).astype(str).str.strip().replace({"nan": "", "None": "", "-": ""})
            left["__idx"] = left.index
            left = left.dropna(subset=["ts", "ip"])
            left = left[left["ip"] != ""]
            if not left.empty:
                left = left.sort_values("ts")
                right = right.sort_values("ts")
                try:
                    joined = pd.merge_asof(
                        left,
                        right[["ts", "ip", "mac", "host_name"]],
                        on="ts",
                        by="ip",
                        direction="backward",
                        tolerance=tol,
                        allow_exact_matches=True,
                    )
                except Exception:
                    joined = pd.DataFrame()

                if joined is not None and not joined.empty:
                    cur_mac = events["mac"].apply(normalize_mac)
                    cur_host = events["host_name"].astype(str).replace({"nan": "", "None": "", "-": ""})
                    for _, r in joined.iterrows():
                        i = r.get("__idx")
                        if i is None:
                            continue
                        mval = normalize_mac(r.get("mac"))
                        hval = str(r.get("host_name") or "").strip()
                        if (cur_mac.loc[i] is None or cur_mac.loc[i] == "") and mval:
                            events.at[i, "mac"] = mval
                        if (not cur_host.loc[i]) and hval:
                            events.at[i, "host_name"] = hval

    events["mac"] = events["mac"].apply(normalize_mac)

    # 3) MAC -> host_name via backward asof join
    if isinstance(mac_hist, pd.DataFrame) and not mac_hist.empty and "ts" in events.columns:
        right = mac_hist.copy()
        right = _ensure_ts_datetime(right)
        for c in ["mac", "host_name"]:
            if c not in right.columns:
                right[c] = None
        right["mac"] = right["mac"].apply(normalize_mac)
        right["host_name"] = right["host_name"].astype(str).replace({"nan": "", "None": "", "-": ""})
        right = right.dropna(subset=["ts", "mac"])
        right = right[right["mac"].astype(str) != ""]

        if not right.empty:
            left = events[["ts", "mac"]].copy()
            left["mac"] = left["mac"].apply(normalize_mac)
            left["__idx"] = left.index
            left = left.dropna(subset=["ts", "mac"])
            left = left[left["mac"].astype(str) != ""]
            if not left.empty:
                left = left.sort_values("ts")
                right = right.sort_values("ts")
                try:
                    joined = pd.merge_asof(
                        left,
                        right[["ts", "mac", "host_name"]],
                        on="ts",
                        by="mac",
                        direction="backward",
                        tolerance=tol,
                        allow_exact_matches=True,
                    )
                except Exception:
                    joined = pd.DataFrame()

                if joined is not None and not joined.empty:
                    cur_host = events["host_name"].astype(str).replace({"nan": "", "None": "", "-": ""})
                    for _, r in joined.iterrows():
                        i = r.get("__idx")
                        if i is None:
                            continue
                        hval = str(r.get("host_name") or "").strip()
                        if (not cur_host.loc[i]) and hval:
                            events.at[i, "host_name"] = hval

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


def _domain_series_from_destination(dest_series: pd.Series) -> pd.Series:
    s = dest_series.astype(str).str.strip()
    s = s.replace({"nan": "", "None": "", "-": ""})
    s = s.str.replace("SNI:", "", regex=False).str.strip()
    tail = s.str.rsplit(":", n=1).str[1]
    base = s.str.rsplit(":", n=1).str[0]
    has_numeric_tail = tail.str.fullmatch(r"\d+").fillna(False)
    s = s.where(~has_numeric_tail, base)
    return s.str.lower()


# =============================================================================
# FALSE POSITIVE FILTERS (DROP NOISE BEFORE UI)
# =============================================================================

_FP_HTTP_URI_RE = re.compile(
    r"(?:/ncsi\.txt$|/connecttest\.txt$|generate_204|hotspot-detect\.html|success\.html)",
    re.IGNORECASE,
)
_FP_UA_HINTS = [
    "Microsoft NCSI",
    "CaptiveNetworkSupport",
    "ConnectivityCheck",
    "NetworkManager",
    "Windows-Connectivity",
]
try:
    _FP_UA_RE = re.compile("|".join(re.escape(x) for x in _FP_UA_HINTS), re.IGNORECASE)
except Exception:
    _FP_UA_RE = None


def _drop_false_positive_rows(df: pd.DataFrame) -> pd.DataFrame:
    """
    Drop common background-noise events that frequently appear as "false positives".

    Notes:
      - This is applied BEFORE caching, so filtered rows won't show anywhere in Shadow AI.
      - These rules are intentionally conservative.
    """
    if df is None or df.empty:
        return df

    ds = df.get("Detection_Source", pd.Series("", index=df.index)).astype(str).str.upper()
    drop = pd.Series(False, index=df.index)

    # 1) SSL: handshake not established (if field exists)
    if "established" in df.columns:
        est = df["established"].astype(str).str.upper().fillna("")
        est_known = est.ne("")
        est_ok = est.isin(["T", "TRUE", "1", "YES"])
        drop = drop | (ds.eq("SSL") & est_known & (~est_ok))

    # 2) DNS: non-success rcode (NXDOMAIN/SERVFAIL/etc.) is typically not actual "usage"
    if "rcode_name" in df.columns:
        rcode = df["rcode_name"].astype(str).str.upper().fillna("")
        rcode_known = rcode.ne("")
        drop = drop | (ds.eq("DNS") & rcode_known & (~rcode.eq("NOERROR")))

    # 3) HTTP: OS connectivity checks (NCSI / captive portal probes)
    if "uri" in df.columns:
        uri = df["uri"].astype(str).fillna("")
        drop = drop | (ds.eq("HTTP") & uri.str.contains(_FP_HTTP_URI_RE, na=False, regex=True))

    if _FP_UA_RE is not None and "user_agent" in df.columns:
        ua = df["user_agent"].astype(str).fillna("")
        drop = drop | (ds.eq("HTTP") & ua.str.contains(_FP_UA_RE, na=False, regex=True))

    # 4) Drop rows with empty destinations (cannot attribute)
    dest = df.get("Destination", pd.Series("", index=df.index)).astype(str).fillna("")
    drop = drop | dest.eq("")

    try:
        return df.loc[~drop].copy()
    except Exception:
        return df



def _is_public_domain_series(domain_series: pd.Series) -> pd.Series:
    d = domain_series.astype(str).str.strip().str.lower()
    has_dot = d.str.contains(r"\.", regex=True, na=False)
    not_local = ~d.str.endswith((".local", ".lan", ".home", ".internal"), na=False)
    not_localhost = ~d.str.startswith("localhost", na=False)
    not_ip = ~d.str.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", na=False)
    not_empty = d.ne("")
    return has_dot & not_local & not_localhost & not_ip & not_empty


def _domain_in_allowlist_series(domain_series: pd.Series, allowlist: List[str]) -> pd.Series:
    d = domain_series.astype(str).str.strip().str.lower()
    if not allowlist:
        return pd.Series(False, index=d.index)
    out = pd.Series(False, index=d.index)
    for raw in allowlist:
        suffix = str(raw).strip().lower().lstrip("*.").strip(".")
        if not suffix:
            continue
        out = out | d.eq(suffix) | d.str.endswith("." + suffix, na=False)
    return out


def _resolve_lookback_dates(all_dates: List[str], target_dates: List[str], baseline_days: int) -> Tuple[str, ...]:
    parsed_targets: List[date] = []
    target_set = {str(x) for x in (target_dates or [])}
    for d in target_set:
        try:
            parsed_targets.append(datetime.strptime(d, "%Y-%m-%d").date())
        except Exception:
            continue
    if not parsed_targets:
        return tuple()

    first_target = min(parsed_targets)
    start = first_target - timedelta(days=max(1, int(baseline_days)))

    out: List[str] = []
    for d in all_dates or []:
        if d in target_set:
            continue
        try:
            dt = datetime.strptime(str(d), "%Y-%m-%d").date()
        except Exception:
            continue
        if start <= dt < first_target:
            out.append(str(d))
    return tuple(sorted(set(out)))


@st.cache_data(show_spinner=False, ttl=300)
def _load_historical_host_domain_pairs_from_cache(parquet_root: Path, lookback_dates: Tuple[str, ...]) -> List[str]:
    root = Path(parquet_root)
    out: set[str] = set()
    for d in lookback_dates or ():
        cpath = cache_ai_events_path(root, str(d))
        if not cpath.exists():
            continue
        df = None
        for cols in (
            ["id.orig_h", "Domain", "Destination"],
            ["id.orig_h", "Domain"],
            ["id.orig_h", "Destination"],
            None,
        ):
            try:
                if cols is None:
                    df = pd.read_parquet(cpath)
                else:
                    df = pd.read_parquet(cpath, columns=cols)
                break
            except Exception:
                continue
        if df is None:
            continue
        if df.empty:
            continue
        if "id.orig_h" not in df.columns:
            continue

        host = _clean_ip_series(df["id.orig_h"]).fillna("")
        if "Domain" in df.columns:
            domain = df["Domain"].astype(str).str.strip().str.lower().replace({"nan": "", "none": "", "-": ""})
        else:
            domain = _domain_series_from_destination(df.get("Destination", pd.Series("", index=df.index)))
        valid = host.ne("") & domain.ne("")
        if not valid.any():
            continue
        pairs = (host[valid] + "|" + domain[valid]).tolist()
        out.update([p for p in pairs if p])
    return sorted(out)


def _append_reason(base: pd.Series, mask: pd.Series, label: str) -> pd.Series:
    out = base.astype(str).replace({"nan": "", "None": ""}).copy()
    m = mask.fillna(False)
    if not m.any():
        return out
    left = m & out.ne("")
    right = m & out.eq("")
    out.loc[left] = out.loc[left] + " | " + label
    out.loc[right] = label
    return out


def _smb_precursor_mask(events: pd.DataFrame, smb_events: pd.DataFrame) -> pd.Series:
    mask_out = pd.Series(False, index=events.index)
    if events.empty or smb_events is None or smb_events.empty:
        return mask_out
    if "id.orig_h" not in events.columns or "ts" not in events.columns:
        return mask_out
    if "id.orig_h" not in smb_events.columns or "ts" not in smb_events.columns:
        return mask_out

    src = events.get("Detection_Source", pd.Series("", index=events.index)).astype(str).str.upper()
    method = events.get("method", pd.Series("", index=events.index)).astype(str).str.upper()
    bytes_out = pd.to_numeric(events.get("Upload_Bytes", 0), errors="coerce").fillna(0)
    is_candidate = src.eq("HTTP") & method.eq("POST") & bytes_out.ge(LARGE_UPLOAD_THRESHOLD_BYTES)
    if not is_candidate.any():
        return mask_out

    lhs = events.loc[is_candidate, ["id.orig_h", "ts"]].copy()
    lhs["id.orig_h"] = _clean_ip_series(lhs["id.orig_h"])
    lhs["ts"] = pd.to_datetime(lhs["ts"], errors="coerce")
    lhs = lhs.dropna(subset=["id.orig_h", "ts"])
    if lhs.empty:
        return mask_out
    lhs["_row_index"] = lhs.index

    rhs = smb_events[["id.orig_h", "ts"]].copy()
    rhs["id.orig_h"] = _clean_ip_series(rhs["id.orig_h"])
    rhs["ts"] = pd.to_datetime(rhs["ts"], errors="coerce")
    rhs = rhs.dropna(subset=["id.orig_h", "ts"])
    if rhs.empty:
        return mask_out
    rhs = rhs.rename(columns={"ts": "smb_ts"})

    try:
        lhs = lhs.sort_values(["id.orig_h", "ts"])
        rhs = rhs.sort_values(["id.orig_h", "smb_ts"])
        merged = pd.merge_asof(
            lhs,
            rhs,
            by="id.orig_h",
            left_on="ts",
            right_on="smb_ts",
            direction="backward",
            tolerance=pd.Timedelta(minutes=SMB_WINDOW_MINUTES),
        )
        flagged = merged.loc[merged["smb_ts"].notna(), "_row_index"].tolist()
        if flagged:
            mask_out.loc[flagged] = True
    except Exception:
        return mask_out

    return mask_out


def _apply_behavioral_signals(
    events: pd.DataFrame,
    *,
    historical_pairs: Optional[set[str]] = None,
    smb_events: Optional[pd.DataFrame] = None,
    baseline_days: int = 30,
) -> pd.DataFrame:
    if events is None or events.empty:
        return events

    out = events.copy()
    out["ts"] = pd.to_datetime(out.get("ts", pd.Series(pd.NaT, index=out.index)), errors="coerce")
    out["Upload_Bytes"] = pd.to_numeric(out.get("Upload_Bytes", 0), errors="coerce").fillna(0)

    if "Domain" not in out.columns:
        out["Domain"] = _domain_series_from_destination(out.get("Destination", pd.Series("", index=out.index)))
    else:
        out["Domain"] = out["Domain"].astype(str).str.strip().str.lower().replace({"nan": "", "none": "", "-": ""})

    host = _clean_ip_series(out.get("id.orig_h", pd.Series("", index=out.index))).fillna("")
    source = out.get("Detection_Source", pd.Series("", index=out.index)).astype(str).str.upper()
    method = out.get("method", pd.Series("", index=out.index)).astype(str).str.upper()
    content_type = out.get("content_type", pd.Series("", index=out.index)).astype(str).str.lower()
    uri = out.get("uri", pd.Series("", index=out.index)).astype(str).str.lower()
    detail = out.get("Detail", pd.Series("", index=out.index)).astype(str).str.lower()
    uri_or_detail = uri.where(uri.str.strip().ne(""), detail)

    is_http_post = source.eq("HTTP") & method.eq("POST")
    out["Large_HTTPS_Upload"] = is_http_post & out["Upload_Bytes"].ge(LARGE_UPLOAD_THRESHOLD_BYTES)
    out["Medium_HTTPS_Upload"] = is_http_post & out["Upload_Bytes"].ge(MEDIUM_UPLOAD_THRESHOLD_BYTES)

    ext_pat = ""
    if FILE_UPLOAD_EXTENSIONS:
        ext_pat = r"\.(?:" + "|".join([re.escape(x) for x in FILE_UPLOAD_EXTENSIONS]) + r")(?:$|[?&#])"
    file_like_uri = uri_or_detail.str.contains(ext_pat, regex=True, na=False) if ext_pat else pd.Series(False, index=out.index)
    file_like_mime = content_type.str.contains(
        r"(csv|excel|spreadsheet|pdf|zip|json|application\/octet-stream)",
        regex=True,
        na=False,
    )
    out["File_Upload_Indicator"] = is_http_post & out["Medium_HTTPS_Upload"] & (file_like_uri | file_like_mime)

    domain = out["Domain"].astype(str).str.strip().str.lower()
    public_domain = _is_public_domain_series(domain)
    allowlisted = _domain_in_allowlist_series(domain, SAAS_ALLOWLIST_DOMAINS)

    pair = (host + "|" + domain).where(host.ne("") & domain.ne(""), "")
    first_seen_ts = out.groupby(pair, dropna=False)["ts"].transform("min")
    first_in_scope = out["ts"].eq(first_seen_ts) & pair.ne("")
    historical_pairs = historical_pairs or set()
    seen_before = pair.isin(historical_pairs) if historical_pairs else pd.Series(False, index=out.index)
    out["First_Seen_SaaS"] = first_in_scope & public_domain & ~allowlisted & ~seen_before

    actor = host.where(host.ne(""), out.get("mac", pd.Series("", index=out.index)).astype(str).str.lower())
    hour = out["ts"].dt.floor("h")
    group_frame = pd.DataFrame(
        {
            "actor": actor.fillna(""),
            "provider": out.get("AI_Provider", pd.Series("", index=out.index)).astype(str),
            "hour": hour,
        },
        index=out.index,
    )
    valid_group = group_frame["actor"].ne("") & group_frame["hour"].notna()
    multi_key = pd.MultiIndex.from_arrays([group_frame["actor"], group_frame["provider"], group_frame["hour"]])

    out["High_Freq_API"] = False
    if valid_group.any():
        grp = out.loc[valid_group].groupby(
            [group_frame.loc[valid_group, "actor"], group_frame.loc[valid_group, "provider"], group_frame.loc[valid_group, "hour"]],
            dropna=False,
        ).agg(calls=("ts", "count"), avg_upload=("Upload_Bytes", "mean"))
        high_idx = grp[(grp["calls"] >= HIGH_FREQUENCY_CALLS_PER_HOUR) & (grp["avg_upload"] <= SMALL_REQUEST_MAX_BYTES)].index
        out["High_Freq_API"] = pd.Series(multi_key.isin(high_idx), index=out.index) & valid_group

    json_post = is_http_post & content_type.str.contains(r"application\/json", regex=True, na=False)
    out["JSON_Heavy_API"] = False
    if (valid_group & json_post).any():
        grp_json = out.loc[valid_group & json_post].groupby(
            [group_frame.loc[valid_group & json_post, "actor"], group_frame.loc[valid_group & json_post, "provider"], group_frame.loc[valid_group & json_post, "hour"]],
            dropna=False,
        ).size()
        json_idx = grp_json[grp_json >= JSON_POST_CALLS_PER_HOUR].index
        out["JSON_Heavy_API"] = pd.Series(multi_key.isin(json_idx), index=out.index) & valid_group & json_post

    existing_strong = out.get("Strong_Signal_Pattern", pd.Series(False, index=out.index)).astype(bool)
    if smb_events is not None:
        out["Strong_Signal_Pattern"] = existing_strong | _smb_precursor_mask(out, smb_events)
    else:
        out["Strong_Signal_Pattern"] = existing_strong
    out["Governance_Alert"] = out["Large_HTTPS_Upload"] & (
        out["First_Seen_SaaS"] | out["File_Upload_Indicator"] | out["High_Freq_API"] | out["JSON_Heavy_API"] | out["Strong_Signal_Pattern"]
    )

    indicators = pd.Series("", index=out.index, dtype="object")
    indicators = _append_reason(indicators, out["First_Seen_SaaS"], f"First-seen SaaS ({int(baseline_days)}d baseline)")
    indicators = _append_reason(indicators, out["Large_HTTPS_Upload"], f"Large HTTPS POST >= {int(round(LARGE_UPLOAD_THRESHOLD_BYTES / (1024 * 1024)))}MB")
    indicators = _append_reason(indicators, out["File_Upload_Indicator"], "File-like upload correlation")
    indicators = _append_reason(indicators, out["JSON_Heavy_API"], "JSON-heavy API traffic")
    indicators = _append_reason(indicators, out["High_Freq_API"], f"High-frequency API ({HIGH_FREQUENCY_CALLS_PER_HOUR}/hour)")
    indicators = _append_reason(indicators, out["Strong_Signal_Pattern"], f"SMB-to-upload precursor <= {SMB_WINDOW_MINUTES}min")
    out["Behavior_Indicators"] = indicators.where(indicators.ne(""), "-")

    basis = out.get("Detection_Basis", pd.Series("", index=out.index)).astype(str).replace({"nan": "", "None": ""})
    basis = _append_reason(basis, out["First_Seen_SaaS"], "First-seen SaaS critical signal")
    basis = _append_reason(basis, out["Governance_Alert"], "Governance alert pattern")
    out["Detection_Basis"] = basis

    return out


def _compute_evidence_type(df: pd.DataFrame) -> pd.Series:
    src = df.get("Detection_Source", pd.Series("", index=df.index)).astype(str).str.upper()
    method = df.get("method", pd.Series("", index=df.index)).astype(str).str.upper()

    out = src.copy()
    out = out.replace({"": "Unknown", "NAN": "Unknown", "NONE": "Unknown"})

    ssl_mask = src.eq("SSL")
    dns_mask = src.str.startswith("DNS", na=False)
    conn_mask = src.str.startswith("CONN", na=False)
    http_mask = src.eq("HTTP")

    out[ssl_mask] = "TLS SNI"
    out[dns_mask] = "DNS query"
    out[conn_mask] = "Local Port"
    if http_mask.any():
        http_ev = ("HTTP+" + method.where(method != "", "")).str.rstrip("+")
        out[http_mask] = http_ev[http_mask]
    return out


def _compute_risk_score(df: pd.DataFrame) -> pd.Series:
    source = df.get("Detection_Source", pd.Series("", index=df.index)).astype(str).str.upper()
    method = df.get("method", pd.Series("", index=df.index)).astype(str).str.upper()
    detail = df.get("Detail", pd.Series("", index=df.index)).astype(str).str.lower()
    bytes_out = pd.to_numeric(df.get("Upload_Bytes", 0), errors="coerce").fillna(0.0)
    client_type = df.get("Client_Type", pd.Series("", index=df.index)).astype(str)
    first_seen = df.get("First_Seen_SaaS", pd.Series(False, index=df.index)).astype(bool)
    governance_alert = df.get("Governance_Alert", pd.Series(False, index=df.index)).astype(bool)
    json_heavy = df.get("JSON_Heavy_API", pd.Series(False, index=df.index)).astype(bool)
    high_freq = df.get("High_Freq_API", pd.Series(False, index=df.index)).astype(bool)
    file_upload = df.get("File_Upload_Indicator", pd.Series(False, index=df.index)).astype(bool)
    strong_signal = df.get("Strong_Signal_Pattern", pd.Series(False, index=df.index)).astype(bool)

    score = pd.Series(10, index=df.index, dtype="int64")
    http = source.eq("HTTP")

    score += http.astype(int) * 20
    score += (http & method.eq("POST")).astype(int) * 20

    gt_5mb = bytes_out >= LARGE_UPLOAD_THRESHOLD_BYTES
    gt_1mb = bytes_out >= MEDIUM_UPLOAD_THRESHOLD_BYTES
    gt_10kb = bytes_out > (10 * 1024)
    score += (http & gt_5mb).astype(int) * 40
    score += (http & (~gt_5mb) & gt_1mb).astype(int) * 20
    score += (http & (~gt_1mb) & gt_10kb).astype(int) * 10

    uri_hit = detail.str.contains(
        r"/upload|/files|/embeddings|/fine-tune|v1/files|v1/embeddings|v1/chat/completions",
        regex=True,
        na=False,
    )
    score += (http & uri_hit).astype(int) * 15

    score += source.eq("SSL").astype(int) * 15
    score += source.str.startswith("DNS", na=False).astype(int) * 8
    score += source.str.startswith("CONN", na=False).astype(int) * 12
    score += client_type.eq("Automation / SDK").astype(int) * 15
    score += first_seen.astype(int) * 25
    score += governance_alert.astype(int) * 25
    score += json_heavy.astype(int) * 10
    score += high_freq.astype(int) * 10
    score += file_upload.astype(int) * 8
    score += strong_signal.astype(int) * 18

    return score.clip(upper=100).astype(int)


def _severity_from_scores(scores: pd.Series) -> pd.Series:
    sev = pd.Series("LOW", index=scores.index, dtype="object")
    sev[scores >= 30] = "MEDIUM"
    sev[scores >= 60] = "HIGH"
    sev[scores >= 80] = "CRITICAL"
    return sev


def _apply_critical_overrides(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    out = df
    risk = pd.to_numeric(out.get("Risk_Score", 0), errors="coerce").fillna(0).astype(int)
    verdict = out.get("Policy_Verdict", pd.Series("", index=out.index)).astype(str)
    first_seen = out.get("First_Seen_SaaS", pd.Series(False, index=out.index)).astype(bool)
    gov_alert = out.get("Governance_Alert", pd.Series(False, index=out.index)).astype(bool)

    critical_mask = first_seen & verdict.eq("Shadow AI")
    high_mask = gov_alert & ~critical_mask

    if critical_mask.any():
        risk.loc[critical_mask] = risk.loc[critical_mask].clip(lower=85)
        out.loc[critical_mask, "Severity"] = "CRITICAL"
    if high_mask.any():
        risk.loc[high_mask] = risk.loc[high_mask].clip(lower=65)
        cur_sev = out.get("Severity", pd.Series("", index=out.index)).astype(str)
        out.loc[high_mask & cur_sev.isin(["LOW", "MEDIUM"]), "Severity"] = "HIGH"

    out["Risk_Score"] = risk
    return out


def _policy_columns(provider: pd.Series) -> Tuple[pd.Series, pd.Series]:
    p = provider.astype(str).str.lower()
    allowed_mask = p.isin(AUTHORIZED_SET)

    verdict = pd.Series("Shadow AI", index=provider.index, dtype="object")
    verdict[allowed_mask] = "Allowed"

    if AUTHORIZED_PROVIDERS:
        basis = pd.Series("Provider is not on allowlist", index=provider.index, dtype="object")
        basis[allowed_mask] = "Provider is on allowlist"
    else:
        basis = pd.Series("authorized_providers is empty (default deny)", index=provider.index, dtype="object")

    return verdict, basis


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
        for p in parquet_root.iterdir():
            if not p.is_dir() or not DATE_DIR_RE.match(p.name):
                continue
            for f in p.rglob("*.parquet"):
                name = f.name.lower()
                if ("known_hosts" in name) or ("knownhost" in name) or ("known_devices" in name) or ("knowndevices" in name):
                    known.append(f)
    except Exception:
        pass
    return sorted(set(known))


@st.cache_data(show_spinner=False)
def _collect_known_files_by_date(parquet_root: Path) -> Dict[str, List[str]]:
    parquet_root = Path(parquet_root)
    out: Dict[str, List[str]] = {}
    if not parquet_root.exists():
        return out
    try:
        for p in parquet_root.iterdir():
            if not p.is_dir() or not DATE_DIR_RE.match(p.name):
                continue
            files: List[str] = []
            for f in p.rglob("*.parquet"):
                name = f.name.lower()
                if ("known_hosts" in name) or ("knownhost" in name) or ("known_devices" in name) or ("knowndevices" in name):
                    files.append(str(f))
            out[p.name] = sorted(set(files))
    except Exception:
        pass
    return out



def _choose_known_files_lookback(known_files_by_date: Dict[str, List[str]], date_str: str, *, lookback_days: int = 30) -> List[Path]:
    """
    Choose known_hosts/known_devices parquet files for identity enrichment WITHOUT using future dates.
    If the selected date has no known_* parquet, pull from a lookback window (default 30 days) ending at date_str.
    """
    try:
        target = datetime.strptime(str(date_str), "%Y-%m-%d").date()
    except Exception:
        return []

    start = target - timedelta(days=int(lookback_days or 30))
    out: List[Path] = []
    for d, files in (known_files_by_date or {}).items():
        try:
            dd = datetime.strptime(str(d), "%Y-%m-%d").date()
        except Exception:
            continue
        if dd < start or dd > target:
            continue
        for p in files or []:
            try:
                out.append(Path(p))
            except Exception:
                continue
    uniq = sorted({str(p) for p in out})
    return [Path(p) for p in uniq]



@st.cache_data(show_spinner=False)
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
            df_cached = _ensure_ts_datetime(df_cached)
            if "ts" in df_cached.columns:
                return df_cached.sort_values("ts", ascending=False)
            return df_cached
        except Exception:
            pass

    # identity maps
    ip_map, mac_map = _build_identity_maps(buckets["dhcp"], known_files)

    events: List[pd.DataFrame] = []
    smb_events_frames: List[pd.DataFrame] = []

    # --- HTTP ---
    http_cols = [
        "uid",
        "ts", "id.orig_h", "id.resp_h", "id.resp_p",
        "host", "uri", "user_agent", "method", "request_body_len", "content_type",
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
        combined = host_s.astype(str)

        prov_all, sig_all = _assign_provider_and_signature(combined)
        mask = prov_all != "Unknown"
        if not mask.any():
            continue

        hit = df.loc[mask].copy()
        hit = _ensure_ts_datetime(hit)

        host_s_hit = hit[host_col].astype(str).fillna("")
        uri_s_hit = hit["uri"].astype(str).fillna("") if "uri" in hit.columns else ""
        hit["AI_Provider"] = prov_all.loc[mask].values
        hit["Signature_Match"] = sig_all.loc[mask].values
        hit["Detection_Source"] = "HTTP"
        hit["Match_Field"] = "HTTP host"

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
        hit["Matched_Value"] = host_s_hit.astype(str)

        hit["Detection_Basis"] = hit["Match_Field"] + " matched '" + hit["Signature_Match"].astype(str) + "'"
        events.append(hit)

    # --- SSL ---
    ssl_cols = ["uid", "ts", "id.orig_h", "id.resp_h", "server_name", "established", "orig_l2_addr", "l2_addr", "src_mac"]
    for f in buckets["ssl"]:
        df = _read_parquet_columns(f, ssl_cols)
        if df.empty:
            continue
        df = _ensure_ts_datetime(df)
        if "server_name" not in df.columns:
            continue

        sni = df["server_name"].astype(str).fillna("")
        prov_all, sig_all = _assign_provider_and_signature(sni)
        mask = prov_all != "Unknown"
        if not mask.any():
            continue

        hit = df.loc[mask].copy()
        hit = _ensure_ts_datetime(hit)

        sni_hit = hit["server_name"].astype(str).fillna("")

        hit["AI_Provider"] = prov_all.loc[mask].values
        hit["Signature_Match"] = sig_all.loc[mask].values
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
    dns_cols = ["uid", "ts", "id.orig_h", "id.resp_h", "query", "qtype_name", "rcode_name", "orig_l2_addr", "l2_addr", "src_mac"]
    for f in buckets["dns"]:
        df = _read_parquet_columns(f, dns_cols)
        if df.empty:
            continue
        df = _ensure_ts_datetime(df)
        if "query" not in df.columns:
            continue

        q = df["query"].astype(str).fillna("")
        prov_all, sig_all = _assign_provider_and_signature(q)
        mask = prov_all != "Unknown"
        if not mask.any():
            continue

        hit = df.loc[mask].copy()
        hit = _ensure_ts_datetime(hit)

        q_hit = hit["query"].astype(str).fillna("")

        hit["AI_Provider"] = prov_all.loc[mask].values
        hit["Signature_Match"] = sig_all.loc[mask].values
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
    conn_cols = ["uid", "ts", "id.orig_h", "id.resp_h", "id.resp_p", "orig_ip_bytes", "orig_l2_addr", "l2_addr", "src_mac"]
    ports = sorted(LOCAL_AI_PORTS.keys())
    conn_uid_map_frames: List[pd.DataFrame] = []
    for f in buckets["conn"]:
        df = _read_parquet_columns(f, conn_cols)
        if df.empty or "id.resp_p" not in df.columns:
            continue
        df = _ensure_ts_datetime(df)
        # Build exact uid→MAC mapping from conn.log (most accurate for per-event attribution)
        try:
            if "uid" in df.columns and "orig_l2_addr" in df.columns:
                um = df[["uid", "ts", "orig_l2_addr"]].copy()
                conn_uid_map_frames.append(um)
        except Exception:
            pass
        rp = pd.to_numeric(df["id.resp_p"], errors="coerce")
        if "id.orig_h" in df.columns:
            smb_mask = rp.eq(445)
            if smb_mask.any():
                smb = df.loc[smb_mask, ["id.orig_h", "ts"]].copy()
                smb = smb.dropna(subset=["id.orig_h", "ts"])
                if not smb.empty:
                    smb_events_frames.append(smb)

        if not ports:
            continue

        mask = rp.isin(ports)
        # Gate local-port detections to internal destinations to avoid tagging non-AI external services.
        try:
            resp_h_series = df.get("id.resp_h", pd.Series("", index=df.index))
            mask = mask & _is_private_ip_series(resp_h_series)
        except Exception:
            pass
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

    
    # Finalize uid→MAC map for this day
    if conn_uid_map_frames:
        try:
            conn_uid_map = pd.concat(conn_uid_map_frames, ignore_index=True)
            conn_uid_map = _ensure_ts_datetime(conn_uid_map)
            conn_uid_map["uid"] = conn_uid_map["uid"].astype(str)
            conn_uid_map["orig_l2_addr"] = conn_uid_map["orig_l2_addr"].apply(normalize_mac)
            conn_uid_map = conn_uid_map.dropna(subset=["uid"]).sort_values("ts")
            conn_uid_map = conn_uid_map.drop_duplicates(subset=["uid"], keep="last")
            conn_uid_map = conn_uid_map.dropna(subset=["orig_l2_addr"])
        except Exception:
            conn_uid_map = pd.DataFrame(columns=["uid", "ts", "orig_l2_addr"])
    else:
        conn_uid_map = pd.DataFrame(columns=["uid", "ts", "orig_l2_addr"])
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
        "method", "uri", "content_type", "Domain", "Evidence_Type",
        "Behavior_Indicators", "First_Seen_SaaS", "Governance_Alert",
        "Large_HTTPS_Upload", "Medium_HTTPS_Upload", "File_Upload_Indicator",
        "High_Freq_API", "JSON_Heavy_API", "Strong_Signal_Pattern",
    ]
    for c in required:
        if c not in final_df.columns:
            final_df[c] = ""

    # de-duplicate exact duplicates (common when logs are split into multiple parquet parts)
    try:
        final_df = final_df.drop_duplicates()
    except Exception:
        pass

    # Attach conn-level L2 MAC by uid (exact match). This prevents IP→MAC drift and fixes
    # 'MAC shows providers I never used' caused by stale DHCP/known_hosts attribution.
    try:
        if isinstance(conn_uid_map, pd.DataFrame) and not conn_uid_map.empty and "uid" in final_df.columns:
            uid_map = conn_uid_map[["uid", "orig_l2_addr"]].copy()
            uid_map["uid"] = uid_map["uid"].astype(str)
            uid_map["orig_l2_addr"] = uid_map["orig_l2_addr"].apply(normalize_mac)
            uid_map = uid_map.dropna(subset=["uid", "orig_l2_addr"]) 
            if not uid_map.empty:
                final_df["uid"] = final_df["uid"].astype(str)
                final_df = final_df.merge(uid_map, on="uid", how="left", suffixes=("", "_conn"))
                if "orig_l2_addr_conn" in final_df.columns:
                    a = final_df.get("orig_l2_addr", pd.Series([None] * len(final_df), index=final_df.index)).apply(normalize_mac)
                    b = final_df["orig_l2_addr_conn"].apply(normalize_mac)
                    final_df["orig_l2_addr"] = a.where(a.notna() & (a != ""), b)
                    final_df = final_df.drop(columns=["orig_l2_addr_conn"])
    except Exception:
        pass

    # identity enrichment
    final_df = _enrich_identity(final_df, ip_map, mac_map)

    # normalize sizes
    final_df["Upload_Bytes"] = pd.to_numeric(final_df.get("Upload_Bytes", 0), errors="coerce").fillna(0)

    # derived domain
    final_df["Domain"] = _domain_series_from_destination(final_df.get("Destination", pd.Series("", index=final_df.index)))

    # Drop common false positives / background noise
    final_df = _drop_false_positive_rows(final_df)

    # policy
    verdict, basis = _policy_columns(final_df["AI_Provider"])
    final_df["Policy_Verdict"] = verdict
    final_df["Policy_Basis"] = basis

    # confidence
    source = final_df.get("Detection_Source", pd.Series("", index=final_df.index)).astype(str).str.upper()
    final_df["Confidence"] = pd.Series("Medium", index=final_df.index)
    final_df.loc[source.isin(["HTTP", "SSL"]), "Confidence"] = "High"

    # evidence and behavior heuristics
    final_df["Evidence_Type"] = _compute_evidence_type(final_df)
    smb_df = (
        pd.concat(smb_events_frames, ignore_index=True)
        if smb_events_frames
        else pd.DataFrame(columns=["id.orig_h", "ts"])
    )
    final_df = _apply_behavioral_signals(
        final_df,
        historical_pairs=None,
        smb_events=smb_df,
        baseline_days=BASELINE_DAYS,
    )

    # risk scoring
    final_df["Risk_Score"] = _compute_risk_score(final_df)
    final_df["Severity"] = _severity_from_scores(final_df["Risk_Score"])
    final_df = _apply_critical_overrides(final_df)

    final_df = final_df.sort_values("ts", ascending=False)

    # write cache
    try:
        cpath.parent.mkdir(parents=True, exist_ok=True)
        final_df.to_parquet(cpath, index=False)
        write_yaml(mpath, expected)
    except Exception:
        pass

    return final_df


# =============================================================================
# CORE LOADER (FAST, REUSABLE CACHE)
# =============================================================================

def _normalize_target_dates(target_dates) -> Tuple[str, ...]:
    if not target_dates:
        return tuple()
    out: List[str] = []
    if isinstance(target_dates, (list, tuple, set)):
        iterable = target_dates
    else:
        iterable = [target_dates]
    for d in iterable:
        d = str(d).strip()
        if d and DATE_DIR_RE.match(d):
            out.append(d)
    # deterministic key (order doesn't matter for output because we sort by ts)
    return tuple(sorted(set(out), reverse=True))


def _load_shadow_ai_data_uncached(parquet_root: Path, target_dates: Tuple[str, ...]) -> pd.DataFrame:
    """
    Multi-date loader that reuses per-day caches (fast).
    Uncached: used behind a resource cache and/or session state.
    """
    parquet_root = Path(parquet_root)
    if not parquet_root.exists():
        return pd.DataFrame()

    known_files_all = _collect_known_files(parquet_root)
    known_files_by_date = _collect_known_files_by_date(parquet_root)

    frames: List[pd.DataFrame] = []
    for d in (target_dates or ()):
        if not d or not DATE_DIR_RE.match(str(d)):
            continue
        known_for_date = [Path(p) for p in known_files_by_date.get(str(d), [])]
        if not known_for_date:
            # IMPORTANT: do not use future-known_* files (can mis-attribute MACs).
            known_for_date = _choose_known_files_lookback(known_files_by_date, str(d), lookback_days=max(7, int(BASELINE_DAYS or 30)))
        if not known_for_date:
            known_for_date = []
        df_d = _build_one_date(parquet_root, str(d), known_for_date)
        if not df_d.empty:
            frames.append(df_d)

    if not frames:
        return pd.DataFrame()

    out = pd.concat(frames, ignore_index=True)
    out = _ensure_ts_datetime(out)
    try:
        out = out.drop_duplicates()
    except Exception:
        pass


    # Cross-date baseline: compute first-seen SaaS relative to prior days.
    all_dates = get_available_dates(parquet_root)
    lookback_dates = _resolve_lookback_dates(all_dates, list(target_dates), BASELINE_DAYS)
    historical_pairs = set(_load_historical_host_domain_pairs_from_cache(parquet_root, lookback_dates)) if lookback_dates else set()

    out = _apply_behavioral_signals(
        out,
        historical_pairs=historical_pairs,
        smb_events=None,
        baseline_days=BASELINE_DAYS,
    )

    out["Risk_Score"] = _compute_risk_score(out)
    out["Severity"] = _severity_from_scores(out["Risk_Score"])
    out = _apply_critical_overrides(out)
    return out.sort_values("ts", ascending=False)


@st.cache_resource(show_spinner=False)
def _load_shadow_ai_data_cached(
    parquet_root_str: str,
    target_dates: Tuple[str, ...],
    cache_bust: int,
    cache_version: str,
    sig_mtime_ns: int,
    baseline_days: int,
) -> pd.DataFrame:
    """
    Resource cache (in-memory, no pickle roundtrip) so search/filter/dialog reruns don't reload/parquet-scan again.
    cache_bust + cache_version + sig_mtime_ns + baseline_days are part of the key for safe invalidation.
    """
    _ = cache_bust, cache_version, sig_mtime_ns, baseline_days  # key-only; keep lint quiet
    return _load_shadow_ai_data_uncached(Path(parquet_root_str), target_dates)


def load_shadow_ai_data(parquet_root: Path, target_dates: List[str], *, cache_bust: int = 0) -> pd.DataFrame:
    """Public loader used by the UI."""
    root = str(Path(parquet_root).resolve())
    td = _normalize_target_dates(target_dates)
    return _load_shadow_ai_data_cached(
        root,
        td,
        int(cache_bust or 0),
        str(CACHE_VERSION),
        int(SIG_MTIME_NS),
        int(BASELINE_DAYS),
    )



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


def _shadow_ai_data_stamp(df: pd.DataFrame) -> Tuple[int, str, str]:
    if df is None or df.empty:
        return (0, "", "")
    ts_raw = df.get("ts", pd.Series([], dtype="datetime64[ns]"))
    if pd.api.types.is_datetime64_any_dtype(ts_raw):
        ts = ts_raw
    else:
        ts = pd.to_datetime(ts_raw, errors="coerce")
    tmax = ts.max()
    tmin = ts.min()
    return (
        int(len(df)),
        str(tmax) if pd.notna(tmax) else "",
        str(tmin) if pd.notna(tmin) else "",
    )


def _shadow_ai_mac_tab_cache_key(
    selected_scope_key: str,
    selected_verdict: List[str],
    selected_severity: List[str],
    provider_filter: List[str],
    basis_field: List[str],
    basis_sig: List[str],
    evidence_filter: List[str],
    min_upload_kb: float,
    only_resolved_mac: bool,
    ignore_dns_only: bool,
    search_q: str,
    data_stamp: Tuple[int, str, str],
) -> Tuple[object, ...]:
    return (
        str(selected_scope_key),
        tuple(sorted([str(x) for x in (selected_verdict or [])])),
        tuple(sorted([str(x) for x in (selected_severity or [])])),
        tuple(sorted([str(x) for x in (provider_filter or [])])),
        tuple(sorted([str(x) for x in (basis_field or [])])),
        tuple(sorted([str(x) for x in (basis_sig or [])])),
        tuple(sorted([str(x) for x in (evidence_filter or [])])),
        float(min_upload_kb or 0),
        bool(only_resolved_mac),
        bool(ignore_dns_only),
        str(search_q or "").strip().lower(),
        data_stamp,
    )


def _build_shadow_ai_mac_tab_frames(filtered: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    mac_view = filtered[filtered["Policy_Verdict"] == "Shadow AI"].copy()
    if mac_view.empty:
        return mac_view, pd.DataFrame()

    mac_view["mac"] = mac_view["mac"].astype(str).str.strip().str.lower()
    mac_view = mac_view[mac_view["mac"].str.contains(":", na=False)]
    if mac_view.empty:
        return mac_view, pd.DataFrame()

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

    return mac_view, mac_summary


def _apply_shadow_ai_filters(
    df: pd.DataFrame,
    *,
    selected_verdict: List[str],
    selected_severity: List[str],
    provider_filter: List[str],
    basis_field: List[str],
    basis_sig: List[str],
    evidence_filter: List[str],
    min_upload_kb: float,
    only_resolved_mac: bool,
    ignore_dns_only: bool,
    search_q: str,
) -> pd.DataFrame:
    filtered = df

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

    q = str(search_q or "").strip().lower()
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

    return filtered


# =============================================================================
# UI HELPERS
# =============================================================================

MAX_ROWS_DISPLAY = 10000
DIALOG_MAX_ROWS = 3000
DIALOG_TIMELINE_MAX_POINTS = 3000
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


def render_shadow_aggrid(
    df: pd.DataFrame,
    gb: GridOptionsBuilder,
    *,
    key: str,
    height: int = 430,
    update_mode=GridUpdateMode.NO_UPDATE,
    grid_options_overrides: Optional[Dict[str, object]] = None,
    auto_fit_columns: bool = True,
):
    grid_options = gb.build()

    # Match Shadow Apps / Shadow Sharings filtering behavior.
    default_col_def = dict(grid_options.get("defaultColDef") or {})
    default_col_def["sortable"] = True
    default_col_def["filter"] = "agSetColumnFilter"
    default_col_def["floatingFilter"] = False
    default_col_def.setdefault("minWidth", 96)
    default_col_def["menuTabs"] = ["filterMenuTab", "generalMenuTab"]
    default_col_def["suppressMenu"] = False

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

    # Enforce per-column menu/filter so every table column has the same 3-dot menu behavior.
    col_defs = list(grid_options.get("columnDefs") or [])
    if col_defs:
        for col_def in col_defs:
            if not isinstance(col_def, dict):
                continue
            col_def.setdefault("sortable", True)
            col_def.setdefault("filter", "agSetColumnFilter")
            col_def.setdefault("floatingFilter", False)
            col_def.setdefault("menuTabs", ["filterMenuTab", "generalMenuTab"])
            col_def.setdefault("suppressMenu", False)
            cfp = dict(col_def.get("filterParams") or {})
            cfp.setdefault("excelMode", "windows")
            cfp.setdefault("buttons", ["apply", "clear", "cancel"])
            cfp.setdefault("closeOnApply", True)
            cfp.setdefault("suppressMiniFilter", False)
            col_def["filterParams"] = cfp
        grid_options["columnDefs"] = col_defs

    if auto_fit_columns:
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
    if grid_options_overrides:
        grid_options.update(grid_options_overrides)

    ag_theme, ag_css = get_aggrid_theme_and_css()
    table_css = dict(ag_css)
    table_css.update(
        {
            ".ag-root-wrapper": {"background-color": "#061120", "color": "#EAF2FF", "border": "1px solid #2A466E"},
            ".ag-header": {"background-color": "#10213E", "color": "#EAF2FF", "border-bottom": "1px solid #3A5A8E"},
            ".ag-header-cell, .ag-header-group-cell": {"background-color": "#10213E", "color": "#EAF2FF", "border-right": "1px solid #2A466E"},
            ".ag-header-cell-menu-button": {
                "opacity": "1 !important",
                "display": "flex !important",
                "align-items": "center",
                "color": "#BFD7FF !important",
            },
            ".ag-header-cell-menu-button:hover": {"color": "#FFFFFF !important"},
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
        fit_columns_on_grid_load=auto_fit_columns,
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


def _close_shadow_ai_mac_dialog(*, preserve_last_selected: bool = True) -> None:
    """
    Close the MAC drilldown dialog and reset grid selection.
    
    Why: AgGrid keeps the last selected row. If we preserve selection + last_selected,
    clicking the same MAC again won't trigger a new open. We bump a nonce so the MAC
    grid re-mounts and clears selection.
    """
    active_mac = str(st.session_state.get("shadow_ai_mac_dialog_mac") or "").strip().lower()
    st.session_state["shadow_ai_mac_dialog_open"] = False
    st.session_state["shadow_ai_mac_dialog_mac"] = None
    # Always clear last_selected so the next click (even same MAC) can re-open.
    st.session_state["shadow_ai_mac_dialog_last_selected"] = None
    if preserve_last_selected and active_mac:
        st.session_state["shadow_ai_mac_dialog_last_selected_preserved"] = active_mac
    else:
        st.session_state["shadow_ai_mac_dialog_last_selected_preserved"] = None
    st.session_state["shadow_ai_mac_grid_nonce"] = int(st.session_state.get("shadow_ai_mac_grid_nonce", 0)) + 1


def _render_shadow_ai_mac_drilldown(
    mac_events: pd.DataFrame,
    *,
    selected_scope_key: str,
    active_mac: str,
    key_prefix: str,
) -> None:
    """
    Device-scoped drilldown. Built to be accurate (MAC-locked) and fast to render.

    Notes:
      - We show a deduplicated view by default to avoid double-counting the same evidence row in the UI.
      - Use the "Show raw duplicates" toggle if you need to see every matching row.
    """
    mac_events = mac_events.copy()

    required = [
        "ts", "Severity", "AI_Provider", "Domain", "Evidence_Type",
        "Detail", "Upload_Bytes", "Destination", "Matched_Value",
        "Match_Field", "Signature_Match", "Detection_Basis", "Policy_Basis",
        "id.orig_h", "host_name", "user_agent", "Risk_Score", "Policy_Verdict",
        "Detection_Source", "Behavior_Indicators", "First_Seen_SaaS", "Governance_Alert",
        "Client_Type", "Confidence",
    ]
    for c in required:
        if c not in mac_events.columns:
            mac_events[c] = "" if c not in ["First_Seen_SaaS", "Governance_Alert"] else False

    mac_events = _ensure_ts_datetime(mac_events)
    mac_events["Upload_Bytes"] = pd.to_numeric(mac_events["Upload_Bytes"], errors="coerce").fillna(0)
    mac_events["Risk_Score"] = pd.to_numeric(mac_events["Risk_Score"], errors="coerce").fillna(0)
    mac_events["Severity"] = mac_events["Severity"].astype(str).str.upper()
    mac_events["Policy_Verdict"] = mac_events["Policy_Verdict"].astype(str)

    mac_events = mac_events.sort_values("ts", ascending=False)

    if mac_events.empty:
        st.warning("No records found for this MAC with current page filters.")
        return

    mac_key = re.sub(r"[^0-9A-Za-z_]+", "_", active_mac).strip("_") or "mac"

    # --- optional dedupe for UI ---
    dedupe_cols = [
        "ts", "AI_Provider", "Domain", "Evidence_Type", "Detail", "Destination",
        "id.orig_h", "Match_Field", "Signature_Match", "Matched_Value", "Detection_Source",
    ]
    dedupe_cols = [c for c in dedupe_cols if c in mac_events.columns]
    mac_events_unique = mac_events.drop_duplicates(subset=dedupe_cols, keep="first") if dedupe_cols else mac_events

    show_raw = st.toggle("Show raw duplicates", value=False, key=f"shadow_ai_mac_show_raw_{selected_scope_key}_{mac_key}_{key_prefix}")
    view_df = mac_events if show_raw else mac_events_unique

    # --- search inside dialog (applies to Overview/Forensics/Event Log) ---
    base_view_df = view_df
    base_n = int(len(base_view_df))

    _search_key = f"shadow_ai_mac_search_{selected_scope_key}_{mac_key}_{key_prefix}"
    q = st.text_input(
        "Search (this MAC)",
        placeholder="provider, domain, detail, destination, IP, host, user-agent…",
        key=_search_key,
    )

    q = str(q or "").strip()
    search_applied = False
    if q:
        terms = [t for t in re.split(r"\s+", q) if t]
        search_cols = [
            "AI_Provider", "Domain", "Evidence_Type", "Detail", "Destination",
            "Matched_Value", "Match_Field", "Signature_Match",
            "Detection_Basis", "Policy_Basis",
            "id.orig_h", "host_name", "user_agent",
            "Policy_Verdict", "Severity",
        ]
        existing = [c for c in search_cols if c in base_view_df.columns]
        if existing and terms:
            mask = pd.Series(True, index=base_view_df.index)
            for term in terms:
                pat = re.escape(term)
                term_mask = pd.Series(False, index=base_view_df.index)
                for col in existing:
                    s = base_view_df[col]
                    if not pd.api.types.is_string_dtype(s):
                        s = s.astype(str)
                    term_mask |= s.fillna("").str.contains(pat, case=False, na=False)
                mask &= term_mask
            view_df = base_view_df.loc[mask].copy()
        else:
            view_df = base_view_df

        search_applied = True
        after_n = int(len(view_df))
        st.caption(
            f"Search: **{q}** — showing **{after_n:,}** of **{base_n:,}** rows "
            f"(space-separated terms are ANDed)."
        )
        if after_n == 0:
            st.warning("No matching records. Clear the search to see all events for this MAC.")

    raw_n = int(len(mac_events))
    dedup_n = int(len(mac_events_unique))
    base_n_eff = raw_n if show_raw else dedup_n
    view_n = int(len(view_df))
    dup_removed = int(max(0, raw_n - base_n_eff))
    search_removed = int(max(0, base_n_eff - view_n))

    high_n = int(view_df["Severity"].isin(["CRITICAL", "HIGH"]).sum())
    providers_n = int(view_df["AI_Provider"].astype(str).replace({"": None, "nan": None}).dropna().nunique())
    upload_mb = float(view_df["Upload_Bytes"].sum()) / 1024 / 1024

    top_host = (
        view_df["host_name"].astype(str).replace({"": None, "nan": None}).dropna().value_counts().head(1).index[0]
        if "host_name" in view_df.columns and view_df["host_name"].astype(str).replace({"": None, "nan": None}).dropna().shape[0] > 0
        else ""
    )
    uniq_ips = int(view_df["id.orig_h"].astype(str).replace({"": None, "nan": None}).dropna().nunique()) if "id.orig_h" in view_df.columns else 0

    d1, d2, d3, d4, d5 = st.columns(5, gap="small")
    d1.metric("Events (view)", f"{view_n:,}")
    d2.metric("Raw events", f"{raw_n:,}")
    d3.metric("Providers", f"{providers_n:,}")
    d4.metric("High/Critical", f"{high_n:,}")
    d5.metric("Upload (MB)", f"{upload_mb:.2f}")

    if dup_removed or (search_applied and search_removed):
        bits = []
        if dup_removed:
            bits.append(f"dedup removed {dup_removed:,} row(s)")
        if search_applied and search_removed:
            bits.append(f"search filtered {search_removed:,} row(s)")
        st.caption(" · ".join(bits))

    meta_line = f"MAC: `{active_mac}`"
    if top_host:
        meta_line += f" | Host: `{top_host}`"
    if uniq_ips:
        meta_line += f" | Unique IPs: **{uniq_ips:,}**"
    st.caption(meta_line)

    st.markdown("#### AI services used by this MAC")
    st.caption("Summary is based on the current view (page filters + duplicate toggle + dialog search).")

    prov_src = view_df.copy()
    prov_src["AI_Provider"] = prov_src["AI_Provider"].astype(str)
    prov_src = prov_src[prov_src["AI_Provider"].str.strip().str.lower().replace({"nan": ""}) != ""].copy()

    if prov_src.empty:
        st.info("No AI providers found for this MAC in the current view.")
    else:
        # Local severity rank for aggregation
        _sev_rank_map = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        _inv_sev = {v: k for k, v in _sev_rank_map.items()}

        def _mode_nonempty(s: pd.Series) -> str:
            s = s.astype(str).replace({"nan": "", "None": ""}).fillna("")
            s = s[s.str.strip() != ""]
            if s.empty:
                return ""
            return str(s.value_counts().index[0])

        def _nunique_nonempty(s: pd.Series) -> int:
            s = s.astype(str).replace({"nan": "", "None": ""}).fillna("").map(lambda v: v.strip())
            s = s[s != ""]
            return int(s.nunique())

        prov_src["_sev_rank"] = prov_src["Severity"].astype(str).str.upper().map(_sev_rank_map).fillna(0).astype(int)

        prov_tbl = prov_src.groupby("AI_Provider", dropna=False).agg(
            Events=("ts", "count"),
            Domains=("Domain", _nunique_nonempty),
            Upload_MB=("Upload_Bytes", lambda x: float(pd.to_numeric(x, errors="coerce").fillna(0).sum()) / 1024 / 1024),
            First_Seen=("ts", "min"),
            Last_Seen=("ts", "max"),
            Highest_Severity_Rank=("_sev_rank", "max"),
            Top_Domain=("Domain", _mode_nonempty),
            Top_Verdict=("Policy_Verdict", _mode_nonempty),
        ).reset_index()

        prov_tbl["Highest_Severity"] = prov_tbl["Highest_Severity_Rank"].map(_inv_sev).fillna("")
        prov_tbl = prov_tbl.drop(columns=["Highest_Severity_Rank"])
        prov_tbl["Upload_MB"] = pd.to_numeric(prov_tbl["Upload_MB"], errors="coerce").fillna(0).round(2)

        prov_tbl["First_Seen"] = pd.to_datetime(prov_tbl["First_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
        prov_tbl["Last_Seen"] = pd.to_datetime(prov_tbl["Last_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")

        prov_tbl = prov_tbl.sort_values(["Events", "Upload_MB"], ascending=False).head(60).copy()
        prov_tbl.insert(0, "#", range(1, len(prov_tbl) + 1))

        gb_prov = _new_grid_builder(prov_tbl, page_size=20)
        gb_prov.configure_column("AI_Provider", header_name="AI Provider", minWidth=175, flex=1.25)
        gb_prov.configure_column("Events", minWidth=90, flex=0.6)
        gb_prov.configure_column("Domains", minWidth=90, flex=0.6)
        gb_prov.configure_column("Upload_MB", header_name="Upload (MB)", minWidth=115, flex=0.7)
        gb_prov.configure_column("Highest_Severity", header_name="Highest Sev", minWidth=115, flex=0.7, cellStyle=_severity_cellstyle())
        gb_prov.configure_column("First_Seen", header_name="First Seen", minWidth=150, flex=0.95)
        gb_prov.configure_column("Last_Seen", header_name="Last Seen", minWidth=150, flex=0.95)
        gb_prov.configure_column("Top_Domain", header_name="Top Domain", minWidth=180, flex=1.25)
        gb_prov.configure_column("Top_Verdict", header_name="Top Verdict", minWidth=125, flex=0.85, cellStyle=_policy_cellstyle())

        render_shadow_aggrid(
            prov_tbl,
            gb_prov,
            key=f"shadow_ai_mac_providers_grid_{selected_scope_key}_{mac_key}_{key_prefix}",
            height=280,
            auto_fit_columns=False,
        )

    tabs = st.tabs(["Overview", "Forensics", "Event Log"])

    with tabs[0]:
        chart_df = view_df
        if len(chart_df) > DIALOG_TIMELINE_MAX_POINTS:
            chart_df = chart_df.head(DIALOG_TIMELINE_MAX_POINTS).copy()
            st.caption(f"Timeline limited to latest {DIALOG_TIMELINE_MAX_POINTS:,} events for faster rendering.")

        cA, cB = st.columns([2, 1])
        with cA:
            figm = px.scatter(
                chart_df,
                x="ts",
                y="AI_Provider",
                size="Risk_Score",
                color="Severity",
                color_discrete_map=SEVERITY_COLORS,
                hover_data=["Domain", "Detail", "Evidence_Type", "Matched_Value", "Detection_Basis", "id.orig_h", "host_name"],
                title="Timeline (this MAC)",
                template=get_plotly_template(),
                render_mode="webgl" if len(chart_df) > 1500 else "auto",
            )
            style_plotly_figure(figm, height=360)
            figm.update_xaxes(title="Time")
            figm.update_yaxes(title="Provider")
            st.plotly_chart(figm, use_container_width=True)

        with cB:
            byprov = view_df.groupby("AI_Provider").agg(
                Events=("ts", "count"),
                Upload_MB=("Upload_Bytes", lambda x: float(x.sum()) / 1024 / 1024),
            ).reset_index()
            byprov = byprov.sort_values(["Events", "Upload_MB"], ascending=False).head(25)
            figp = px.bar(
                byprov,
                x="Events",
                y="AI_Provider",
                orientation="h",
                title="Top providers (events)",
                template=get_plotly_template(),
            )
            style_plotly_figure(figp, height=360, show_legend=False)
            figp.update_xaxes(title="Events")
            figp.update_yaxes(title=None)
            st.plotly_chart(figp, use_container_width=True)

        dom = view_df["Domain"].astype(str).replace({"": None, "nan": None}).dropna()
        if not dom.empty:
            top_dom = dom.value_counts().head(15).reset_index()
            top_dom.columns = ["Domain", "Events"]
            figd = px.bar(
                top_dom.sort_values("Events", ascending=True),
                x="Events",
                y="Domain",
                orientation="h",
                title="Top domains (events)",
                template=get_plotly_template(),
            )
            style_plotly_figure(figd, height=340, show_legend=False)
            figd.update_xaxes(title="Events")
            figd.update_yaxes(title=None)
            st.plotly_chart(figd, use_container_width=True)

    with tabs[1]:
        st.markdown("#### Priority incidents (this MAC)")
        pri = view_df[
            view_df["Severity"].isin(["CRITICAL", "HIGH"])
            | view_df.get("Governance_Alert", pd.Series(False, index=view_df.index)).astype(bool)
            | view_df.get("First_Seen_SaaS", pd.Series(False, index=view_df.index)).astype(bool)
        ].copy()

        if pri.empty:
            st.success("No high-severity or governance incidents for this MAC in the current view.")
        else:
            pri_cols = [
                "ts", "Severity", "Policy_Verdict",
                "AI_Provider", "Domain", "Evidence_Type",
                "Upload_Bytes", "Detail", "Destination",
                "id.orig_h", "host_name", "user_agent",
                "Behavior_Indicators", "Detection_Basis", "Policy_Basis",
            ]
            for c in pri_cols:
                if c not in pri.columns:
                    pri[c] = ""
            pri_grid = pri[pri_cols].head(150).copy()
            pri_grid.insert(0, "#", range(1, len(pri_grid) + 1))
            pri_grid["ts"] = pd.to_datetime(pri_grid["ts"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
            pri_grid["Upload_Bytes"] = pd.to_numeric(pri_grid["Upload_Bytes"], errors="coerce").fillna(0).astype(int)

            gb_pri = _new_grid_builder(pri_grid, page_size=20)
            gb_pri.configure_column("ts", header_name="Time", minWidth=150, flex=1.0)
            gb_pri.configure_column("Severity", minWidth=90, flex=0.7, cellStyle=_severity_cellstyle())
            gb_pri.configure_column("Policy_Verdict", header_name="Verdict", minWidth=105, flex=0.8, cellStyle=_policy_cellstyle())
            gb_pri.configure_column("AI_Provider", header_name="Provider", minWidth=150, flex=1.1)
            gb_pri.configure_column("Domain", minWidth=170, flex=1.2)
            gb_pri.configure_column("Evidence_Type", header_name="Evidence", minWidth=120, flex=0.9)
            gb_pri.configure_column("Upload_Bytes", header_name="Bytes", minWidth=95, flex=0.7)
            gb_pri.configure_column("Detail", minWidth=220, flex=1.8)
            gb_pri.configure_column("Destination", minWidth=180, flex=1.4)
            gb_pri.configure_column("id.orig_h", header_name="IP", minWidth=125, flex=0.9)
            gb_pri.configure_column("host_name", header_name="Host", minWidth=130, flex=0.9)
            gb_pri.configure_column("user_agent", header_name="User Agent", minWidth=220, flex=1.7)
            gb_pri.configure_column("Behavior_Indicators", header_name="Indicators", minWidth=160, flex=1.1)
            gb_pri.configure_column("Detection_Basis", header_name="Detection Basis", minWidth=190, flex=1.4)
            gb_pri.configure_column("Policy_Basis", header_name="Policy Basis", minWidth=160, flex=1.2)

            render_shadow_aggrid(
                pri_grid,
                gb_pri,
                key=f"shadow_ai_mac_priority_grid_{selected_scope_key}_{mac_key}_{key_prefix}",
                height=520,
                auto_fit_columns=False,
            )

        st.markdown("#### Evidence breakdown (this MAC)")
        ev = view_df["Evidence_Type"].astype(str).replace({"": None, "nan": None}).dropna()
        if not ev.empty:
            evc = ev.value_counts().head(10).reset_index()
            evc.columns = ["Evidence", "Events"]
            fige = px.bar(
                evc.sort_values("Events", ascending=True),
                x="Events",
                y="Evidence",
                orientation="h",
                title="Top evidence types",
                template=get_plotly_template(),
            )
            style_plotly_figure(fige, height=320, show_legend=False)
            fige.update_xaxes(title="Events")
            fige.update_yaxes(title=None)
            st.plotly_chart(fige, use_container_width=True)

    with tabs[2]:
        mac_event_cols = [
            "ts", "Severity", "Policy_Verdict",
            "AI_Provider", "Domain", "Evidence_Type",
            "Detail", "Upload_Bytes", "Destination",
            "Matched_Value", "Match_Field", "Signature_Match",
            "Detection_Basis", "Policy_Basis",
            "id.orig_h", "host_name", "user_agent",
        ]
        for c in mac_event_cols:
            if c not in view_df.columns:
                view_df[c] = ""
        mac_event_grid = view_df[mac_event_cols].head(DIALOG_MAX_ROWS).copy()
        mac_event_grid.insert(0, "#", range(1, len(mac_event_grid) + 1))
        mac_event_grid["ts"] = pd.to_datetime(mac_event_grid["ts"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
        mac_event_grid["Upload_Bytes"] = pd.to_numeric(mac_event_grid["Upload_Bytes"], errors="coerce").fillna(0).astype(int)
        if len(view_df) > DIALOG_MAX_ROWS:
            st.caption(f"Showing latest {DIALOG_MAX_ROWS:,} rows in the event log.")

        gb_events = _new_grid_builder(mac_event_grid, page_size=25)
        gb_events.configure_column("ts", header_name="Time", minWidth=150, flex=1.0)
        gb_events.configure_column("Severity", minWidth=90, flex=0.7, cellStyle=_severity_cellstyle())
        gb_events.configure_column("Policy_Verdict", header_name="Verdict", minWidth=105, flex=0.8, cellStyle=_policy_cellstyle())
        gb_events.configure_column("AI_Provider", header_name="Provider", minWidth=150, flex=1.1)
        gb_events.configure_column("Domain", minWidth=170, flex=1.2)
        gb_events.configure_column("Evidence_Type", header_name="Evidence", minWidth=120, flex=0.9)
        gb_events.configure_column("Detail", minWidth=220, flex=1.8)
        gb_events.configure_column("Upload_Bytes", header_name="Bytes", minWidth=95, flex=0.7)
        gb_events.configure_column("Destination", minWidth=180, flex=1.4)
        gb_events.configure_column("Matched_Value", header_name="Matched", minWidth=180, flex=1.3)
        gb_events.configure_column("Match_Field", header_name="Field", minWidth=120, flex=0.9)
        gb_events.configure_column("Signature_Match", header_name="Signature", minWidth=130, flex=1.0)
        gb_events.configure_column("Detection_Basis", header_name="Detection Basis", minWidth=190, flex=1.4)
        gb_events.configure_column("Policy_Basis", header_name="Policy Basis", minWidth=160, flex=1.2)
        gb_events.configure_column("id.orig_h", header_name="IP", minWidth=125, flex=0.9)
        gb_events.configure_column("host_name", header_name="Host", minWidth=130, flex=0.9)
        gb_events.configure_column("user_agent", header_name="User Agent", minWidth=220, flex=1.7)

        render_shadow_aggrid(
            mac_event_grid,
            gb_events,
            key=f"shadow_ai_mac_events_grid_{selected_scope_key}_{mac_key}_{key_prefix}",
            height=560,
            auto_fit_columns=False,
        )

@st.dialog("MAC Drilldown - Shadow AI (Forensics)", width="large")
def show_shadow_ai_mac_dialog(mac_scoped: pd.DataFrame, *, selected_scope_key: str) -> None:
    active_mac = str(st.session_state.get("shadow_ai_mac_dialog_mac") or "").strip().lower()
    if not active_mac:
        st.info("No MAC selected.")
        return

    c_left, c_right = st.columns([1.0, 3.5])
    with c_left:
        if st.button("Close", use_container_width=True, type="primary", key=f"shadow_ai_mac_dlg_close_{selected_scope_key}"):
            _close_shadow_ai_mac_dialog()
            st.rerun()
    with c_right:
        st.caption(f"Scope locked to MAC `{active_mac}`")

    _render_shadow_ai_mac_drilldown(
        mac_scoped,
        selected_scope_key=selected_scope_key,
        active_mac=active_mac,
        key_prefix=f"dlg_{selected_scope_key}",
    )


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
            min-height: 88px;
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
        div[data-testid="stDialog"] [data-testid="stDialogCloseButton"],
        div[data-testid="stDialog"] button[aria-label="Close"] {
            display: none !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _shadow_ai_bust_ui_caches() -> None:
    """Clear Shadow AI session caches and refresh Streamlit caches (used by this page)."""
    st.session_state["_shadow_ai_cache_bust_v1"] = int(st.session_state.get("_shadow_ai_cache_bust_v1", 0)) + 1
    # Drop only Shadow AI page caches (scope + filters + MAC tab)
    for k in [
        "_shadow_ai_scope_df_key_v1",
        "_shadow_ai_scope_df_v1",
        "_shadow_ai_filtered_cache_v1",
        "_shadow_ai_mac_tab_cache_v1",
    ]:
        st.session_state.pop(k, None)
    # Close any pending dialog so rerun doesn't double-open it
    st.session_state["shadow_ai_mac_dialog_open"] = False
    st.session_state["shadow_ai_mac_dialog_mac"] = None


    # Full refresh (re-read yaml/signatures and rebuild caches)
    st.cache_data.clear()
    st.cache_resource.clear()


# =============================================================================
# UI RENDERER
# =============================================================================

def render_shadow_ai(parquet_root: Path):
    inject_shadow_ai_css()
    st.session_state.setdefault("shadow_ai_selected_mac", None)
    st.session_state.setdefault("shadow_ai_mac_dialog_open", False)
    st.session_state.setdefault("shadow_ai_mac_dialog_mac", None)
    st.session_state.setdefault("shadow_ai_mac_dialog_last_selected", None)
    st.session_state.setdefault("shadow_ai_mac_grid_nonce", 0)
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
            _shadow_ai_bust_ui_caches()
            st.rerun()

    with st.expander("Detection basis (how Shadow AI is decided)", expanded=False):
        st.write(
            "Events are generated when Zeek telemetry matches `ai_signatures.yaml` (HTTP host/uri, TLS SNI, DNS query) "
            "or a configured local AI port (`conn id.resp_p`). Regex misses get a fuzzy alias fallback "
            "(fuzzywuzzy), then generic AI naming heuristics (`gpt`, `copilot`, `agent`, `llm`, `ai`) for unknown SaaS."
        )
        st.write(
            f"Behavior scoring includes first-seen SaaS detection over a {BASELINE_DAYS}-day baseline, "
            f"large HTTPS POST uploads (>= {int(round(LARGE_UPLOAD_THRESHOLD_BYTES/(1024*1024)))}MB), "
            "file-like upload correlation, JSON-heavy API usage, high-frequency API bursts, and SMB->upload precursor checks."
        )
        st.write(
            "Evidence columns include Match_Field, Signature_Match, Matched_Value, Detection_Basis, Policy_Basis, "
            "Evidence_Type, Behavior_Indicators, First_Seen_SaaS, Governance_Alert, and Confidence."
        )

    provider_values = sorted(
        set((RAW_AI_SIGNATURES or {}).keys())
        | set(FUZZY_PROVIDER_ALIASES.keys())
        | set(LOCAL_AI_PORTS.values())
    )
    port_signature_values = {f"port {p}" for p in sorted(LOCAL_AI_PORTS.keys())}
    signature_values = sorted({frag for _, frags in (RAW_AI_SIGNATURES or {}).items() for frag in (frags or [])} | port_signature_values)
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
    # Scope behavior: always interpret selected day in Asia/Manila local time (with automatic boundary coverage)
    scope_mode = "local_auto"

    # If selecting a single day, also load the previous folder date to cover UTC↔local boundaries.
    if selected_date == "All Available Dates":
        target_dates = available_dates
    else:
        target_dates = [selected_date] if selected_date else []
        if target_dates:
            try:
                d0 = datetime.strptime(str(target_dates[0]), "%Y-%m-%d").date()
                prev = (d0 - timedelta(days=1)).strftime("%Y-%m-%d")
                if prev in available_dates and prev not in target_dates:
                    target_dates.append(prev)
            except Exception:
                pass
    # Keep a hot in-session copy so search/filter/dialog reruns don't reload/unpickle.
    st.session_state.setdefault("_shadow_ai_cache_bust_v1", 0)
    cache_bust = int(st.session_state.get("_shadow_ai_cache_bust_v1", 0))
    scope_df_key = (
        cache_bust,
        str(parquet_root.resolve()),
        tuple(target_dates),
        str(CACHE_VERSION),
        int(SIG_MTIME_NS),
        int(BASELINE_DAYS),
    )

    if st.session_state.get("_shadow_ai_scope_df_key_v1") == scope_df_key and isinstance(st.session_state.get("_shadow_ai_scope_df_v1"), pd.DataFrame):
        df = st.session_state.get("_shadow_ai_scope_df_v1")
    else:
        with st.spinner("Analyzing telemetry (cache warm-up)..."):
            df = load_shadow_ai_data(parquet_root, target_dates, cache_bust=cache_bust)
        st.session_state["_shadow_ai_scope_df_key_v1"] = scope_df_key
        st.session_state["_shadow_ai_scope_df_v1"] = df
        # Base changed => drop derived caches
        st.session_state.pop("_shadow_ai_filtered_cache_v1", None)
        st.session_state.pop("_shadow_ai_mac_tab_cache_v1", None)

    # Apply display scope for a single selected day (keeps UI accurate without rebuilding caches)
    raw_df = df
    scope_decision = "all_dates"
    if selected_date != "All Available Dates" and selected_date and DATE_DIR_RE.match(str(selected_date)):
        scoped, scope_decision = _apply_date_scope(raw_df, str(selected_date), mode=scope_mode)
        # If strict local-day scope yields nothing, fall back to showing raw folder contents.
        if scoped.empty and scope_mode != "folder":
            scoped, scope_decision = _apply_date_scope(raw_df, str(selected_date), mode="folder")
        df = scoped


    if df.empty:
        st.info("No AI signatures detected in the selected range.")
        return

    source_data_stamp = _shadow_ai_data_stamp(df)
    filter_cache_key = _shadow_ai_mac_tab_cache_key(
        selected_scope_key=selected_scope_key,
        selected_verdict=selected_verdict,
        selected_severity=selected_severity,
        provider_filter=provider_filter,
        basis_field=basis_field,
        basis_sig=basis_sig,
        evidence_filter=evidence_filter,
        min_upload_kb=float(min_upload_kb or 0),
        only_resolved_mac=only_resolved_mac,
        ignore_dns_only=ignore_dns_only,
        search_q=search_q,
        data_stamp=source_data_stamp,
    )
    filter_cache_state = st.session_state.get("_shadow_ai_filtered_cache_v1", {})
    if isinstance(filter_cache_state, dict) and filter_cache_state.get("key") == filter_cache_key:
        filtered = filter_cache_state.get("df", pd.DataFrame())
    else:
        filtered = _apply_shadow_ai_filters(
            df,
            selected_verdict=selected_verdict,
            selected_severity=selected_severity,
            provider_filter=provider_filter,
            basis_field=basis_field,
            basis_sig=basis_sig,
            evidence_filter=evidence_filter,
            min_upload_kb=float(min_upload_kb or 0),
            only_resolved_mac=only_resolved_mac,
            ignore_dns_only=ignore_dns_only,
            search_q=search_q,
        )
        st.session_state["_shadow_ai_filtered_cache_v1"] = {"key": filter_cache_key, "df": filtered}

    if filtered.empty:
        st.warning("No data matches your filters.")
        return

    dialog_mac_pending = str(st.session_state.get("shadow_ai_mac_dialog_mac") or "").strip().lower()
    if st.session_state.get("shadow_ai_mac_dialog_open") and dialog_mac_pending:
        mac_cache_state = st.session_state.get("_shadow_ai_mac_tab_cache_v1", {})
        if isinstance(mac_cache_state, dict) and mac_cache_state.get("key") == filter_cache_key:
            mac_view_for_dialog = mac_cache_state.get("mac_view", pd.DataFrame())
            mac_summary_for_dialog = mac_cache_state.get("mac_summary", pd.DataFrame())
        else:
            mac_view_for_dialog, mac_summary_for_dialog = _build_shadow_ai_mac_tab_frames(filtered)
            st.session_state["_shadow_ai_mac_tab_cache_v1"] = {
                "key": filter_cache_key,
                "mac_view": mac_view_for_dialog,
                "mac_summary": mac_summary_for_dialog,
            }

        scoped_dialog = mac_view_for_dialog.loc[mac_view_for_dialog["mac"].eq(dialog_mac_pending)].copy() if not mac_view_for_dialog.empty else pd.DataFrame()
        st.session_state["shadow_ai_mac_dialog_open"] = False
        show_shadow_ai_mac_dialog(scoped_dialog, selected_scope_key=selected_scope_key)
        st.stop()

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

        mac_cache_key = _shadow_ai_mac_tab_cache_key(
            selected_scope_key=selected_scope_key,
            selected_verdict=selected_verdict,
            selected_severity=selected_severity,
            provider_filter=provider_filter,
            basis_field=basis_field,
            basis_sig=basis_sig,
            evidence_filter=evidence_filter,
            min_upload_kb=float(min_upload_kb or 0),
            only_resolved_mac=only_resolved_mac,
            ignore_dns_only=ignore_dns_only,
            search_q=search_q,
            data_stamp=source_data_stamp,
        )
        mac_cache_state = st.session_state.get("_shadow_ai_mac_tab_cache_v1", {})
        if isinstance(mac_cache_state, dict) and mac_cache_state.get("key") == mac_cache_key:
            mac_view = mac_cache_state.get("mac_view", pd.DataFrame())
            mac_summary = mac_cache_state.get("mac_summary", pd.DataFrame())
        else:
            mac_view, mac_summary = _build_shadow_ai_mac_tab_frames(filtered)
            st.session_state["_shadow_ai_mac_tab_cache_v1"] = {
                "key": mac_cache_key,
                "mac_view": mac_view,
                "mac_summary": mac_summary,
            }

        if mac_view.empty or mac_summary.empty:
            _close_shadow_ai_mac_dialog(preserve_last_selected=False)
            st.info("No Shadow AI events with resolved MAC in the current view.")
        else:
            mac_grid = mac_summary.copy()
            mac_grid.insert(0, "#", range(1, len(mac_grid) + 1))
            mac_grid["Last_Seen"] = pd.to_datetime(mac_grid["Last_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
            mac_grid["First_Seen"] = pd.to_datetime(mac_grid["First_Seen"], errors="coerce").dt.strftime("%m-%d %H:%M:%S").fillna("")
            mac_grid["Total_Upload_MB"] = pd.to_numeric(mac_grid["Total_Upload_MB"], errors="coerce").fillna(0).round(2)

            gb_mac = _new_grid_builder(mac_grid, page_size=15)
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
            gb_mac.configure_selection(selection_mode="single", use_checkbox=False)
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
            mac_only_click_js = JsCode(
                """
                function(params) {
                    if (!params || !params.column || !params.node) return;
                    const colId = params.column.getColId ? params.column.getColId() : '';
                    if (colId === 'mac') {
                        params.node.setSelected(true, true);
                    }
                }
                """
            )
            gb_mac.configure_column("mac", header_name="MAC (Click)", minWidth=150, cellStyle=clickable_mac_style)
            mac_response = render_shadow_aggrid(
                mac_grid,
                gb_mac,
                key=f"shadow_ai_mac_summary_grid_{selected_scope_key}_{st.session_state.get('shadow_ai_mac_grid_nonce', 0)}",
                height=430,
                update_mode=GridUpdateMode.SELECTION_CHANGED,
                grid_options_overrides={
                    "rowSelection": "single",
                    "suppressRowClickSelection": True,
                    "rowMultiSelectWithClick": False,
                    "onCellClicked": mac_only_click_js,
                },
                auto_fit_columns=False,
            )

            selected_mac = _extract_selected_mac(mac_response.get("selected_rows", None))
            if selected_mac:
                prev = st.session_state.get("shadow_ai_mac_dialog_last_selected")
                if selected_mac != prev:
                    st.session_state["shadow_ai_selected_mac"] = selected_mac
                    st.session_state["shadow_ai_mac_dialog_last_selected"] = selected_mac
                    st.session_state["shadow_ai_mac_dialog_mac"] = selected_mac
                    st.session_state["shadow_ai_mac_dialog_open"] = True
                    st.rerun()
            else:
                st.session_state["shadow_ai_mac_dialog_last_selected"] = None

            mac_list = [str(x).strip().lower() for x in mac_summary["mac"].tolist() if str(x).strip()]
            active_mac = str(st.session_state.get("shadow_ai_selected_mac") or st.session_state.get("shadow_ai_mac_dialog_mac") or "").strip().lower()
            if active_mac not in mac_list and mac_list:
                active_mac = mac_list[0]
                st.session_state["shadow_ai_selected_mac"] = active_mac

            st.caption(f"Click a MAC row to open drilldown dialog. Current MAC: `{active_mac}`")

            dialog_mac = str(st.session_state.get("shadow_ai_mac_dialog_mac") or "").strip().lower()
            if st.session_state.get("shadow_ai_mac_dialog_open") and dialog_mac:
                st.session_state["shadow_ai_mac_dialog_open"] = False
                scoped_dialog = mac_view.loc[mac_view["mac"].eq(dialog_mac)].copy()
                show_shadow_ai_mac_dialog(scoped_dialog, selected_scope_key=selected_scope_key)

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
                "Matched_Value", "Detection_Basis", "Behavior_Indicators",
                "First_Seen_SaaS", "Governance_Alert",
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
    # TAB: POLICY / NOISE CONTROL
    # =============================================================================
    with tabs[5]:
        st.markdown("### Policy posture / noise controls")

        st.write("Allowlist behavior: if `authorized_providers` is empty, the system defaults to deny and everything is Shadow AI.")
        st.write("To allow specific providers, add provider names (exact keys) to `authorized_providers` in `ai_signatures.yaml`.")

        # show allowlist content
        st.markdown("#### Current allowlist (authorized_providers)")
        if AUTHORIZED_PROVIDERS:
            st.code("\n".join(AUTHORIZED_PROVIDERS))
        else:
            st.info("authorized_providers is empty (default deny).")

        st.markdown("#### Detection settings")
        st.code(yaml.safe_dump(
            {
                "baseline_days": BASELINE_DAYS,
                "large_https_post_threshold_mb": round(LARGE_UPLOAD_THRESHOLD_BYTES / (1024 * 1024), 2),
                "medium_https_post_threshold_mb": round(MEDIUM_UPLOAD_THRESHOLD_BYTES / (1024 * 1024), 2),
                "high_frequency_calls_per_hour": HIGH_FREQUENCY_CALLS_PER_HOUR,
                "json_post_calls_per_hour": JSON_POST_CALLS_PER_HOUR,
                "small_request_max_kb": int(SMALL_REQUEST_MAX_BYTES / 1024),
                "smb_window_minutes": SMB_WINDOW_MINUTES,
                "file_upload_extensions": FILE_UPLOAD_EXTENSIONS,
                "saas_allowlist_domains": SAAS_ALLOWLIST_DOMAINS,
            },
            sort_keys=False,
        ))

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
