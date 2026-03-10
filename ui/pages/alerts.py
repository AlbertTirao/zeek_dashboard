import hashlib
import html
import ipaddress
import json
import os
import re
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import duckdb
import pandas as pd
import streamlit as st
import yaml
from .header_layout import inject_traffic_style_header_css, render_traffic_style_header

DEFAULT_ROW_LIMIT_OPTIONS: tuple[int, ...] = (100, 250, 500, 1000, 2000, 5000)


def _closest_row_option(options: list[int], target: int) -> int:
    if not options:
        return max(int(target or 1), 1)
    safe_target = max(int(target or options[0]), 1)
    return min(options, key=lambda value: abs(int(value) - safe_target))


def _normalize_row_limit_options(total_rows: int, options: tuple[int, ...]) -> list[int]:
    out = sorted({int(x) for x in options if int(x) > 0})
    if not out:
        out = [100, 250, 500, 1000]
    if total_rows > 0 and total_rows not in out:
        out.append(int(total_rows))
        out = sorted(set(out))
    return out


def row_limit_selector(
    *,
    key_prefix: str,
    total_rows: int,
    label: str = "Rows shown",
    default_limit: int = 500,
    options: tuple[int, ...] = DEFAULT_ROW_LIMIT_OPTIONS,
) -> int:
    row_options = _normalize_row_limit_options(int(total_rows or 0), options)
    state_key = f"{key_prefix}_row_limit"
    if state_key not in st.session_state:
        st.session_state[state_key] = _closest_row_option(row_options, default_limit)

    current = _closest_row_option(row_options, int(st.session_state.get(state_key, default_limit)))
    if int(st.session_state.get(state_key, default_limit)) != current:
        st.session_state[state_key] = current

    index = row_options.index(current) if current in row_options else 0
    chosen = st.selectbox(label, options=row_options, index=index, key=state_key)
    try:
        return max(int(chosen), 1)
    except Exception:
        return max(int(current), 1)


def cap_dataframe_rows(df: pd.DataFrame, limit: int) -> pd.DataFrame:
    if not isinstance(df, pd.DataFrame):
        return pd.DataFrame()
    try:
        safe_limit = max(int(limit), 1)
    except Exception:
        safe_limit = 500
    return df.head(safe_limit).copy()


def render_rows_caption(*, total_rows: int, shown_rows: int) -> None:
    if int(total_rows) > int(shown_rows):
        st.caption(f"Showing {shown_rows:,} of {total_rows:,} rows. Narrow filters or increase row limit for more.")
    else:
        st.caption(f"Showing {shown_rows:,} rows.")

# --- Optional vendor lookup (fallback) ---
try:
    from mac_vendor_lookup import MacLookup  # pip install mac-vendor-lookup
    VENDOR_LIB_AVAILABLE = True
except Exception:
    VENDOR_LIB_AVAILABLE = False


# =============================================================================
# CONFIG
# =============================================================================
CACHE_VERSION = "alerts-cache-v3-fastload-ui"
CACHE_DIRNAME = "_cache_alerts"

DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAC_HEX_RE = re.compile(r"[^0-9a-fA-F]")

PREFERRED_AUTH_KEYS = [
    "authorized_macs",
    "allowlist",
    "authorized_devices",
    "devices",
    "authorized",
]

SRC_DEFS = [
    ("dhcp", ["dhcp"]),
    ("arp", ["arp"]),
    ("conn", ["conn"]),
]
KNOWN_HOSTS_KEYWORDS = ["known_hosts", "knownhost", "known-hosts"]
ROLLING_TIME_WINDOWS_DAYS = {
    "Last 7 Days": 7,
    "Last 30 Days": 30,
}
ALERT_TIME_RANGE_OPTIONS = ["Last 7 Days", "Last 30 Days", "Specific Date", "All Time"]


# =============================================================================
# SQL PATH QUOTING (fixes f-string quote issues)
# =============================================================================
def _sql_quote_path(p: Path) -> str:
    return str(p).replace("'", "''")


# =============================================================================
# DUCKDB
# =============================================================================
@st.cache_resource(show_spinner=False)
def _duckdb_conn():
    con = duckdb.connect(database=":memory:")

    try:
        n = os.cpu_count() or 4
        con.execute(f"SET threads TO {max(2, min(n, 8))}")
    except Exception:
        pass

    try:
        con.execute("SET memory_limit='4GB'")
    except Exception:
        pass

    # These reduce overhead a lot on repeated parquet scans
    try:
        con.execute("PRAGMA enable_object_cache")
    except Exception:
        pass

    try:
        con.execute("PRAGMA enable_progress_bar=false")
    except Exception:
        pass

    # Optional but often helps: avoid spilling to slow default temp
    try:
        tmp = Path("./.duckdb_temp")
        tmp.mkdir(parents=True, exist_ok=True)
        tmp_sql = str(tmp).replace("'", "''")
        con.execute(f"SET temp_directory='{tmp_sql}'")
    except Exception:
        pass

    return con


@lru_cache(maxsize=512)
def _schema_cols_cached(parquet_path_str: str, mtime: float, size: int) -> Tuple[str, ...]:
    """
    Cache schema extraction per file signature (path + mtime + size).
    Avoids repeated DESCRIBE cost across reruns/days.
    """
    con = _duckdb_conn()
    try:
        df = con.execute("DESCRIBE SELECT * FROM parquet_scan(?)", [parquet_path_str]).df()
        cols = [str(x) for x in df["column_name"].tolist()]
        return tuple(cols)
    except Exception:
        return tuple()


def _duckdb_schema_cols(con: duckdb.DuckDBPyConnection, parquet_path: Path) -> List[str]:
    try:
        st_ = parquet_path.stat()
        return list(_schema_cols_cached(str(parquet_path), float(st_.st_mtime), int(st_.st_size)))
    except Exception:
        try:
            df = con.execute("DESCRIBE SELECT * FROM parquet_scan(?)", [str(parquet_path)]).df()
            return [str(x) for x in df["column_name"].tolist()]
        except Exception:
            return []


# =============================================================================
# NORMALIZATION
# =============================================================================
def normalize_mac(x) -> Optional[str]:
    if x is None:
        return None
    if isinstance(x, (bytes, bytearray)) and len(x) == 6:
        hx = bytes(x).hex()
    else:
        hx = MAC_HEX_RE.sub("", str(x))
    if len(hx) != 12:
        return None
    return ":".join(hx[i : i + 2] for i in range(0, 12, 2)).lower()


def is_broadcast_mac(mac: Optional[str]) -> bool:
    return mac == "ff:ff:ff:ff:ff:ff"


def mac_spoofing_status(mac: Optional[str]) -> str:
    """
    Heuristic flag:
    A locally administered MAC often has the second hex digit of the first byte
    set to 2, 6, A, or E (e.g., 02:xx..., 06:xx..., 0A:xx..., 0E:xx...).
    """
    m = normalize_mac(mac)
    if not m:
        return "Unknown"

    first_byte = m.split(":", 1)[0]
    if len(first_byte) != 2:
        return "Unknown"

    return "MAC Randomization" if first_byte[1].lower() in {"2", "6", "a", "e"} else "No"


# =============================================================================
# IP HELPERS
# =============================================================================
def _normalize_ip(value) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    if not s or s.lower() in {"nan", "none", "-"}:
        return None
    return s


def _is_private_ip(ip_value: Optional[str]) -> bool:
    if not ip_value:
        return False
    try:
        return ipaddress.ip_address(ip_value).is_private
    except Exception:
        return False


# =============================================================================
# CHANGED: BANNED MACS (shared across pages) + INVENTORY MAC SET (known_hosts)
# - Alerts still builds event-driven tables, but header metrics now use the same
#   "device inventory" as Device Overview: unique MACs from known_hosts parquets.
# =============================================================================
def load_banned_macs(ban_file: Path) -> set:
    """Load banned MACs from banned_macs.yaml in the same format used by the other pages."""
    if not ban_file.exists():
        return set()
    try:
        data = yaml.safe_load(ban_file.read_text(encoding="utf-8"))
    except Exception:
        return set()

    raw_list = _extract_yaml_list(data, ban_file.stem, preferred_keys=["banned_macs", "banned"])
    banned = set()
    for item in raw_list:
        if isinstance(item, dict) and "mac" in item:
            m = normalize_mac(item.get("mac"))
        else:
            m = normalize_mac(item)
        if m and not is_broadcast_mac(m):
            banned.add(m)
    return banned


@st.cache_data(show_spinner=False, ttl=300)
def load_inventory_macs(parquet_root_str: str) -> set:
    """CHANGED: Canonical device universe from known_hosts across ALL date folders."""
    by_date_str = _discover_date_dirs(parquet_root_str)
    kh_paths = []
    for date_str, dirs in by_date_str.items():
        for d in dirs:
            p = Path(d) / "known_hosts.parquet"
            if p.exists():
                kh_paths.append(str(p))

    if not kh_paths:
        return set()

    con = duckdb.connect(database=":memory:", read_only=False)
    try:
        # schema can vary; we only require a 'mac' column
        df = con.execute("SELECT * FROM read_parquet($1)", [kh_paths]).df()
    except Exception:
        return set()
    finally:
        con.close()

    if "mac" not in df.columns:
        return set()

    macs = df["mac"].map(normalize_mac).dropna()
    macs = macs[~macs.map(is_broadcast_mac)]
    return set(macs.tolist())


# =============================================================================
# YAML ALLOWLIST
# =============================================================================
def _extract_yaml_list(data, stem_key: str, preferred_keys: List[str]) -> List:
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in preferred_keys:
            if k in data and isinstance(data[k], list):
                return data[k]
        if stem_key and stem_key in data and isinstance(data[stem_key], list):
            return data[stem_key]
        for v in data.values():
            if isinstance(v, list):
                return v
    return []


def _auth_file_sig(p: Path) -> Tuple[str, float, int]:
    try:
        st_ = p.stat()
        return (str(p), float(st_.st_mtime), int(st_.st_size))
    except Exception:
        return (str(p), 0.0, 0)


@st.cache_data(show_spinner=False)
def _load_authorized_macs_cached(auth_file_str: str, sig: Tuple[str, float, int]) -> Tuple[str, ...]:
    allowed: set = set()
    file_path = Path(auth_file_str)

    if file_path.suffix != ".yaml":
        yaml_path = file_path.with_suffix(".yaml")
        if yaml_path.exists():
            file_path = yaml_path

    if not file_path.exists():
        return tuple()

    try:
        data = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except Exception:
        return tuple()

    raw_list = _extract_yaml_list(data, file_path.stem, PREFERRED_AUTH_KEYS)

    for item in raw_list:
        if isinstance(item, dict) and "mac" in item:
            m = normalize_mac(item.get("mac"))
        else:
            m = normalize_mac(item)
        if m:
            allowed.add(m)

    return tuple(sorted(allowed))


def load_authorized_macs(auth_file: str) -> set:
    file_path = Path(auth_file)

    if file_path.suffix != ".yaml":
        yaml_path = file_path.with_suffix(".yaml")
        if yaml_path.exists():
            file_path = yaml_path

    if not file_path.exists():
        return set()

    sig = _auth_file_sig(file_path)
    return set(_load_authorized_macs_cached(str(file_path), sig))


@st.cache_data(show_spinner=False, ttl=300)
def _build_ip_to_mac_map_cached(
    parquet_root_str: str,
    auth_file_str: str,
    auth_sig: Tuple[str, float, int],
) -> Dict[str, str]:
    # Keep this argument in the signature so cache invalidates when allowlist changes.
    _ = auth_sig

    ip_to_mac: Dict[str, str] = {}

    # Seed map from authorized YAML entries that include explicit IPs.
    auth_path = Path(auth_file_str)
    if auth_path.suffix != ".yaml":
        yaml_path = auth_path.with_suffix(".yaml")
        if yaml_path.exists():
            auth_path = yaml_path

    if auth_path.exists():
        try:
            auth_data = yaml.safe_load(auth_path.read_text(encoding="utf-8"))
        except Exception:
            auth_data = None

        auth_rows = _extract_yaml_list(auth_data, auth_path.stem, PREFERRED_AUTH_KEYS)
        for item in auth_rows:
            if not isinstance(item, dict):
                continue
            mac_norm = normalize_mac(item.get("mac"))
            ip_norm = _normalize_ip(item.get("ip"))
            if mac_norm and ip_norm and _is_private_ip(ip_norm):
                ip_to_mac[ip_norm] = mac_norm

    # Strengthen map with historical known_hosts observations (latest IP ownership wins).
    by_date_str = _discover_date_dirs(parquet_root_str)
    con = _duckdb_conn()
    kh_frames: List[pd.DataFrame] = []

    for _date_str, day_dirs in by_date_str.items():
        for day_dir_str in day_dirs:
            day_dir = Path(day_dir_str)
            known_hosts_path = _find_log_file_in_day(day_dir, KNOWN_HOSTS_KEYWORDS)
            if not known_hosts_path or not known_hosts_path.exists():
                continue

            cols = _duckdb_schema_cols(con, known_hosts_path)
            if not cols:
                continue

            mac_col = _choose_first_present(cols, ["mac", "MAC Address", "host_mac", "l2addr"])
            ip_col = _choose_first_present(
                cols,
                ["host_ip", "host", "ip", "addr", "IP Address", "client_addr", "assigned_addr"],
            )
            ts_col = _choose_first_present(cols, ["ts", "timestamp", "time"])
            if not mac_col or not ip_col:
                continue

            mac_expr = _duck_mac_norm_expr(f'"{mac_col}"')
            ts_expr = _duck_ts_expr(f'"{ts_col}"') if ts_col else "NULL"
            ip_expr = f'cast("{ip_col}" as varchar)'

            sql = f"""
            SELECT
              {ts_expr} AS ts_dt,
              {mac_expr} AS mac_norm,
              NULLIF(NULLIF({ip_expr}, ''), 'nan') AS ip
            FROM parquet_scan('{_sql_quote_path(known_hosts_path)}')
            WHERE {mac_expr} IS NOT NULL
              AND {ip_expr} IS NOT NULL
            """
            try:
                kh_frames.append(con.execute(sql).df())
            except Exception:
                continue

    if kh_frames:
        kh = pd.concat(kh_frames, ignore_index=True)
        kh["ip"] = kh["ip"].map(_normalize_ip)
        kh = kh.dropna(subset=["mac_norm", "ip"])
        kh = kh[kh["ip"].map(_is_private_ip)]

        if not kh.empty:
            kh["ts_dt"] = pd.to_datetime(kh["ts_dt"], errors="coerce", utc=True)
            kh = kh.sort_values("ts_dt", na_position="first")
            kh = kh.drop_duplicates(subset=["ip"], keep="last")
            for ip_value, mac_norm in zip(kh["ip"].astype(str), kh["mac_norm"].astype(str)):
                ip_to_mac[ip_value] = mac_norm

    return ip_to_mac


@st.cache_data(show_spinner=False, ttl=300)
def _infer_events_from_ip_logs_cached(
    parquet_root_str: str,
    selected_date_dirs_str: Tuple[Tuple[str, str], ...],
    auth_file_str: str,
    auth_sig: Tuple[str, float, int],
) -> pd.DataFrame:
    """
    Fallback when DHCP/ARP/CONN are missing for a selected day:
    infer MAC activity from private IP observations in other Zeek logs.
    """
    ip_to_mac = _build_ip_to_mac_map_cached(parquet_root_str, auth_file_str, auth_sig)
    if not ip_to_mac:
        return pd.DataFrame(columns=["ts_dt", "mac_norm", "ip", "host", "source"])

    con = _duckdb_conn()
    ip_candidates = [
        "id.orig_h",
        "id.resp_h",
        "src_ip",
        "dst_ip",
        "ip",
        "host",
        "host_ip",
        "client_addr",
        "assigned_addr",
    ]
    chunks: List[pd.DataFrame] = []

    for _date_str, day_dir_str in selected_date_dirs_str:
        day_dir = Path(day_dir_str)
        candidates: List[Path] = []

        try:
            candidates.extend(sorted(day_dir.glob("*.parquet")))
        except Exception:
            pass

        try:
            for sub in day_dir.iterdir():
                if not sub.is_dir():
                    continue
                name_l = sub.name.lower()
                if CACHE_DIRNAME.lower() in name_l or "_shadow_cache" in name_l:
                    continue
                candidates.extend(sorted(sub.glob("*.parquet")))
        except Exception:
            pass

        for fp in candidates:
            fp_name_l = fp.name.lower()
            if (
                "dhcp" in fp_name_l
                or "arp" in fp_name_l
                or "conn" in fp_name_l
                or "known_hosts" in fp_name_l
            ):
                continue

            cols = _duckdb_schema_cols(con, fp)
            if not cols:
                continue

            ts_col = _choose_first_present(cols, ["ts", "timestamp", "time"])
            if not ts_col:
                continue

            present_ip_cols = [c for c in ip_candidates if c in cols]
            if not present_ip_cols:
                continue

            ts_expr = _duck_ts_expr(f'"{ts_col}"')
            for ip_col in present_ip_cols:
                ip_expr = f'cast("{ip_col}" as varchar)'
                sql = f"""
                SELECT
                  {ts_expr} AS ts_dt,
                  {ip_expr} AS ip
                FROM parquet_scan('{_sql_quote_path(fp)}')
                WHERE {ip_expr} IS NOT NULL
                """
                try:
                    df = con.execute(sql).df()
                except Exception:
                    continue

                if df.empty:
                    continue

                df["ip"] = df["ip"].map(_normalize_ip)
                df = df.dropna(subset=["ip", "ts_dt"])
                if df.empty:
                    continue

                df["mac_norm"] = df["ip"].map(ip_to_mac)
                df = df.dropna(subset=["mac_norm"])
                if df.empty:
                    continue

                df["host"] = pd.NA
                df["source"] = f"{fp.stem}:{ip_col}"
                chunks.append(df[["ts_dt", "mac_norm", "ip", "host", "source"]])

    if not chunks:
        return pd.DataFrame(columns=["ts_dt", "mac_norm", "ip", "host", "source"])

    inferred = pd.concat(chunks, ignore_index=True)
    inferred["ts_dt"] = pd.to_datetime(inferred["ts_dt"], errors="coerce")
    inferred = inferred.dropna(subset=["ts_dt", "mac_norm"])

    if inferred.empty:
        return pd.DataFrame(columns=["ts_dt", "mac_norm", "ip", "host", "source"])

    inferred["mac_norm"] = inferred["mac_norm"].astype(str)
    inferred["source"] = inferred["source"].fillna("").astype(str)

    source_map = (
        inferred[inferred["source"] != ""]
        .groupby("mac_norm")["source"]
        .agg(lambda s: ", ".join(sorted(set(s))))
        .to_dict()
    )

    latest = (
        inferred.sort_values("ts_dt", ascending=False)
        .drop_duplicates(subset=["mac_norm"], keep="first")
        .copy()
    )
    latest["source"] = latest["mac_norm"].map(source_map).fillna(latest["source"])

    return (
        latest[["ts_dt", "mac_norm", "ip", "host", "source"]]
        .sort_values("ts_dt", ascending=False)
        .reset_index(drop=True)
    )


# =============================================================================
# CACHE HELPERS (per-date + per-physical-dir)
# =============================================================================
def cache_dir(parquet_root: Path) -> Path:
    return parquet_root / CACHE_DIRNAME


def _dir_key(date_dir: Path) -> str:
    return hashlib.md5(str(date_dir).encode("utf-8")).hexdigest()[:10]


def _cache_dir_for(parquet_root: Path, date_str: str, date_dir: Path) -> Path:
    return cache_dir(parquet_root) / f"date={date_str}" / f"src={_dir_key(date_dir)}"


def _events_cache_path(parquet_root: Path, date_str: str, date_dir: Path) -> Path:
    return _cache_dir_for(parquet_root, date_str, date_dir) / "alerts_events.parquet"


def _known_hosts_cache_path(parquet_root: Path, date_str: str, date_dir: Path) -> Path:
    return _cache_dir_for(parquet_root, date_str, date_dir) / "known_hosts_norm.parquet"


def _meta_path(parquet_root: Path, date_str: str, date_dir: Path) -> Path:
    return _cache_dir_for(parquet_root, date_str, date_dir) / "meta.json"


def _file_sig(p: Optional[Path]) -> Optional[dict]:
    if not p or not p.exists():
        return None
    try:
        st_ = p.stat()
        return {"path": str(p), "mtime": float(st_.st_mtime), "size": int(st_.st_size)}
    except Exception:
        return {"path": str(p), "mtime": None, "size": None}


def _compute_signature(
    date_str: str,
    date_dir: Path,
    dhcp_path: Optional[Path],
    arp_path: Optional[Path],
    conn_path: Optional[Path],
    known_hosts_path: Optional[Path],
) -> dict:
    return {
        "cache_version": CACHE_VERSION,
        "date": date_str,
        "date_dir": str(date_dir),
        "inputs": {
            "dhcp": _file_sig(dhcp_path),
            "arp": _file_sig(arp_path),
            "conn": _file_sig(conn_path),
            "known_hosts": _file_sig(known_hosts_path),
        },
    }


def _read_meta(meta_p: Path) -> Optional[dict]:
    if not meta_p.exists():
        return None
    try:
        return json.loads(meta_p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_meta(meta_p: Path, meta: dict) -> None:
    meta_p.parent.mkdir(parents=True, exist_ok=True)
    meta_p.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")


def _cache_is_fresh(meta_p: Path, expected_meta: dict) -> bool:
    return _read_meta(meta_p) == expected_meta


# =============================================================================
# PARQUET DISCOVERY
# =============================================================================
def _extract_date_from_dirname(name: str) -> Optional[str]:
    if DATE_DIR_RE.match(name):
        return name
    if name.startswith("date="):
        tail = name.split("date=", 1)[1]
        if DATE_DIR_RE.match(tail):
            return tail
    return None


@st.cache_data(show_spinner=False, ttl=300)
def _discover_date_dirs(parquet_root_str: str) -> Dict[str, List[str]]:
    """
    Faster discovery using os.scandir.
    - Look for direct children that are date dirs or date= dirs
    - Also look 1 level deeper (covers common layouts)
    - Avoid scanning inside cache folders
    """
    root = Path(parquet_root_str)
    by_date: Dict[str, List[str]] = {}

    def _is_cache_like(name_l: str) -> bool:
        # Mirror other pages: never treat cache/hidden folders as source date dirs.
        if name_l.startswith("_"):
            return True
        if "cache" in name_l:
            return True
        if name_l == CACHE_DIRNAME.lower():
            return True
        if name_l.startswith("_shadow_cache"):
            return True
        if CACHE_DIRNAME.lower() in name_l:
            return True
        return False

    def _maybe_add_dir(full_path: str, base_name: str):
        bn_l = base_name.lower()
        if _is_cache_like(bn_l):
            return
        ds = _extract_date_from_dirname(base_name)
        if ds:
            by_date.setdefault(ds, []).append(full_path)

    try:
        with os.scandir(root) as it:
            for entry in it:
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    _maybe_add_dir(entry.path, entry.name)

                    if _is_cache_like(entry.name.lower()):
                        continue

                    try:
                        with os.scandir(entry.path) as it2:
                            for e2 in it2:
                                if e2.is_dir(follow_symlinks=False):
                                    _maybe_add_dir(e2.path, e2.name)
                    except Exception:
                        pass
                except Exception:
                    continue
    except Exception:
        # Fallback to Path if scandir fails
        try:
            for p in root.iterdir():
                if p.is_dir():
                    _maybe_add_dir(str(p), p.name)
                    try:
                        for p2 in p.iterdir():
                            if p2.is_dir():
                                _maybe_add_dir(str(p2), p2.name)
                    except Exception:
                        pass
        except Exception:
            pass

    for k in list(by_date.keys()):
        by_date[k] = sorted(by_date[k], key=lambda s: s)
    return by_date


@st.cache_data(show_spinner=False, ttl=300)
def _find_log_file_in_day_cached(day_dir_str: str, keywords: Tuple[str, ...], day_dir_mtime: float) -> Optional[str]:
    """
    Cached log discovery per day_dir + mtime.
    Prevents repeated glob/scans on every rerun.
    """
    day_dir = Path(day_dir_str)

    # 1) exact hits first
    for k in keywords:
        exact = day_dir / f"{k}.parquet"
        if exact.exists():
            return str(exact)

    candidates: List[Path] = []
    try:
        candidates.extend(list(day_dir.glob("*.parquet")))
    except Exception:
        pass

    try:
        for sub in day_dir.iterdir():
            if sub.is_dir():
                if CACHE_DIRNAME.lower() in sub.name.lower() or "_shadow_cache" in sub.name.lower():
                    continue
                candidates.extend(list(sub.glob("*.parquet")))
    except Exception:
        pass

    if not candidates:
        return None

    kw = [k.lower() for k in keywords]
    matches = [p for p in candidates if any(k in p.name.lower() for k in kw)]
    if not matches:
        return None

    matches.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return str(matches[0])


def _find_log_file_in_day(day_dir: Path, keywords: List[str]) -> Optional[Path]:
    try:
        mtime = float(day_dir.stat().st_mtime)
    except Exception:
        mtime = 0.0

    out = _find_log_file_in_day_cached(str(day_dir), tuple(keywords), mtime)
    return Path(out) if out else None


# =============================================================================
# DUCKDB SQL HELPERS
# =============================================================================
def _duck_mac_norm_expr(col_sql: str) -> str:
    hx = f"regexp_replace(lower(cast({col_sql} as varchar)), '[^0-9a-f]', '', 'g')"
    return (
        "case "
        f"when length({hx}) = 12 then "
        f"substr({hx},1,2)||':'||substr({hx},3,2)||':'||substr({hx},5,2)||':'||substr({hx},7,2)||':'||substr({hx},9,2)||':'||substr({hx},11,2) "
        "else NULL end"
    )


def _duck_ts_expr(col_sql: str) -> str:
    ts_as_ts = f"try_cast({col_sql} as timestamp)"
    v = f"try_cast({col_sql} as double)"

    v_as_seconds = (
        "case "
        f"when {v} is null then null "
        f"when abs({v}) > 1e17 then ({v} / 1e9) "
        f"when abs({v}) > 1e14 then ({v} / 1e6) "
        f"when abs({v}) > 1e11 then ({v} / 1e3) "
        f"else {v} end"
    )

    ts_from_num = f"to_timestamp({v_as_seconds})"
    return (
        "case "
        f"when {ts_as_ts} is not null then {ts_as_ts} "
        f"when {v} is not null then {ts_from_num} "
        "else null end"
    )


def _choose_first_present(cols: List[str], preferred: List[str]) -> Optional[str]:
    colset = set(cols)
    for c in preferred:
        if c in colset:
            return c
    return None


# =============================================================================
# BUILD PER-DIR CACHE
# =============================================================================
def _build_cache_for_date_dir(
    con: duckdb.DuckDBPyConnection,
    parquet_root: Path,
    date_str: str,
    date_dir: Path,
) -> Tuple[Path, Path]:
    dhcp_path = _find_log_file_in_day(date_dir, ["dhcp"])
    arp_path = _find_log_file_in_day(date_dir, ["arp"])
    conn_path = _find_log_file_in_day(date_dir, ["conn"])
    known_hosts_path = _find_log_file_in_day(date_dir, KNOWN_HOSTS_KEYWORDS)

    expected_meta = _compute_signature(date_str, date_dir, dhcp_path, arp_path, conn_path, known_hosts_path)

    events_out = _events_cache_path(parquet_root, date_str, date_dir)
    kh_out = _known_hosts_cache_path(parquet_root, date_str, date_dir)
    meta_p = _meta_path(parquet_root, date_str, date_dir)

    events_out.parent.mkdir(parents=True, exist_ok=True)

    if events_out.exists() and kh_out.exists() and _cache_is_fresh(meta_p, expected_meta):
        return events_out, kh_out

    # 1) Events
    parts: List[str] = []
    for src_name, src_path, mac_pref, ip_pref, host_pref, ts_pref in [
        (
            "dhcp",
            dhcp_path,
            ["client_chaddr", "chaddr", "client_mac", "mac", "hardware_address"],
            ["assigned_addr", "client_addr", "id.orig_h", "id.resp_h", "src_ip", "dst_ip", "ip"],
            ["host_name", "client_fqdn", "hostname", "host"],
            ["ts", "timestamp", "time"],
        ),
        (
            "arp",
            arp_path,
            ["mac", "orig_l2_addr", "resp_l2_addr", "orig_mac", "resp_mac", "hardware_address"],
            ["id.orig_h", "id.resp_h", "src_ip", "dst_ip", "ip"],
            ["host_name", "hostname", "host"],
            ["ts", "timestamp", "time"],
        ),
        (
            "conn",
            conn_path,
            ["orig_l2_addr", "resp_l2_addr", "orig_mac", "resp_mac", "hardware_address"],
            ["id.orig_h", "id.resp_h", "src_ip", "dst_ip", "ip"],
            ["host_name", "hostname", "host"],
            ["ts", "timestamp", "time"],
        ),
    ]:
        if not src_path or not src_path.exists():
            continue

        cols = _duckdb_schema_cols(con, src_path)
        if not cols:
            continue

        mac_col = _choose_first_present(cols, mac_pref)
        ts_col = _choose_first_present(cols, ts_pref)
        ip_col = _choose_first_present(cols, ip_pref)
        host_col = _choose_first_present(cols, host_pref)
        if not mac_col:
            continue

        mac_norm = _duck_mac_norm_expr(f'"{mac_col}"')
        ts_dt = _duck_ts_expr(f'"{ts_col}"') if ts_col else "NULL"
        ip_sql = f'cast("{ip_col}" as varchar)' if ip_col else "NULL"
        host_sql = f'cast("{host_col}" as varchar)' if host_col else "NULL"

        parts.append(
            f"""
            SELECT
              {ts_dt} AS ts_dt,
              {mac_norm} AS mac_norm,
              NULLIF(NULLIF({ip_sql}, ''), 'nan') AS ip,
              NULLIF(NULLIF({host_sql}, ''), 'nan') AS host,
              '{src_name}' AS source
            FROM parquet_scan('{_sql_quote_path(src_path)}')
            """
        )

    if parts:
        union_sql = "\nUNION ALL\n".join(parts)
        final_sql = f"""
        SELECT ts_dt, mac_norm, ip, host, source
        FROM ({union_sql})
        WHERE mac_norm IS NOT NULL
          AND ts_dt IS NOT NULL
          AND mac_norm != 'ff:ff:ff:ff:ff:ff'
        """
        con.execute(f"COPY ({final_sql}) TO '{_sql_quote_path(events_out)}' (FORMAT PARQUET)")
    else:
        pd.DataFrame(columns=["ts_dt", "mac_norm", "ip", "host", "source"]).to_parquet(events_out, index=False)

    # 2) known_hosts
    if known_hosts_path and known_hosts_path.exists():
        cols = _duckdb_schema_cols(con, known_hosts_path)
        mac_col = _choose_first_present(cols, ["mac", "MAC Address", "host_mac", "l2addr"])
        ip_col = _choose_first_present(cols, ["host_ip", "ip", "addr", "IP Address", "host"])
        vendor_col = _choose_first_present(cols, ["vendor", "Vendor", "manuf", "manufacturer"])

        if mac_col:
            mac_norm = _duck_mac_norm_expr(f'"{mac_col}"')
            ip_sql = f'cast("{ip_col}" as varchar)' if ip_col else "NULL"
            vendor_sql = f'cast("{vendor_col}" as varchar)' if vendor_col else "NULL"
            kh_sql = f"""
            SELECT
              {mac_norm} AS mac_norm,
              NULLIF(NULLIF({ip_sql}, ''), 'nan') AS ip,
              NULLIF(NULLIF({vendor_sql}, ''), 'nan') AS vendor
            FROM parquet_scan('{_sql_quote_path(known_hosts_path)}')
            WHERE {mac_norm} IS NOT NULL
            """
            con.execute(f"COPY ({kh_sql}) TO '{_sql_quote_path(kh_out)}' (FORMAT PARQUET)")
        else:
            pd.DataFrame(columns=["mac_norm", "ip", "vendor"]).to_parquet(kh_out, index=False)
    else:
        pd.DataFrame(columns=["mac_norm", "ip", "vendor"]).to_parquet(kh_out, index=False)

    _write_meta(meta_p, expected_meta)
    return events_out, kh_out


def _load_cached_for_date_dirs(
    parquet_root: Path,
    selected_date_dirs: List[Tuple[str, Path]],
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    SPEED UPDATE (no UI/logic change):
    - Still builds/uses the same per-dir parquet caches on disk
    - When loading, aggregates to "latest per MAC" inside DuckDB
      to avoid loading huge raw event rows into pandas.
    """
    con = _duckdb_conn()

    events_paths: List[str] = []
    kh_paths: List[str] = []

    for date_str, date_dir in selected_date_dirs:
        events_p, kh_p = _build_cache_for_date_dir(con, parquet_root, date_str, date_dir)
        if events_p.exists():
            events_paths.append(str(events_p))
        if kh_p.exists():
            kh_paths.append(str(kh_p))

    # ---- FAST LOAD: events aggregated in DuckDB (latest per mac) ----
    if events_paths:
        agg_sql = """
        WITH ev AS (
          SELECT ts_dt, mac_norm, ip, host, source
          FROM read_parquet(?, union_by_name=true)
        ),
        clean AS (
          SELECT
            try_cast(ts_dt AS timestamp) AS ts_dt,
            cast(mac_norm AS varchar) AS mac_norm,
            NULLIF(NULLIF(cast(ip AS varchar), ''), 'nan') AS ip,
            NULLIF(NULLIF(cast(host AS varchar), ''), 'nan') AS host,
            cast(source AS varchar) AS source
          FROM ev
          WHERE mac_norm IS NOT NULL
            AND ts_dt IS NOT NULL
            AND mac_norm != 'ff:ff:ff:ff:ff:ff'
        ),
        latest AS (
          SELECT ts_dt, mac_norm, ip, host
          FROM clean
          QUALIFY row_number() OVER (PARTITION BY mac_norm ORDER BY ts_dt DESC) = 1
        ),
        ip_last AS (
          SELECT mac_norm, ip
          FROM clean
          WHERE ip IS NOT NULL
          QUALIFY row_number() OVER (PARTITION BY mac_norm ORDER BY ts_dt DESC) = 1
        ),
        host_last AS (
          SELECT mac_norm, host
          FROM clean
          WHERE host IS NOT NULL
          QUALIFY row_number() OVER (PARTITION BY mac_norm ORDER BY ts_dt DESC) = 1
        ),
        src AS (
          SELECT mac_norm,
                 string_agg(DISTINCT source, ', ' ORDER BY source) AS source
          FROM clean
          GROUP BY mac_norm
        )
        SELECT
          latest.ts_dt AS ts_dt,
          latest.mac_norm AS mac_norm,
          ip_last.ip AS ip,
          host_last.host AS host,
          src.source AS source
        FROM latest
        LEFT JOIN ip_last USING(mac_norm)
        LEFT JOIN host_last USING(mac_norm)
        LEFT JOIN src USING(mac_norm)
        ORDER BY ts_dt DESC
        """
        events = con.execute(agg_sql, [events_paths]).df()
    else:
        events = pd.DataFrame(columns=["ts_dt", "mac_norm", "ip", "host", "source"])

    if kh_paths:
        known_hosts = con.execute(
            "SELECT * FROM read_parquet(?, union_by_name=true)",
            [kh_paths],
        ).df()
    else:
        known_hosts = pd.DataFrame(columns=["mac_norm", "ip", "vendor"])

    return events, known_hosts


@st.cache_data(show_spinner=False, ttl=600)
def _load_cached_for_date_dirs_cached(
    parquet_root_str: str,
    selected_date_dirs_str: Tuple[Tuple[str, str], ...],
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Cache loaded/aggregated frames briefly to avoid rebuilding on every UI rerun
    (search, source filter, view toggle, etc.).
    """
    selected = [(d, Path(p)) for d, p in selected_date_dirs_str]
    return _load_cached_for_date_dirs(Path(parquet_root_str), selected)


# =============================================================================
# BUSINESS LOGIC
# =============================================================================
def _apply_time_filter(events: pd.DataFrame, mode: str, selected_date: Optional[str]) -> Tuple[pd.DataFrame, str]:
    def _rolling_days(selected_mode: str) -> int:
        return ROLLING_TIME_WINDOWS_DAYS.get(selected_mode, ROLLING_TIME_WINDOWS_DAYS["Last 7 Days"])

    def _rolling_label(selected_mode: str, cutoff_ts: pd.Timestamp) -> str:
        label = selected_mode if selected_mode in ROLLING_TIME_WINDOWS_DAYS else "Last 7 Days"
        return f"{label} (since {cutoff_ts.strftime('%Y-%m-%d %H:%M')})"

    if events is None or events.empty:
        if mode == "All Time":
            return (
                pd.DataFrame(columns=["ts_dt", "mac_norm", "ip", "host", "source"]),
                "All Time",
            )
        if mode == "Specific Date" and selected_date:
            return (
                pd.DataFrame(columns=["ts_dt", "mac_norm", "ip", "host", "source"]),
                f"Specific Date ({selected_date})",
            )
        cutoff = pd.Timestamp.now() - pd.Timedelta(days=_rolling_days(mode))
        return (
            pd.DataFrame(columns=["ts_dt", "mac_norm", "ip", "host", "source"]),
            _rolling_label(mode, cutoff),
        )

    tmp = events.copy()
    tmp["ts_dt"] = pd.to_datetime(tmp["ts_dt"], errors="coerce")

    tz = getattr(tmp["ts_dt"].dtype, "tz", None)
    is_tz_aware = tz is not None
    now = pd.Timestamp.now(tz=tz) if is_tz_aware else pd.Timestamp.now()

    tmp = tmp.dropna(subset=["ts_dt", "mac_norm"])

    if mode == "All Time":
        return tmp, "All Time"

    if mode in ROLLING_TIME_WINDOWS_DAYS:
        cutoff = now - pd.Timedelta(days=_rolling_days(mode))
        tmp = tmp[tmp["ts_dt"] >= cutoff]
        return tmp, _rolling_label(mode, cutoff)

    if mode == "Specific Date" and selected_date:
        start_naive = datetime.strptime(selected_date, "%Y-%m-%d")
        if is_tz_aware:
            start = pd.Timestamp(start_naive).tz_localize(tz)
            end = start + pd.Timedelta(days=1)
        else:
            start = pd.Timestamp(start_naive)
            end = start + pd.Timedelta(days=1)
        tmp = tmp[(tmp["ts_dt"] >= start) & (tmp["ts_dt"] < end)]
        return tmp, f"Specific Date ({selected_date})"

    # Default to Last 7 Days semantics if an unexpected mode is passed.
    cutoff = now - pd.Timedelta(days=7)
    tmp = tmp[tmp["ts_dt"] >= cutoff]
    return tmp, _rolling_label("Last 7 Days", cutoff)


def build_known_maps(known_hosts_df: pd.DataFrame) -> Tuple[Dict[str, str], Dict[str, str]]:
    mac_to_ip: Dict[str, str] = {}
    mac_to_vendor: Dict[str, str] = {}

    if known_hosts_df is None or known_hosts_df.empty:
        return mac_to_ip, mac_to_vendor

    kh = known_hosts_df.copy()
    kh["mac_norm"] = kh["mac_norm"].astype("string")
    kh = kh.dropna(subset=["mac_norm"])

    if "ip" in kh.columns:
        kh_ip = kh.dropna(subset=["ip"]).copy()
        mac_to_ip = dict(zip(kh_ip["mac_norm"].astype(str), kh_ip["ip"].astype(str)))

    if "vendor" in kh.columns:
        kh_v = kh.dropna(subset=["vendor"]).copy()
        mac_to_vendor = dict(zip(kh_v["mac_norm"].astype(str), kh_v["vendor"].astype(str)))

    return mac_to_ip, mac_to_vendor


def build_device_table(events: pd.DataFrame, mac_to_ip: Dict[str, str]) -> pd.DataFrame:
    if events is None or events.empty:
        return pd.DataFrame()

    tmp = events.copy()
    tmp["mac_norm"] = tmp["mac_norm"].astype("string")
    tmp["ts_dt"] = pd.to_datetime(tmp["ts_dt"], errors="coerce")
    tmp = tmp.dropna(subset=["mac_norm", "ts_dt"])

    if "host" in tmp.columns:
        tmp["host"] = tmp["host"].astype("string").replace(["nan", "None", "none", "-", ""], pd.NA)
    if "ip" in tmp.columns:
        tmp["ip"] = tmp["ip"].astype("string").replace(
            ["None", "none", "-", "nan", "0.0.0.0", "Unknown IP", ""], pd.NA
        )

    # Events are already "latest per MAC" from DuckDB. Keep this step lightweight.
    latest = (
        tmp.sort_values("ts_dt", ascending=False)
        .drop_duplicates(subset=["mac_norm"], keep="first")
        .copy()
    )
    latest["ip"] = latest["mac_norm"].map(mac_to_ip).fillna(latest["ip"])
    latest["seen_in"] = (
        latest["source"].fillna("").astype(str) if "source" in latest.columns else ""
    )

    return latest.sort_values("ts_dt", ascending=False)


# =============================================================================
# VENDOR LOOKUP
# =============================================================================
@st.cache_resource(show_spinner=False)
def _vendor_lookup():
    if not VENDOR_LIB_AVAILABLE:
        return None
    try:
        return MacLookup()
    except Exception:
        return None


def resolve_vendor(mac_norm: Optional[str], mac_to_vendor: Dict[str, str], mac_lookup) -> str:
    if not mac_norm:
        return "Unknown Vendor"

    if mac_norm in mac_to_vendor:
        return mac_to_vendor[mac_norm]

    st.session_state.setdefault("_alerts_vendor_cache", {})
    vcache: Dict[str, str] = st.session_state["_alerts_vendor_cache"]

    if mac_norm in vcache:
        return vcache[mac_norm]

    if mac_lookup:
        try:
            v = mac_lookup.lookup(mac_norm)
            if v:
                vcache[mac_norm] = v
                return v
        except Exception:
            pass

    if not VENDOR_LIB_AVAILABLE:
        vcache[mac_norm] = "Unknown (install mac-vendor-lookup)"
        return vcache[mac_norm]

    vcache[mac_norm] = "Unknown Vendor"
    return vcache[mac_norm]


# =============================================================================
# UI HELPERS
# =============================================================================
def build_display_table(df: pd.DataFrame, include_mac_spoofing: bool = False) -> pd.DataFrame:
    working = df.copy()
    cols = ["ts_dt", "ip", "mac_norm", "vendor", "host", "seen_in", "status"]

    if include_mac_spoofing:
        if "mac_norm" in working.columns:
            working["mac_spoofing"] = working["mac_norm"].map(mac_spoofing_status)
        else:
            working["mac_spoofing"] = "Unknown"
        cols.append("mac_spoofing")

    if "note" in working.columns:
        cols.append("note")

    out = working[cols].rename(
        columns={
            "ts_dt": "Last Seen",
            "ip": "IP Address",
            "mac_norm": "MAC Address",
            "vendor": "Vendor",
            "host": "Host Name",
            "seen_in": "Source",
            "status": "Status",
            "mac_spoofing": "Mac Spoofing",
            "note": "Note",
        }
    ).copy()
    return out


def style_status(val):
    return "color:#ff4b4b;font-weight:bold;" if str(val).startswith("Unauthorized") else ""


def inject_alerts_page_css():
    st.markdown(
        """
        <style>
        :root {
            --alerts-panel-border: rgba(255,255,255,0.12);
            --alerts-panel-bg: rgba(255,255,255,0.03);
            --alerts-panel-shadow: 0 14px 38px rgba(0,0,0,0.25);
            --alerts-accent-cyan: #00F7FF;
        }

        .stApp {
            background:
                radial-gradient(1200px 550px at 10% -5%, rgba(0, 247, 255, 0.08), transparent 45%),
                radial-gradient(900px 460px at 90% 8%, rgba(246, 48, 73, 0.08), transparent 42%),
                #040B18;
        }

        .block-container,
        .main .block-container,
        [data-testid="stMainBlockContainer"] {
            padding-top: 0.2rem !important;
            padding-bottom: 1.05rem !important;
            padding-left: 30px !important;
            padding-right: 30px !important;
            max-width: 100% !important;
        }

        [data-testid="stAppViewContainer"] > .main,
        [data-testid="stAppViewContainer"] .main,
        section.main {
            padding-left: 0 !important;
            padding-right: 0 !important;
            margin-left: 0 !important;
            margin-right: 0 !important;
            max-width: 100% !important;
        }

        .alerts-page-header {
            display:flex;
            align-items:flex-end;
            justify-content:space-between;
            gap: 18px;
            margin-bottom: 14px;
            padding: 18px 20px;
            border-radius: 18px;
            border: 1px solid var(--alerts-panel-border);
            background:
              radial-gradient(circle at top right, rgba(0,247,255,0.08), transparent 40%),
              linear-gradient(135deg, rgba(255,255,255,0.045), rgba(255,255,255,0.015));
            box-shadow: var(--alerts-panel-shadow);
        }

        .alerts-page-title {
            font-size: 44px;
            font-weight: 900;
            line-height: 1.0;
            letter-spacing: -0.4px;
        }

        .alerts-page-sub {
            opacity: 0.74;
            font-size: 13px;
            margin-top: 6px;
        }

        .alerts-chip {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border: 1px solid rgba(255,255,255,0.18);
            background: rgba(255,255,255,0.05);
            border-radius: 999px;
            padding: 7px 12px;
            font-size: 12px;
            font-weight: 700;
            white-space: nowrap;
        }

        .alerts-dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: var(--alerts-accent-cyan);
            box-shadow: 0 0 10px rgba(0,247,255,0.8);
        }

        .alerts-toolbar {
            border: 1px solid var(--alerts-panel-border);
            background: var(--alerts-panel-bg);
            border-radius: 16px;
            padding: 12px 14px 10px 14px;
            margin-bottom: 14px;
            box-shadow: var(--alerts-panel-shadow);
        }

        .alerts-toolbar-title {
            font-size: 15px;
            font-weight: 800;
            margin-bottom: 2px;
        }

        .alerts-toolbar-sub {
            font-size: 12px;
            opacity: 0.72;
            margin-bottom: 8px;
        }

        .alerts-section-title {
            font-size: 24px;
            font-weight: 900;
            margin: 14px 0 3px 0;
        }

        .alerts-section-sub {
            opacity: 0.74;
            font-size: 12px;
            margin: 0 0 10px 0;
        }

        .alerts-table-meta {
            opacity: 0.8;
            font-size: 12px;
            margin: 6px 1px 8px 1px;
        }

        .alerts-table-shell {
            border: 1px solid var(--alerts-panel-border);
            background: var(--alerts-panel-bg);
            border-radius: 16px;
            padding: 8px 8px 4px 8px;
            box-shadow: var(--alerts-panel-shadow);
        }

        div[data-testid="stTextInput"] input { border-radius: 14px !important; }
        div[data-testid="stSelectbox"] > div { border-radius: 14px !important; }
        button { border-radius: 14px !important; }

        div[data-testid="stDownloadButton"] button {
            border-radius: 999px !important;
            padding: 0.35rem 0.85rem !important;
        }

        @media (max-width: 1200px) {
            .alerts-page-header {
                align-items: flex-start;
                flex-direction: column;
            }
            .alerts-page-title {
                font-size: 36px;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def inject_alert_metric_card_css():
    st.markdown(
        """
        <style>
        .st-key-alert_card_total button,
        .st-key-alert_card_verified button,
        .st-key-alert_card_unauth button,
        div[data-testid="stButton"].st-key-alert_card_total > button,
        div[data-testid="stButton"].st-key-alert_card_verified > button,
        div[data-testid="stButton"].st-key-alert_card_unauth > button,
        div.st-key-alert_card_total > button,
        div.st-key-alert_card_verified > button,
        div.st-key-alert_card_unauth > button {
            height: 146px !important;
            min-height: 146px !important;
            width: 100% !important;
            padding: 0 !important;
            border-radius: 20px !important;
            border: 1px solid rgba(255,255,255,0.12) !important;
            background: rgba(255,255,255,0.035) !important;
            transition: 160ms ease;
            cursor: pointer !important;
            font-size: 0 !important;
            line-height: 0 !important;
            box-shadow: 0 16px 45px rgba(0,0,0,0.28);
        }

        .st-key-alert_card_total button:hover,
        .st-key-alert_card_verified button:hover,
        .st-key-alert_card_unauth button:hover,
        div[data-testid="stButton"].st-key-alert_card_total > button:hover,
        div[data-testid="stButton"].st-key-alert_card_verified > button:hover,
        div[data-testid="stButton"].st-key-alert_card_unauth > button:hover,
        div.st-key-alert_card_total > button:hover,
        div.st-key-alert_card_verified > button:hover,
        div.st-key-alert_card_unauth > button:hover {
            transform: translateY(-2px);
            border-color: rgba(0,247,255,0.26) !important;
            background: rgba(255,255,255,0.055) !important;
        }

        .alerts-metric-overlay {
            margin-top: -166px !important;
            height: 146px !important;
            padding: 16px 16px !important;
            border-radius: 20px !important;
            pointer-events: none !important;
            position: relative !important;
            z-index: 2 !important;
            border: 1px solid transparent;
            display: flex;
            flex-direction: column;
            width: 100%;
            box-sizing: border-box;
            text-align: left;
        }

        .alerts-metric-overlay.is-active {
            border-color: rgba(0,247,255,0.45);
            background: rgba(0,247,255,0.06);
        }

        .alerts-metric-overlay.is-danger .alerts-metric-value { color: #ff6b6b; }
        .alerts-metric-overlay.is-good .alerts-metric-value { color: #8df3ad; }

        .alerts-metric-label {
            font-size: 14px;
            opacity: 0.82;
        }

        .alerts-metric-value {
            font-size: 42px;
            font-weight: 800;
            line-height: 1.02;
            margin-top: 2px;
            letter-spacing: -0.5px;
        }

        .alerts-metric-note {
            font-size: 12px;
            opacity: 0.66;
            margin-top: 5px;
            min-height: 18px;
        }

        .alerts-metric-hint {
            font-size: 11px;
            opacity: 0.58;
            margin-top: auto;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_alert_metric_card(
    label: str,
    value,
    *,
    note: str,
    key: str,
    view_name: str,
    is_active: bool = False,
    tone: str = "neutral",
) -> None:
    clicked = st.button(" ", key=key, width="stretch")

    label_safe = html.escape(str(label))
    value_safe = html.escape(str(value))
    note_safe = html.escape(str(note))

    tone_cls = ""
    if tone == "danger":
        tone_cls = "is-danger"
    elif tone == "good":
        tone_cls = "is-good"

    active_cls = "is-active" if is_active else ""

    st.markdown(
        f"""
        <div class="alerts-metric-overlay {active_cls} {tone_cls}">
            <div class="alerts-metric-label">{label_safe}</div>
            <div class="alerts-metric-value">{value_safe}</div>
            <div class="alerts-metric-note">{note_safe}</div>
            <div class="alerts-metric-hint">Click to view</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if clicked:
        st.session_state["unauth_macs_view"] = view_name
        st.rerun()


# =============================================================================
# MAIN RENDER
# =============================================================================
def render(parquet_root: str, authorized_macs_file: str):
    root = Path(parquet_root)
    if not root.exists():
        st.error(f"Directory '{parquet_root}' not found.")
        return

    by_date_str = _discover_date_dirs(str(root))
    by_date: Dict[str, List[Path]] = {k: [Path(p) for p in v] for k, v in by_date_str.items()}
    available_dates = sorted(by_date.keys(), reverse=True)

    if not available_dates:
        st.info("No date folders found. Expected 'YYYY-MM-DD' or 'date=YYYY-MM-DD' under parquet root.")
        return

    st.session_state.setdefault("alerts_time_mode", "Last 7 Days")
    st.session_state.setdefault("alerts_time_date", available_dates[0])

    # Ensure legacy saved values (e.g., a removed mode) do not break the UI after removing options.
    if st.session_state.get("alerts_time_mode") not in ALERT_TIME_RANGE_OPTIONS:
        st.session_state["alerts_time_mode"] = "Last 7 Days"

    inject_alerts_page_css()
    inject_traffic_style_header_css()

    updated_txt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    render_traffic_style_header(
        title="Alerts Overview",
        subtitle="Device trust posture and activity anomalies",
        chip_label="Live monitoring",
        updated_txt=updated_txt,
    )
    inject_alert_metric_card_css()

    st.markdown("<div class='alerts-toolbar'>", unsafe_allow_html=True)
    st.markdown(
        "<div class='alerts-toolbar-title'>Filter Scope</div>"
        "<div class='alerts-toolbar-sub'>Choose the time window used for counters and table results.</div>",
        unsafe_allow_html=True,
    )
    tr_col1, tr_col2 = st.columns([1.2, 2.8], vertical_alignment="center")
    with tr_col1:
        time_mode = st.selectbox(
            "Time Range:",
            ALERT_TIME_RANGE_OPTIONS,
            index=ALERT_TIME_RANGE_OPTIONS.index(st.session_state["alerts_time_mode"])
            if st.session_state["alerts_time_mode"] in ALERT_TIME_RANGE_OPTIONS
            else 0,
            key="alerts_time_mode",
        )

    selected_date = None
    with tr_col2:
        if time_mode == "Specific Date":
            selected_date = st.selectbox(
                "Select Date:",
                options=available_dates,
                index=0
                if st.session_state.get("alerts_time_date") not in available_dates
                else available_dates.index(st.session_state["alerts_time_date"]),
                key="alerts_time_date",
            )
        else:
            st.markdown("<div style='height: 2.2rem;'></div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    allowed_macs = load_authorized_macs(authorized_macs_file)

    # =============================================================================
    # CHANGED (FIX): Keep ban list for filtering, but DO NOT use global inventory
    # counts for the cards, because they don't change for "Specific Date".
    # Cards are now computed from the filtered scoped table inside _render_alerts_ui.
    # =============================================================================
    auth_path = Path(authorized_macs_file)
    if auth_path.suffix != ".yaml":
        y = auth_path.with_suffix(".yaml")
        if y.exists():
            auth_path = y
    ban_file = auth_path.with_name("banned_macs.yaml")
    banned_macs = load_banned_macs(ban_file)

    # Keep these parameters for compatibility, but they no longer drive the UI cards.
    inventory_total = 0
    inventory_verified = 0
    inventory_unauthorized = 0

    # Allowlist-change detection (session-based)
    st.session_state.setdefault("_alerts_prev_allowed_set", None)
    prev_allowed = st.session_state.get("_alerts_prev_allowed_set")
    if prev_allowed is None:
        prev_allowed = set(allowed_macs)
    removed_from_allowlist = sorted(set(prev_allowed) - set(allowed_macs))
    added_to_allowlist = sorted(set(allowed_macs) - set(prev_allowed))
    st.session_state["_alerts_prev_allowed_set"] = set(allowed_macs)

    # Select dirs
    selected_date_dirs: List[Tuple[str, Path]] = []

    if time_mode == "Specific Date" and selected_date:
        for p in by_date.get(selected_date, []):
            selected_date_dirs.append((selected_date, p))
    elif time_mode == "All Time":
        for d in available_dates:
            for p in by_date[d]:
                selected_date_dirs.append((d, p))
    else:
        rolling_days = ROLLING_TIME_WINDOWS_DAYS.get(time_mode, ROLLING_TIME_WINDOWS_DAYS["Last 7 Days"])
        cutoff_date = datetime.now().date() - timedelta(days=rolling_days)
        for d in available_dates:
            try:
                dd = datetime.strptime(d, "%Y-%m-%d").date()
            except Exception:
                continue
            if dd < cutoff_date:
                break
            if dd >= cutoff_date:
                for p in by_date[d]:
                    selected_date_dirs.append((d, p))

    if not selected_date_dirs:
        st.info("No parquet date folders matched the selected time range.")
        _render_alerts_ui(
            devices=pd.DataFrame(columns=["ts_dt", "ip", "mac_norm", "vendor", "host", "seen_in", "status"]),
            range_label="No date folders matched",
            allowed_macs=allowed_macs,
            removed_from_allowlist=removed_from_allowlist,
            added_to_allowlist=added_to_allowlist,
            mac_to_ip={},
            mac_to_vendor={},
            mac_lookup=_vendor_lookup(),
            events=pd.DataFrame(columns=["ts_dt", "mac_norm", "ip", "host", "source"]),
            inventory_total=0,
            inventory_verified=0,
            inventory_unauthorized=0,
        )
        return

    selected_date_dirs_key = tuple((d, str(p)) for d, p in selected_date_dirs)
    with st.spinner("Loading alerts (DuckDB cache)…"):
        raw_events, known_hosts_norm = _load_cached_for_date_dirs_cached(str(root), selected_date_dirs_key)

    events, range_label = _apply_time_filter(raw_events, time_mode, selected_date)
    fallback_scope_note = None

    if time_mode == "Specific Date" and selected_date and (events is None or events.empty):
        auth_sig = _auth_file_sig(auth_path)
        inferred_events = _infer_events_from_ip_logs_cached(
            str(root),
            selected_date_dirs_key,
            str(auth_path),
            auth_sig,
        )
        if inferred_events is not None and not inferred_events.empty:
            events, range_label = _apply_time_filter(inferred_events, time_mode, selected_date)
            fallback_scope_note = (
                "Selected date has no DHCP/ARP/CONN capture. "
                "Counts are inferred from private-IP activity mapped to known MAC addresses."
            )

    mac_to_ip, mac_to_vendor = build_known_maps(known_hosts_norm)
    devices = build_device_table(events, mac_to_ip) if not events.empty else pd.DataFrame(
        columns=["ts_dt", "ip", "mac_norm", "host", "seen_in", "source"]
    )

    # exclude banned devices from alert tables
    if not devices.empty and banned_macs and "mac_norm" in devices.columns:
        devices = devices[~devices["mac_norm"].astype(str).isin(banned_macs)].copy()

    mac_lookup = _vendor_lookup()

    if not devices.empty:
        macs = devices["mac_norm"].astype(str)
        uniq = pd.unique(macs)
        vmap = {m: resolve_vendor(m, mac_to_vendor, mac_lookup) for m in uniq}
        devices["vendor"] = macs.map(vmap)

        devices["status"] = macs.map(lambda m: "Verified" if m in allowed_macs else "Unauthorized")
    else:
        devices = pd.DataFrame(columns=["ts_dt", "ip", "mac_norm", "vendor", "host", "seen_in", "status"])

    _render_alerts_ui(
        devices=devices,
        range_label=range_label,
        allowed_macs=allowed_macs,
        removed_from_allowlist=removed_from_allowlist,
        added_to_allowlist=added_to_allowlist,
        mac_to_ip=mac_to_ip,
        mac_to_vendor=mac_to_vendor,
        mac_lookup=mac_lookup,
        events=events,
        inventory_total=inventory_total,
        inventory_verified=inventory_verified,
        inventory_unauthorized=inventory_unauthorized,
        inference_note=fallback_scope_note,
    )


# =============================================================================
# UI RENDER (removed allowlist logic ALWAYS ON; "new unauthorized" removed)
# =============================================================================
def _render_alerts_ui(
    devices: pd.DataFrame,
    range_label: str,
    allowed_macs: set,
    removed_from_allowlist: List[str],
    added_to_allowlist: List[str],
    mac_to_ip: Dict[str, str],
    mac_to_vendor: Dict[str, str],
    mac_lookup,
    events: pd.DataFrame,
    inventory_total: int,
    inventory_verified: int,
    inventory_unauthorized: int,
    inference_note: Optional[str] = None,
) -> None:
    if devices is None:
        devices = pd.DataFrame()

    if inference_note:
        st.info(inference_note)

    verified_df = devices[devices.get("status", "") == "Verified"].copy() if not devices.empty else pd.DataFrame()
    unauth_df = devices[devices.get("status", "") == "Unauthorized"].copy() if not devices.empty else pd.DataFrame()

    # ---- removed allowlist ALWAYS ON ----
    removed_set = set(removed_from_allowlist)

    last_seen_map = {}
    last_ip_map = {}
    last_host_map = {}
    last_src_map = {}

    if events is not None and not events.empty:
        ev = events.copy()
        ev["ts_dt"] = pd.to_datetime(ev["ts_dt"], errors="coerce")
        ev = ev.dropna(subset=["mac_norm", "ts_dt"])
        if not ev.empty:
            ev["mac_norm"] = ev["mac_norm"].astype(str)
            ev = ev.sort_values("ts_dt", ascending=False).drop_duplicates(subset=["mac_norm"], keep="first")
            last_seen_map = dict(zip(ev["mac_norm"], ev["ts_dt"]))
            if "ip" in ev.columns:
                ip_series = ev["ip"].where(ev["ip"].notna())
                last_ip_map = dict(zip(ev["mac_norm"], ip_series))
            if "host" in ev.columns:
                host_series = ev["host"].where(ev["host"].notna())
                last_host_map = dict(zip(ev["mac_norm"], host_series))
            if "source" in ev.columns:
                src_series = ev["source"].fillna("").astype(str)
                last_src_map = dict(zip(ev["mac_norm"], src_series))

    # Synthetic rows for removed allowlist MACs not currently in devices table (ALWAYS ON)
    if removed_from_allowlist:
        existing = (
            set(devices["mac_norm"].astype(str).tolist())
            if not devices.empty and "mac_norm" in devices.columns
            else set()
        )
        removed_rows = []
        for m in removed_from_allowlist:
            if m in existing:
                continue
            removed_rows.append(
                {
                    "ts_dt": last_seen_map.get(m, pd.NaT),
                    "mac_norm": m,
                    "ip": last_ip_map.get(m) or mac_to_ip.get(m) or pd.NA,
                    "host": last_host_map.get(m) or pd.NA,
                    "seen_in": last_src_map.get(m, ""),
                    "vendor": resolve_vendor(m, mac_to_vendor, mac_lookup),
                    "status": "Unauthorized",
                    "note": "Removed from allowlist",
                }
            )
        if removed_rows:
            devices = pd.concat([devices, pd.DataFrame(removed_rows)], ignore_index=True)

    # annotate existing rows that are removed from allowlist (ALWAYS ON)
    if not devices.empty and "mac_norm" in devices.columns and removed_set:
        if "note" not in devices.columns:
            devices["note"] = ""
        mask = devices["mac_norm"].astype(str).isin(list(removed_set))
        devices.loc[mask, "note"] = devices.loc[mask, "note"].replace("", "Removed from allowlist")

    # Rebuild derived views after augment
    if not devices.empty and "status" in devices.columns:
        verified_df = devices[devices["status"] == "Verified"].copy()
        unauth_df = devices[devices["status"] == "Unauthorized"].copy()
    else:
        verified_df = pd.DataFrame()
        unauth_df = pd.DataFrame()

    st.session_state.setdefault("unauth_macs_view", "Unauthorized")
    view = st.session_state.get("unauth_macs_view", "Unauthorized")

    # =============================================================================
    # CHANGED (FIX): Cards must be scope-aware (Specific Date / Last 30 Days / All Time)
    # Use the filtered + augmented tables for the card numbers.
    # =============================================================================
    def _count_unique_macs(df: pd.DataFrame) -> int:
        if df is None or df.empty or "mac_norm" not in df.columns:
            return 0
        return int(df["mac_norm"].astype(str).nunique())

    scope_total = _count_unique_macs(devices)
    scope_verified = _count_unique_macs(verified_df)
    scope_unauthorized = _count_unique_macs(unauth_df)

    colA, colB, colC = st.columns([1, 1, 1])

    with colA:
        render_alert_metric_card(
            "Total Devices",
            scope_total,
            note=f"Scope: {range_label}",
            key="alert_card_total",
            view_name="Total",
            is_active=view == "Total",
        )

    with colB:
        render_alert_metric_card(
            "Verified Devices",
            scope_verified,
            note="Allowlisted in selected scope",
            key="alert_card_verified",
            view_name="Verified",
            is_active=view == "Verified",
            tone="good",
        )

    with colC:
        render_alert_metric_card(
            "Unauthorized Devices",
            scope_unauthorized,
            note="Outside allowlist in selected scope",
            key="alert_card_unauth",
            view_name="Unauthorized",
            is_active=view == "Unauthorized",
            tone="danger",
        )

    # Priority alerts (removed allowlist still has highest priority)
    if removed_from_allowlist:
        st.error(f"ALLOWLIST ALERT: {len(removed_from_allowlist)} MAC(s) REMOVED from allowlist - {range_label}")
        st.caption("Removed MACs are included in the table below as 'Unauthorized' with note 'Removed from allowlist'.")
    elif scope_unauthorized > 0:
        st.warning(f"Unauthorized devices present: {scope_unauthorized} - {range_label}")
    else:
        st.success(f"System Secure. No unauthorized devices detected - {range_label}")

    if view == "Total":
        section_title = f"All Devices (Latest Seen) - {range_label}"
        df_to_show = devices.copy()
    elif view == "Verified":
        section_title = f"Verified Devices (Latest Seen) - {range_label}"
        df_to_show = verified_df
    else:
        section_title = f"Unauthorized Devices (Latest Seen) - {range_label}"
        df_to_show = unauth_df

    st.markdown(f"<div class='alerts-section-title'>{html.escape(section_title)}</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='alerts-section-sub'>Search, filter by source, and export the current table view.</div>",
        unsafe_allow_html=True,
    )

    if df_to_show is None or df_to_show.empty:
        st.info("No records to display.")
        return

    if "ts_dt" in df_to_show.columns:
        df_to_show["ts_dt"] = pd.to_datetime(df_to_show["ts_dt"], errors="coerce")

    table = build_display_table(df_to_show, include_mac_spoofing=(view == "Unauthorized"))

    if "Last Seen" in table.columns:
        table = table.sort_values("Last Seen", ascending=False, na_position="last")

    source_options = ["All Sources"]
    if "Source" in table.columns:
        source_values = sorted({str(v).strip() for v in table["Source"].dropna().astype(str) if str(v).strip()})
        source_options.extend(source_values)

    view_key = view.lower()
    search_state_key = f"alerts_table_search_applied_{view_key}"
    source_state_key = f"alerts_table_source_applied_{view_key}"
    search_draft_key = f"alerts_table_search_draft_{view_key}"
    source_draft_key = f"alerts_table_source_draft_{view_key}"

    if search_state_key not in st.session_state:
        st.session_state[search_state_key] = ""
    if source_state_key not in st.session_state or st.session_state[source_state_key] not in source_options:
        st.session_state[source_state_key] = "All Sources"

    if search_draft_key not in st.session_state:
        st.session_state[search_draft_key] = str(st.session_state.get(search_state_key, "") or "")
    if source_draft_key not in st.session_state or st.session_state[source_draft_key] not in source_options:
        st.session_state[source_draft_key] = st.session_state[source_state_key]

    with st.form(f"alerts_table_filters_form_{view_key}", clear_on_submit=False):
        toolbar_col1, toolbar_col2, toolbar_col3, toolbar_col4 = st.columns([2.0, 1.15, 0.95, 0.9], vertical_alignment="bottom")
        with toolbar_col1:
            st.text_input(
                "Search table",
                placeholder="MAC, IP, host, vendor",
                key=search_draft_key,
            )
        with toolbar_col2:
            st.selectbox(
                "Source",
                options=source_options,
                key=source_draft_key,
            )
        with toolbar_col3:
            apply_filters = st.form_submit_button("Apply Filters", use_container_width=True)
        with toolbar_col4:
            reset_filters = st.form_submit_button("Reset", use_container_width=True)

    if reset_filters:
        st.session_state[search_state_key] = ""
        st.session_state[source_state_key] = "All Sources"
        st.session_state[search_draft_key] = ""
        st.session_state[source_draft_key] = "All Sources"
        st.rerun()

    if apply_filters:
        st.session_state[search_state_key] = str(st.session_state.get(search_draft_key, "") or "").strip()
        src_choice = str(st.session_state.get(source_draft_key, "All Sources") or "All Sources")
        st.session_state[source_state_key] = src_choice if src_choice in source_options else "All Sources"

    search_query = str(st.session_state.get(search_state_key, "") or "").strip()
    selected_source = str(st.session_state.get(source_state_key, "All Sources") or "All Sources")

    filtered_table = table.copy()

    if selected_source != "All Sources" and "Source" in filtered_table.columns:
        target_source = selected_source.lower()
        filtered_table = filtered_table[
            filtered_table["Source"].astype(str).apply(
                lambda cell: target_source in [x.strip().lower() for x in str(cell).split(",")]
            )
        ]

    if search_query:
        q = search_query.lower()
        search_cols = [
            c
            for c in ["MAC Address", "IP Address", "Vendor", "Host Name", "Source", "Status", "mac spoofing", "Note"]
            if c in filtered_table.columns
        ]
        if search_cols:
            mask = (
                filtered_table[search_cols]
                .fillna("")
                .astype(str)
                .apply(lambda row: row.str.lower().str.contains(q, regex=False), axis=1)
                .any(axis=1)
            )
            filtered_table = filtered_table[mask]

    dl_col1, dl_col2 = st.columns([1.0, 4.0], vertical_alignment="bottom")
    with dl_col1:
        csv_bytes = filtered_table.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download CSV",
            data=csv_bytes,
            file_name=f"alerts_{view.lower()}_devices.csv",
            mime="text/csv",
            width="stretch",
            key=f"alerts_dl_{view.lower()}",
        )

    if filtered_table.empty:
        st.info("No records matched the current filters.")
        return

    with dl_col2:
        row_limit = row_limit_selector(
            key_prefix=f"alerts_table_{view_key}",
            total_rows=len(filtered_table),
            label="Rows shown",
            default_limit=500,
        )
    shown_table = cap_dataframe_rows(filtered_table, row_limit)
    st.markdown(
        f"<div class='alerts-table-meta'>Showing <b>{len(shown_table)}</b> of <b>{len(filtered_table)}</b> filtered rows ({len(table):,} total before filters).</div>",
        unsafe_allow_html=True,
    )
    render_rows_caption(total_rows=len(filtered_table), shown_rows=len(shown_table))
    st.markdown("<div class='alerts-table-shell'>", unsafe_allow_html=True)
    st.dataframe(
        shown_table.style.map(style_status, subset=["Status"]),
        width="stretch",
        hide_index=True,
        column_config={
            "Last Seen": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD HH:mm:ss"),
        },
    )
    st.markdown("</div>", unsafe_allow_html=True)
    return

