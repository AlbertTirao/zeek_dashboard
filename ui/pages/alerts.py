import hashlib
import html
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


@st.cache_data(show_spinner=False, ttl=120)
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
    if events is None or events.empty:
        return events, ""

    tmp = events.copy()
    tmp["ts_dt"] = pd.to_datetime(tmp["ts_dt"], errors="coerce")

    tz = getattr(tmp["ts_dt"].dtype, "tz", None)
    is_tz_aware = tz is not None
    now = pd.Timestamp.now(tz="UTC") if is_tz_aware else pd.Timestamp.now()

    tmp = tmp.dropna(subset=["ts_dt", "mac_norm"])

    if mode == "Last 7 Days":
        cutoff = now - pd.Timedelta(days=7)
        tmp = tmp[tmp["ts_dt"] >= cutoff]
        return tmp, f"Last 7 Days (since {cutoff.strftime('%Y-%m-%d %H:%M')})"

    if mode == "Specific Date" and selected_date:
        start_naive = datetime.strptime(selected_date, "%Y-%m-%d")
        if is_tz_aware:
            start = pd.Timestamp(start_naive, tz="UTC")
            end = start + pd.Timedelta(days=1)
        else:
            start = pd.Timestamp(start_naive)
            end = start + pd.Timedelta(days=1)
        tmp = tmp[(tmp["ts_dt"] >= start) & (tmp["ts_dt"] < end)]
        return tmp, f"Specific Date ({selected_date})"

    # No legacy removed mode: default to Last 7 Days semantics if an unexpected mode is passed.
    cutoff = now - pd.Timedelta(days=7)
    tmp = tmp[tmp["ts_dt"] >= cutoff]
    return tmp, f"Last 7 Days (since {cutoff.strftime('%Y-%m-%d %H:%M')})"


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
def build_display_table(df: pd.DataFrame) -> pd.DataFrame:
    cols = ["ts_dt", "ip", "mac_norm", "vendor", "host", "seen_in", "status"]
    if "note" in df.columns:
        cols.append("note")

    out = df[cols].rename(
        columns={
            "ts_dt": "Last Seen",
            "ip": "IP Address",
            "mac_norm": "MAC Address",
            "vendor": "Vendor",
            "host": "Host Name",
            "seen_in": "Source",
            "status": "Status",
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
    clicked = st.button(" ", key=key, use_container_width=True)

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
    if st.session_state.get("alerts_time_mode") not in ["Last 7 Days", "Specific Date"]:
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
            ["Last 7 Days", "Specific Date"],
            index=["Last 7 Days", "Specific Date"].index(st.session_state["alerts_time_mode"])
            if st.session_state["alerts_time_mode"] in ["Last 7 Days", "Specific Date"]
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
    else:
        cutoff_date = datetime.now().date() - timedelta(days=7)
        for d in available_dates:
            try:
                dd = datetime.strptime(d, "%Y-%m-%d").date()
            except Exception:
                continue
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
) -> None:
    if devices is None:
        devices = pd.DataFrame()

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
    # CHANGED (FIX): Cards must be scope-aware (Specific Date / Last 7 Days)
    # Use the filtered + augmented tables for the card numbers.
    # =============================================================================
    scope_total = int(len(devices)) if devices is not None else 0
    scope_verified = int(len(verified_df))
    scope_unauthorized = int(len(unauth_df))

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
    elif len(unauth_df) > 0:
        st.warning(f"Unauthorized devices present: {len(unauth_df)} - {range_label}")
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

    table = build_display_table(df_to_show)

    if "Last Seen" in table.columns:
        table = table.sort_values("Last Seen", ascending=False, na_position="last")

    source_options = ["All Sources"]
    if "Source" in table.columns:
        source_values = sorted({str(v).strip() for v in table["Source"].dropna().astype(str) if str(v).strip()})
        source_options.extend(source_values)

    toolbar_col1, toolbar_col2, toolbar_col3 = st.columns([2.2, 1.2, 1.1], vertical_alignment="bottom")
    with toolbar_col1:
        search_query = st.text_input(
            "Search table",
            value="",
            placeholder="MAC, IP, host, vendor",
            key=f"alerts_table_search_{view.lower()}",
        ).strip()
    with toolbar_col2:
        selected_source = st.selectbox(
            "Source",
            options=source_options,
            index=0,
            key=f"alerts_table_source_{view.lower()}",
        )

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
        search_cols = [c for c in ["MAC Address", "IP Address", "Vendor", "Host Name", "Source", "Status", "Note"] if c in filtered_table.columns]
        if search_cols:
            mask = (
                filtered_table[search_cols]
                .fillna("")
                .astype(str)
                .apply(lambda row: row.str.lower().str.contains(q, regex=False), axis=1)
                .any(axis=1)
            )
            filtered_table = filtered_table[mask]

    with toolbar_col3:
        csv_bytes = filtered_table.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download CSV",
            data=csv_bytes,
            file_name=f"alerts_{view.lower()}_devices.csv",
            mime="text/csv",
            use_container_width=True,
            key=f"alerts_dl_{view.lower()}",
        )

    if filtered_table.empty:
        st.info("No records matched the current filters.")
        return

    st.markdown(
        f"<div class='alerts-table-meta'>Showing <b>{len(filtered_table)}</b> of <b>{len(table)}</b> rows.</div>",
        unsafe_allow_html=True,
    )
    st.markdown("<div class='alerts-table-shell'>", unsafe_allow_html=True)
    st.dataframe(
        filtered_table.style.map(style_status, subset=["Status"]),
        use_container_width=True,
        hide_index=True,
        column_config={
            "Last Seen": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD HH:mm:ss"),
        },
    )
    st.markdown("</div>", unsafe_allow_html=True)
    return
