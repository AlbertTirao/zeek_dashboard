# ui/pages/anonymization_network.py
# Advanced anonymization network detection (Proxy/VPN/Tor) with fast per-day cache.

from __future__ import annotations

import ipaddress
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence, Set, Tuple

import duckdb
import pandas as pd
import plotly.express as px
import requests
import streamlit as st
import yaml

if TYPE_CHECKING:
    from st_aggrid import GridOptionsBuilder as GridOptionsBuilderType
else:
    GridOptionsBuilderType = Any

try:
    from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode
    HAS_AGGRID = True
except Exception:
    AgGrid = None  # type: ignore
    GridOptionsBuilder = None  # type: ignore
    DataReturnMode = None  # type: ignore
    HAS_AGGRID = False

    class _GridUpdateModeFallback:
        NO_UPDATE = "NO_UPDATE"
        SELECTION_CHANGED = "SELECTION_CHANGED"
        MODEL_CHANGED = "MODEL_CHANGED"
        VALUE_CHANGED = "VALUE_CHANGED"

    GridUpdateMode = _GridUpdateModeFallback()  # type: ignore

    def JsCode(value):  # type: ignore
        return value

DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Fast-load cache strategy aligned with Shadow Apps.
CACHE_VERSION = "anonymization-network-cache-v3-fastload"
CACHE_DIRNAME = "_shadow_cache_anonymization_network"
CACHE_SCORE_VERSION = "anonymization-network-score-v4-vpn-detect"

HTTP_TIMEOUT = 20

UNKNOWN = {
    "",
    "-",
    "unknown",
    "nan",
    "nat",
    "none",
    "null",
    "(empty)",
    "*",
    "<nil>",
    "<na>",
    "n/a",
    "na",
    "no match",
    "nomatch",
    "no-match",
}
PROXY_FEED_URL = "https://free-proxy-list.net/"
PROXY_FEED_TTL_SECONDS = 6 * 60 * 60
TOR_FEED_URL = "https://check.torproject.org/exit-addresses"
TOR_FEED_TTL_SECONDS = 24 * 60 * 60

PROXY_PORTS = {3128, 8080, 8000, 8888, 1080}
VPN_PORTS = {1194, 51820, 500, 4500, 1701, 1723}
TOR_PORTS = {9001, 9030}
VPN_EXPECTED_PROTO = {
    1194: "udp",
    51820: "udp",
    500: "udp",
    4500: "udp",
    1701: "udp",
    1723: "tcp",
}

VPN_HOST_KEYWORDS = (
    "vpn",
    "wireguard",
    "openvpn",
    "ipsec",
    "l2tp",
    "pptp",
    "nordvpn",
    "surfshark",
    "expressvpn",
    "protonvpn",
    "mullvad",
    "outline",
    "tailscale",
    "zerotier",
)
PROXY_HOST_KEYWORDS = (
    "proxy",
    "forward-proxy",
    "forward_proxy",
    "socks",
    "socks5",
    "squid",
    "anonymizer",
    "relay",
    "tunnel",
)
TOR_HOST_KEYWORDS = (
    "torproject",
    "onionoo.torproject.org",
    "check.torproject.org",
    ".onion",
    "tor relay",
)


# Canonical VPN provider labels for display fallback (used when IP2Proxy/provider fields are missing).
# Normalization: we strip all non-alphanumeric characters and lowercase before matching.
VPN_PROVIDER_CANONICAL = [
    ("privateinternetaccess", "Private Internet Access (PIA)"),
    ("nortonsecurevpn", "Norton Secure VPN"),
    ("avastsecurelinevpn", "Avast SecureLine VPN"),
    ("vpnproxymaster", "VPN Proxy Master"),
    ("hotspotshield", "Hotspot Shield"),
    ("expressvpn", "ExpressVPN"),
    ("cyberghost", "CyberGhost"),
    ("surfshark", "Surfshark"),
    ("protonvpn", "Proton VPN"),
    ("windscribe", "Windscribe"),
    ("ipvanish", "IPVanish"),
    ("vyprvpn", "VyprVPN"),
    ("mozillavpn", "Mozilla VPN"),
    ("privadovpn", "PrivadoVPN"),
    ("amneziavpn", "Amnezia VPN"),
    ("turbovpn", "Turbo VPN"),
    ("superzvpn", "Super Z VPN"),
    ("snapvpn", "Snap VPN"),
    ("zenmate", "Zenmate"),
    ("whoervpn", "Whoer VPN"),
    ("witopia", "WiTopia"),
    ("wifimask", "WifiMask"),
    ("bolehvpn", "BolehVPN"),
    ("azirevpn", "AzireVPN"),
    ("cactusvpn", "CactusVPN"),
    ("allsafevpn", "AllSafeVPN"),
    ("cheapvpn", "Cheap VPN"),
    ("bearvpn", "BearVPN"),
    ("airvpn", "AirVPN"),
    ("ivpn", "IVPN"),
    ("mullvad", "Mullvad"),
    ("outline", "Outline"),
    ("tailscale", "Tailscale"),
    ("zerotier", "ZeroTier"),
    ("nordvpn", "NordVPN"),
]
VPN_PROVIDER_CANONICAL = sorted(VPN_PROVIDER_CANONICAL, key=lambda kv: len(kv[0]), reverse=True)


def _normalize_provider_blob(s: pd.Series) -> pd.Series:
    return (
        s.fillna("")
        .astype(str)
        .str.lower()
        .str.replace(r"[^a-z0-9]+", "", regex=True)
    )


def _guess_vpn_provider_from_text(text_blob: pd.Series) -> pd.Series:
    """Return a canonical VPN provider label if any provider keyword is present; else empty string."""
    norm = _normalize_provider_blob(text_blob)
    out = pd.Series("", index=norm.index, dtype="object")
    for key, label in VPN_PROVIDER_CANONICAL:
        m = out.eq("") & norm.str.contains(key, na=False)
        if bool(m.any()):
            out.loc[m] = label
    return out

MIN_FLOW_BYTES = 50 * 1024
TLS_TUNNEL_MIN_BYTES = 250 * 1024
TLS_TUNNEL_MIN_DURATION = 90.0
STABLE_TUNNEL_PAIR_BYTES = 5 * 1024 * 1024


def _compile_keyword_regex(tokens: Sequence[str]) -> re.Pattern[str]:
    cleaned = [str(t).strip().lower() for t in tokens if str(t).strip()]
    if not cleaned:
        return re.compile(r"$^")
    patt = r"(?:^|[.\-_/])(?:" + "|".join(re.escape(t) for t in cleaned) + r")(?:$|[.\-_/])"
    return re.compile(patt, re.IGNORECASE)


VPN_HOST_RE = _compile_keyword_regex(VPN_HOST_KEYWORDS)
PROXY_HOST_RE = _compile_keyword_regex(PROXY_HOST_KEYWORDS)
TOR_HOST_RE = re.compile(
    r"(?:torproject\.org|onionoo\.torproject\.org|check\.torproject\.org|\.onion\b|tor\b)",
    re.IGNORECASE,
)


def parse_tor_feed_ips(text: str, normalize_ip) -> Set[str]:
    ips: Set[str] = set()
    for line in (text or "").splitlines():
        line = str(line).strip()
        if not line.startswith("ExitAddress "):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip_s = normalize_ip(parts[1])
        if ip_s:
            ips.add(ip_s)
    return ips


def compute_tor_match(resp_ip: pd.Series, tor_ips: Set[str]) -> pd.Series:
    return resp_ip.astype(str).isin(tor_ips)


def parse_open_proxy_feed_pairs(text: str, normalize_ip) -> tuple[Set[str], Set[str]]:
    ips: Set[str] = set()
    ip_ports: Set[str] = set()
    matches = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{2,5})\b", text or "")
    for ip_s, port_s in matches:
        ip_norm = normalize_ip(ip_s)
        if not ip_norm:
            continue
        try:
            port_i = int(port_s)
        except Exception:
            continue
        if 1 <= port_i <= 65535:
            ips.add(ip_norm)
            ip_ports.add(f"{ip_norm}:{port_i}")
    return ips, ip_ports


def compute_proxy_matches(
    resp_ip: pd.Series,
    resp_port: pd.Series,
    proxy_ips: Set[str],
    proxy_ip_ports: Set[str],
) -> tuple[pd.Series, pd.Series]:
    dst_ip = resp_ip.astype(str)
    dst_ip_port = dst_ip + ":" + resp_port.astype(str)
    return dst_ip.isin(proxy_ips), dst_ip_port.isin(proxy_ip_ports)


def compute_vpn_port_score_with_proto(resp_port: pd.Series, proto: pd.Series) -> tuple[pd.Series, pd.Series]:
    port = pd.to_numeric(resp_port, errors="coerce").fillna(0).astype(int)
    proto_s = proto.fillna("").astype(str).str.strip().str.lower()
    score = pd.Series(0, index=port.index, dtype="int64")
    reason = pd.Series("", index=port.index, dtype="object")
    for p in VPN_PORTS:
        m = port.eq(int(p))
        if not bool(m.any()):
            continue
        score.loc[m] = 45
        expect = VPN_EXPECTED_PROTO.get(int(p), "")
        if expect:
            mismatch = m & proto_s.ne("") & proto_s.ne(expect)
            if bool(mismatch.any()):
                score.loc[mismatch] = 30
                reason.loc[mismatch] = f"vpn_port {p} (proto mismatch: {proto_s.loc[mismatch]})"
            reason.loc[m & ~mismatch] = f"vpn_port {p}/{expect}"
        else:
            reason.loc[m] = f"vpn_port {p}"
    return score, reason


def compute_vpn_indicator_match(vpn_indicator: pd.Series, unknown_tokens: Set[str]) -> pd.Series:
    indicator = vpn_indicator.fillna("").astype(str).str.strip().str.lower()
    return indicator.ne("") & ~indicator.isin(unknown_tokens)


def compute_vpn_keyword_match(destination_host: pd.Series, ssl_server_name: pd.Series, vpn_host: pd.Series) -> pd.Series:
    host_blob = (
        destination_host.fillna("").astype(str)
        + " "
        + ssl_server_name.fillna("").astype(str)
        + " "
        + vpn_host.fillna("").astype(str)
    ).str.lower()
    return host_blob.str.contains(VPN_HOST_RE, regex=True, na=False)


def compute_proxy_keyword_match(destination_host: pd.Series, http_host: pd.Series, http_uri: pd.Series) -> pd.Series:
    host_blob = (
        destination_host.fillna("").astype(str)
        + " "
        + http_host.fillna("").astype(str)
        + " "
        + http_uri.fillna("").astype(str)
    ).str.lower()
    return host_blob.str.contains(PROXY_HOST_RE, regex=True, na=False)


def compute_tor_keyword_match(destination_host: pd.Series, dns_query: pd.Series) -> pd.Series:
    host_blob = (
        destination_host.fillna("").astype(str)
        + " "
        + dns_query.fillna("").astype(str)
    ).str.lower()
    return host_blob.str.contains(TOR_HOST_RE, regex=True, na=False)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def _write_text(path: Path, content: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except Exception:
        pass


def _read_json(path: Path) -> dict:
    try:
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_json(path: Path, payload: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
    except Exception:
        pass


def cache_dir(parquet_root: Path) -> Path:
    return Path(parquet_root) / CACHE_DIRNAME


def cache_base_path(parquet_root: Path, date_str: str) -> Path:
    return cache_dir(parquet_root) / f"date={date_str}" / "anonymization_network_base.parquet"


def cache_meta_path(parquet_root: Path, date_str: str) -> Path:
    return cache_dir(parquet_root) / f"date={date_str}" / "meta.json"


def cache_scored_path(parquet_root: Path, date_str: str) -> Path:
    return cache_dir(parquet_root) / f"date={date_str}" / "anonymization_network_scored.parquet"


def cache_scored_meta_path(parquet_root: Path, date_str: str) -> Path:
    return cache_dir(parquet_root) / f"date={date_str}" / "scored_meta.json"


def feed_cache_dir(parquet_root: Path, date_str: str) -> Path:
    return cache_dir(parquet_root) / f"date={date_str}" / "feeds"


def _feed_paths(parquet_root: Path, date_str: str) -> Dict[str, Path]:
    d = feed_cache_dir(parquet_root, date_str)
    return {
        "tor_cache": d / "tor_exit_ips.txt",
        "tor_meta": d / "tor_meta.json",
        "proxy_cache": d / "open_proxy_ips.txt",
        "proxy_pair_cache": d / "open_proxy_ip_ports.txt",
        "proxy_meta": d / "proxy_meta.json",
    }


def purge_date_cache_files(parquet_root: Path, date_str: str) -> int:
    removed = 0
    fp = _feed_paths(parquet_root, date_str)
    paths = [
        cache_base_path(parquet_root, date_str),
        cache_meta_path(parquet_root, date_str),
        cache_scored_path(parquet_root, date_str),
        cache_scored_meta_path(parquet_root, date_str),
        fp["tor_cache"],
        fp["tor_meta"],
        fp["proxy_cache"],
        fp["proxy_pair_cache"],
        fp["proxy_meta"],
    ]
    for p in paths:
        try:
            if p.exists():
                p.unlink()
                removed += 1
        except Exception:
            continue
    return removed


def _file_signature(paths: List[Path]) -> List[List[object]]:
    sig: List[List[object]] = []
    for p in paths:
        try:
            st_ = p.stat()
            sig.append([str(p.resolve()), int(st_.st_mtime_ns), int(st_.st_size)])
        except Exception:
            continue
    return sig


def _meta_expected(files_sig: Dict[str, List[List[object]]]) -> dict:
    return {"cache_version": CACHE_VERSION, "files_sig": files_sig}


def _path_sig(path: Path) -> Dict[str, object]:
    try:
        st_ = path.stat()
        return {"path": str(path.resolve()), "mtime_ns": int(st_.st_mtime_ns), "size": int(st_.st_size)}
    except Exception:
        return {"path": str(path), "mtime_ns": 0, "size": 0}


def _scored_meta_expected(
    *,
    base_sig: Dict[str, List[List[object]]],
    feed_sig: dict,
    ip2_sig: dict,
) -> dict:
    return {
        "cache_version": CACHE_SCORE_VERSION,
        "base_files_sig": base_sig,
        "feed_sig": feed_sig,
        "ip2_sig": ip2_sig,
    }


def _normalize_ip(value: object) -> str:
    s = str(value or "").strip()
    if s.lower() in UNKNOWN:
        return ""
    s = s.strip("[]").split("%", 1)[0].strip()
    if not s or s.lower() in UNKNOWN:
        return ""
    try:
        return str(ipaddress.ip_address(s))
    except Exception:
        return ""


def _is_internal_ip(value: object) -> bool:
    ip_s = _normalize_ip(value)
    if not ip_s:
        return False
    try:
        ip = ipaddress.ip_address(ip_s)
        return bool(ip.is_private or ip.is_link_local or ip.is_loopback or ip.is_multicast)
    except Exception:
        return False


def _truthy(s: pd.Series) -> pd.Series:
    return s.fillna("").astype(str).str.strip().str.lower().isin({"1", "t", "true", "yes", "y"})


def _normalize_missing_text(value: object) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    return "" if s.lower() in UNKNOWN else s


def _clean(s: pd.Series) -> pd.Series:
    return s.fillna("").astype(str).map(_normalize_missing_text)


def _nonempty_col_mask(df: pd.DataFrame, col: str) -> bool:
    if col not in df.columns:
        return False
    s = df[col]
    if pd.api.types.is_bool_dtype(s):
        return bool(s.fillna(False).astype(bool).any())
    if pd.api.types.is_numeric_dtype(s):
        return bool(pd.to_numeric(s, errors="coerce").fillna(0).ne(0).any())
    return bool(_clean(s).ne("").any())


def _drop_empty_columns(df: pd.DataFrame) -> tuple[pd.DataFrame, List[str]]:
    if df is None or df.empty:
        return df, []
    keep: List[str] = []
    drop: List[str] = []
    for col in df.columns:
        if _nonempty_col_mask(df, str(col)):
            keep.append(str(col))
        else:
            drop.append(str(col))
    out = df[keep].copy() if keep else df.iloc[:, 0:0].copy()
    return out, drop


def _drop_empty_rows(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    keep_mask = pd.Series(False, index=df.index, dtype=bool)
    for col in df.columns:
        s = df[col]
        if pd.api.types.is_bool_dtype(s):
            keep_mask = keep_mask | s.fillna(False).astype(bool)
        elif pd.api.types.is_numeric_dtype(s):
            keep_mask = keep_mask | pd.to_numeric(s, errors="coerce").fillna(0).ne(0)
        else:
            keep_mask = keep_mask | _clean(s).ne("")
    return df[keep_mask].copy()


def _drop_empty_rows_and_columns(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    out = _drop_empty_rows(df)
    base_cols = [str(c) for c in out.columns]
    preserve_cols = [
        c
        for c in base_cols
        if c in {"#", "_row_id", "Allow", "Allowlisted"} or c.startswith("_allow_")
    ]
    candidate_cols = [c for c in base_cols if c not in preserve_cols]
    if candidate_cols:
        candidate_df = out[candidate_cols].copy()
        candidate_df, _ = _drop_empty_columns(candidate_df)
        keep_set = set(candidate_df.columns).union(set(preserve_cols))
    else:
        keep_set = set(preserve_cols)
    keep_cols = [c for c in base_cols if c in keep_set]
    out = out[keep_cols].copy() if keep_cols else out.iloc[:, 0:0].copy()
    out = _drop_empty_rows(out)
    return out


def _first_nonempty(s: pd.Series) -> str:
    for v in s:
        x = str(v or "").strip()
        if x and x.lower() not in UNKNOWN:
            return x
    return ""


def _to_datetime(df: pd.DataFrame, col: str = "ts") -> pd.DataFrame:
    out = df.copy()
    if col not in out.columns:
        out[col] = pd.NaT
        return out
    raw = out[col].fillna("").astype(str).str.strip()
    num = pd.to_numeric(raw, errors="coerce")
    if len(num) and float(num.notna().mean()) >= 0.8:
        out[col] = pd.to_datetime(num, errors="coerce", unit="s")
    else:
        out[col] = pd.to_datetime(raw, errors="coerce")
    return out


def _append_reason(base: pd.Series, mask: pd.Series, reason: str) -> pd.Series:
    if not bool(mask.any()):
        return base
    idx = base.index[mask]
    prior = base.loc[idx].astype(str)
    base.loc[idx] = prior.where(prior.eq(""), prior + "; ") + str(reason)
    return base


def _append_reason_series(base: pd.Series, mask: pd.Series, extra: pd.Series) -> pd.Series:
    if not bool(mask.any()):
        return base
    idx = base.index[mask]
    prior = base.loc[idx].astype(str)
    add = extra.loc[idx].fillna("").astype(str)
    add = add.where(add.ne(""), "-")
    base.loc[idx] = prior.where(prior.eq(""), prior + "; ") + add
    return base


def _is_fresh(meta_path: Path, ttl_seconds: int) -> bool:
    meta = _read_json(meta_path)
    ts = float(meta.get("fetched_at_epoch", 0) or 0)
    return ts > 0 and (time.time() - ts) <= float(ttl_seconds)


def _fmt_meta_ts(meta: dict) -> str:
    ts = float(meta.get("fetched_at_epoch", 0) or 0)
    if ts <= 0:
        return "-"
    try:
        return pd.to_datetime(ts, unit="s", utc=True).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "-"


def _download_text(url: str) -> str:
    headers = {"User-Agent": "Zeek-Dashboard-Shadow-Tunnels/1.0"}
    resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()
    return resp.text


def _load_cached_ip_set(path: Path) -> Set[str]:
    out: Set[str] = set()
    for line in _read_text(path).splitlines():
        ip_s = _normalize_ip(line.strip())
        if ip_s:
            out.add(ip_s)
    return out


def _save_ip_set(path: Path, values: Set[str]) -> None:
    _write_text(path, "\n".join(sorted(values)))


def _load_cached_str_set(path: Path) -> Set[str]:
    out: Set[str] = set()
    for line in _read_text(path).splitlines():
        s = str(line).strip()
        if s:
            out.add(s)
    return out


def _save_str_set(path: Path, values: Set[str]) -> None:
    _write_text(path, "\n".join(sorted(values)))


def _refresh_feed(
    *,
    name: str,
    url: str,
    cache_path: Path,
    meta_path: Path,
    ttl_seconds: int,
    parser,
    force: bool,
) -> dict:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cached_ips = _load_cached_ip_set(cache_path) if cache_path.exists() else set()
    cached_meta = _read_json(meta_path)
    if not force and cache_path.exists() and cached_ips and _is_fresh(meta_path, ttl_seconds):
        return {
            "name": name,
            "status": "cache-fresh",
            "ips": sorted(cached_ips),
            "count": int(len(cached_ips)),
            "updated_at": _fmt_meta_ts(cached_meta),
            "error": "",
        }
    try:
        fresh_text = _download_text(url)
        fresh_ips = set(parser(fresh_text))
        if not fresh_ips:
            raise ValueError("Feed parsed successfully but returned zero IPs.")
        _save_ip_set(cache_path, fresh_ips)
        meta = {"name": name, "url": url, "fetched_at_epoch": float(time.time()), "count": int(len(fresh_ips))}
        _write_json(meta_path, meta)
        return {
            "name": name,
            "status": "live",
            "ips": sorted(fresh_ips),
            "count": int(len(fresh_ips)),
            "updated_at": _fmt_meta_ts(meta),
            "error": "",
        }
    except Exception as exc:
        if cached_ips:
            return {
                "name": name,
                "status": "cache-stale",
                "ips": sorted(cached_ips),
                "count": int(len(cached_ips)),
                "updated_at": _fmt_meta_ts(cached_meta),
                "error": str(exc),
            }
        return {"name": name, "status": "unavailable", "ips": [], "count": 0, "updated_at": "-", "error": str(exc)}


def load_feeds(parquet_root: Path, date_str: str, force: bool = False) -> Dict[str, dict]:
    root = Path(parquet_root)
    paths = _feed_paths(root, str(date_str))
    tor = _refresh_feed(
        name="Tor exits",
        url=TOR_FEED_URL,
        cache_path=paths["tor_cache"],
        meta_path=paths["tor_meta"],
        ttl_seconds=TOR_FEED_TTL_SECONDS,
        parser=lambda text: parse_tor_feed_ips(text, _normalize_ip),
        force=force,
    )

    # Open proxy feed keeps both IP and IP:PORT sets for more accurate matching.
    paths["proxy_cache"].parent.mkdir(parents=True, exist_ok=True)
    cached_ips = _load_cached_ip_set(paths["proxy_cache"]) if paths["proxy_cache"].exists() else set()
    cached_pairs = _load_cached_str_set(paths["proxy_pair_cache"]) if paths["proxy_pair_cache"].exists() else set()
    cached_meta = _read_json(paths["proxy_meta"])
    if (not force) and paths["proxy_cache"].exists() and paths["proxy_pair_cache"].exists() and cached_ips and _is_fresh(paths["proxy_meta"], PROXY_FEED_TTL_SECONDS):
        proxy = {
            "name": "Open proxies",
            "status": "cache-fresh",
            "ips": sorted(cached_ips),
            "ip_ports": sorted(cached_pairs),
            "count": int(len(cached_ips)),
            "pair_count": int(len(cached_pairs)),
            "updated_at": _fmt_meta_ts(cached_meta),
            "error": "",
        }
    else:
        try:
            raw = _download_text(PROXY_FEED_URL)
            fresh_ips, fresh_pairs = parse_open_proxy_feed_pairs(raw, _normalize_ip)
            if not fresh_ips:
                raise ValueError("Feed parsed successfully but returned zero IPs.")
            _save_ip_set(paths["proxy_cache"], fresh_ips)
            _save_str_set(paths["proxy_pair_cache"], fresh_pairs)
            meta = {
                "name": "Open proxies",
                "url": PROXY_FEED_URL,
                "fetched_at_epoch": float(time.time()),
                "count": int(len(fresh_ips)),
                "pair_count": int(len(fresh_pairs)),
            }
            _write_json(paths["proxy_meta"], meta)
            proxy = {
                "name": "Open proxies",
                "status": "live",
                "ips": sorted(fresh_ips),
                "ip_ports": sorted(fresh_pairs),
                "count": int(len(fresh_ips)),
                "pair_count": int(len(fresh_pairs)),
                "updated_at": _fmt_meta_ts(meta),
                "error": "",
            }
        except Exception as exc:
            if cached_ips:
                proxy = {
                    "name": "Open proxies",
                    "status": "cache-stale",
                    "ips": sorted(cached_ips),
                    "ip_ports": sorted(cached_pairs),
                    "count": int(len(cached_ips)),
                    "pair_count": int(len(cached_pairs)),
                    "updated_at": _fmt_meta_ts(cached_meta),
                    "error": str(exc),
                }
            else:
                proxy = {
                    "name": "Open proxies",
                    "status": "unavailable",
                    "ips": [],
                    "ip_ports": [],
                    "count": 0,
                    "pair_count": 0,
                    "updated_at": "-",
                    "error": str(exc),
                }
    return {"tor": tor, "proxy": proxy}


def _pick_column(columns: Sequence[str], candidates: Sequence[str]) -> Optional[str]:
    low = {str(c).strip().lower(): str(c) for c in columns}
    for cand in candidates:
        if cand.lower() in low:
            return low[cand.lower()]
    return None


def _to_bool(s: pd.Series) -> pd.Series:
    low = s.fillna("").astype(str).str.strip().str.lower()
    num = pd.to_numeric(low, errors="coerce").fillna(0)
    return low.isin({"1", "true", "t", "yes", "y"}) | num.gt(0)


@st.cache_data(show_spinner=False)
def _load_ip2proxy_lookup_cached(path_str: str, mtime_ns: int, size_bytes: int) -> pd.DataFrame:
    _ = (mtime_ns, size_bytes)
    path = Path(path_str)
    raw = pd.read_parquet(path) if path.suffix.lower() == ".parquet" else pd.read_csv(path)
    if raw.empty:
        return pd.DataFrame(columns=["ip", "ip2proxy_proxy_type", "ip2proxy_provider", "ip2proxy_is_vpn", "ip2proxy_is_tor", "ip2proxy_is_pub"])

    ip_col = _pick_column(raw.columns, ["ip", "ip_address", "id.resp_h", "query", "dst_ip", "destination_ip"])
    if not ip_col:
        return pd.DataFrame(columns=["ip", "ip2proxy_proxy_type", "ip2proxy_provider", "ip2proxy_is_vpn", "ip2proxy_is_tor", "ip2proxy_is_pub"])

    type_col = _pick_column(raw.columns, ["proxy_type", "type", "ip2proxy_type"])
    provider_col = _pick_column(raw.columns, ["provider", "proxy_provider", "proxy_provider_name", "isp"])
    vpn_col = _pick_column(raw.columns, ["is_vpn", "vpn"])
    tor_col = _pick_column(raw.columns, ["is_tor", "tor"])
    pub_col = _pick_column(raw.columns, ["is_pub", "is_proxy", "pub"])

    out = pd.DataFrame(index=raw.index)
    out["ip"] = raw[ip_col].astype(str).map(_normalize_ip)
    out["ip2proxy_proxy_type"] = raw[type_col].astype(str).str.strip().str.upper() if type_col else ""
    out["ip2proxy_provider"] = raw[provider_col].astype(str).str.strip() if provider_col else ""
    out["ip2proxy_is_vpn"] = _to_bool(raw[vpn_col]) if vpn_col else out["ip2proxy_proxy_type"].eq("VPN")
    out["ip2proxy_is_tor"] = _to_bool(raw[tor_col]) if tor_col else out["ip2proxy_proxy_type"].eq("TOR")
    out["ip2proxy_is_pub"] = (
        _to_bool(raw[pub_col]) if pub_col else out["ip2proxy_proxy_type"].isin({"PUB", "WEB", "RES", "DCH", "SES"})
    )
    out = out[out["ip"].ne("")].copy()
    out = out.drop_duplicates(subset=["ip"], keep="first")
    return out


def load_ip2proxy_lookup() -> Tuple[pd.DataFrame, str, dict]:
    candidates: List[Path] = []
    env = str(os.getenv("IP2PROXY_LOOKUP_FILE", "")).strip()
    if env:
        candidates.append(Path(env))
    candidates.extend(
        [
            PROJECT_ROOT / "data" / "ip2proxy_lookup.parquet",
            PROJECT_ROOT / "data" / "ip2proxy_lookup.csv",
            PROJECT_ROOT / "data" / "ip2proxy_cache.parquet",
            PROJECT_ROOT / "data" / "ip2proxy_cache.csv",
        ]
    )
    for path in candidates:
        if not path.exists():
            continue
        try:
            st_info = path.stat()
            if st_info.st_size > 400 * 1024 * 1024:
                return (
                    pd.DataFrame(columns=["ip", "ip2proxy_proxy_type", "ip2proxy_provider", "ip2proxy_is_vpn", "ip2proxy_is_tor", "ip2proxy_is_pub"]),
                    f"IP2Proxy file too large for in-memory merge: {path.name}",
                    _path_sig(path),
                )
            df = _load_ip2proxy_lookup_cached(str(path.resolve()), int(st_info.st_mtime_ns), int(st_info.st_size))
            return df, f"Loaded IP2Proxy lookup: {path.name} ({len(df):,} rows)", _path_sig(path)
        except Exception as exc:
            return (
                pd.DataFrame(columns=["ip", "ip2proxy_proxy_type", "ip2proxy_provider", "ip2proxy_is_vpn", "ip2proxy_is_tor", "ip2proxy_is_pub"]),
                f"IP2Proxy load failed ({path.name}): {exc}",
                _path_sig(path),
            )
    return (
        pd.DataFrame(columns=["ip", "ip2proxy_proxy_type", "ip2proxy_provider", "ip2proxy_is_vpn", "ip2proxy_is_tor", "ip2proxy_is_pub"]),
        "No local IP2Proxy file found (data/ip2proxy_lookup.parquet or env IP2PROXY_LOOKUP_FILE).",
        {"path": "", "mtime_ns": 0, "size": 0},
    )


def load_anonymization_allowlist() -> tuple[dict, str]:
    candidates = [
        PROJECT_ROOT / "config" / "anonymization_network_allowlist.yaml",
        PROJECT_ROOT / "config" / "anonymization_allowlist.yaml",
        PROJECT_ROOT / "data" / "anonymization_allowlist.yaml",
    ]
    base = {
        "source_ips": set(),
        "source_macs": set(),
        "destination_ips": set(),
        "destination_hosts": set(),
    }
    for p in candidates:
        if not p.exists():
            continue
        try:
            loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            for key in ["source_ips", "source_macs", "destination_ips", "destination_hosts"]:
                values = loaded.get(key) or []
                if isinstance(values, str):
                    values = [values]
                base[key].update(
                    {
                        str(v).strip().lower()
                        for v in values
                        if str(v).strip()
                    }
                )
            return base, f"Allowlist loaded: {p.name}"
        except Exception as exc:
            return base, f"Allowlist read failed ({p.name}): {exc}"
    return base, "Allowlist file not found (config/anonymization_network_allowlist.yaml)"


ANONYMIZATION_ALLOWLIST_KEYS = (
    "source_ips",
    "source_macs",
    "destination_ips",
    "destination_hosts",
)


def _anonymization_allowlist_candidates() -> List[Path]:
    return [
        PROJECT_ROOT / "config" / "anonymization_network_allowlist.yaml",
        PROJECT_ROOT / "config" / "anonymization_allowlist.yaml",
        PROJECT_ROOT / "data" / "anonymization_allowlist.yaml",
    ]


def _resolve_anonymization_allowlist_path_for_write() -> Path:
    candidates = _anonymization_allowlist_candidates()
    for p in candidates:
        if p.exists():
            return p
    return candidates[0]


def _normalize_allowlist_entry(key: str, value: object) -> str:
    k = str(key or "").strip()
    if k not in ANONYMIZATION_ALLOWLIST_KEYS:
        return ""

    if k in {"source_ips", "destination_ips"}:
        return _normalize_ip(value)

    raw = str(value or "").strip().lower()
    if not raw or raw in UNKNOWN:
        return ""

    if k == "destination_hosts":
        if raw.startswith("*."):
            base = raw[2:].strip(".")
            return f"*.{base}" if base else ""
        return raw.strip(".")

    # source_macs
    return raw


def _coerce_checkbox_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def add_anonymization_allowlist_entries(entries: Dict[str, object]) -> tuple[bool, str]:
    normalized_to_add: Dict[str, str] = {}
    for key in ANONYMIZATION_ALLOWLIST_KEYS:
        norm = _normalize_allowlist_entry(key, entries.get(key))
        if norm:
            normalized_to_add[key] = norm
    if not normalized_to_add:
        return False, "No valid allowlist entries selected."

    path = _resolve_anonymization_allowlist_path_for_write()
    try:
        path_label = str(path.resolve())
    except Exception:
        path_label = str(path)
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    except Exception:
        loaded = {}
    if not isinstance(loaded, dict):
        loaded = {}

    merged_lists: Dict[str, List[str]] = {}
    added = 0
    for key in ANONYMIZATION_ALLOWLIST_KEYS:
        cur = loaded.get(key, [])
        if isinstance(cur, str):
            cur = [cur]
        if not isinstance(cur, list):
            cur = []
        dedup: List[str] = []
        seen: Set[str] = set()
        for item in cur:
            norm = _normalize_allowlist_entry(key, item)
            if not norm:
                continue
            lk = norm.lower()
            if lk in seen:
                continue
            seen.add(lk)
            dedup.append(norm)

        new_val = normalized_to_add.get(key, "")
        if new_val and new_val.lower() not in seen:
            dedup.append(new_val)
            seen.add(new_val.lower())
            added += 1

        merged_lists[key] = dedup

    out = dict(loaded)
    for key in ANONYMIZATION_ALLOWLIST_KEYS:
        out[key] = merged_lists.get(key, [])

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            yaml.safe_dump(out, f, sort_keys=False)
    except Exception as exc:
        return False, f"Failed to update allowlist ({path_label}): {exc}"

    if added <= 0:
        return True, f"Selected values are already allowlisted in {path_label}."
    return True, f"Added {added} allowlist entr{'y' if added == 1 else 'ies'} to {path_label}."


def _open_anonymization_allow_dialog(candidate: dict) -> None:
    st.session_state["anonym_net_allow_candidate"] = candidate
    st.session_state["anonym_net_allow_dialog_open"] = True


def _close_anonymization_allow_dialog() -> None:
    st.session_state["anonym_net_allow_dialog_open"] = False
    st.session_state.pop("anonym_net_allow_candidate", None)


def _bump_anonymization_table_nonce() -> None:
    st.session_state["anonym_net_table_nonce"] = int(st.session_state.get("anonym_net_table_nonce", 0)) + 1


@st.dialog("Allowlist Network Entry", width="small", dismissible=False)
def show_anonymization_allow_dialog() -> None:
    candidate = st.session_state.get("anonym_net_allow_candidate") or {}
    row_key = re.sub(r"[^A-Za-z0-9_]+", "_", str(candidate.get("_allow_key") or "row"))[:120] or "row"
    write_path = _resolve_anonymization_allowlist_path_for_write()
    try:
        write_label = str(write_path.resolve())
    except Exception:
        write_label = str(write_path)

    source_ip = _normalize_allowlist_entry("source_ips", candidate.get("source_ip"))
    source_mac = _normalize_allowlist_entry("source_macs", candidate.get("source_mac"))
    destination_ip = _normalize_allowlist_entry("destination_ips", candidate.get("destination_ip"))
    destination_host = _normalize_allowlist_entry("destination_hosts", candidate.get("destination_host"))

    has_any = any([source_ip, source_mac, destination_ip, destination_host])
    st.markdown("Confirm allowlisting for this anonymization event.")
    st.markdown(f"- Source IP: `{source_ip or '-'}`")
    st.markdown(f"- Source MAC: `{source_mac or '-'}`")
    st.markdown(f"- Destination IP: `{destination_ip or '-'}`")
    st.markdown(f"- Destination Host: `{destination_host or '-'}`")
    st.caption(f"Selected values will be written to `{write_label}`.")

    sel_source_ip = st.checkbox(
        "Add Source IP",
        value=bool(source_ip),
        disabled=(not bool(source_ip)),
        key=f"anonym_net_allow_sel_source_ip_{row_key}",
    )
    sel_source_mac = st.checkbox(
        "Add Source MAC",
        value=False,
        disabled=(not bool(source_mac)),
        key=f"anonym_net_allow_sel_source_mac_{row_key}",
    )
    sel_destination_ip = st.checkbox(
        "Add Destination IP",
        value=bool(destination_ip),
        disabled=(not bool(destination_ip)),
        key=f"anonym_net_allow_sel_destination_ip_{row_key}",
    )
    sel_destination_host = st.checkbox(
        "Add Destination Host",
        value=bool(destination_host),
        disabled=(not bool(destination_host)),
        key=f"anonym_net_allow_sel_destination_host_{row_key}",
    )
    selected_any = bool(sel_source_ip or sel_source_mac or sel_destination_ip or sel_destination_host)

    c1, c2 = st.columns(2)
    with c1:
        if st.button(
            "Allowlist Selected",
            type="primary",
            use_container_width=True,
            disabled=(not has_any or not selected_any),
            key="anonym_net_allow_confirm_btn",
        ):
            payload: Dict[str, object] = {}
            if sel_source_ip:
                payload["source_ips"] = source_ip
            if sel_source_mac:
                payload["source_macs"] = source_mac
            if sel_destination_ip:
                payload["destination_ips"] = destination_ip
            if sel_destination_host:
                payload["destination_hosts"] = destination_host
            ok, msg = add_anonymization_allowlist_entries(payload)
            if ok:
                _close_anonymization_allow_dialog()
                _bump_anonymization_table_nonce()
                st.success(msg)
                st.rerun()
            st.error(msg)
    with c2:
        if st.button("Cancel", use_container_width=True, key="anonym_net_allow_cancel_btn"):
            _close_anonymization_allow_dialog()
            _bump_anonymization_table_nonce()
            st.rerun()


def _host_allowlist_match(host_s: pd.Series, patterns: Set[str]) -> pd.Series:
    host = _clean(host_s).str.lower().str.strip(".")
    if not patterns:
        return pd.Series(False, index=host.index, dtype=bool)
    mask = pd.Series(False, index=host.index, dtype=bool)
    for raw in patterns:
        p = str(raw or "").strip().lower()
        if not p:
            continue
        if p.startswith("*."):
            suffix = p[1:]
            mask = mask | host.str.endswith(suffix, na=False) | host.eq(p[2:])
        else:
            mask = mask | host.eq(p) | host.str.endswith("." + p, na=False)
    return mask


def compute_allowlist_mask(df: pd.DataFrame, allowlist: dict) -> pd.Series:
    if df is None or df.empty:
        return pd.Series(dtype=bool)
    source_ips = set(allowlist.get("source_ips") or set())
    source_macs = set(allowlist.get("source_macs") or set())
    destination_ips = set(allowlist.get("destination_ips") or set())
    destination_hosts = set(allowlist.get("destination_hosts") or set())

    src_ip_hit = _clean(df.get("id.orig_h", pd.Series(index=df.index))).str.lower().isin(source_ips) if source_ips else pd.Series(False, index=df.index, dtype=bool)
    src_mac_hit = _clean(df.get("mac", pd.Series(index=df.index))).str.lower().isin(source_macs) if source_macs else pd.Series(False, index=df.index, dtype=bool)
    dst_ip_hit = _clean(df.get("id.resp_h", pd.Series(index=df.index))).str.lower().isin(destination_ips) if destination_ips else pd.Series(False, index=df.index, dtype=bool)
    dst_host_hit = _host_allowlist_match(df.get("Destination_Host", pd.Series(index=df.index)), destination_hosts) if destination_hosts else pd.Series(False, index=df.index, dtype=bool)
    return (src_ip_hit | src_mac_hit | dst_ip_hit | dst_host_hit).fillna(False).astype(bool)


@st.cache_resource
def _duck_conn():
    con = duckdb.connect(database=":memory:")
    try:
        con.execute("SET memory_limit='4GB'")
    except Exception:
        pass
    try:
        con.execute("SET threads TO 4")
    except Exception:
        pass
    return con


def _sql_list(paths: Sequence[Path]) -> str:
    items: List[str] = []
    for p in paths:
        items.append("'" + p.resolve().as_posix().replace("'", "''") + "'")
    return "[" + ",".join(items) + "]"


def _duck_read(paths: List[Path]) -> pd.DataFrame:
    if not paths:
        return pd.DataFrame()
    con = _duck_conn()
    try:
        return con.execute(f"SELECT * FROM read_parquet({_sql_list(paths)}, union_by_name=TRUE)").fetchdf()
    except Exception:
        dfs: List[pd.DataFrame] = []
        for p in paths:
            try:
                dfs.append(pd.read_parquet(p))
            except Exception:
                continue
        return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()


@st.cache_data(show_spinner=False)
def get_available_dates(parquet_root: Path) -> List[str]:
    root = Path(parquet_root)
    if not root.exists():
        return []
    out: List[str] = []
    for p in root.iterdir():
        if p.is_dir() and DATE_DIR_RE.match(p.name):
            out.append(p.name)
    return sorted(out, reverse=True)


def _collect_date_files(date_dir: Path) -> Dict[str, List[Path]]:
    buckets: Dict[str, List[Path]] = {
        "conn": [],
        "http": [],
        "ssl": [],
        "dns": [],
        "vpn": [],
        "tunnel": [],
        "x509": [],
    }
    if not date_dir.exists():
        return buckets
    for f in date_dir.rglob("*.parquet"):
        n = f.name.lower()
        if n.startswith("conn"):
            buckets["conn"].append(f)
        elif n.startswith("http"):
            buckets["http"].append(f)
        elif n.startswith("ssl"):
            buckets["ssl"].append(f)
        elif n.startswith("dns"):
            buckets["dns"].append(f)
        elif n.startswith("vpn_detect"):
            buckets["vpn"].append(f)
        elif n.startswith("tunnel"):
            buckets["tunnel"].append(f)
        elif n.startswith("x509"):
            buckets["x509"].append(f)
    for k in buckets:
        buckets[k] = sorted(buckets[k])
    return buckets


def _date_sig_map(files: Dict[str, List[Path]]) -> Dict[str, List[List[object]]]:
    return {
        "conn": _file_signature(files.get("conn", [])),
        "http": _file_signature(files.get("http", [])),
        "ssl": _file_signature(files.get("ssl", [])),
        "dns": _file_signature(files.get("dns", [])),
        "vpn": _file_signature(files.get("vpn", [])),
        "tunnel": _file_signature(files.get("tunnel", [])),
        "x509": _file_signature(files.get("x509", [])),
    }


def _date_sig_key(sig_map: Dict[str, List[List[object]]]) -> Tuple[Tuple[str, str, int, int], ...]:
    flat: List[Tuple[str, str, int, int]] = []
    for bucket in sorted(sig_map.keys()):
        for row in sig_map.get(bucket, []):
            try:
                path_s = str(row[0])
                mtime_ns = int(row[1])
                size_b = int(row[2])
            except Exception:
                continue
            flat.append((bucket, path_s, mtime_ns, size_b))
    return tuple(flat)


def _prepare_conn(df: pd.DataFrame) -> pd.DataFrame:
    cols = ["ts", "uid", "id.orig_h", "id.resp_h", "id.resp_p", "proto", "service", "orig_ip_bytes", "resp_ip_bytes", "duration", "local_orig", "orig_l2_addr"]
    c = df.copy() if df is not None else pd.DataFrame()
    for col in cols:
        if col not in c.columns:
            c[col] = ""
    c = c[cols].copy()
    c = _to_datetime(c, "ts")
    c = c.dropna(subset=["ts"])
    c["uid"] = _clean(c["uid"])
    c["id.orig_h"] = _clean(c["id.orig_h"]).map(_normalize_ip)
    c["id.resp_h"] = _clean(c["id.resp_h"]).map(_normalize_ip)
    c["id.resp_p"] = pd.to_numeric(c["id.resp_p"], errors="coerce").fillna(0).astype(int)
    c["proto"] = _clean(c["proto"]).str.lower()
    c["service"] = _clean(c["service"]).str.lower()
    c["orig_ip_bytes"] = pd.to_numeric(c["orig_ip_bytes"], errors="coerce").fillna(0)
    c["resp_ip_bytes"] = pd.to_numeric(c["resp_ip_bytes"], errors="coerce").fillna(0)
    c["duration"] = pd.to_numeric(c["duration"], errors="coerce").fillna(0)
    c["mac"] = _clean(c["orig_l2_addr"]).str.lower()

    c = c[c["id.resp_h"].ne("")].copy()
    orig_internal = c["id.orig_h"].map(_is_internal_ip)
    resp_internal = c["id.resp_h"].map(_is_internal_ip)
    outbound = (orig_internal | _truthy(c["local_orig"])) & (~resp_internal)
    return c[outbound].copy()


def _prepare_http(df: pd.DataFrame) -> pd.DataFrame:
    cols = ["uid", "ts", "method", "host", "uri"]
    h = df.copy() if df is not None else pd.DataFrame()
    for col in cols:
        if col not in h.columns:
            h[col] = ""
    h = h[cols].copy()
    h = _to_datetime(h, "ts")
    h["uid"] = _clean(h["uid"])
    h = h[h["uid"].ne("")]
    h["method"] = _clean(h["method"]).str.upper()
    h["host"] = _clean(h["host"]).str.lower().str.strip(".")
    h["uri"] = _clean(h["uri"])
    if h.empty:
        return pd.DataFrame(columns=["uid", "http_method", "http_host", "http_uri"])
    agg = h.sort_values("ts", ascending=False).groupby("uid", as_index=False).agg({"method": _first_nonempty, "host": _first_nonempty, "uri": _first_nonempty})
    return agg.rename(columns={"method": "http_method", "host": "http_host", "uri": "http_uri"})


def _prepare_ssl(df: pd.DataFrame) -> pd.DataFrame:
    cols = ["uid", "ts", "server_name", "next_protocol", "version", "cipher", "resumed"]
    s = df.copy() if df is not None else pd.DataFrame()
    for col in cols:
        if col not in s.columns:
            s[col] = ""
    s = s[cols].copy()
    s = _to_datetime(s, "ts")
    s["uid"] = _clean(s["uid"])
    s = s[s["uid"].ne("")]
    s["server_name"] = _clean(s["server_name"]).str.lower().str.strip(".")
    s["next_protocol"] = _clean(s["next_protocol"]).str.lower()
    s["version"] = _clean(s["version"]).str.lower()
    s["cipher"] = _clean(s["cipher"]).str.lower()
    s["resumed"] = _clean(s["resumed"]).str.lower()
    if s.empty:
        return pd.DataFrame(columns=["uid", "ssl_server_name", "ssl_alpn", "ssl_version", "ssl_cipher", "ssl_resumed"])
    agg = s.sort_values("ts", ascending=False).groupby("uid", as_index=False).agg(
        {
            "server_name": _first_nonempty,
            "next_protocol": _first_nonempty,
            "version": _first_nonempty,
            "cipher": _first_nonempty,
            "resumed": _first_nonempty,
        }
    )
    return agg.rename(
        columns={
            "server_name": "ssl_server_name",
            "next_protocol": "ssl_alpn",
            "version": "ssl_version",
            "cipher": "ssl_cipher",
            "resumed": "ssl_resumed",
        }
    )


def _prepare_vpn(df: pd.DataFrame) -> pd.DataFrame:
    cols = ["uid", "ts", "indicator", "host"]
    v = df.copy() if df is not None else pd.DataFrame()
    for col in cols:
        if col not in v.columns:
            v[col] = ""
    v = v[cols].copy()
    v = _to_datetime(v, "ts")
    v["uid"] = _clean(v["uid"])
    v = v[v["uid"].ne("")]
    v["indicator"] = _clean(v["indicator"]).str.lower()
    v["host"] = _clean(v["host"]).str.lower().str.strip(".")
    if v.empty:
        return pd.DataFrame(columns=["uid", "vpn_indicator", "vpn_host"])
    agg = v.sort_values("ts", ascending=False).groupby("uid", as_index=False).agg({"indicator": _first_nonempty, "host": _first_nonempty})
    return agg.rename(columns={"indicator": "vpn_indicator", "host": "vpn_host"})


def _prepare_dns(df: pd.DataFrame) -> pd.DataFrame:
    cols = ["ts", "id.orig_h", "query"]
    d = df.copy() if df is not None else pd.DataFrame()
    for col in cols:
        if col not in d.columns:
            d[col] = ""
    d = d[cols].copy()
    d = _to_datetime(d, "ts")
    d = d.dropna(subset=["ts"])
    d["id.orig_h"] = _clean(d["id.orig_h"]).map(_normalize_ip)
    d["query"] = _clean(d["query"]).str.lower().str.strip(".")
    d = d[d["id.orig_h"].ne("")].copy()
    if d.empty:
        return pd.DataFrame(
            columns=[
                "id.orig_h",
                "dns_keyword_hit",
                "dns_proxy_hit",
                "dns_vpn_hit",
                "dns_tor_hit",
                "dns_keyword_count",
                "dns_keyword_query",
            ]
        )

    d["dns_proxy_hit"] = d["query"].str.contains(PROXY_HOST_RE, regex=True, na=False)
    d["dns_vpn_hit"] = d["query"].str.contains(VPN_HOST_RE, regex=True, na=False)
    d["dns_tor_hit"] = d["query"].str.contains(TOR_HOST_RE, regex=True, na=False)
    d["dns_keyword_hit"] = d["dns_proxy_hit"] | d["dns_vpn_hit"] | d["dns_tor_hit"]
    keyword_latest = (
        d[d["dns_keyword_hit"]]
        .sort_values("ts", ascending=False)
        .drop_duplicates(subset=["id.orig_h"], keep="first")[["id.orig_h", "query"]]
        .rename(columns={"query": "dns_keyword_query"})
    )
    agg = d.groupby("id.orig_h", as_index=False).agg(
        dns_keyword_hit=("dns_keyword_hit", "max"),
        dns_proxy_hit=("dns_proxy_hit", "max"),
        dns_vpn_hit=("dns_vpn_hit", "max"),
        dns_tor_hit=("dns_tor_hit", "max"),
        dns_keyword_count=("dns_keyword_hit", "sum"),
    )
    agg = agg.merge(keyword_latest, on="id.orig_h", how="left")
    agg["dns_keyword_count"] = pd.to_numeric(agg["dns_keyword_count"], errors="coerce").fillna(0).astype(int)
    agg["dns_keyword_query"] = _clean(agg["dns_keyword_query"])
    return agg


def _prepare_tunnel(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    cols = ["uid", "ts", "id.orig_h", "id.resp_h", "tunnel_type", "action"]
    t = df.copy() if df is not None else pd.DataFrame()
    for col in cols:
        if col not in t.columns:
            t[col] = ""
    t = t[cols].copy()
    t = _to_datetime(t, "ts")
    t["uid"] = _clean(t["uid"])
    t["id.orig_h"] = _clean(t["id.orig_h"]).map(_normalize_ip)
    t["id.resp_h"] = _clean(t["id.resp_h"]).map(_normalize_ip)
    t["tunnel_type"] = _clean(t["tunnel_type"]).str.lower()
    t["action"] = _clean(t["action"]).str.lower()
    t = t[(t["id.orig_h"].ne("")) & (t["id.resp_h"].ne(""))].copy()

    uid_df = pd.DataFrame(columns=["uid", "tunnel_type_uid", "tunnel_action_uid"])
    uid_src = t[t["uid"].ne("")].copy()
    if not uid_src.empty:
        uid_df = (
            uid_src.sort_values("ts", ascending=False)
            .groupby("uid", as_index=False)
            .agg({"tunnel_type": _first_nonempty, "action": _first_nonempty})
            .rename(columns={"tunnel_type": "tunnel_type_uid", "action": "tunnel_action_uid"})
        )

    pair_df = pd.DataFrame(columns=["id.orig_h", "id.resp_h", "tunnel_type_pair", "tunnel_action_pair"])
    if not t.empty:
        pair_df = (
            t.sort_values("ts", ascending=False)
            .groupby(["id.orig_h", "id.resp_h"], as_index=False)
            .agg({"tunnel_type": _first_nonempty, "action": _first_nonempty})
            .rename(columns={"tunnel_type": "tunnel_type_pair", "action": "tunnel_action_pair"})
        )

    return uid_df, pair_df


def _build_one_date(parquet_root: Path, date_str: str, files_sig: Dict[str, List[List[object]]]) -> pd.DataFrame:
    cpath = cache_base_path(parquet_root, date_str)
    mpath = cache_meta_path(parquet_root, date_str)
    expected = _meta_expected(files_sig)
    meta = _read_json(mpath)

    # Fast path: return pre-built per-date parquet cache when source signatures match.
    if cpath.exists() and meta == expected:
        try:
            cached = pd.read_parquet(cpath)
            if not cached.empty:
                cached = _to_datetime(cached, "ts")
                return cached.sort_values("ts", ascending=False).reset_index(drop=True)
        except Exception:
            pass

    files = _collect_date_files(Path(parquet_root) / date_str)
    conn = _prepare_conn(_duck_read(files["conn"]))
    if conn.empty:
        return pd.DataFrame()
    http = _prepare_http(_duck_read(files["http"]))
    ssl = _prepare_ssl(_duck_read(files["ssl"]))
    vpn = _prepare_vpn(_duck_read(files["vpn"]))
    dns = _prepare_dns(_duck_read(files["dns"]))
    tunnel_uid, tunnel_pair = _prepare_tunnel(_duck_read(files["tunnel"]))

    out = conn.merge(http, on="uid", how="left")
    out = out.merge(ssl, on="uid", how="left")
    out = out.merge(vpn, on="uid", how="left")
    if not dns.empty:
        out = out.merge(dns, on="id.orig_h", how="left")
    if not tunnel_uid.empty:
        out = out.merge(tunnel_uid, on="uid", how="left")
    if not tunnel_pair.empty:
        out = out.merge(tunnel_pair, on=["id.orig_h", "id.resp_h"], how="left")

    for col in [
        "http_method",
        "http_host",
        "http_uri",
        "ssl_server_name",
        "ssl_alpn",
        "ssl_version",
        "ssl_cipher",
        "ssl_resumed",
        "vpn_indicator",
        "vpn_host",
        "dns_keyword_query",
        "tunnel_type_uid",
        "tunnel_action_uid",
        "tunnel_type_pair",
        "tunnel_action_pair",
    ]:
        if col not in out.columns:
            out[col] = ""
        out[col] = _clean(out[col])

    for col in ["dns_keyword_hit", "dns_proxy_hit", "dns_vpn_hit", "dns_tor_hit"]:
        if col not in out.columns:
            out[col] = False
        out[col] = out[col].where(out[col].notna(), False).astype(bool)
    if "dns_keyword_count" not in out.columns:
        out["dns_keyword_count"] = 0
    out["dns_keyword_count"] = pd.to_numeric(out["dns_keyword_count"], errors="coerce").fillna(0).astype(int)

    out["tunnel_type"] = out["tunnel_type_uid"]
    m = out["tunnel_type"].eq("")
    out.loc[m, "tunnel_type"] = out.loc[m, "tunnel_type_pair"]
    out["tunnel_action"] = out["tunnel_action_uid"]
    m = out["tunnel_action"].eq("")
    out.loc[m, "tunnel_action"] = out.loc[m, "tunnel_action_pair"]
    out["tunnel_hit"] = out["tunnel_type"].ne("") | out["tunnel_action"].ne("")

    out["Destination_Host"] = out["http_host"]
    m = out["Destination_Host"].eq("")
    out.loc[m, "Destination_Host"] = out.loc[m, "ssl_server_name"]
    m = out["Destination_Host"].eq("")
    out.loc[m, "Destination_Host"] = out.loc[m, "vpn_host"]
    m = out["Destination_Host"].eq("")
    out.loc[m, "Destination_Host"] = out.loc[m, "id.resp_h"]
    out["total_bytes"] = (
        pd.to_numeric(out["orig_ip_bytes"], errors="coerce").fillna(0)
        + pd.to_numeric(out["resp_ip_bytes"], errors="coerce").fillna(0)
    )
    out = out.sort_values("ts", ascending=False).reset_index(drop=True)

    try:
        cpath.parent.mkdir(parents=True, exist_ok=True)
        out.to_parquet(cpath, index=False)
        _write_json(mpath, expected)
    except Exception:
        pass

    return out


@st.cache_data(show_spinner=False)
def _load_base_cached(parquet_root_str: str, date_str: str, sig_key: Tuple[Tuple[str, str, int, int], ...]) -> pd.DataFrame:
    _ = sig_key
    parquet_root = Path(parquet_root_str)
    files = _collect_date_files(parquet_root / date_str)
    sig_map = _date_sig_map(files)
    return _build_one_date(parquet_root, date_str, sig_map)


def load_base(parquet_root: Path, date_str: str) -> pd.DataFrame:
    root = Path(parquet_root).resolve()
    files = _collect_date_files(root / date_str)
    sig_map = _date_sig_map(files)
    return _load_base_cached(str(root), str(date_str), _date_sig_key(sig_map))


def _feed_signature(parquet_root: Path, date_str: str) -> dict:
    paths = _feed_paths(parquet_root, date_str)
    return {
        "tor_cache": _path_sig(paths["tor_cache"]),
        "tor_meta": _path_sig(paths["tor_meta"]),
        "proxy_cache": _path_sig(paths["proxy_cache"]),
        "proxy_pair_cache": _path_sig(paths["proxy_pair_cache"]),
        "proxy_meta": _path_sig(paths["proxy_meta"]),
    }


def score_events(
    base: pd.DataFrame,
    tor_ips: Set[str],
    proxy_ips: Set[str],
    proxy_ip_ports: Set[str],
    ip2: pd.DataFrame,
) -> pd.DataFrame:
    if base is None or base.empty:
        return pd.DataFrame()
    out = base.copy()

    if ip2 is not None and not ip2.empty:
        out = out.merge(ip2, how="left", left_on="id.resp_h", right_on="ip")
    else:
        out["ip2proxy_proxy_type"] = ""
        out["ip2proxy_provider"] = ""
        out["ip2proxy_is_vpn"] = False
        out["ip2proxy_is_tor"] = False
        out["ip2proxy_is_pub"] = False

    out["ip2proxy_proxy_type"] = _clean(out["ip2proxy_proxy_type"]).str.upper()
    out["ip2proxy_provider"] = _clean(out["ip2proxy_provider"])
    ip2_vpn = out["ip2proxy_is_vpn"].fillna(False).astype(bool) | out["ip2proxy_proxy_type"].eq("VPN")
    ip2_tor = out["ip2proxy_is_tor"].fillna(False).astype(bool) | out["ip2proxy_proxy_type"].eq("TOR")
    ip2_pub = out["ip2proxy_is_pub"].fillna(False).astype(bool) | out["ip2proxy_proxy_type"].isin(
        {"PUB", "WEB", "DCH", "RES", "SES", "PROXY"}
    )

    out["id.resp_p"] = pd.to_numeric(out["id.resp_p"], errors="coerce").fillna(0).astype(int)
    out["duration"] = pd.to_numeric(out["duration"], errors="coerce").fillna(0)
    out["total_bytes"] = pd.to_numeric(out["total_bytes"], errors="coerce").fillna(0)
    out["orig_ip_bytes"] = pd.to_numeric(out["orig_ip_bytes"], errors="coerce").fillna(0)
    out["resp_ip_bytes"] = pd.to_numeric(out["resp_ip_bytes"], errors="coerce").fillna(0)

    tor_relay = compute_tor_match(out["id.resp_h"], tor_ips)
    proxy_feed_ip, proxy_feed_pair = compute_proxy_matches(out["id.resp_h"], out["id.resp_p"], proxy_ips, proxy_ip_ports)
    connect_tunnel = out["http_method"].astype(str).str.upper().eq("CONNECT")
    proxy_port = out["id.resp_p"].isin(PROXY_PORTS)
    proxy_keyword = compute_proxy_keyword_match(out["Destination_Host"], out["http_host"], out["http_uri"])

    vpn_port_score, vpn_port_reason = compute_vpn_port_score_with_proto(out["id.resp_p"], out["proto"])
    vpn_port = vpn_port_score.gt(0)
    vpn_indicator = compute_vpn_indicator_match(out["vpn_indicator"], UNKNOWN)
    vpn_keyword = compute_vpn_keyword_match(out["Destination_Host"], out["ssl_server_name"], out["vpn_host"])
    tunnel_encap = out["tunnel_hit"].fillna(False).astype(bool)
    tls_tunnel_like = (
        _clean(out["ssl_server_name"]).eq("")
        & out["id.resp_p"].eq(443)
        & out["total_bytes"].ge(float(TLS_TUNNEL_MIN_BYTES))
        & out["duration"].ge(float(TLS_TUNNEL_MIN_DURATION))
    )

    tor_port = out["id.resp_p"].isin(TOR_PORTS)
    tor_keyword = compute_tor_keyword_match(out["Destination_Host"], out["dns_keyword_query"])

    dns_proxy = out["dns_proxy_hit"].fillna(False).astype(bool)
    dns_vpn = out["dns_vpn_hit"].fillna(False).astype(bool)
    dns_tor = out["dns_tor_hit"].fillna(False).astype(bool)
    dns_any = dns_proxy | dns_vpn | dns_tor

    host_key = _clean(out["Destination_Host"])
    host_key = host_key.where(host_key.ne(""), out["id.resp_h"].astype(str))
    proxy_spread = (
        pd.DataFrame({"id.orig_h": out["id.orig_h"], "id.resp_h": out["id.resp_h"], "dest_key": host_key})
        .groupby(["id.orig_h", "id.resp_h"], dropna=False)["dest_key"]
        .transform(lambda s: s[s.astype(str).str.strip().ne("")].nunique())
    )
    proxy_gateway = proxy_spread.ge(4)

    pair_volume = (
        out.groupby(["id.orig_h", "id.resp_h"], as_index=False)["total_bytes"]
        .sum()
        .rename(columns={"total_bytes": "pair_total_bytes"})
    )
    pair_volume["stable_candidate"] = pair_volume["pair_total_bytes"].ge(float(STABLE_TUNNEL_PAIR_BYTES))
    stable_counts = (
        pair_volume[pair_volume["stable_candidate"]]
        .groupby("id.orig_h", as_index=False)
        .size()
        .rename(columns={"size": "stable_pair_count"})
    )
    pair_volume = pair_volume.merge(stable_counts, on="id.orig_h", how="left")
    pair_volume["stable_pair_count"] = pd.to_numeric(pair_volume["stable_pair_count"], errors="coerce").fillna(0).astype(int)
    pair_volume["vpn_stable_large"] = pair_volume["stable_candidate"] & pair_volume["stable_pair_count"].between(1, 3)
    out = out.merge(pair_volume[["id.orig_h", "id.resp_h", "vpn_stable_large"]], on=["id.orig_h", "id.resp_h"], how="left")
    vpn_stable_large = out["vpn_stable_large"].fillna(False).astype(bool)

    proxy_score = pd.Series(0, index=out.index, dtype="int64")
    vpn_score = pd.Series(0, index=out.index, dtype="int64")
    tor_score = pd.Series(0, index=out.index, dtype="int64")
    reason = pd.Series("", index=out.index, dtype="object")

    proxy_score = proxy_score + connect_tunnel.astype(int) * 80
    reason = _append_reason(reason, connect_tunnel, "proxy_explicit: HTTP CONNECT tunneling (+80)")
    proxy_score = proxy_score + proxy_port.astype(int) * 25
    reason = _append_reason(reason, proxy_port, "proxy_port: destination port in {3128,8080,8000,8888,1080} (+25)")
    proxy_score = proxy_score + proxy_keyword.astype(int) * 20
    reason = _append_reason(reason, proxy_keyword, "proxy_keyword: proxy/vpn/tunnel host pattern (+20)")
    proxy_score = proxy_score + proxy_gateway.astype(int) * 20
    reason = _append_reason(reason, proxy_gateway, "proxy_gateway: many destination domains behind one destination IP (+20)")
    proxy_score = proxy_score + proxy_feed_pair.astype(int) * 30
    reason = _append_reason(reason, proxy_feed_pair, "proxy_feed_pair: open proxy IP:PORT feed match (+30)")
    proxy_score = proxy_score + proxy_feed_ip.astype(int) * 20
    reason = _append_reason(reason, proxy_feed_ip, "proxy_feed_ip: open proxy IP feed match (+20)")
    proxy_score = proxy_score + dns_proxy.astype(int) * 20
    reason = _append_reason(reason, dns_proxy, "dns_proxy_keyword: DNS query matched proxy keyword (+20)")
    proxy_score = proxy_score + ip2_pub.astype(int) * 65
    reason = _append_reason_series(
        reason,
        ip2_pub,
        pd.Series("ip2proxy_proxy: " + out["ip2proxy_provider"].astype(str) + " (+65)", index=out.index),
    )

    vpn_score = vpn_score + vpn_port_score
    vpn_port_reason_scored = vpn_port_reason.where(
        vpn_port_reason.eq(""),
        vpn_port_reason + " (+" + vpn_port_score.astype(int).astype(str) + ")",
    )
    reason = _append_reason_series(reason, vpn_port, vpn_port_reason_scored)
    vpn_score = vpn_score + vpn_indicator.astype(int) * 90
    reason = _append_reason_series(
        reason,
        vpn_indicator,
        pd.Series("vpn_vendor_hit: vpn_detect_v2 indicator " + out["vpn_indicator"].astype(str) + " (+90)", index=out.index),
    )
    vpn_score = vpn_score + tunnel_encap.astype(int) * 70
    reason = _append_reason_series(
        reason,
        tunnel_encap,
        pd.Series(
            "tunnel_encap: "
            + out["tunnel_type"].astype(str)
            + " "
            + out["tunnel_action"].astype(str)
            + " (+70)",
            index=out.index,
        ),
    )
    vpn_score = vpn_score + tls_tunnel_like.astype(int) * 35
    reason = _append_reason(reason, tls_tunnel_like, "tls_tunnel_like: no SNI + port 443 + long/high-byte TLS flow (+35)")
    vpn_score = vpn_score + vpn_stable_large.astype(int) * 35
    reason = _append_reason(reason, vpn_stable_large, "vpn_stable_large: stable 1-3 large tunnel destinations (+35)")
    vpn_score = vpn_score + vpn_keyword.astype(int) * 20
    reason = _append_reason(reason, vpn_keyword, "vpn_keyword: host/SNI suggests VPN infrastructure (+20)")
    vpn_score = vpn_score + dns_vpn.astype(int) * 20
    reason = _append_reason(reason, dns_vpn, "dns_vpn_keyword: DNS query matched VPN keyword (+20)")
    vpn_score = vpn_score + ip2_vpn.astype(int) * 75
    reason = _append_reason_series(
        reason,
        ip2_vpn,
        pd.Series("ip2proxy_vpn: " + out["ip2proxy_provider"].astype(str) + " (+75)", index=out.index),
    )

    tor_score = tor_score + tor_relay.astype(int) * 95
    reason = _append_reason(reason, tor_relay, "tor_relay_ip: destination IP in Tor relay set (+95)")
    tor_score = tor_score + tor_port.astype(int) * 35
    reason = _append_reason(reason, tor_port, "tor_port: destination port in {9001,9030} (+35)")
    tor_score = tor_score + tor_keyword.astype(int) * 20
    reason = _append_reason(reason, tor_keyword, "tor_keyword: destination/DNS indicates Tor infra (+20)")
    tor_score = tor_score + dns_tor.astype(int) * 20
    reason = _append_reason(reason, dns_tor, "dns_tor_keyword: DNS query matched torproject/onion keyword (+20)")
    tor_score = tor_score + ip2_tor.astype(int) * 85
    reason = _append_reason_series(
        reason,
        ip2_tor,
        pd.Series("ip2proxy_tor: " + out["ip2proxy_provider"].astype(str) + " (+85)", index=out.index),
    )

    strong_masks = [
        connect_tunnel,
        vpn_indicator,
        tunnel_encap,
        tor_relay,
        ip2_vpn,
        ip2_tor,
        ip2_pub,
    ]
    weak_masks = [
        proxy_port,
        proxy_keyword,
        proxy_gateway,
        proxy_feed_pair,
        proxy_feed_ip,
        vpn_port,
        vpn_keyword,
        tls_tunnel_like,
        vpn_stable_large,
        tor_port,
        tor_keyword,
        dns_any,
    ]
    strong_count = sum(mask.astype(int) for mask in strong_masks)
    weak_count = sum(mask.astype(int) for mask in weak_masks)
    evidence_count = strong_count + weak_count

    # Do not suppress tiny flows when vpn_detect_v2 already provided strong VPN evidence.
    tiny_suppressed = out["total_bytes"].lt(float(MIN_FLOW_BYTES)) & ~connect_tunnel & ~tor_relay & ~vpn_indicator
    weak_suppressed = strong_count.eq(0) & weak_count.lt(2)
    suppress_mask = tiny_suppressed | weak_suppressed
    if bool(suppress_mask.any()):
        proxy_score.loc[suppress_mask] = 0
        vpn_score.loc[suppress_mask] = 0
        tor_score.loc[suppress_mask] = 0
    reason = _append_reason(reason, tiny_suppressed, "suppressed: tiny flow < 50KB without CONNECT/Tor relay evidence")
    reason = _append_reason(reason, weak_suppressed, "suppressed: fewer than two weak signals and no strong signal")

    score_frame = pd.DataFrame({"Proxy": proxy_score, "VPN": vpn_score, "Tor": tor_score}, index=out.index)
    risk_score = score_frame.max(axis=1).astype(int)
    category = score_frame.idxmax(axis=1)
    category = category.where(risk_score.gt(0), "Unclassified")
    high_multi = score_frame.ge(90).sum(axis=1).ge(2)
    if bool(high_multi.any()):
        idx_multi = category.index[high_multi]
        category.loc[idx_multi] = score_frame.loc[idx_multi].apply(
            lambda r: "/".join([k for k in ["Proxy", "VPN", "Tor"] if int(r.get(k, 0)) >= 90]),
            axis=1,
        )

    confidence = pd.Series("Informational", index=out.index, dtype="object")
    confidence.loc[risk_score.between(35, 59)] = "Low"
    confidence.loc[risk_score.between(60, 89)] = "Medium"
    confidence.loc[risk_score >= 90] = "High"

    out["Proxy_Score"] = proxy_score.astype(int)
    out["VPN_Score"] = vpn_score.astype(int)
    out["Tor_Score"] = tor_score.astype(int)
    out["Risk_Score"] = risk_score.astype(int)
    out["Confidence"] = confidence
    out["Category"] = category
    out["Reason"] = reason.where(reason.ne(""), "-")
    out["Strong_Signal_Count"] = strong_count.astype(int)
    out["Weak_Signal_Count"] = weak_count.astype(int)
    out["Evidence_Count"] = evidence_count.astype(int)
    out["Suppressed_Tiny_Flow"] = tiny_suppressed
    out["Suppressed_Weak_Signal"] = weak_suppressed
    out["High_Confidence_Evidence"] = strong_count.gt(0)
    out["Destination"] = _clean(out["Destination_Host"]) + ":" + out["id.resp_p"].astype(str)
    return out.sort_values(["Risk_Score", "ts"], ascending=[False, False]).reset_index(drop=True)


def load_scored_date(
    parquet_root: Path,
    date_str: str,
    *,
    feed_sig: dict,
    tor_ips: Set[str],
    proxy_ips: Set[str],
    proxy_ip_ports: Set[str],
    ip2_df: pd.DataFrame,
    ip2_sig: dict,
) -> pd.DataFrame:
    root = Path(parquet_root).resolve()
    files = _collect_date_files(root / date_str)
    base_sig = _date_sig_map(files)
    expected = _scored_meta_expected(base_sig=base_sig, feed_sig=feed_sig, ip2_sig=ip2_sig)
    cpath = cache_scored_path(root, date_str)
    mpath = cache_scored_meta_path(root, date_str)

    if cpath.exists() and _read_json(mpath) == expected:
        try:
            cached = pd.read_parquet(cpath)
            if not cached.empty:
                cached = _to_datetime(cached, "ts")
                return cached.sort_values(["Risk_Score", "ts"], ascending=[False, False]).reset_index(drop=True)
        except Exception:
            pass

    base_df = load_base(root, date_str)
    if base_df.empty:
        return pd.DataFrame()
    scored = score_events(base_df, tor_ips, proxy_ips, proxy_ip_ports, ip2_df)
    try:
        cpath.parent.mkdir(parents=True, exist_ok=True)
        scored.to_parquet(cpath, index=False)
        _write_json(mpath, expected)
    except Exception:
        pass
    return scored


def _feed_label(meta: dict) -> str:
    out = f"{meta.get('status','unknown')} | {int(meta.get('count',0)):,} IPs"
    if "pair_count" in meta:
        out += f" | {int(meta.get('pair_count', 0)):,} IP:PORT"
    out += f" | {meta.get('updated_at','-')}"
    return out


def _grid_data_signature(df: pd.DataFrame) -> tuple:
    if not isinstance(df, pd.DataFrame):
        return ("invalid",)
    n_rows = int(len(df))
    cols = tuple(str(c) for c in df.columns)
    if n_rows <= 0:
        return (n_rows, cols, "empty")
    sig_cols = [c for c in ["event_date", "ts", "uid", "id.orig_h", "id.resp_h", "id.resp_p", "Confidence", "Category", "Risk_Score"] if c in df.columns]
    if not sig_cols:
        sig_cols = list(df.columns[: min(5, len(df.columns))])
    sample = pd.concat([df.head(3), df.tail(3)], ignore_index=True)[sig_cols].copy()
    for c in sig_cols:
        sample[c] = sample[c].astype(str)
    digest = hashlib.sha1(sample.to_csv(index=False).encode("utf-8")).hexdigest()
    return (n_rows, cols, digest)


def _table_height_for_rows(
    n_rows: int,
    *,
    row_px: int = 34,
    header_px: int = 48,
    min_px: int = 300,
    max_px: int = 620,
) -> int:
    try:
        rows = max(int(n_rows), 1)
    except Exception:
        rows = 1
    return max(min_px, min(max_px, header_px + rows * row_px))


def _is_dark_theme() -> bool:
    try:
        base = st.get_option("theme.base")
        if isinstance(base, str) and base.lower() in {"light", "dark"}:
            return base.lower() == "dark"
    except Exception:
        pass
    return True


def get_plotly_template() -> str:
    return "plotly_dark" if _is_dark_theme() else "plotly_white"


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


def _confidence_cellstyle() -> JsCode:
    return JsCode(
        """
        function(params) {
            const v = (params.value || '').toString().toUpperCase();
            const base = { 'textAlign': 'center' };
            if (v === 'HIGH') return Object.assign(base, { 'color': '#ef4444', 'fontWeight': '900' });
            if (v === 'MEDIUM') return Object.assign(base, { 'color': '#f59e0b', 'fontWeight': '800' });
            if (v === 'LOW') return Object.assign(base, { 'color': '#22c55e', 'fontWeight': '700' });
            if (v === 'INFORMATIONAL') return Object.assign(base, { 'color': '#94a3b8', 'fontWeight': '600' });
            return base;
        }
        """
    )


def _category_cellstyle() -> JsCode:
    return JsCode(
        """
        function(params) {
            const v = (params.value || '').toString().toUpperCase();
            const base = { 'textAlign': 'center' };
            if (v.includes('TOR')) return Object.assign(base, { 'color': '#ef4444', 'fontWeight': '900' });
            if (v.includes('VPN')) return Object.assign(base, { 'color': '#f97316', 'fontWeight': '800' });
            if (v.includes('PROXY')) return Object.assign(base, { 'color': '#38bdf8', 'fontWeight': '800' });
            return base;
        }
        """
    )


def render_shadow_aggrid(
    df: pd.DataFrame,
    gb: GridOptionsBuilderType,
    *,
    key: str,
    height: int = 430,
    update_mode=GridUpdateMode.NO_UPDATE,
    wrap_shell: bool = True,
    hide_top_border: bool = False,
    grid_options_overrides: Optional[Dict[str, object]] = None,
    auto_fit_columns: bool = True,
):
    if not HAS_AGGRID:
        if wrap_shell:
            st.markdown("<div class='shadow-table-shell'>", unsafe_allow_html=True)
        st.dataframe(df, use_container_width=True, hide_index=True, height=height)
        if wrap_shell:
            st.markdown("</div>", unsafe_allow_html=True)
        return None

    df = _drop_empty_rows_and_columns(df)
    grid_options = gb.build()

    visible_fields = {str(c) for c in df.columns}
    col_defs_raw = list(grid_options.get("columnDefs") or [])
    if col_defs_raw and visible_fields:
        pruned_col_defs = []
        for col_def in col_defs_raw:
            if not isinstance(col_def, dict):
                continue
            field = str(col_def.get("field") or col_def.get("colId") or "")
            if field and field not in visible_fields:
                continue
            pruned_col_defs.append(col_def)
        grid_options["columnDefs"] = pruned_col_defs

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
    root_wrapper_style = {"background-color": "#061120", "color": "#EAF2FF", "border": "1px solid #2A466E"}
    if hide_top_border:
        root_wrapper_style["border-top"] = "0 !important"
    table_css.update(
        {
            ".ag-root-wrapper": root_wrapper_style,
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
            ".ag-menu, .ag-popup-child": {
                "background-color": "#0A1730 !important",
                "color": "#EAF2FF !important",
                "border": "1px solid #2D456C !important",
            },
            ".ag-set-filter-list, .ag-virtual-list-viewport": {
                "background-color": "#071224 !important",
                "color": "#EAF2FF !important",
            },
            ".ag-input-field-input, .ag-text-field-input": {
                "background-color": "#071224 !important",
                "color": "#EAF2FF !important",
                "border": "1px solid #2D456C !important",
            },
        }
    )

    if wrap_shell:
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
    if wrap_shell:
        st.markdown("</div>", unsafe_allow_html=True)
    return grid_response


def _render_table_information(summary_line: str, detail_lines: List[str]) -> None:
    with st.expander("Table information", expanded=False):
        if str(summary_line or "").strip():
            st.markdown(str(summary_line))
        for line in detail_lines or []:
            if str(line or "").strip():
                st.markdown(str(line))


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


def inject_anonymization_network_css():
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
        .shadow-callout {
            border: 0;
            background: var(--panel-bg);
            border-radius: 10px;
            padding: 0.5rem 0.72rem;
            font-size: 0.84rem;
            margin-bottom: 0.45rem;
        }
        .shadow-filter-shell {
            border: 0;
            background: transparent;
            border-radius: 0;
            padding: 0;
            margin-bottom: 0.45rem;
            box-shadow: none;
        }
        .shadow-filter-shell-primary {
            border-top: 0;
            padding-top: 0;
        }
        .shadow-detection-basis [data-testid="stExpander"] {
            border: 0 !important;
            box-shadow: none !important;
            background: transparent !important;
        }
        .shadow-detection-basis [data-testid="stExpander"] details {
            border: 0 !important;
            background: transparent !important;
        }
        [data-testid="stExpander"] details > div[role="region"] {
            border-top: 0 !important;
        }
        [data-testid="stVerticalBlockBorderWrapper"] {
            border: 0 !important;
            box-shadow: none !important;
        }
        hr {
            border: 0 !important;
            height: 0 !important;
            margin: 0 !important;
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
            border: 0;
            background: linear-gradient(180deg, rgba(2,6,23,0.5), rgba(2,6,23,0.35));
            border-radius: 12px;
            padding: 0.56rem 0.62rem 0.46rem 0.62rem;
            margin-bottom: 0.75rem;
        }
        [data-testid="stMetric"] {
            background: var(--panel-bg);
            border: 0;
            border-radius: 12px;
            padding: 0.55rem 0.75rem;
            min-height: 118px;
            height: 118px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }
        [data-testid="stMetric"] > div {
            height: 100%;
            display: grid;
            grid-template-rows: auto auto minmax(1.1rem, auto);
            align-content: start;
            row-gap: 0.1rem;
        }
        [data-testid="stMetricDelta"] {
            min-height: 1.1rem;
            line-height: 1.1rem;
            display: inline-flex !important;
            width: auto !important;
            max-width: max-content !important;
            align-self: flex-start !important;
        }
        [data-testid="stMetricDelta"] > div {
            width: auto !important;
            max-width: max-content !important;
        }
        [data-testid="stMetricDelta"] p {
            margin: 0 !important;
        }
        [data-testid="stMetricLabel"] p {
            font-size: 0.75rem;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            font-weight: 600;
        }
        .shadow-table-shell .ag-menu,
        .shadow-table-shell .ag-popup-child,
        .shadow-table-shell .ag-theme-alpine .ag-menu,
        .shadow-table-shell .ag-theme-alpine-dark .ag-menu,
        .shadow-table-shell .ag-theme-alpine .ag-popup-child,
        .shadow-table-shell .ag-theme-alpine-dark .ag-popup-child {
            background: #0A1730 !important;
            color: #EAF2FF !important;
            border: 1px solid #2D456C !important;
        }
        .shadow-table-shell .ag-set-filter-list,
        .shadow-table-shell .ag-virtual-list-viewport,
        .shadow-table-shell .ag-theme-alpine .ag-set-filter-list,
        .shadow-table-shell .ag-theme-alpine-dark .ag-set-filter-list {
            background: #071224 !important;
            color: #EAF2FF !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def inject_shadow_tunnels_css():
    # Backward-compatible alias.
    inject_anonymization_network_css()


def ensure_scored_cache(
    parquet_root: Path,
    target_dates: List[str],
    *,
    feeds: dict,
    ip2_df: pd.DataFrame,
    ip2_sig: dict,
) -> None:
    total = max(len(target_dates), 1)
    prog = st.progress(0, text="Preparing optimized cache...")
    for i, d in enumerate(target_dates, start=1):
        _ = load_scored_date(
            parquet_root,
            d,
            feed_sig=_feed_signature(parquet_root, d),
            tor_ips=set(feeds.get("tor", {}).get("ips", [])),
            proxy_ips=set(feeds.get("proxy", {}).get("ips", [])),
            proxy_ip_ports=set(feeds.get("proxy", {}).get("ip_ports", [])),
            ip2_df=ip2_df,
            ip2_sig=ip2_sig,
        )
        prog.progress(int(i / total * 100), text="Preparing optimized cache...")
    prog.empty()


def read_scored_cached_files(parquet_root: Path, target_dates: List[str]) -> List[str]:
    out: List[str] = []
    for d in target_dates:
        p = cache_scored_path(Path(parquet_root), d)
        if p.exists():
            out.append(str(p.resolve()))
    return out


def _scored_sig(files: List[str]) -> Tuple[Tuple[str, int, int], ...]:
    rows: List[Tuple[str, int, int]] = []
    for f in files:
        try:
            p = Path(f)
            st_ = p.stat()
            rows.append((str(p.resolve()), int(st_.st_mtime_ns), int(st_.st_size)))
        except Exception:
            continue
    return tuple(rows)


@st.cache_data(show_spinner=False)
def _load_scored_scope_cached(sig: Tuple[Tuple[str, int, int], ...]) -> pd.DataFrame:
    paths = [Path(row[0]) for row in sig]
    if not paths:
        return pd.DataFrame()
    df = _duck_read(paths)
    if df is None or df.empty:
        return pd.DataFrame()
    return _to_datetime(df, "ts")


def load_scored_scope(files: List[str]) -> pd.DataFrame:
    sig = _scored_sig(files)
    if not sig:
        return pd.DataFrame()
    return _load_scored_scope_cached(sig)


def _top_reason_list(reasons: pd.Series, limit: int = 3) -> str:
    counts: Dict[str, int] = {}
    for raw in reasons.fillna("").astype(str):
        for part in raw.split(";"):
            token = part.strip()
            if not token or token == "-":
                continue
            counts[token] = int(counts.get(token, 0)) + 1
    if not counts:
        return "-"
    ordered = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    return "; ".join([k for k, _ in ordered[:limit]])


def _top_destination_list(group: pd.DataFrame, limit: int = 3) -> str:
    if group is None or group.empty:
        return "-"
    g = group.copy()
    g["dest_label"] = g["id.resp_h"].astype(str) + " (" + _clean(g["Destination_Host"]).astype(str) + ")"
    top = g["dest_label"].value_counts().head(limit).index.tolist()
    return "; ".join(top) if top else "-"


def build_soc_rollup(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame()
    rows: List[dict] = []
    for (src_ip, mac), g in df.groupby(["id.orig_h", "mac"], dropna=False):
        g = g.copy()
        g = _to_datetime(g, "ts")
        g = g.sort_values(["Risk_Score", "ts"], ascending=[False, False])
        top = g.iloc[0] if not g.empty else {}
        first_seen = pd.to_datetime(g["ts"], errors="coerce").min()
        last_seen = pd.to_datetime(g["ts"], errors="coerce").max()
        dst_hosts = _clean(g["Destination_Host"]).replace("", pd.NA).dropna()
        rows.append(
            {
                "Source_IP": _clean(pd.Series([src_ip])).iloc[0],
                "MAC": _clean(pd.Series([mac])).str.lower().iloc[0],
                "Top_Category": str(top.get("Category", "")),
                "Confidence": str(top.get("Confidence", "")),
                "Top_Score": int(pd.to_numeric(top.get("Risk_Score", 0), errors="coerce") or 0),
                "Events": int(len(g)),
                "Top_Reasons": _top_reason_list(g["Reason"]),
                "Top_Destinations": _top_destination_list(g),
                "First_Seen": first_seen.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(first_seen) else "",
                "Last_Seen": last_seen.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(last_seen) else "",
                "Upload_MB": round(float(pd.to_numeric(g["orig_ip_bytes"], errors="coerce").fillna(0).sum()) / (1024 * 1024), 2),
                "Download_MB": round(float(pd.to_numeric(g["resp_ip_bytes"], errors="coerce").fillna(0).sum()) / (1024 * 1024), 2),
                "Duration_s": round(float(pd.to_numeric(g["duration"], errors="coerce").fillna(0).sum()), 2),
                "Distinct_Dst_IPs": int(g["id.resp_h"].astype(str).replace("", pd.NA).dropna().nunique()),
                "Distinct_Dst_Hosts": int(dst_hosts.nunique()),
            }
        )
    out = pd.DataFrame(rows)
    if out.empty:
        return out
    return out.sort_values(["Top_Score", "Events"], ascending=[False, False]).reset_index(drop=True)


def _derive_detection_source(df: pd.DataFrame) -> pd.Series:
    if df is None or df.empty:
        return pd.Series(dtype="object")

    out = pd.Series("CONN", index=df.index, dtype="object")

    http = (
        _clean(df.get("http_method", pd.Series("", index=df.index))).ne("")
        | _clean(df.get("http_host", pd.Series("", index=df.index))).ne("")
    )
    ssl = _clean(df.get("ssl_server_name", pd.Series("", index=df.index))).ne("")
    tunnel = (
        _clean(df.get("tunnel_type", pd.Series("", index=df.index))).ne("")
        | _clean(df.get("tunnel_action", pd.Series("", index=df.index))).ne("")
        | df.get("tunnel_hit", pd.Series(False, index=df.index)).fillna(False).astype(bool)
    )
    vpn = (
        _clean(df.get("vpn_indicator", pd.Series("", index=df.index))).ne("")
        | _clean(df.get("vpn_host", pd.Series("", index=df.index))).ne("")
    )
    dns = (
        _clean(df.get("dns_keyword_query", pd.Series("", index=df.index))).ne("")
        | df.get("dns_keyword_hit", pd.Series(False, index=df.index)).fillna(False).astype(bool)
    )
    feed = (
        _clean(df.get("ip2proxy_proxy_type", pd.Series("", index=df.index))).ne("")
        | df.get("tor_relay_hit", pd.Series(False, index=df.index)).fillna(False).astype(bool)
        | df.get("proxy_feed_ip_hit", pd.Series(False, index=df.index)).fillna(False).astype(bool)
        | df.get("proxy_feed_pair_hit", pd.Series(False, index=df.index)).fillna(False).astype(bool)
    )

    out.loc[feed] = "FEED"
    out.loc[dns] = "DNS"
    out.loc[tunnel] = "TUNNEL"
    out.loc[ssl] = "SSL"
    out.loc[http] = "HTTP"
    # Keep vpn_detect_v2 evidence visible as a distinct source label.
    out.loc[vpn] = "VPN_DETECT_V2"
    return out


def render_anonymization_network(parquet_root: Path):
    inject_anonymization_network_css()
    st.session_state.setdefault("anonym_net_allow_dialog_open", False)
    st.session_state.setdefault("anonym_net_allow_candidate", None)
    st.session_state.setdefault("anonym_net_table_nonce", 0)
    st.markdown("### Anonymization Network (Proxy / VPN / Tor)")
    st.markdown(
        "<div class='shadow-callout'>Advanced anonymization detection with correlation scoring across Zeek "
        "conn/http/ssl/dns/tunnel/vpn_detect_v2, plus feed-backed Tor/proxy intelligence and fast cache loading.</div>",
        unsafe_allow_html=True,
    )
    st.markdown("<div class='shadow-detection-basis'>", unsafe_allow_html=True)
    with st.expander("Detection basis", expanded=False):
        st.markdown(
            "Detections are produced from correlated Zeek telemetry (`conn/http/ssl/dns/tunnel/vpn_detect_v2`) with "
            "feed-backed Tor/proxy enrichment and local VPN/provider inference."
        )
        st.markdown(
            "Primary scoring signals include explicit proxy behavior (`http.method == CONNECT`, proxy ports), VPN/Tor "
            "indicators (`vpn_detect_v2`, VPN ports, Tor relay hits), and tunnel-like transport behavior "
            "(TLS no-SNI + sustained transfer + duration)."
        )
        st.markdown(
            "Weak DNS keyword evidence for Tor/VPN/Proxy is retained as supporting context and combined with stronger "
            "signals to avoid over-scoring isolated matches."
        )
        st.markdown(
            "False-positive controls suppress tiny flows (`<50KB`) unless strong indicators exist, and require multiple "
            "weak indicators when strong evidence is absent."
        )
        st.markdown("Confidence thresholds: `>=90 High`, `60-89 Medium`, `35-59 Low`.")
        st.info(
            "Optional local `IP2Proxy` lookup (`data/ip2proxy_lookup.parquet` or env `IP2PROXY_LOOKUP_FILE`) is used as supporting enrichment."
        )
    st.markdown("</div>", unsafe_allow_html=True)
    if not HAS_AGGRID:
        st.caption("AgGrid package not available in this runtime; using dataframe fallback.")

    dates = get_available_dates(parquet_root)
    if not dates:
        st.error("No dated parquet folders found.")
        return

    date_sel_state = str(st.session_state.get("anonym_net_date", dates[0]))
    if date_sel_state not in dates:
        date_sel_state = dates[0]
    date_sel = st.selectbox("Dataset Scope", dates, index=dates.index(date_sel_state), key="anonym_net_date")

    feeds = load_feeds(parquet_root, date_sel, force=False)
    ip2, _, ip2_sig = load_ip2proxy_lookup()
    allowlist, _ = load_anonymization_allowlist()

    q = st.text_input(
        "Search (IP Host Provider Reason UID MAC)",
        placeholder="Enter keywords...",
        key="anonym_net_q",
    ).strip().lower()

    target_dates = [date_sel]

    ensure_scored_cache(
        parquet_root,
        target_dates,
        feeds=feeds,
        ip2_df=ip2,
        ip2_sig=ip2_sig,
    )

    cached_files = read_scored_cached_files(parquet_root, target_dates)
    if not cached_files:
        st.info("No cached anonymization files available for selected date.")
        return
    scored = load_scored_scope(cached_files)

    if scored.empty:
        st.info("No scored events.")
        return
    scored = _to_datetime(scored, "ts")
    scored["event_date"] = pd.to_datetime(scored["ts"], errors="coerce").dt.strftime("%Y-%m-%d").fillna("")
    scored["Allowlisted"] = compute_allowlist_mask(scored, allowlist)

    view = scored.copy()
    view["Detection_Source"] = _derive_detection_source(view)

    cat_opts = sorted(view["Category"].dropna().astype(str).unique().tolist())
    source_opts = sorted([x for x in view["Detection_Source"].dropna().astype(str).unique().tolist() if x])

    st.markdown("<div class='shadow-filter-shell shadow-filter-shell-primary'>", unsafe_allow_html=True)
    c6, c7 = st.columns([1.0, 1.0])
    with c6:
        conf_filter = st.multiselect(
            "Confidence",
            ["High", "Medium", "Low"],
            default=["High", "Medium", "Low"],
            key="anonym_net_conf",
        )
    with c7:
        source_filter = st.multiselect("Source", source_opts, default=source_opts, key="anonym_net_source_filter")
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div class='shadow-filter-shell'>", unsafe_allow_html=True)
    cat_filter = st.multiselect("Category", cat_opts, default=cat_opts, key="anonym_net_cat")
    st.markdown("</div>", unsafe_allow_html=True)

    if conf_filter:
        view = view[view["Confidence"].isin(conf_filter)].copy()
    if source_filter:
        view = view[view["Detection_Source"].isin(source_filter)].copy()
    if cat_filter:
        view = view[view["Category"].isin(cat_filter)].copy()
    if q:
        blob = (
            view["id.orig_h"].astype(str) + " " + view["id.resp_h"].astype(str) + " " + view["Destination_Host"].astype(str)
            + " " + view["ip2proxy_provider"].astype(str) + " " + view["Reason"].astype(str) + " " + view["uid"].astype(str) + " " + view["mac"].astype(str)
        ).str.lower()
        view = view[blob.str.contains(re.escape(q), na=False)].copy()

    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Events", f"{len(view):,}")
    m2.metric("High", f"{int((view['Confidence']=='High').sum()):,}")
    m3.metric("Proxy", f"{int(view['Category'].astype(str).str.contains('Proxy', case=False, na=False).sum()):,}")
    m4.metric("VPN", f"{int(view['Category'].astype(str).str.contains('VPN', case=False, na=False).sum()):,}")
    m5.metric("Tor", f"{int(view['Category'].astype(str).str.contains('Tor', case=False, na=False).sum()):,}")
    m6.metric("High Evidence", f"{int(view['High_Confidence_Evidence'].fillna(False).astype(bool).sum()):,}")

    if st.session_state.get("anonym_net_allow_dialog_open") and st.session_state.get("anonym_net_allow_candidate"):
        show_anonymization_allow_dialog()

    if view.empty:
        st.warning("No events match current filters.")
        return

    chart1, chart2 = st.columns(2)
    with chart1:
        cat_frame = (
            view.groupby("Category", dropna=False)
            .size()
            .reset_index(name="Events")
            .sort_values("Events", ascending=False)
        )
        fig_cat = px.bar(
            cat_frame,
            x="Category",
            y="Events",
            color="Category",
            title="Events By Category",
        )
        style_plotly_figure(fig_cat, height=350, show_legend=False)
        st.plotly_chart(fig_cat, use_container_width=True)
    with chart2:
        src_frame = (
            view.groupby("id.orig_h", dropna=False)["Risk_Score"]
            .max()
            .reset_index()
            .rename(columns={"id.orig_h": "Source_IP", "Risk_Score": "Max_Risk_Score"})
            .sort_values("Max_Risk_Score", ascending=False)
            .head(10)
        )
        fig_src = px.bar(
            src_frame,
            x="Source_IP",
            y="Max_Risk_Score",
            title="Top Source IP (Max Risk)",
            color="Max_Risk_Score",
            color_continuous_scale="Reds",
        )
        style_plotly_figure(fig_src, height=350, show_legend=False)
        st.plotly_chart(fig_src, use_container_width=True)

    soc_rollup = build_soc_rollup(view)
    if not soc_rollup.empty:
        st.markdown("#### Top destinations/reasons")
        soc_table = soc_rollup.copy()
        for col in ["Top_Score", "Events", "Distinct_Dst_IPs", "Distinct_Dst_Hosts"]:
            soc_table[col] = pd.to_numeric(soc_table[col], errors="coerce").fillna(0).astype(int)
        for col in ["Upload_MB", "Download_MB", "Duration_s"]:
            soc_table[col] = pd.to_numeric(soc_table[col], errors="coerce").fillna(0).round(2)
        soc_table = _drop_empty_rows(soc_table)
        soc_table, soc_hidden_cols = _drop_empty_columns(soc_table)
        if soc_hidden_cols:
            st.caption("Hidden empty columns: " + ", ".join(soc_hidden_cols))
        if soc_table.empty:
            st.info("Top destinations/reasons has no non-empty rows after cleanup.")
        elif HAS_AGGRID and GridOptionsBuilder is not None:
            gb_soc = GridOptionsBuilder.from_dataframe(soc_table)
            gb_soc.configure_default_column(
                resizable=True,
                sortable=True,
                filter=True,
                minWidth=104,
                wrapText=False,
                autoHeight=False,
            )
            gb_soc.configure_grid_options(
                rowHeight=34,
                headerHeight=42,
                animateRows=False,
            )
            gb_soc.configure_pagination(paginationAutoPageSize=False, paginationPageSize=20)
            gb_soc.configure_column("Source_IP", header_name="source ip", minWidth=128)
            gb_soc.configure_column("MAC", header_name="mac", minWidth=120)
            gb_soc.configure_column("Top_Category", header_name="category", cellStyle=_category_cellstyle(), minWidth=110, maxWidth=140)
            gb_soc.configure_column("Confidence", header_name="confidence", cellStyle=_confidence_cellstyle(), minWidth=108, maxWidth=130)
            gb_soc.configure_column("Top_Score", header_name="top score", type=["numericColumn"], minWidth=96, maxWidth=116)
            gb_soc.configure_column("Events", header_name="events", type=["numericColumn"], minWidth=88, maxWidth=108)
            gb_soc.configure_column("Top_Reasons", header_name="top reasons", minWidth=260, flex=1.4)
            gb_soc.configure_column("Top_Destinations", header_name="top destinations", minWidth=250, flex=1.2)
            gb_soc.configure_column("First_Seen", header_name="first seen", minWidth=160)
            gb_soc.configure_column("Last_Seen", header_name="last seen", minWidth=160)
            gb_soc.configure_column("Upload_MB", header_name="upload mb", type=["numericColumn"], minWidth=110, maxWidth=125)
            gb_soc.configure_column("Download_MB", header_name="download mb", type=["numericColumn"], minWidth=115, maxWidth=130)
            gb_soc.configure_column("Duration_s", header_name="duration s", type=["numericColumn"], minWidth=105, maxWidth=120)
            gb_soc.configure_column("Distinct_Dst_IPs", header_name="distinct dst ips", type=["numericColumn"], minWidth=130, maxWidth=150)
            gb_soc.configure_column("Distinct_Dst_Hosts", header_name="distinct dst hosts", type=["numericColumn"], minWidth=145, maxWidth=165)
            soc_response = render_shadow_aggrid(
                soc_table,
                gb_soc,
                key=f"anonym_net_soc_table_{date_sel}",
                height=_table_height_for_rows(len(soc_table), min_px=290, max_px=520),
                update_mode=GridUpdateMode.SELECTION_CHANGED,
                wrap_shell=False,
                hide_top_border=True,
            )
            _render_table_information(
                f"{len(soc_table):,} destination/reason rows shown.",
                [
                    "Rows are grouped by `Source_IP` + `MAC` and summarize `Top_Destinations` and `Top_Reasons`.",
                    "`Top_Score`, `Confidence`, and `Events` help prioritize which devices to triage first.",
                ],
            )
            export_soc = pd.DataFrame(soc_response.get("data", [])) if isinstance(soc_response, dict) else pd.DataFrame()
            if export_soc.empty:
                export_soc = soc_table.copy()
            st.download_button(
                "Download CSV",
                data=export_soc.to_csv(index=False).encode("utf-8"),
                file_name=f"anonymization_top_destinations_reasons_{date_sel}.csv",
                mime="text/csv",
                key=f"anonym_net_soc_csv_{date_sel}",
            )
        else:
            st.dataframe(
                soc_table,
                use_container_width=True,
                hide_index=True,
                height=min(450, 84 + 34 * max(len(soc_table), 1)),
            )
            _render_table_information(
                f"{len(soc_table):,} destination/reason rows shown.",
                [
                    "Rows are grouped by `Source_IP` + `MAC` and summarize `Top_Destinations` and `Top_Reasons`.",
                    "`Top_Score`, `Confidence`, and `Events` help prioritize which devices to triage first.",
                ],
            )
            st.download_button(
                "Download CSV",
                data=soc_table.to_csv(index=False).encode("utf-8"),
                file_name=f"anonymization_top_destinations_reasons_{date_sel}.csv",
                mime="text/csv",
                key=f"anonym_net_soc_csv_{date_sel}",
            )

    view["event_data"] = view["event_date"]
    show_cols = [
        "uid",
        "event_data",
        "ts",
        "Confidence",
        "Detection_Source",
        "Category",
        "id.orig_h",
        "mac",
        "id.resp_h",
        "id.resp_p",
        "Destination_Host",
        "http_method",
        "ssl_server_name",
        "ip2proxy_proxy_type",
        "ip2proxy_provider",
        "vpn_indicator",
        "dns_keyword_query",
        "tunnel_type",
        "orig_ip_bytes",
        "resp_ip_bytes",
        "total_bytes",
        "duration",
    ]
    for col in show_cols:
        if col not in view.columns:
            view[col] = ""
    # Sort on the full view (Risk_Score may not be in show_cols)
    if "Risk_Score" not in view.columns:
        view["Risk_Score"] = 0
    view["Risk_Score"] = pd.to_numeric(view["Risk_Score"], errors="coerce").fillna(0).astype(int)

    view_sorted = view.sort_values(["Risk_Score", "ts"], ascending=[False, False]).reset_index(drop=True)

    # Fill sparse enrichment fields with best-effort labels and avoid noisy "No match".
    for _c in [
        "ip2proxy_proxy_type",
        "ip2proxy_provider",
        "vpn_indicator",
        "vpn_host",
        "Reason",
        "Category",
        "Destination_Host",
        "ssl_server_name",
        "http_host",
        "http_uri",
    ]:
        if _c not in view_sorted.columns:
            view_sorted[_c] = ""

    cat_u = _clean(view_sorted["Category"]).str.upper()
    ptype = _clean(view_sorted["ip2proxy_proxy_type"]).str.upper()
    ptype_empty = ptype.eq("")
    if bool(ptype_empty.any()):
        fallback_type = pd.Series("", index=view_sorted.index, dtype="object")
        fallback_type.loc[cat_u.str.contains("TOR", na=False)] = "TOR"
        fallback_type.loc[cat_u.str.contains("VPN", na=False)] = "VPN"
        fallback_type.loc[cat_u.str.contains("PROXY", na=False)] = "PROXY"
        ptype.loc[ptype_empty] = fallback_type.loc[ptype_empty]
    view_sorted["ip2proxy_proxy_type"] = ptype

    provider = _clean(view_sorted["ip2proxy_provider"])
    provider_empty = provider.eq("")
    blob = (
        _clean(view_sorted["Destination_Host"])
        + " "
        + _clean(view_sorted["ssl_server_name"])
        + " "
        + _clean(view_sorted["vpn_host"])
        + " "
        + _clean(view_sorted["vpn_indicator"])
        + " "
        + _clean(view_sorted["http_host"])
        + " "
        + _clean(view_sorted["http_uri"])
    )
    provider_guess = _guess_vpn_provider_from_text(blob)
    vpn_host_s = _clean(view_sorted["vpn_host"])
    provider = provider.where(~provider_empty, provider_guess)
    provider = provider.where(~(provider.eq("") & vpn_host_s.ne("")), vpn_host_s)
    view_sorted["ip2proxy_provider"] = provider

    vind = _clean(view_sorted["vpn_indicator"])
    vind_empty = vind.eq("")
    reason_s = _clean(view_sorted["Reason"]).str.lower()
    vind.loc[vind_empty & vpn_host_s.ne("")] = vpn_host_s.loc[vind_empty & vpn_host_s.ne("")]
    still = vind.eq("")
    vpn_cat = cat_u.str.contains("VPN", na=False)
    vind.loc[still & vpn_cat & reason_s.str.contains("vpn_port", na=False)] = "vpn_port"
    still = vind.eq("")
    vind.loc[still & vpn_cat & reason_s.str.contains("tls_tunnel_like", na=False)] = "tls_tunnel_like"
    still = vind.eq("")
    vind.loc[still & vpn_cat & reason_s.str.contains("vpn_keyword", na=False)] = "vpn_keyword"
    still = vind.eq("")
    vind.loc[still & vpn_cat & reason_s.str.contains("vpn_stable_large", na=False)] = "vpn_stable_large"
    still = vind.eq("")
    vind.loc[still & vpn_cat & provider_guess.ne("")] = provider_guess.loc[still & vpn_cat & provider_guess.ne("")]
    view_sorted["vpn_indicator"] = vind

    # Normalize common placeholder tokens to blank.
    placeholder_tokens = {"no match", "nomatch", "no-match", "unknown", "(empty)", "-", "none", "null", "*"}
    for _c in ["ip2proxy_proxy_type", "ip2proxy_provider", "vpn_indicator", "dns_keyword_query", "tunnel_type", "ssl_server_name", "http_method"]:
        s = _clean(view_sorted[_c])
        view_sorted[_c] = s.where(~s.str.lower().isin(placeholder_tokens), "")

    # Keep only meaningful rows, then deduplicate repeated events.
    row_blob = (
        _clean(view_sorted["uid"])
        + _clean(view_sorted["id.orig_h"])
        + _clean(view_sorted["id.resp_h"])
        + _clean(view_sorted["Destination_Host"])
        + _clean(view_sorted["http_method"])
        + _clean(view_sorted["ssl_server_name"])
        + _clean(view_sorted["vpn_indicator"])
        + _clean(view_sorted["dns_keyword_query"])
        + _clean(view_sorted["tunnel_type"])
    )
    view_sorted = view_sorted[row_blob.ne("")].copy()

    uid_key = _clean(view_sorted["uid"])
    ts_bucket = pd.to_datetime(view_sorted["ts"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M").fillna("")
    view_sorted["event_fingerprint"] = uid_key
    m_uid = view_sorted["event_fingerprint"].eq("")
    view_sorted.loc[m_uid, "event_fingerprint"] = (
        _clean(view_sorted.loc[m_uid, "id.orig_h"])
        + "|"
        + _clean(view_sorted.loc[m_uid, "id.resp_h"])
        + "|"
        + pd.to_numeric(view_sorted.loc[m_uid, "id.resp_p"], errors="coerce").fillna(0).astype(int).astype(str)
        + "|"
        + _clean(view_sorted.loc[m_uid, "Destination_Host"])
        + "|"
        + _clean(view_sorted.loc[m_uid, "Category"])
        + "|"
        + ts_bucket.loc[m_uid]
    )
    view_sorted = view_sorted.drop_duplicates(subset=["event_fingerprint"], keep="first")

    dedup_subset = [
        "event_data",
        "id.orig_h",
        "id.resp_h",
        "id.resp_p",
        "Destination_Host",
        "http_method",
        "ssl_server_name",
        "ip2proxy_proxy_type",
        "ip2proxy_provider",
        "vpn_indicator",
        "dns_keyword_query",
        "tunnel_type",
        "Category",
        "Confidence",
    ]
    dedup_subset = [c for c in dedup_subset if c in view_sorted.columns]
    if dedup_subset:
        view_sorted = view_sorted.drop_duplicates(subset=dedup_subset, keep="first")

    top_n = 100
    view_sorted = view_sorted.sort_values(["Risk_Score", "ts"], ascending=[False, False]).head(top_n).copy()

    table = view_sorted.reindex(columns=show_cols).copy()
    table["id.resp_p"] = pd.to_numeric(table["id.resp_p"], errors="coerce").fillna(0).astype(int)
    table["orig_ip_bytes"] = pd.to_numeric(table["orig_ip_bytes"], errors="coerce").fillna(0).astype(int)
    table["resp_ip_bytes"] = pd.to_numeric(table["resp_ip_bytes"], errors="coerce").fillna(0).astype(int)
    table["total_bytes"] = pd.to_numeric(table["total_bytes"], errors="coerce").fillna(0).astype(int)
    table["duration"] = pd.to_numeric(table["duration"], errors="coerce").fillna(0).round(2)
    table["event_data"] = table["event_data"].fillna("").astype(str)
    table["ts"] = pd.to_datetime(table["ts"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S").fillna("")

    # Final strict cleanup on base display columns first.
    table = _drop_empty_rows(table)
    table, hidden_cols = _drop_empty_columns(table)
    table = _drop_empty_rows(table)
    if hidden_cols:
        st.caption("Hidden empty columns: " + ", ".join(hidden_cols))
    if table.empty:
        st.warning("No non-empty events to display after cleanup.")
        return

    # Add actionable allowlist controls after cleanup so action columns are never auto-dropped.
    allowlisted_src = (
        view_sorted.get("Allowlisted", pd.Series(False, index=view_sorted.index))
        .fillna(False)
        .astype(bool)
    )
    allow_key_src = view_sorted.get("event_fingerprint", pd.Series("", index=view_sorted.index)).fillna("").astype(str)
    allow_key_src = allow_key_src.where(allow_key_src.str.strip().ne(""), view_sorted.index.astype(str))
    src_ip_src = _clean(view_sorted.get("id.orig_h", pd.Series("", index=view_sorted.index))).map(_normalize_ip)
    src_mac_src = _clean(view_sorted.get("mac", pd.Series("", index=view_sorted.index))).str.lower()
    dst_ip_src = _clean(view_sorted.get("id.resp_h", pd.Series("", index=view_sorted.index))).map(_normalize_ip)
    dst_host_src = _clean(view_sorted.get("Destination_Host", pd.Series("", index=view_sorted.index))).str.lower().str.strip(".")

    allowlisted_col = allowlisted_src.reindex(table.index).fillna(False).astype(bool)
    allow_col = allowlisted_col.copy()
    if "Destination_Host" in table.columns:
        insert_at = int(table.columns.get_loc("Destination_Host")) + 1
        table.insert(insert_at, "Allowlisted", allowlisted_col)
        table.insert(insert_at + 1, "Allow", allow_col)
    else:
        table["Allowlisted"] = allowlisted_col
        table["Allow"] = allow_col
    table["_allow_key"] = allow_key_src.reindex(table.index).fillna("").astype(str)
    table["_allow_src_ip"] = src_ip_src.reindex(table.index).fillna("").astype(str)
    table["_allow_src_mac"] = src_mac_src.reindex(table.index).fillna("").astype(str)
    table["_allow_dst_ip"] = dst_ip_src.reindex(table.index).fillna("").astype(str)
    table["_allow_dst_host"] = dst_host_src.reindex(table.index).fillna("").astype(str)

    original_allow_map = {
        str(k): _coerce_checkbox_bool(v)
        for k, v in zip(table["_allow_key"].tolist(), table["Allow"].tolist())
    }

    st.markdown("#### Proxy/VPN/Tor Incidents")
    st.caption(f"Showing top {len(view_sorted):,} unique events (highest risk and most recent).")

    table_response = None
    if HAS_AGGRID and GridOptionsBuilder is not None:
        gb = GridOptionsBuilder.from_dataframe(table)
        gb.configure_default_column(
            resizable=True,
            sortable=True,
            filter=True,
            minWidth=96,
            wrapText=False,
            autoHeight=False,
        )
        gb.configure_grid_options(
            rowHeight=34,
            headerHeight=42,
            animateRows=False,
        )
        gb.configure_pagination(paginationAutoPageSize=False, paginationPageSize=20)

        def _cfg(col: str, **kwargs):
            if col in table.columns:
                gb.configure_column(col, **kwargs)

        allow_editable = JsCode(
            """
            function(params) {
                const already = !!(params.data && params.data.Allowlisted);
                if (already) return false;
                const srcIp = (params.data && params.data._allow_src_ip ? params.data._allow_src_ip : '').toString().trim();
                const srcMac = (params.data && params.data._allow_src_mac ? params.data._allow_src_mac : '').toString().trim();
                const dstIp = (params.data && params.data._allow_dst_ip ? params.data._allow_dst_ip : '').toString().trim();
                const dstHost = (params.data && params.data._allow_dst_host ? params.data._allow_dst_host : '').toString().trim();
                return !!(srcIp || srcMac || dstIp || dstHost);
            }
            """
        )

        _cfg("uid", header_name="uid", minWidth=148)
        _cfg("event_data", header_name="event_data", minWidth=118, maxWidth=136)
        _cfg("ts", header_name="ts", minWidth=165)
        _cfg("Confidence", header_name="confidence", cellStyle=_confidence_cellstyle(), minWidth=108, maxWidth=132)
        _cfg("Detection_Source", header_name="source", minWidth=98, maxWidth=122)
        _cfg("Category", header_name="category", cellStyle=_category_cellstyle(), minWidth=108, maxWidth=132)
        _cfg("id.orig_h", header_name="source ip", minWidth=126)
        _cfg("mac", header_name="mac", minWidth=118)
        _cfg("id.resp_h", header_name="destination ip", minWidth=128)
        _cfg("id.resp_p", header_name="dst port", type=["numericColumn"], minWidth=92, maxWidth=108, cellStyle={"textAlign": "right"})
        _cfg("Destination_Host", header_name="destination host/sni", minWidth=210, flex=1.3)
        _cfg("Allowlisted", header_name="allowlisted", minWidth=108, maxWidth=126, cellRenderer="agCheckboxCellRenderer", editable=False, filter=False)
        _cfg(
            "Allow",
            header_name="allow",
            width=86,
            editable=allow_editable,
            cellRenderer="agCheckboxCellRenderer",
            cellEditor="agCheckboxCellEditor",
            singleClickEdit=True,
            filter=False,
            sortable=False,
            suppressMovable=True,
        )
        _cfg("http_method", header_name="http methods", minWidth=112, maxWidth=132)
        _cfg("ssl_server_name", header_name="ssl_servername", minWidth=190, flex=1.1)
        _cfg("ip2proxy_proxy_type", header_name="ip2proxy_proxy_type", minWidth=145, maxWidth=170)
        _cfg("ip2proxy_provider", header_name="ip2proxy_providors", minWidth=180, flex=1.1)
        _cfg("vpn_indicator", header_name="vpn indicators", minWidth=130, maxWidth=165)
        _cfg("dns_keyword_query", header_name="dns_keyword_query", minWidth=210, flex=1.0)
        _cfg("tunnel_type", header_name="tunnel_type", minWidth=130, maxWidth=170)
        _cfg("orig_ip_bytes", header_name="orig_ip_bytes", type=["numericColumn"], minWidth=120, maxWidth=140, cellStyle={"textAlign": "right"})
        _cfg("resp_ip_bytes", header_name="resp_ip_bytes", type=["numericColumn"], minWidth=120, maxWidth=140, cellStyle={"textAlign": "right"})
        _cfg("total_bytes", header_name="total_bytes", type=["numericColumn"], minWidth=115, maxWidth=140, cellStyle={"textAlign": "right"})
        _cfg("duration", header_name="durations", type=["numericColumn"], minWidth=100, maxWidth=120, cellStyle={"textAlign": "right"})
        _cfg("_allow_key", hide=True)
        _cfg("_allow_src_ip", hide=True)
        _cfg("_allow_src_mac", hide=True)
        _cfg("_allow_dst_ip", hide=True)
        _cfg("_allow_dst_host", hide=True)
        gb.configure_selection("single", use_checkbox=False)
        table_response = render_shadow_aggrid(
            table,
            gb,
            key=f"anonym_net_table_{date_sel}_{int(st.session_state.get('anonym_net_table_nonce', 0))}",
            height=_table_height_for_rows(len(table), min_px=320, max_px=640),
            update_mode=(GridUpdateMode.VALUE_CHANGED | GridUpdateMode.MODEL_CHANGED),
            wrap_shell=False,
            hide_top_border=True,
        )
    else:
        render_shadow_aggrid(
            table.drop(columns=["Allow", "_allow_key", "_allow_src_ip", "_allow_src_mac", "_allow_dst_ip", "_allow_dst_host"], errors="ignore"),
            gb=None,  # type: ignore[arg-type]
            key=f"anonym_net_table_{date_sel}_{int(st.session_state.get('anonym_net_table_nonce', 0))}",
            height=_table_height_for_rows(len(table), min_px=320, max_px=640),
            update_mode=GridUpdateMode.SELECTION_CHANGED,
            wrap_shell=False,
            hide_top_border=True,
        )

    if HAS_AGGRID and isinstance(table_response, dict):
        edited = table_response.get("data", None)
        if isinstance(edited, pd.DataFrame):
            edited_df = edited.copy()
        elif isinstance(edited, list):
            edited_df = pd.DataFrame(edited)
        else:
            edited_df = pd.DataFrame()

        if (
            not edited_df.empty
            and "Allow" in edited_df.columns
            and "_allow_key" in edited_df.columns
            and not st.session_state.get("anonym_net_allow_dialog_open")
        ):
            edited_df["Allow"] = edited_df["Allow"].apply(_coerce_checkbox_bool)
            edited_df["Allowlisted"] = edited_df.get("Allowlisted", False)
            edited_df["Allowlisted"] = edited_df["Allowlisted"].apply(_coerce_checkbox_bool)
            edited_df["_was_allowed"] = edited_df["_allow_key"].astype(str).map(
                lambda k: bool(original_allow_map.get(k, False))
            )
            newly_allowed = edited_df[
                (edited_df["Allow"])
                & (~edited_df["_was_allowed"])
                & (~edited_df["Allowlisted"])
            ]
            if not newly_allowed.empty:
                pick = newly_allowed.iloc[0]
                _open_anonymization_allow_dialog(
                    {
                        "_allow_key": str(pick.get("_allow_key", "")),
                        "source_ip": str(pick.get("_allow_src_ip", "")),
                        "source_mac": str(pick.get("_allow_src_mac", "")),
                        "destination_ip": str(pick.get("_allow_dst_ip", "")),
                        "destination_host": str(pick.get("_allow_dst_host", "")),
                    }
                )
                st.rerun()

    _render_table_information(
        f"{len(table):,} incident rows shown for the selected dataset scope.",
        [
            "Rows are event-level Proxy/VPN/Tor incidents after dedup and current filters/search.",
            "`Allow` is editable for non-allowlisted rows and writes to the allowlist after confirmation.",
            "Sorting is risk-first (`Risk_Score`, then `ts`) and capped to the top 100 unique events.",
        ],
    )
    export_table = pd.DataFrame(table_response.get("data", [])) if isinstance(table_response, dict) else pd.DataFrame()
    if export_table.empty:
        export_table = table.drop(
            columns=["Allow", "_allow_key", "_allow_src_ip", "_allow_src_mac", "_allow_dst_ip", "_allow_dst_host"],
            errors="ignore",
        ).copy()
    st.download_button(
        "Download CSV",
        data=export_table.to_csv(index=False).encode("utf-8"),
        file_name=f"anonymization_network_{date_sel}.csv",
        mime="text/csv",
        key=f"anonym_net_csv_{date_sel}",
    )

def render_shadow_tunnels(parquet_root: Path):
    # Backward-compatible alias.
    render_anonymization_network(parquet_root)
