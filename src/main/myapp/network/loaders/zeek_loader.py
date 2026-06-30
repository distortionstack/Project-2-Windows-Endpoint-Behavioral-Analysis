"""zeek_loader.py — Parses Zeek ASCII TSV conn.log into NetworkFlow rows."""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import pandas as pd

from src.main.myapp.network.schemas import NETWORK_FLOW_COLUMNS, empty_network_df

logger = logging.getLogger(__name__)


def _parse_header(path: Path) -> Tuple[List[str], Set[str]]:
    """
    Read #fields and placeholder values from a Zeek log header.
    Returns (field_names, placeholder_set).
    The data rows themselves use real tab characters; only #separator says '\\x09' as literal text.
    """
    fields: List[str] = []
    placeholders: Set[str] = {"-", "(empty)"}

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                parts = line.split("\t")
                fields = parts[1:]
            elif line.startswith("#unset_field"):
                parts = line.split("\t")
                if len(parts) > 1:
                    placeholders.add(parts[1])
            elif line.startswith("#empty_field"):
                parts = line.split("\t")
                if len(parts) > 1:
                    placeholders.add(parts[1])
            elif not line.startswith("#"):
                break

    return fields, placeholders


def _coerce(val: str, placeholders: Set[str]) -> Optional[str]:
    """Return None for Zeek placeholder values, otherwise the raw string."""
    return None if val in placeholders else val


def _load_zeek_conn(path: Path) -> pd.DataFrame:
    """Parse a Zeek conn.log; return rows mapped to NETWORK_FLOW_COLUMNS (minus _source_type)."""
    try:
        fields, placeholders = _parse_header(path)
    except Exception:
        logger.warning(f"Failed to read Zeek header from {path}", exc_info=True)
        return pd.DataFrame()

    if not fields:
        logger.warning(f"No #fields line found in {path}")
        return pd.DataFrame()

    # Build index map: field name → column position (never hardcode positions)
    idx: Dict[str, int] = {name: i for i, name in enumerate(fields)}

    rows = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split("\t")
                if len(parts) < len(fields):
                    continue

                def get(name: str) -> Optional[str]:
                    i = idx.get(name)
                    if i is None or i >= len(parts):
                        return None
                    return _coerce(parts[i], placeholders)

                # Timestamp: Zeek epoch float seconds → UTC pd.Timestamp
                ts_raw = get("ts")
                try:
                    ts = pd.to_datetime(float(ts_raw), unit="s", utc=True) if ts_raw else None
                except (ValueError, TypeError):
                    ts = None

                proto_raw = get("proto")
                proto = proto_raw.upper() if proto_raw else None

                def _int(val: Optional[str]) -> Optional[int]:
                    try:
                        return int(val) if val is not None else None
                    except (ValueError, TypeError):
                        return None

                def _float(val: Optional[str]) -> Optional[float]:
                    try:
                        return float(val) if val is not None else None
                    except (ValueError, TypeError):
                        return None

                rows.append({
                    "@timestamp":   ts,
                    "uid":          get("uid"),
                    "src_ip":       get("id.orig_h"),
                    "src_port":     _int(get("id.orig_p")),
                    "dst_ip":       get("id.resp_h"),
                    "dst_port":     _int(get("id.resp_p")),
                    "proto":        proto,
                    "duration_sec": _float(get("duration")),
                    "bytes_sent":   _int(get("orig_bytes")),
                    "bytes_recv":   _int(get("resp_bytes")),
                    "pkts_sent":    _int(get("orig_pkts")),
                    "pkts_recv":    _int(get("resp_pkts")),
                    "conn_state":   get("conn_state"),
                })

    except Exception:
        logger.warning(f"Failed to parse Zeek conn.log {path}", exc_info=True)
        return pd.DataFrame()

    return pd.DataFrame(rows) if rows else pd.DataFrame()


def _load_zeek_dns(path: Path) -> Dict[str, str]:
    """Parse a Zeek dns.log; return {uid: dns_query} for enriching conn.log rows."""
    uid_dns: Dict[str, str] = {}
    try:
        fields, placeholders = _parse_header(path)
        if not fields:
            return uid_dns
        idx = {name: i for i, name in enumerate(fields)}
        uid_i = idx.get("uid")
        query_i = idx.get("query")
        if uid_i is None or query_i is None:
            return uid_dns
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split("\t")
                if max(uid_i, query_i) >= len(parts):
                    continue
                uid = _coerce(parts[uid_i], placeholders)
                query = _coerce(parts[query_i], placeholders)
                if uid and query and uid not in uid_dns:
                    uid_dns[uid] = query
    except Exception:
        logger.warning(f"Failed to parse Zeek dns.log {path}", exc_info=True)
    return uid_dns


def load_zeek(path: Path) -> pd.DataFrame:
    """Load a Zeek log. conn.log is loaded as flow records; dns.log is used only for enrichment."""
    path = Path(path)

    if path.name != "conn.log":
        if path.name == "dns.log":
            logger.info(f"Skipping {path} — dns.log is used only for enrichment alongside conn.log")
        else:
            logger.warning(f"Unsupported Zeek log type '{path.name}'; only conn.log is loaded as flows")
        return empty_network_df()

    conn_df = _load_zeek_conn(path)
    if conn_df is None or conn_df.empty:
        return empty_network_df()

    # DNS enrichment: look for dns.log in the same directory
    dns_path = path.parent / "dns.log"
    if dns_path.exists():
        uid_dns = _load_zeek_dns(dns_path)
        if uid_dns and "uid" in conn_df.columns:
            conn_df["dns_query"] = conn_df["uid"].map(uid_dns)

    # Drop uid helper column before enforcing contract
    conn_df = conn_df.drop(columns=["uid"], errors="ignore")
    conn_df["_source_type"] = "zeek"

    # Ensure all contract columns are present
    for col in NETWORK_FLOW_COLUMNS:
        if col not in conn_df.columns:
            conn_df[col] = None

    return conn_df[NETWORK_FLOW_COLUMNS]
