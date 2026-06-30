"""features.py — Heuristic network flow feature extraction."""

import logging

import pandas as pd

from src.main.myapp.config.regex import DNS_SUSP_RE_DYNAMIC, SUSP_IP_RE, SUSP_PORTS

logger = logging.getLogger(__name__)


def add_network_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add boolean indicator columns (susp_port, susp_ip, susp_domain) to the network DataFrame."""
    if df is None or df.empty:
        return df

    df = df.copy()

    # susp_port: dst_port or src_port in SUSP_PORTS
    def _is_susp_port(row) -> bool:
        for col in ("dst_port", "src_port"):
            val = row.get(col)
            if val is not None and pd.notna(val):
                try:
                    if int(val) in SUSP_PORTS:
                        return True
                except (ValueError, TypeError):
                    pass
        return False

    df["susp_port"] = df.apply(_is_susp_port, axis=1).fillna(False)

    # susp_ip: dst_ip matches SUSP_IP_RE
    if "dst_ip" in df.columns:
        df["susp_ip"] = df["dst_ip"].fillna("").apply(
            lambda ip: bool(SUSP_IP_RE.search(ip)) if ip else False
        )
    else:
        df["susp_ip"] = False

    # susp_domain: dns_query or tls_sni matches DNS_SUSP_RE_DYNAMIC
    def _is_susp_domain(row) -> bool:
        for col in ("dns_query", "tls_sni"):
            val = row.get(col)
            if val and pd.notna(val):
                if DNS_SUSP_RE_DYNAMIC.search(str(val)):
                    return True
        return False

    df["susp_domain"] = df.apply(_is_susp_domain, axis=1).fillna(False)

    return df
