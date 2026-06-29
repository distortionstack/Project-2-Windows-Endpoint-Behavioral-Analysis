"""network.py — Network connection and DNS feature extraction."""

import logging
import re

import numpy as np
import pandas as pd

from src.main.myapp.config.constants import SysmonEventIDs
from src.main.myapp.config.regex import SUSP_IP_RE, SUSP_PORTS, DNS_SUSP_RE_DYNAMIC

logger = logging.getLogger(__name__)


def extract_network_features(df: pd.DataFrame) -> pd.DataFrame:
    m = df["_event_name"].astype(str).str.contains("Network Connection", na=False)
    if not m.any():
        return df
    if "DestinationPort" not in df.columns or "DestinationIp" not in df.columns:
        return df

    ports   = pd.to_numeric(df["DestinationPort"], errors="coerce")
    ips     = df["DestinationIp"].astype(str)

    df["susp_port"]  = (m & ports.isin(SUSP_PORTS)).astype("int8")
    df["susp_ip"]    = (m & ips.str.match(SUSP_IP_RE.pattern)).astype("int8")

    df["destination_port"] = np.where(m, pd.to_numeric(df["DestinationPort"], errors="coerce"), np.nan)
    df["destination_ip"]   = np.where(m, df["DestinationIp"].astype(str), np.nan)

    return df


def extract_dns_features(df: pd.DataFrame) -> pd.DataFrame:
    m = df["EventID"] == SysmonEventIDs.DNS_QUERY
    if not m.any():
        return df
    if "QueryName" not in df.columns:
        return df

    df["susp_dns"] = (
        m & df["QueryName"].astype(str).str.contains(DNS_SUSP_RE_DYNAMIC.pattern, flags=re.I, regex=True)
    ).astype("int8")
    return df
