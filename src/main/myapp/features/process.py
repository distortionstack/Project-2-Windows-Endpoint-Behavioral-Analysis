"""process.py — Process Create, Process Access, and meta feature extraction."""

import logging
import re

import numpy as np
import pandas as pd

from src.main.myapp.config.constants import _FLAT_TAXONOMY, BOOL_FEATURES
from src.main.myapp.config.regex import (
    PS_RE_ADVANCED, MSHTA_RE, RUNDLL32_RE, LSASS_RE,
)

logger = logging.getLogger(__name__)


def calculate_entropy(text: str) -> float:
    if not text or len(text) == 0:
        return 0.0
    text_str = str(text)
    probs = [float(text_str.count(c)) / len(text_str) for c in set(text_str)]
    return -sum(p * np.log2(p) for p in probs)


def _get_text_series(df: pd.DataFrame) -> pd.Series:
    cols = ["_process", "_cmd", "_parent", "HostApplication", "message"]
    parts = [df[c].fillna("").astype(str) for c in cols if c in df.columns]
    if not parts:
        return pd.Series([""] * len(df), index=df.index)
    return pd.concat(parts, axis=1).agg(" ".join, axis=1)


def tag_event_names(df: pd.DataFrame) -> pd.DataFrame:
    if "_channel" not in df.columns or "EventID" not in df.columns:
        logger.warning(
            "tag_event_names: missing _channel or EventID — "
            "filling _event_name with 'Unknown Event'."
        )
        df["_event_name"] = "Unknown Event"
        return df

    temp_keys = df["_channel"].astype(str) + "_" + df["EventID"].astype(str)
    df["_event_name"] = temp_keys.map(_FLAT_TAXONOMY).fillna("Unknown Event")

    if logger.isEnabledFor(logging.DEBUG):
        unknown_count = (df["_event_name"] == "Unknown Event").sum()
        if unknown_count > 0:
            logger.debug(
                f"tag_event_names: {unknown_count}/{len(df)} rows tagged 'Unknown Event'. "
                f"Sample unmapped keys: {temp_keys[df['_event_name'] == 'Unknown Event'].unique()[:5].tolist()}"
            )

    return df


def extract_process_features(df: pd.DataFrame, text: pd.Series) -> pd.DataFrame:
    m = df["_event_name"].astype(str).str.contains("Process Create", na=False)
    if not m.any():
        return df

    df["has_powershell"] = (m & text.str.contains(PS_RE_ADVANCED.pattern, flags=re.I, regex=True)).astype("int8")

    office_parent = df["_parent"].astype(str).str.contains(
        r"(winword|excel|powerpnt|outlook|chrome|msedge)\.exe", re.I
    )
    suspicious_child = df["_process"].astype(str).str.contains(
        r"(cmd|powershell|pwsh|wmic|mshta|rundll32|certutil)\.exe", re.I
    )
    df["office_spawned_shell"] = (m & office_parent & suspicious_child).astype("int8")

    if "OriginalFileName" in df.columns:
        df["has_mshta"] = (m & df["OriginalFileName"].astype(str).str.contains(r"mshta\.exe", re.I)).astype("int8")
        df["has_rundll32"] = (m & df["OriginalFileName"].astype(str).str.contains(r"rundll32\.exe", re.I)).astype("int8")
    else:
        df["has_mshta"] = (m & df["_process"].astype(str).str.contains(MSHTA_RE.pattern, flags=re.I, regex=True)).astype("int8")
        df["has_rundll32"] = (m & df["_process"].astype(str).str.contains(RUNDLL32_RE.pattern, flags=re.I, regex=True)).astype("int8")

    return df


def extract_injection_features(df: pd.DataFrame) -> pd.DataFrame:
    is_create_remote_thread = df["_event_name"].astype(str).str.contains("CreateRemoteThread", na=False)

    is_proc_access = df["_event_name"].astype(str).str.contains("Process Access", na=False)

    if "AccessMask" in df.columns:
        mask_str = df["AccessMask"].astype(str)
    elif "winlog.event_data.AccessMask" in df.columns:
        mask_str = df["winlog.event_data.AccessMask"].astype(str)
    else:
        mask_str = pd.Series([""] * len(df), index=df.index)

    suspicious_masks = mask_str.str.contains(
        r"0x143A|0x1F3FFF|0x0010|0x0400", na=False, regex=True
    )

    df["is_process_injection"] = (
        is_create_remote_thread | (is_proc_access & suspicious_masks)
    ).astype("int8")
    return df


def extract_access_features(df: pd.DataFrame) -> pd.DataFrame:
    m = df["_event_name"].astype(str).str.contains("Process Access", na=False)
    if not m.any():
        return df
    if "_target_image" not in df.columns:
        return df

    df["is_lsass_access"] = (
        m & df["_target_image"].astype(str).str.contains(LSASS_RE.pattern, flags=re.I, regex=True)
    ).astype("int8")
    return df


def extract_meta_features(df: pd.DataFrame) -> pd.DataFrame:
    df["cmd_len"]    = df["_cmd"].astype(str).str.len()
    df["proc_depth"] = df["_process"].astype(str).str.count(r"\\")
    df["hour"]       = df["@timestamp"].dt.hour.fillna(-1).astype(int)
    df["is_system"]  = (
        df["_user"].astype(str).str.contains(
            r"^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$", na=False, regex=True
        )
    ).astype("int8")
    return df


def extract_time_delta(df: pd.DataFrame) -> pd.DataFrame:
    if "@timestamp" not in df.columns or "_host" not in df.columns:
        df["time_delta_seconds"] = 0.0
        return df

    sorted_idx = df.sort_values(["_host", "@timestamp"]).index
    deltas = (
        df.loc[sorted_idx]
        .groupby("_host")["@timestamp"]
        .diff()
        .dt.total_seconds()
        .fillna(0.0)
    )
    df["time_delta_seconds"] = deltas.reindex(df.index).fillna(0.0)
    return df


def init_bool_columns(df: pd.DataFrame) -> pd.DataFrame:
    for col in BOOL_FEATURES:
        if col not in df.columns:
            df[col] = np.int8(0)
    return df
