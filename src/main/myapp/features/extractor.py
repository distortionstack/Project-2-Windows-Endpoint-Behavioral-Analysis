"""extractor.py — Main feature extraction orchestrator (run_detection)."""

import logging

import pandas as pd

from src.main.myapp.features.process import (
    tag_event_names,
    extract_process_features,
    extract_access_features,
    extract_injection_features,
    extract_meta_features,
    extract_time_delta,
    init_bool_columns,
    _get_text_series,
)
from src.main.myapp.features.command import extract_command_features
from src.main.myapp.features.network import extract_network_features, extract_dns_features
from src.main.myapp.features.file import extract_file_features, extract_dll_features

logger = logging.getLogger(__name__)


def run_detection(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    df = tag_event_names(df)

    for c in ["_cmd", "_process", "_parent", "_user"]:
        if c not in df:
            df[c] = ""

    combined_text_fields = _get_text_series(df)

    df = extract_process_features(df, combined_text_fields)
    df = extract_command_features(df, combined_text_fields)
    df = extract_network_features(df)
    df = extract_file_features(df)
    df = extract_dll_features(df)
    df = extract_access_features(df)
    df = extract_dns_features(df)
    df = extract_injection_features(df)
    df = extract_meta_features(df)
    df = extract_time_delta(df)
    df = init_bool_columns(df)

    if "cmd_entropy" not in df.columns:
        df["cmd_entropy"] = 0.0
    else:
        df["cmd_entropy"] = df["cmd_entropy"].fillna(0.0)

    return df
