"""file.py — File Create, Image Loaded (DLL), and registry feature extraction."""

import logging
import re

import numpy as np
import pandas as pd

from src.main.myapp.config.regex import TEMP_FILE_RE, TEMP_DLL_RE

logger = logging.getLogger(__name__)


def extract_file_features(df: pd.DataFrame) -> pd.DataFrame:
    m = df["_event_name"].astype(str).str.contains("File Create", na=False)
    if not m.any():
        return df
    if "_target_filename" not in df.columns:
        return df

    df["is_temp_write"] = (
        m & df["_target_filename"].astype(str).str.contains(TEMP_FILE_RE.pattern, flags=re.I, regex=True)
    ).astype("int8")
    return df


def extract_dll_features(df: pd.DataFrame) -> pd.DataFrame:
    m = df["_event_name"].astype(str).str.contains("Image Loaded", na=False)
    if not m.any():
        return df
    if "_image_loaded" not in df.columns:
        return df

    df["susp_dll_path"] = (
        m & df["_image_loaded"].astype(str).str.contains(TEMP_DLL_RE.pattern, flags=re.I, regex=True)
    ).astype("int8")
    return df
