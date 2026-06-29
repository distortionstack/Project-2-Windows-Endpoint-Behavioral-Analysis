"""command.py — Command-line feature extraction (entropy, encoding, LOLBins)."""

import logging
import re
import numpy as np
import pandas as pd

from src.main.myapp.config.regex import ENC_RE, CERTUTIL_RE

logger = logging.getLogger(__name__)


def calculate_entropy(text: str) -> float:
    if not text or len(text) == 0:
        return 0.0
    text_str = str(text)
    probs = [float(text_str.count(c)) / len(text_str) for c in set(text_str)]
    return -sum(p * np.log2(p) for p in probs)


def extract_command_features(df: pd.DataFrame, text: pd.Series) -> pd.DataFrame:
    m = df["_event_name"].astype(str).str.contains("Process Create", na=False)
    if not m.any():
        return df

    df["cmd_entropy"] = np.where(m, df["_cmd"].apply(calculate_entropy), 0.0)
    df["has_base64"] = (m & text.str.contains(ENC_RE.pattern, flags=re.I, regex=True)).astype("int8")
    df["has_certutil"] = (m & df["_cmd"].astype(str).str.contains(CERTUTIL_RE.pattern, flags=re.I, regex=True)).astype("int8")

    return df
