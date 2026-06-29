"""severity.py — Anomaly severity scoring, behavioral hits, threat mapping."""

import logging

import numpy as np
import pandas as pd

from src.main.myapp.config.constants import REASON_MAP
from src.main.myapp.config.settings import get

logger = logging.getLogger(__name__)

DEFAULT_TIME_WINDOW = get("ml.time_window", "5min")


def add_severity(agg: pd.DataFrame) -> pd.DataFrame:
    signal_cols = [c for c in agg.columns if c.endswith("_sum")]
    agg["behavioral_hits"] = (agg[signal_cols] > 0).sum(axis=1)

    if "anomaly_risk" not in agg.columns:
        agg["anomaly_risk"] = 0.0

    max_hits = max(agg["behavioral_hits"].max(), 1)
    agg["severity_score"] = agg["behavioral_hits"] + (agg["anomaly_risk"] * max_hits * 0.5)

    severity_bins = get("ml.severity_thresholds", {
        "low": [0, 1],
        "medium": [1, 3],
        "high": [3, 6],
        "critical": [6, 999999],
    })

    bins = []
    labels = []
    for label, (lower, upper) in sorted(severity_bins.items(), key=lambda x: x[1][0]):
        if not bins or lower != bins[-1]:
            bins.append(lower - 0.001)
        bins.append(upper)
        labels.append(label)

    agg["severity"] = pd.cut(agg["severity_score"], bins=bins, labels=labels[:len(bins) - 1])

    reasons_data = {}
    for col, label in REASON_MAP:
        if col in agg.columns:
            reasons_data[label] = (agg[col] > 0).astype(bool)

    top_reasons_list = []
    for idx in range(len(agg)):
        hits = [label for label, value in reasons_data.items() if value.iloc[idx]]
        if not hits and agg["is_anomaly"].iloc[idx]:
            top_reasons_list.append("Behavioral anomaly")
        else:
            top_reasons_list.append(", ".join(hits[:4]) if hits else "—")

    agg["top_reasons"] = top_reasons_list

    return agg


def map_threats(df: pd.DataFrame, agg: pd.DataFrame):
    suspicious_cols = ["_host", "ml_time_window", "severity", "severity_score",
                       "anomaly_score", "top_reasons"]
    suspicious = agg[suspicious_cols].copy()

    df = df.copy()
    if "ml_time_window" not in df.columns:
        df["ml_time_window"] = df["@timestamp"].dt.floor(DEFAULT_TIME_WINDOW)

    threats = df.merge(suspicious, on=["_host", "ml_time_window"], how="inner")

    logger.info(f"Mapped {len(threats)} threat events from {len(suspicious)} suspicious windows")
    return suspicious, threats
