"""evaluation.py — Post-prediction feature deviation analysis."""

import logging

import pandas as pd

logger = logging.getLogger(__name__)


def compute_feature_deviation(X: pd.DataFrame, features: list, mask: pd.Series) -> pd.Series:
    if not mask.any():
        return pd.Series(dtype=float)
    feat_deviation = pd.Series({
        c: float(X[c][mask].mean() - X[c].mean())
        for c in features
    }).abs().sort_values(ascending=False)
    return feat_deviation
