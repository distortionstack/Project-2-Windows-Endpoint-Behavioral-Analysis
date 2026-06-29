"""preprocessing.py — Feature preparation and RobustScaler for ML pipeline."""

import logging

import pandas as pd
from sklearn.preprocessing import RobustScaler

from src.main.myapp.config.constants import ML_FEATURES

logger = logging.getLogger(__name__)


def prepare_features(agg: pd.DataFrame):
    features = [f for f in ML_FEATURES if f in agg.columns]
    missing = set(ML_FEATURES) - set(features)
    if missing:
        logger.warning(f"Missing ML features (will be skipped): {missing}")
    X = agg[features].fillna(0).astype(float)
    return X, features


def scale_features(X, scaler=None, fit=False):
    if scaler is None:
        scaler = RobustScaler()
    if fit:
        X_scaled = scaler.fit_transform(X)
    else:
        X_scaled = scaler.transform(X)
    return X_scaled, scaler
