"""predict.py — Anomaly scoring and full ML inference orchestration."""

import logging

import pandas as pd

from src.main.myapp.config.settings import get
from src.main.myapp.ml.preprocessing import prepare_features, scale_features
from src.main.myapp.ml.train import (
    load_models, save_models, train_model,
    MIN_WINDOWS_FOR_ML, SCALER_FILE, IFOREST_FILE, MODEL_DIR,
)
from src.main.myapp.ml.evaluation import compute_feature_deviation
from src.main.myapp.features.aggregate import aggregate
from src.main.myapp.detection.severity import add_severity, map_threats

logger = logging.getLogger(__name__)


def score_anomalies(model, X_scaled, agg):
    raw_score = model.score_samples(X_scaled)
    agg["anomaly_score"] = -raw_score
    agg["is_anomaly"] = model.predict(X_scaled) == -1
    agg["anomaly_risk"] = agg["anomaly_score"].rank(pct=True)
    return agg


def run_isolation_forest(agg: pd.DataFrame, use_saved_model: bool = True):
    if len(agg) < MIN_WINDOWS_FOR_ML:
        logger.warning(
            f"Only {len(agg)} windows — need >= {MIN_WINDOWS_FOR_ML} for reliable Isolation Forest. "
            "Falling back to rule-based only."
        )
        agg["anomaly_score"] = 0.0
        agg["is_anomaly"] = False
        agg["anomaly_risk"] = 0.0
        return agg, pd.Series(dtype=float)

    X, features = prepare_features(agg)

    if use_saved_model and IFOREST_FILE.exists() and SCALER_FILE.exists():
        logger.info(f"[*] Loading pre-trained model from {MODEL_DIR} ...")
        scaler, model = load_models()
        X_scaled, _ = scale_features(X, scaler=scaler, fit=False)
        logger.info("Successfully used loaded model for inference")
    else:
        logger.info("[*] No existing model found (or forced to retrain). Training new Isolation Forest...")
        X_scaled, scaler = scale_features(X, fit=True)
        model = train_model(X_scaled)
        if get("model_persistence.enabled", True):
            save_models(scaler, model)
            logger.info(f"[*] Model saved successfully to {MODEL_DIR}")

    agg = score_anomalies(model, X_scaled, agg)
    feat_deviation = compute_feature_deviation(X, features, agg["is_anomaly"])

    return agg, feat_deviation


def run_ml(df: pd.DataFrame, use_saved_model: bool = False):
    agg = aggregate(df)
    agg, feat_dev = run_isolation_forest(agg, use_saved_model=use_saved_model)
    agg = add_severity(agg)
    suspicious, threats = map_threats(df, agg)
    return agg, feat_dev, suspicious, threats
