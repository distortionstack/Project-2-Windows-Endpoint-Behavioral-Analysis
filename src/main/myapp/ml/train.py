"""train.py — Isolation Forest training and model persistence."""

import logging
from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest

from src.main.myapp.config.settings import get

logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "models"
SCALER_FILE = MODEL_DIR / get("model_persistence.scaler_filename", "robust_scaler.pkl")
IFOREST_FILE = MODEL_DIR / get("model_persistence.isolation_forest_filename", "isolation_forest.pkl")
MIN_WINDOWS_FOR_ML = get("ml.min_windows_for_ml", 50)


def _ensure_model_dir():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)


def save_models(scaler, model):
    _ensure_model_dir()
    joblib.dump(scaler, SCALER_FILE)
    joblib.dump(model, IFOREST_FILE)
    logger.info(f"Models saved: {SCALER_FILE}, {IFOREST_FILE}")


def load_models():
    if not SCALER_FILE.exists() or not IFOREST_FILE.exists():
        return None, None
    scaler = joblib.load(SCALER_FILE)
    model = joblib.load(IFOREST_FILE)
    logger.info("Models loaded from disk")
    return scaler, model


def train_model(X_scaled):
    iforest_config = get("ml.isolation_forest", {})
    model = IsolationForest(
        n_estimators=iforest_config.get("n_estimators", 200),
        contamination=iforest_config.get("contamination", "auto"),
        random_state=iforest_config.get("random_state", 42),
        n_jobs=-1,
    )
    model.fit(X_scaled)
    return model
