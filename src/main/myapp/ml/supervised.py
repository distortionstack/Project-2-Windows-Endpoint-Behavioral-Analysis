"""supervised.py — LightGBM multi-class training and inference on aggregated windows."""

import logging
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, RobustScaler

from src.main.myapp.config.constants import ML_FEATURES
from src.main.myapp.config.settings import get
from src.main.myapp.features.aggregate import aggregate
from src.main.myapp.features.extractor import run_detection
from src.main.myapp.loader.normalize import normalize

logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "models"
LGBM_FILE = MODEL_DIR / get("model_persistence.lightgbm_filename", "lightgbm_model.txt")
LGBM_SCALER_FILE = MODEL_DIR / get("model_persistence.lightgbm_scaler_filename", "lightgbm_scaler.pkl")
LGBM_ENCODER_FILE = MODEL_DIR / get("model_persistence.lightgbm_encoder_filename", "lightgbm_encoder.pkl")
LGBM_FEATURES_FILE = MODEL_DIR / get("model_persistence.lightgbm_features_filename", "lightgbm_features.pkl")


def _ensure_model_dir():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)


def _load_data(source_paths: list[str]) -> pd.DataFrame:
    frames = []
    for path in source_paths:
        logger.info(f"Loading source: {path}")
        raw = normalize(pd.read_json(path, lines=True) if path.endswith((".json", ".jsonl", ".ndjson")) else pd.read_csv(path))
        frames.append(raw)
    return pd.concat(frames, ignore_index=True)


def _extract_technique_label(source_path: str) -> str:
    path = source_path.lower()
    if "credential_access" in path:
        return "T1003"
    if "defense_evasion" in path:
        return "T1055"
    if "execution" in path:
        return "T1059"
    if "persistence" in path:
        return "T1547"
    if "privilege_escalation" in path:
        return "T1548"
    if "discovery" in path:
        return "T1087"
    if "lateral_movement" in path:
        return "T1021"
    if "collection" in path:
        return "T1005"
    if "exfiltration" in path:
        return "T1048"
    if "command_and_control" in path:
        return "T1071"
    return "T9999"


def prepare_training_data(
    sources: list[tuple[str, str]],
) -> tuple[pd.DataFrame, np.ndarray, list[str]]:
    all_windows = []
    all_labels = []

    for src_path, technique_label in sources:
        logger.info(f"Processing {technique_label}: {src_path}")
        try:
            raw = normalize(
                pd.read_json(src_path, lines=True)
                if src_path.endswith((".json", ".jsonl", ".ndjson"))
                else pd.read_csv(src_path)
            )
        except Exception as e:
            logger.warning(f"Failed to load {src_path}: {e}")
            continue
        df = run_detection(raw)
        agg = aggregate(df)
        if agg.empty:
            continue
        agg["technique_id"] = technique_label
        all_windows.append(agg)
        all_labels.extend([technique_label] * len(agg))

    if not all_windows:
        raise ValueError("No training data loaded from any source")

    combined = pd.concat(all_windows, ignore_index=True)
    logger.info(f"Training data: {len(combined)} windows across {len(set(all_labels))} techniques")

    features = [f for f in ML_FEATURES if f in combined.columns]
    X = combined[features].fillna(0).astype(float)
    y = np.array(all_labels)
    return X, y, features


def train_lightgbm(
    X: pd.DataFrame,
    y: np.ndarray,
    features: list[str],
    save: bool = True,
) -> tuple[lgb.LGBMClassifier, RobustScaler, LabelEncoder]:
    logger.info(f"Training LightGBM on {len(X)} samples with {len(features)} features")

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    lgb_config = get("lightgbm", {})
    model = lgb.LGBMClassifier(
        objective="multiclass",
        num_class=len(le.classes_),
        n_estimators=lgb_config.get("n_estimators", 200),
        max_depth=lgb_config.get("max_depth", 10),
        learning_rate=lgb_config.get("learning_rate", 0.05),
        num_leaves=lgb_config.get("num_leaves", 31),
        subsample=lgb_config.get("subsample", 0.8),
        colsample_bytree=lgb_config.get("colsample_bytree", 0.8),
        random_state=lgb_config.get("random_state", 42),
        n_jobs=lgb_config.get("n_jobs", -1),
        verbose=lgb_config.get("verbose", -1),
    )

    model.fit(
        X_scaled, y_enc,
        eval_set=[(X_scaled, y_enc)],
        eval_metric="multi_logloss",
    )

    logger.info(f"LightGBM training complete. Classes: {list(le.classes_)}")

    if save:
        _ensure_model_dir()
        joblib.dump(scaler, LGBM_SCALER_FILE)
        joblib.dump(le, LGBM_ENCODER_FILE)
        joblib.dump(features, LGBM_FEATURES_FILE)
        model.booster_.save_model(str(LGBM_FILE))
        logger.info(f"LightGBM model saved to {LGBM_FILE}")

    return model, scaler, le


def load_supervised_model() -> tuple[lgb.Booster, RobustScaler, LabelEncoder, list[str]] | None:
    if not LGBM_FILE.exists():
        logger.warning(f"No LightGBM model found at {LGBM_FILE}")
        return None
    model = lgb.Booster(model_file=str(LGBM_FILE))
    scaler = joblib.load(LGBM_SCALER_FILE)
    le = joblib.load(LGBM_ENCODER_FILE)
    features = joblib.load(LGBM_FEATURES_FILE)
    logger.info(f"LightGBM model loaded from {LGBM_FILE} ({len(le.classes_)} classes)")
    return model, scaler, le, features


def predict_supervised(
    agg: pd.DataFrame,
    model: lgb.Booster | lgb.LGBMClassifier,
    scaler: RobustScaler,
    le: LabelEncoder,
    features: list[str],
) -> pd.DataFrame:
    present = [f for f in features if f in agg.columns]
    missing = set(features) - set(present)
    if missing:
        logger.warning(f"Missing features during prediction: {missing}")

    X = agg[present].fillna(0).astype(float)
    X_scaled = scaler.transform(X)

    if isinstance(model, lgb.LGBMClassifier):
        y_prob = model.predict_proba(X_scaled)
    else:
        y_prob = model.predict(X_scaled)
    y_pred_idx = np.argmax(y_prob, axis=1)

    agg["supervised_technique"] = le.inverse_transform(y_pred_idx)
    agg["supervised_confidence"] = np.max(y_prob, axis=1)

    for i, cls_name in enumerate(le.classes_):
        col = f"prob_{cls_name}"
        agg[col] = y_prob[:, i]

    return agg
