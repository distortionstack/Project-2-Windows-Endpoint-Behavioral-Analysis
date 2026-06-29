"""comparator.py — Compare ML detections vs Sigma rule matches."""

import logging

import pandas as pd

logger = logging.getLogger(__name__)


def compare_ml_vs_sigma(agg: pd.DataFrame, df: pd.DataFrame) -> dict:
    if "sigma_matched_rules" not in df.columns:
        df = df.copy()
        df["sigma_matched_rules"] = [[] for _ in range(len(df))]
    if "ml_time_window" not in df.columns:
        df = df.copy()
        from src.main.myapp.config.settings import get
        time_window = get("ml.time_window", "5min")
        df["ml_time_window"] = pd.to_datetime(
            df["@timestamp"], errors="coerce",
        ).dt.floor(time_window)

    sigma_window_match = (
        df.groupby(["_host", "ml_time_window"])["sigma_matched_rules"]
        .apply(lambda x: any(len(r) > 0 for r in x))
        .reset_index(name="sigma_matched")
    )

    comp = agg[["_host", "ml_time_window", "is_anomaly"]].merge(
        sigma_window_match, on=["_host", "ml_time_window"], how="left",
    )
    comp["sigma_matched"] = comp["sigma_matched"].fillna(False)

    ml_pos = comp["is_anomaly"]
    sig_pos = comp["sigma_matched"]

    tp = int((ml_pos & sig_pos).sum())
    fp = int((ml_pos & ~sig_pos).sum())
    fn = int((~ml_pos & sig_pos).sum())
    tn = int((~ml_pos & ~sig_pos).sum())

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    event_comparison = _compare_events(df)

    return {
        "window_level": {
            "total_windows": len(comp),
            "ml_positive_windows": int(ml_pos.sum()),
            "sigma_positive_windows": int(sig_pos.sum()),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
        },
        "event_level": event_comparison,
    }


def _compare_events(df: pd.DataFrame) -> dict:
    has_sigma = "sigma_matched_rules" in df.columns
    sigma_matched = (
        df["sigma_matched_rules"].apply(len) > 0
        if has_sigma
        else pd.Series(False, index=df.index)
    )

    total_events = len(df)
    sigma_positive = int(sigma_matched.sum())

    return {
        "total_events": total_events,
        "sigma_matched_events": sigma_positive,
        "sigma_match_rate": round(sigma_positive / total_events, 4)
        if total_events > 0
        else 0.0,
    }
