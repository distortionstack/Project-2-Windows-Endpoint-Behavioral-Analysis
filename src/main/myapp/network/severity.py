"""severity.py — Heuristic severity scoring for network flows (mirrors detection/severity.py)."""

import logging

import pandas as pd

from src.main.myapp.config.settings import get

logger = logging.getLogger(__name__)


def score_row(row) -> float:
    """Compute a heuristic severity score 0–10 for a single network flow row."""
    score = 0.0

    if pd.notna(row.get("alert_severity")):
        # Suricata severity: 1=highest, 3=lowest — invert onto a 0–10 scale
        score += {1: 8, 2: 5, 3: 2}.get(int(row["alert_severity"]), 2)

    if row.get("susp_port"):
        score += 3
    if row.get("susp_ip"):
        score += 4
    if row.get("susp_domain"):
        score += 3

    # Failed/rejected connection to suspicious target is scan-like behaviour
    if row.get("conn_state") in ("S0", "REJ", "RSTO", "RSTR") and (
        row.get("susp_port") or row.get("susp_ip")
    ):
        score += 1

    return min(score, 10.0)


def add_network_severity(df: pd.DataFrame) -> pd.DataFrame:
    """Add severity_score, severity label, and top_reasons columns to the network DataFrame."""
    if df is None or df.empty:
        return df

    df = df.copy()

    severity_bins = get("ml.severity_thresholds", {
        "low":      [0, 1],
        "medium":   [1, 3],
        "high":     [3, 6],
        "critical": [6, 999999],
    })

    df["severity_score"] = df.apply(score_row, axis=1)

    # Build pd.cut bins — same approach as detection/severity.py
    bins = []
    labels = []
    for label, (lower, upper) in sorted(severity_bins.items(), key=lambda x: x[1][0]):
        if not bins or lower != bins[-1]:
            bins.append(lower - 0.001)
        bins.append(upper)
        labels.append(label)

    df["severity"] = pd.cut(df["severity_score"], bins=bins, labels=labels[: len(bins) - 1])
    df["severity"] = df["severity"].astype(str)

    def _top_reasons(row) -> str:
        reasons = []
        if row.get("susp_port"):
            reasons.append("Suspicious Port")
        if row.get("susp_ip"):
            reasons.append("Suspicious IP")
        if row.get("susp_domain"):
            reasons.append("Suspicious Domain")
        sig = row.get("alert_signature")
        if sig and pd.notna(sig):
            reasons.append(str(sig)[:60])
        return ", ".join(reasons) if reasons else "—"

    df["top_reasons"] = df.apply(_top_reasons, axis=1)

    return df
