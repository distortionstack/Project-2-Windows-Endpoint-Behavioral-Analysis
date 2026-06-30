"""json_export.py — Export pipeline results to JSON files."""

import json
import logging
from pathlib import Path

import pandas as pd

from src.main.myapp.features.sequence import detect_sequences, summarize_chains

logger = logging.getLogger(__name__)


def export_results(threats, agg, out_dir: Path):
    export_cols = [
        "@timestamp", "_host", "EventID", "_channel", "_action",
        "_process", "_parent", "_cmd", "_net_dst",
        "susp_port", "susp_ip", "susp_dns",
        "anomaly_score", "severity", "top_reasons", "mitre_techniques",
        "Hashes", "Signed", "SignatureStatus",
    ]
    available = [c for c in export_cols if c in threats.columns]
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    threats[available].to_json(out_dir / "alerts_full.json", orient="records", indent=2)
    agg.to_json(out_dir / "aggregated_windows.json", orient="records", indent=2)


def _load_supervised_metrics(out_dir: Path) -> dict | None:
    sup_path = out_dir / "supervised_metrics.json"
    if sup_path.exists():
        try:
            with open(sup_path) as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load supervised_metrics.json: {e}")
    return None


def export_evaluation(
    evaluation: dict,
    out_dir: Path,
    df: pd.DataFrame | None = None,
    chain_result: dict | None = None,
):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    full: dict = {
        "sigma_comparison": evaluation,
    }

    sup = _load_supervised_metrics(out_dir)
    if sup:
        full["supervised_metrics"] = sup

    if chain_result is not None:
        full["attack_chain_analysis"] = chain_result
    elif df is not None:
        try:
            seq = detect_sequences(df)
            chain_summary = summarize_chains(seq)
            full["attack_chain_analysis"] = chain_summary
        except Exception as e:
            logger.warning(f"Chain analysis failed: {e}")

    path = out_dir / "evaluation_metrics.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(full, f, indent=2, default=str)
    logger.info(f"Evaluation metrics saved to {path}")
