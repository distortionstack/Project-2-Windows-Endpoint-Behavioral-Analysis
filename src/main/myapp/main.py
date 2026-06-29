"""main.py — Windows Endpoint Behavioral Analysis pipeline (orchestrator)."""

import argparse
import logging
import sys
import webbrowser
from pathlib import Path

import sys
from pathlib import Path

# ดึง path ของโฟลเดอร์ src เข้ามาอยู่ในระบบ search ของ Python
sys.path.append(str(Path(__file__).resolve().parents[3]))

# หลังจากนั้นค่อยทำการ import ตามปกติ

from src.main.myapp.utils.logger import setup_logging
from src.main.myapp.loader.cache import get_smart_data
from src.main.myapp.loader.normalize import normalize
from src.main.myapp.features.extractor import run_detection
from src.main.myapp.ml.predict import run_ml
from src.main.myapp.features.mitre import tag_dataframe
from src.main.myapp.export.json_export import export_results, export_evaluation
from src.main.myapp.dashboard.builder import build_dashboard
from src.main.myapp.sigma.loader import load_rules
from src.main.myapp.sigma.matcher import match_rules
from src.main.myapp.sigma.comparator import compare_ml_vs_sigma
from src.main.myapp.ml.supervised import (
    load_supervised_model, predict_supervised, prepare_training_data,
    train_lightgbm, _extract_technique_label,
)
from src.main.myapp.ml.metrics import evaluate_model

setup_logging()
logger = logging.getLogger(__name__)

OUT_DIR   = Path(__file__).resolve().parent.parent / "output"
OUT_DASH  = OUT_DIR / "dashboard.html"


def parse_args():
    parser = argparse.ArgumentParser(description="Analyze Windows endpoint event logs.")
    parser.add_argument(
        "-s", "--source", action="append",
        default=["https://github.com/OTRF/Security-Datasets/raw/refs/heads/master/datasets/compound/LSASS_campaign_01/metasploit_logonpasswords_lsass_memory_dump.zip"],
        required=False,
        help="Input source (path, URL, ZIP, tar.gz, JSON, CSV).",
    )
    parser.add_argument("--force-update", action="store_true", help="Ignore cache and reload sources.")
    parser.add_argument("--no-browser",   action="store_true", help="Do not auto-open dashboard.")
    parser.add_argument(
        "--model-type", choices=["isolation_forest", "lightgbm"],
        default="isolation_forest",
        help="ML model type for detection (default: isolation_forest).",
    )
    parser.add_argument(
        "--train", action="store_true",
        help="Train LightGBM model on loaded sources before inference.",
    )
    return parser.parse_args()


def validate_data(df):
    if df is None or df.empty:
        raise ValueError(
            "Pipeline validation failed: No data loaded. "
            "Please check your data source (URL, file path, archive)."
        )

    if "@timestamp" not in df.columns:
        raise KeyError(
            "Pipeline validation failed: Missing mandatory column '@timestamp'. "
            "Ensure your source contains timestamp information."
        )

    if "EventID" not in df.columns:
        raise KeyError(
            "Pipeline validation failed: Missing mandatory column 'EventID'. "
            "Ensure your source contains Windows event IDs."
        )

    logger.info(f"Data validation passed: {len(df):,} events from {df['_host'].nunique()} hosts")


def run_detection_and_aggregate(df: pd.DataFrame) -> pd.DataFrame:
    from src.main.myapp.features.aggregate import aggregate
    return aggregate(df)


def print_summary(df, agg, suspicious_windows, threats, evaluation=None, supervised_eval=None):
    print()
    print("+------------------------------------------------------+")
    print("|     WINDOWS ENDPOINT BEHAVIORAL ANALYSIS RESULTS     |")
    print("+------------------------------------------------------+")
    print(f"|  Total events           : {len(df):>6,}                    |")
    print(f"|  Total hosts            : {df['_host'].nunique():>6,}                    |")
    print(f"|  5-min windows          : {len(agg):>6,}                    |")
    print(f"|  Anomalous windows (ML) : {int(agg['is_anomaly'].sum()):>6,}                    |")
    print(f"|  Suspicious windows     : {len(suspicious_windows):>6,}                    |")
    print(f"|  Events in susp windows : {len(threats):>6,}                    |")
    print("+------------------------------------------------------+")
    if evaluation:
        ew = evaluation["window_level"]
        print(f"|  Sigma-matched windows  : {ew['sigma_positive_windows']:>6,}                    |")
        print(f"|  ML vs Sigma precision  : {ew['precision']:>6.1%}                    |")
        print(f"|  ML vs Sigma recall     : {ew['recall']:>6.1%}                    |")
        print("+------------------------------------------------------+")
    print(f"|  alerts_full.json       -> {OUT_DIR / 'alerts_full.json'}          |")
    print(f"|  aggregated_windows.json-> {OUT_DIR / 'aggregated_windows.json'}     |")
    if supervised_eval:
        print(f"|  Supervised accuracy    : {supervised_eval['accuracy']:>6.1%}                    |")
        print(f"|  Supervised macro F1   : {supervised_eval['macro_avg']['f1_score']:>6.1%}                    |")
        print("+------------------------------------------------------+")
    print(f"|  evaluation_metrics.json-> {OUT_DIR / 'evaluation_metrics.json'}     |")
    print(f"|  dashboard.html         -> {OUT_DASH}            |")
    print("+------------------------------------------------------+")

    bool_cols = [c for c in df.columns if c.startswith("has_") or c.startswith("is_") or c.startswith("susp_")]
    if bool_cols:
        print("\nBehavioral Signal Summary:")
        for col in sorted(bool_cols):
            total = int(df[col].sum())
            if total > 0:
                print(f"   {col:<30} : {total:>4}")


def run_pipeline(sources, force_update=False, open_browser=True, model_type="isolation_forest", do_train=False):
    try:
        if do_train and model_type == "lightgbm":
            print("[TRAIN] Preparing supervised training data...")
            labeled = [(src, _extract_technique_label(src)) for src in sources]
            X, y, features = prepare_training_data(labeled)
            model, scaler, le = train_lightgbm(X, y, features, save=True)
            logger.info(f"Training complete: {len(le.classes_)} techniques")

            X_scaled = scaler.transform(X)
            if hasattr(model, "predict_proba"):
                y_prob = model.predict_proba(X_scaled)
                y_pred_idx = y_prob.argmax(axis=1)
            else:
                y_prob = model.predict(X_scaled)
                y_pred_idx = y_prob.argmax(axis=1)
            y_pred = le.inverse_transform(y_pred_idx)
            supervised_eval = evaluate_model(y, y_pred, y_prob, list(le.classes_), output_dir=OUT_DIR)
            export_evaluation({"window_level": {}, "event_level": {}}, OUT_DIR)
            logger.info(f"Training complete: accuracy={supervised_eval['accuracy']:.3f}, macro-F1={supervised_eval['macro_avg']['f1_score']:.3f}")
            return

        print("[1/5] Loading & normalising...")
        df = normalize(get_smart_data(sources, force_update=force_update))
        validate_data(df)

        print("[2/5] Running behavioral feature extraction...")
        df = run_detection(df)

        print("[2.5/5] Tagging MITRE ATT&CK techniques on full dataset...")
        df = tag_dataframe(df)

        supervised_eval = None

        if model_type == "lightgbm":
            print("[3/5] Running LightGBM supervised prediction...")
            agg = run_detection_and_aggregate(df)

            model_bundle = load_supervised_model()
            if model_bundle is None:
                logger.warning("No LightGBM model found. Run with --train first.")
                agg["supervised_technique"] = ""
                agg["supervised_confidence"] = 0.0
                feat_deviation = pd.Series(dtype=float)
                suspicious_windows = pd.DataFrame()
                threats = pd.DataFrame()
            else:
                model, scaler, le, features = model_bundle
                agg = predict_supervised(agg, model, scaler, le, features)
                logger.info(
                    f"Top predicted technique: {agg['supervised_technique'].mode().iloc[0] if not agg.empty else 'N/A'}"
                )
                feat_deviation = pd.Series(dtype=float)
                suspicious_windows = agg[agg["supervised_confidence"] > 0.5].copy() if "supervised_confidence" in agg.columns else agg.nsmallest(10, "supervised_confidence").copy()
                threats = df.merge(
                    suspicious_windows[["_host", "ml_time_window"]],
                    on=["_host", "ml_time_window"], how="inner",
                ) if not suspicious_windows.empty else pd.DataFrame()

            export_results(threats, agg, OUT_DIR)

        else:
            print("[3/5] Running ML pipeline (Isolation Forest)...")
            agg, feat_deviation, suspicious_windows, threats = run_ml(df)
            logger.info(f"ML complete. Anomalous windows: {agg['is_anomaly'].sum()}")

            print("[4/5] MITRE tags already applied from full dataset...")

            export_results(threats, agg, OUT_DIR)

        print("[5/6] Running Sigma rule matching...")
        sigma_rules = load_rules(force_update=False)
        df = match_rules(df, sigma_rules)
        evaluation = compare_ml_vs_sigma(agg, df)

        if "mitre_techniques" not in df.columns:
            df = tag_dataframe(df)
        export_evaluation(evaluation, OUT_DIR, df=df)
        logger.info(
            f"Sigma: {evaluation['window_level']['sigma_positive_windows']} windows matched, "
            f"{evaluation['event_level']['sigma_matched_events']} events matched"
        )

        print("[6/6] Building dashboard...")
        build_dashboard(df, agg, suspicious_windows, threats, feat_deviation, OUT_DASH, evaluation=evaluation)
        print_summary(df, agg, suspicious_windows, threats, evaluation, supervised_eval)

        if open_browser:
            webbrowser.open(OUT_DASH.resolve().as_uri())

        logger.info("Pipeline completed successfully!")

    except FileNotFoundError as e:
        logger.error(f"File error: {e}")
        raise SystemExit(1)
    except KeyError as e:
        logger.error(f"Schema error: {e}")
        raise SystemExit(1)
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise SystemExit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        raise SystemExit(1)


def main():
    args = parse_args()
    run_pipeline(
        args.source,
        force_update=args.force_update,
        open_browser=not args.no_browser,
        model_type=args.model_type,
        do_train=args.train,
    )


if __name__ == "__main__":
    main()
