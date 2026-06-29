"""metrics.py — Classification metrics, confusion matrix, ROC/PR curves for supervised evaluation."""

import io
import json
import logging
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    auc,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    roc_curve,
)

logger = logging.getLogger(__name__)

sns.set_style("darkgrid")


def compute_classification_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray | None = None,
    class_names: list[str] | None = None,
) -> dict:
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    per_technique = {}
    for cls_name, metrics in report.items():
        if cls_name in ("accuracy", "macro avg", "weighted avg"):
            continue
        per_technique[cls_name] = {
            "precision": round(metrics["precision"], 4),
            "recall": round(metrics["recall"], 4),
            "f1_score": round(metrics["f1-score"], 4),
            "support": int(metrics["support"]),
        }
    return {
        "per_technique": per_technique,
        "accuracy": round(report.get("accuracy", 0), 4),
        "macro_avg": {
            "precision": round(report.get("macro avg", {}).get("precision", 0), 4),
            "recall": round(report.get("macro avg", {}).get("recall", 0), 4),
            "f1_score": round(report.get("macro avg", {}).get("f1-score", 0), 4),
        },
        "weighted_avg": {
            "precision": round(report.get("weighted avg", {}).get("precision", 0), 4),
            "recall": round(report.get("weighted avg", {}).get("recall", 0), 4),
            "f1_score": round(report.get("weighted avg", {}).get("f1-score", 0), 4),
        },
    }


def generate_confusion_matrix(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: list[str],
    save_path: str | None = None,
) -> dict:
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(max(8, len(class_names) * 0.8), max(6, len(class_names) * 0.6)))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=class_names, yticklabels=class_names, ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_title("Confusion Matrix")

    plotly_data = {
        "type": "confusion_matrix",
        "labels": class_names,
        "matrix": cm.tolist(),
    }

    if save_path:
        fig.savefig(save_path, bbox_inches="tight", dpi=150)
        logger.info(f"Confusion matrix saved to {save_path}")

    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=150)
    buf.seek(0)
    plt.close(fig)

    return {"plotly": plotly_data}


def generate_roc_curves(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    class_names: list[str],
    save_path: str | None = None,
) -> dict:
    n_classes = len(class_names)
    y_true_bin = pd.get_dummies(y_true).reindex(columns=class_names, fill_value=0).to_numpy()

    roc_data = {"type": "roc_curves", "curves": []}
    fig, ax = plt.subplots(figsize=(8, 6))

    for i, cls_name in enumerate(class_names):
        fpr, tpr, _ = roc_curve(y_true_bin[:, i], y_prob[:, i])
        roc_auc = auc(fpr, tpr)
        roc_data["curves"].append({
            "class": cls_name,
            "fpr": fpr.tolist(),
            "tpr": tpr.tolist(),
            "auc": round(roc_auc, 4),
        })
        ax.plot(fpr, tpr, lw=2, label=f"{cls_name} (AUC={roc_auc:.3f})")

    ax.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.5)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curves (One-vs-Rest)")
    ax.legend(loc="lower right")

    if save_path:
        fig.savefig(save_path, bbox_inches="tight", dpi=150)
        logger.info(f"ROC curves saved to {save_path}")

    plt.close(fig)
    return roc_data


def generate_pr_curves(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    class_names: list[str],
    save_path: str | None = None,
) -> dict:
    n_classes = len(class_names)
    y_true_bin = pd.get_dummies(y_true).reindex(columns=class_names, fill_value=0).to_numpy()

    pr_data = {"type": "pr_curves", "curves": []}
    fig, ax = plt.subplots(figsize=(8, 6))

    for i, cls_name in enumerate(class_names):
        precision, recall, _ = precision_recall_curve(y_true_bin[:, i], y_prob[:, i])
        pr_auc = auc(recall, precision)
        pr_data["curves"].append({
            "class": cls_name,
            "precision": precision.tolist(),
            "recall": recall.tolist(),
            "auc": round(pr_auc, 4),
        })
        ax.plot(recall, precision, lw=2, label=f"{cls_name} (AUC={pr_auc:.3f})")

    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curves (One-vs-Rest)")
    ax.legend(loc="lower left")

    if save_path:
        fig.savefig(save_path, bbox_inches="tight", dpi=150)
        logger.info(f"PR curves saved to {save_path}")

    plt.close(fig)
    return pr_data


def evaluate_model(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray,
    class_names: list[str],
    output_dir: str | Path | None = None,
) -> dict:
    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

    metrics = compute_classification_metrics(y_true, y_pred, y_prob, class_names)
    cm_data = generate_confusion_matrix(
        y_true, y_pred, class_names,
        save_path=str(output_dir / "confusion_matrix.png") if output_dir else None,
    )
    roc_data = generate_roc_curves(
        y_true, y_prob, class_names,
        save_path=str(output_dir / "roc_curves.png") if output_dir else None,
    )
    pr_data = generate_pr_curves(
        y_true, y_prob, class_names,
        save_path=str(output_dir / "pr_curves.png") if output_dir else None,
    )

    result = {
        **metrics,
        "confusion_matrix": cm_data,
        "roc_curves": roc_data,
        "pr_curves": pr_data,
    }

    if output_dir:
        result_path = output_dir / "supervised_metrics.json"
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
        logger.info(f"Supervised metrics saved to {result_path}")

    return result
