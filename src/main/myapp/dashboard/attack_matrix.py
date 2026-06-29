"""attack_matrix.py — MITRE ATT&CK Matrix heatmap (Plotly)."""

import logging

import numpy as np
import pandas as pd
import plotly.graph_objects as go

from src.main.myapp.config.mitre import TECHNIQUE_NAMES, TECHNIQUE_TACTIC, TACTIC_ORDER
from src.main.myapp.dashboard.theme import BASE_LAYOUT

logger = logging.getLogger(__name__)


def _count_techniques(df: pd.DataFrame) -> dict[str, int]:
    counts: dict[str, int] = {}
    if "mitre_techniques" not in df.columns:
        return counts
    for techniques in df["mitre_techniques"]:
        if isinstance(techniques, list):
            for t in techniques:
                counts[t] = counts.get(t, 0) + 1
    return counts


def build_attack_matrix(df: pd.DataFrame) -> go.Figure:
    technique_counts = _count_techniques(df)

    if not technique_counts:
        fig = go.Figure()
        fig.add_annotation(
            text="No MITRE technique data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
        )
        fig.update_layout(
            **BASE_LAYOUT,
            title="MITRE ATT&CK Matrix",
            height=320,
        )
        return fig

    tracked_techniques = sorted(
        t for t in technique_counts
        if t in TECHNIQUE_TACTIC
    )

    if not tracked_techniques:
        tracked_techniques = sorted(technique_counts.keys())

    tactics_in_use: list[str] = []
    tactic_techs: dict[str, list[str]] = {}
    for t in tracked_techniques:
        tac = TECHNIQUE_TACTIC.get(t, "Other")
        tactic_techs.setdefault(tac, []).append(t)

    for tac in TACTIC_ORDER:
        if tac in tactic_techs:
            tactics_in_use.append(tac)
    for tac in sorted(tactic_techs):
        if tac not in tactics_in_use:
            tactics_in_use.append(tac)

    all_techs_sorted: list[str] = []
    for tac in tactics_in_use:
        all_techs_sorted.extend(sorted(tactic_techs[tac], key=lambda x: TECHNIQUE_NAMES.get(x, x)))

    x_labels = []
    for t in all_techs_sorted:
        name = TECHNIQUE_NAMES.get(t, t)
        x_labels.append(f"{t}<br>{name}")

    z_matrix: list[list[int]] = []
    for tac in tactics_in_use:
        row = []
        for t in all_techs_sorted:
            if TECHNIQUE_TACTIC.get(t, "Other") == tac:
                row.append(technique_counts.get(t, 0))
            else:
                row.append(0)
        z_matrix.append(row)

    z_arr = np.array(z_matrix, dtype=float)
    z_arr[z_arr == 0] = None

    fig = go.Figure()

    colors = [
        [0.0, "#0d1117"],
        [0.001, "#1a1a2e"],
        [0.2, "#4a154b"],
        [0.4, "#8b1a4a"],
        [0.6, "#c62828"],
        [0.8, "#e53935"],
        [1.0, "#ff5252"],
    ]

    fig.add_trace(go.Heatmap(
        z=z_arr,
        x=x_labels,
        y=tactics_in_use,
        colorscale=colors,
        hovertemplate=(
            "<b>%{x}</b><br>"
            "Tactic: %{y}<br>"
            "Detections: %{z}<extra></extra>"
        ),
        xgap=3,
        ygap=3,
    ))

    fig.update_layout(**BASE_LAYOUT)
    
    fig.update_layout(
        margin=dict(l=10, r=10, t=60, b=10),
        title=dict(
            text="MITRE ATT&CK Matrix – Detection Coverage",
            font=dict(size=14),
        ),
        xaxis=dict(
            tickangle=45,
            side="top",
        ),
        yaxis=dict(
            dtick=1,
        ),
        height=max(320, len(tactics_in_use) * 40 + 80),
        hovermode="closest"
    )
    return fig
