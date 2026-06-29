"""chain_timeline.py — Attack chain Sankey / timeline visualization."""

import logging

import plotly.graph_objects as go

from src.main.myapp.dashboard.theme import BASE_LAYOUT

logger = logging.getLogger(__name__)

TACTIC_COLORS: dict[str, str] = {
    "Resource Development": "#7c4dff",
    "Initial Access":       "#00bcd4",
    "Execution":            "#ff5722",
    "Persistence":          "#9c27b0",
    "Privilege Escalation": "#e91e63",
    "Defense Evasion":      "#ff9800",
    "Credential Access":    "#f44336",
    "Discovery":            "#2196f3",
    "Lateral Movement":     "#ffeb3b",
    "Collection":           "#4caf50",
    "Command and Control":  "#00e5ff",
    "Exfiltration":         "#3f51b5",
    "Impact":               "#795548",
    "Other":                "#9e9e9e",
}


def build_chain_sankey(transition_counts) -> go.Figure:
    fig = go.Figure()

    if transition_counts is None or transition_counts.empty:
        fig.add_annotation(
            text="No attack chain transitions detected",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
        )
        fig.update_layout(**BASE_LAYOUT, title="Attack Chain Sankey", height=320)
        return fig

    all_nodes: list[str] = []
    node_map: dict[str, int] = {}
    sources: list[int] = []
    targets: list[int] = []
    values: list[int] = []
    node_colors: list[str] = []

    for _, row in transition_counts.iterrows():
        src = row["from_tactic"]
        tgt = row["to_tactic"]
        val = int(row["count"])

        if src not in node_map:
            node_map[src] = len(all_nodes)
            all_nodes.append(src)
            node_colors.append(TACTIC_COLORS.get(src, "#9e9e9e"))
        if tgt not in node_map:
            node_map[tgt] = len(all_nodes)
            all_nodes.append(tgt)
            node_colors.append(TACTIC_COLORS.get(tgt, "#9e9e9e"))

        sources.append(node_map[src])
        targets.append(node_map[tgt])
        values.append(val)

    if not all_nodes:
        fig.add_annotation(
            text="No attack chain transitions detected",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
        )
        fig.update_layout(**BASE_LAYOUT, title="Attack Chain Sankey", height=320)
        return fig

    fig.add_trace(go.Sankey(
        node=dict(
            pad=20,
            thickness=20,
            line=dict(color="rgba(255,255,255,0.2)", width=0.5),
            label=all_nodes,
            color=node_colors,
        ),
        link=dict(
            source=sources,
            target=targets,
            value=values,
            color="rgba(255,255,255,0.15)",
            hovertemplate=(
                "%{source.label} → %{target.label}<br>"
                "Transitions: %{value}<extra></extra>"
            ),
        ),
    ))

    fig.update_layout(
        **BASE_LAYOUT,
        title=dict(text="Attack Chain Sankey (Tactic Transitions)", font=dict(size=14)),
        height=max(400, len(all_nodes) * 30 + 100),
    )

    return fig


def build_pattern_summary(pattern_df) -> go.Figure:
    fig = go.Figure()

    if pattern_df is None or pattern_df.empty:
        fig.add_annotation(
            text="No known attack chain patterns detected",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
        )
        fig.update_layout(**BASE_LAYOUT, title="Known Attack Chain Patterns", height=240)
        return fig

    pc = pattern_df["pattern"].value_counts()
    fig.add_trace(go.Bar(
        x=pc.values,
        y=pc.index,
        orientation="h",
        marker_color="#ff5252",
        hovertemplate="Pattern: %{y}<br>Occurrences: %{x}<extra></extra>",
    ))

    fig.update_layout(
        **BASE_LAYOUT,
        title=dict(text="Known Attack Chain Patterns", font=dict(size=14)),
        height=max(240, len(pc) * 40 + 60),
        xaxis=dict(title="Occurrences", gridcolor="rgba(255,255,255,0.05)"),
        yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
    )

    return fig
