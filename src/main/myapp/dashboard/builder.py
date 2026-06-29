"""builder.py — SOC HTML Dashboard chart builders, table builders, and assembler."""

import logging
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from src.main.myapp.dashboard.attack_matrix import build_attack_matrix
from src.main.myapp.dashboard.chain_timeline import build_chain_sankey, build_pattern_summary
from src.main.myapp.features.sequence import detect_sequences
from src.main.myapp.dashboard.theme import (
    C_BG, C_CARD, C_BORD, C_RED, C_AMBER, C_GREEN, C_BLUE, C_PURPLE, C_TEXT, C_MUTED,
    BASE_LAYOUT, SYSMON_LABELS, BEHAVIORAL_LABELS, _div, _severity_badge,
)

logger = logging.getLogger(__name__)


def build_charts(df, agg, suspicious_windows, feat_deviation, threats):
    tl = suspicious_windows.copy() if suspicious_windows is not None else pd.DataFrame()
    time_col = "ml_time_window" if "ml_time_window" in tl.columns else "time_window"
    if time_col not in tl.columns and not tl.empty:
        tl = tl.reset_index()
    if tl.empty or time_col not in tl.columns:
        tl = pd.DataFrame({time_col: pd.Series(dtype="datetime64[ns]")})
    tl[time_col] = pd.to_datetime(tl[time_col], errors="coerce")
    tl_grp = tl.groupby(time_col).size().reset_index(name="count")
    fig1 = go.Figure()
    if not tl_grp.empty:
        fig1.add_trace(go.Scatter(
            x=tl_grp[time_col], y=tl_grp["count"],
            fill="tozeroy", fillcolor="rgba(248,81,73,0.12)",
            line=dict(color=C_RED, width=2), name="Suspicious Windows",
        ))
    fig1.update_layout(**BASE_LAYOUT, title="Threat Timeline (5-min windows)", height=240)
    fig1.update_xaxes(gridcolor=C_BORD, zeroline=False)
    fig1.update_yaxes(gridcolor=C_BORD, zeroline=False)

    if suspicious_windows is not None and not suspicious_windows.empty and "_host" in suspicious_windows.columns:
        top_hosts = (suspicious_windows.groupby("_host").size()
                     .reset_index(name="windows").nlargest(10, "windows"))
        fig2 = go.Figure(go.Bar(x=top_hosts["windows"], y=top_hosts["_host"],
                                orientation="h", marker_color=C_RED))
    else:
        fig2 = go.Figure()
    fig2.update_layout(**BASE_LAYOUT, title="Top Suspicious Hosts", height=280)
    fig2.update_xaxes(gridcolor=C_BORD)
    fig2.update_yaxes(gridcolor=C_BORD)

    if "EventID" in df.columns and not df.empty:
        eid_df = df["EventID"].value_counts().nlargest(10).reset_index()
        eid_df.columns = ["EventID", "count"]
        eid_df["label"] = eid_df["EventID"].map(SYSMON_LABELS).fillna(eid_df["EventID"].astype(str))
        fig3 = go.Figure(go.Bar(x=eid_df["count"], y=eid_df["label"],
                                orientation="h", marker_color=C_BLUE))
    else:
        fig3 = go.Figure()
    fig3.update_layout(**BASE_LAYOUT, title="Event ID Distribution", height=300)
    fig3.update_xaxes(gridcolor=C_BORD)
    fig3.update_yaxes(gridcolor=C_BORD)

    behav_cols = [c for c in agg.columns if c in BEHAVIORAL_LABELS] if not agg.empty else []
    if behav_cols and not agg.empty:
        behav_series = pd.Series(
            {BEHAVIORAL_LABELS[k]: int(agg[k].sum()) for k in behav_cols}
        ).sort_values()
        fig4 = go.Figure(go.Bar(
            x=behav_series.values, y=behav_series.index, orientation="h",
            marker_color=[C_RED if v > 0 else C_MUTED for v in behav_series.values],
        ))
    else:
        fig4 = go.Figure()
    fig4.update_layout(**BASE_LAYOUT, title="Behavioral Signal Breakdown", height=360)
    fig4.update_xaxes(gridcolor=C_BORD)
    fig4.update_yaxes(gridcolor=C_BORD)

    if feat_deviation is not None and not feat_deviation.empty:
        fig5 = go.Figure(go.Bar(x=feat_deviation.values, y=feat_deviation.index,
                                orientation="h", marker_color=C_AMBER))
    else:
        fig5 = go.Figure()
    fig5.update_layout(**BASE_LAYOUT, title="Feature Deviation (Anomaly vs All)", height=360)
    fig5.update_xaxes(gridcolor=C_BORD)
    fig5.update_yaxes(gridcolor=C_BORD)

    fig6 = go.Figure()
    if not agg.empty and "is_anomaly" in agg.columns and "anomaly_score" in agg.columns:
        normal = agg[~agg["is_anomaly"]]["anomaly_score"]
        anomaly = agg[agg["is_anomaly"]]["anomaly_score"]
        if not normal.empty:
            fig6.add_trace(go.Histogram(x=normal, name="Normal",
                                        marker_color=C_GREEN, opacity=0.7, nbinsx=30))
        if not anomaly.empty:
            fig6.add_trace(go.Histogram(x=anomaly, name="Anomaly",
                                        marker_color=C_RED, opacity=0.85, nbinsx=20))
    fig6.update_layout(**BASE_LAYOUT, barmode="overlay",
                       title="Anomaly Score Distribution", height=280,
                       legend=dict(bgcolor="rgba(0,0,0,0)"))
    fig6.update_xaxes(gridcolor=C_BORD)
    fig6.update_yaxes(gridcolor=C_BORD)

    if threats is not None and not threats.empty and "_process" in threats.columns:
        top_procs = threats["_process"].value_counts().nlargest(10).reset_index()
        top_procs.columns = ["_process", "count"]
        fig7 = go.Figure(go.Bar(x=top_procs["count"], y=top_procs["_process"],
                                orientation="h", marker_color=C_AMBER))
    else:
        fig7 = go.Figure()
    fig7.update_layout(**BASE_LAYOUT, title="Top Suspicious Executables", height=320)
    fig7.update_xaxes(gridcolor=C_BORD)
    fig7.update_yaxes(gridcolor=C_BORD)

    if "severity" in agg.columns and not agg.empty:
        sev_counts = agg["severity"].value_counts().reindex(
            ["low", "medium", "high", "critical"]
        ).fillna(0)
        fig8 = go.Figure(go.Bar(
            x=sev_counts.values, y=sev_counts.index, orientation="h",
            marker_color=[C_GREEN, C_AMBER, C_RED, "#ff0000"],
        ))
    else:
        fig8 = go.Figure()
    fig8.update_layout(**BASE_LAYOUT, title="Severity Distribution", height=240)
    fig8.update_xaxes(gridcolor=C_BORD)
    fig8.update_yaxes(gridcolor=C_BORD)

    if "_channel" in df.columns and not df.empty:
        ch_counts = df["_channel"].value_counts().reset_index()
        ch_counts.columns = ["Channel", "Count"]
        fig9 = px.pie(
            ch_counts, values="Count", names="Channel",
            hole=0.45,
            color_discrete_sequence=px.colors.qualitative.Vivid,
        )
        fig9.update_traces(textposition="inside", textinfo="percent+label")
        fig9.update_layout(**BASE_LAYOUT, title="Data Provenance (Log Sources by Channel)", height=360)
    else:
        fig9 = go.Figure()
        fig9.update_layout(**BASE_LAYOUT, title="Data Provenance (Log Sources by Channel)", height=360)

    if "_event_name" in df.columns and not df.empty:
        ev_counts = df["_event_name"].value_counts().head(15).reset_index()
        ev_counts.columns = ["Event Name", "Count"]
        fig10 = px.bar(
            ev_counts, x="Count", y="Event Name", orientation="h",
            color="Count", color_continuous_scale="Blues",
        )
        fig10.update_layout(yaxis={"categoryorder": "total ascending"})
        fig10.update_layout(**BASE_LAYOUT, title="Top 15 Event Types (by Taxonomy)", height=520)
    else:
        fig10 = go.Figure()
        fig10.update_layout(**BASE_LAYOUT, title="Top 15 Event Types (by Taxonomy)", height=520)

    return fig1, fig2, fig3, fig4, fig5, fig6, fig7, fig8, fig9, fig10


def build_window_table(df_in, max_rows=15):
    if df_in is None or df_in.empty:
        return ""
    df_plot = df_in.reset_index(drop=True)
    sort_col = "severity_score" if "severity_score" in df_plot.columns else df_plot.columns[0]
    time_col = "ml_time_window" if "ml_time_window" in df_plot.columns else "time_window"
    rows = ""
    for _, r in df_plot.sort_values(sort_col, ascending=False).head(max_rows).iterrows():
        sev = _severity_badge(str(r.get("severity", "—")))
        host = r.get("_host", "")
        reasons = r.get("top_reasons")
        if not reasons or str(reasons).strip() in ("", "—"):
            reasons = ", ".join([
                k.replace("_sum", "").replace("has_", "").replace("_", " ")
                for k in BEHAVIORAL_LABELS
                if k in df_plot.columns and bool(r.get(k, 0))
            ][:4]) or "—"
        rows += (
            f"<tr>"
            f"<td>{str(r.get(time_col, ''))[:16]}</td>"
            f"<td>{host}</td>"
            f"<td>{sev}</td>"
            f"<td>{r.get('severity_score', 0):.1f}</td>"
            f"<td>{r.get('anomaly_score', 0):.3f}</td>"
            f"<td title='{reasons}'>{reasons}</td>"
            f"</tr>"
        )
    return rows


def build_event_table(df_in, max_rows=25):
    if df_in is None or df_in.empty:
        return ""

    sort_col = (
        "severity_score"     if "severity_score"     in df_in.columns else
        "has_attack_sig_sum" if "has_attack_sig_sum" in df_in.columns else
        df_in.columns[0]
    )
    df_plot = df_in.sort_values(sort_col, ascending=False).head(max_rows)

    # --- helpers -----------------------------------------------------------

    def _basename(path: str) -> str:
        """Return just the filename from a full path, or the string as-is."""
        if not path or path in ("UNKNOWN", "nan", ""):
            return "\u2014"
        import os
        base = os.path.basename(path.replace("\\", "/"))
        return base if base else path

    def _truncate(s: str, n: int = 40) -> str:
        s = str(s).strip()
        if not s or s in ("UNKNOWN", "nan"):
            return "\u2014"
        return s[:n] + "\u2026" if len(s) > n else s

    def _mitre_badges(mitre_list) -> str:
        if not isinstance(mitre_list, list) or not mitre_list:
            return "\u2014"
        badges = []
        for t in mitre_list[:4]:          # cap at 4 badges per row
            color = C_RED if "T1003" in t or "T1055" in t else C_AMBER
            badges.append(
                f'<span style="background:rgba(255,255,255,0.06);'
                f'border:1px solid {color}33;border-radius:3px;'
                f'padding:1px 5px;font-size:10px;color:{color};'
                f'white-space:nowrap">{t}</span>'
            )
        return " ".join(badges)

    def _channel_badge(channel: str) -> str:
        colors = {
            "sysmon":     C_BLUE,
            "security":   C_AMBER,
            "powershell": C_PURPLE,
            "defender":   C_GREEN,
        }
        c = colors.get(channel.lower(), C_MUTED)
        return (
            f'<span style="background:{c}22;border:1px solid {c}44;'
            f'border-radius:3px;padding:1px 6px;font-size:10px;'
            f'color:{c};font-weight:600">{channel}</span>'
        )

    def _action_icon(action: str, event_id: int) -> str:
        """Return a short label + color for the action type."""
        icons = {
            "process_create":  ("EXEC",  C_BLUE),
            "network_connect": ("NET",   C_GREEN),
            "process_access":  ("PTRACE", C_RED),
            "registry_modify": ("REG",   C_AMBER),
            "file_modify":     ("FILE",  C_MUTED),
            "dns_query":       ("DNS",   C_PURPLE),
        }
        label, color = icons.get(action, ("EVT", C_MUTED))
        return (
            f'<span style="font-size:9px;font-weight:700;letter-spacing:.5px;'
            f'color:{color}">{label}</span>'
        )

    def _severity_dot(sev: str) -> str:
        colors = {"critical": C_RED, "high": C_RED, "medium": C_AMBER, "low": C_GREEN}
        c = colors.get(str(sev).lower(), C_MUTED)
        return f'<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:{c};margin-right:4px"></span>'

    # --- build process-access detail cell ---------------------------------

    def _proc_access_detail(r) -> str:
        """
        For EventID 10 (Process Access), show target image, access mask, call trace.
        Returns empty string for non-access events.
        """
        eid = int(r.get("EventID", 0)) if r.get("EventID") else 0
        action = str(r.get("_action", ""))
        if eid != 10 and action != "process_access":
            return ""

        target_img = str(r.get("_target_image", "") or r.get("_target", "") or "").strip()
        target_img = _basename(target_img) or "?"

        granted = str(r.get("GrantedAccess", "") or "").strip()
        granted = granted if granted and granted not in ("nan", "UNKNOWN", "") else "?"

        call_trace = str(r.get("CallTrace", "") or "").strip()
        call_short = (call_trace[:60] + "\u2026") if len(call_trace) > 60 else call_trace
        call_short = call_short if call_short and call_short not in ("nan", "UNKNOWN") else ""

        is_lsass = bool(r.get("is_lsass_access", 0))
        is_inject = bool(r.get("is_process_injection", 0))

        lsass_badge = (
            f' <span style="background:{C_RED}22;border:1px solid {C_RED}55;'
            f'border-radius:3px;padding:0 4px;font-size:9px;color:{C_RED}">LSASS</span>'
            if is_lsass else ""
        )
        inject_badge = (
            f' <span style="background:{C_AMBER}22;border:1px solid {C_AMBER}55;'
            f'border-radius:3px;padding:0 4px;font-size:9px;color:{C_AMBER}">INJECT</span>'
            if is_inject else ""
        )

        lines = [
            f'<span style="color:{C_MUTED};font-size:10px">Target: </span>'
            f'<span style="color:{C_RED}">{target_img}</span>{lsass_badge}{inject_badge}',
            f'<span style="color:{C_MUTED};font-size:10px">Access: </span>'
            f'<span style="color:{C_AMBER};font-family:monospace">{granted}</span>',
        ]
        if call_short:
            lines.append(
                f'<span style="color:{C_MUTED};font-size:10px">Trace: </span>'
                f'<span style="color:{C_MUTED};font-size:10px">{call_short}</span>'
            )
        return "<br>".join(lines)

    # --- build context cell (cmd / net_dst / target depending on event) ---

    def _context_cell(r) -> str:
        action = str(r.get("_action", ""))
        eid = int(r.get("EventID", 0)) if r.get("EventID") else 0

        if action == "network_connect":
            net = str(r.get("_net_dst", "") or "").strip()
            if net and net not in ("UNKNOWN", "nan", ":"):
                return (
                    f'<span style="color:{C_GREEN};font-family:monospace;font-size:11px">'
                    f'{_truncate(net, 35)}</span>'
                )

        if action == "dns_query":
            target = str(r.get("_target", "") or "").strip()
            if target and target not in ("UNKNOWN", "nan"):
                return (
                    f'<span style="color:{C_PURPLE};font-size:11px">'
                    f'{_truncate(target, 35)}</span>'
                )

        cmd = str(r.get("_cmd", "") or "").strip()
        if cmd and cmd not in ("UNKNOWN", "nan"):
            return (
                f'<span style="color:{C_MUTED};font-size:10px;font-family:monospace"'
                f' title="{cmd}">{_truncate(cmd, 55)}</span>'
            )
        return "\u2014"

    # --- render rows -------------------------------------------------------

    rows = ""
    for i, (_, r) in enumerate(df_plot.iterrows()):
        ts      = str(r.get("@timestamp", ""))[:19].replace("T", " ")
        channel = str(r.get("_channel", "")).strip() or "unknown"
        eid     = int(r.get("EventID", 0)) if r.get("EventID") else 0
        evname  = str(r.get("_event_name", "")).strip() or f"EID {eid}"
        action  = str(r.get("_action", "other_activity"))
        proc    = _basename(str(r.get("_process", "") or ""))
        parent  = _basename(str(r.get("_parent", "") or ""))
        host    = _truncate(str(r.get("_host", "") or ""), 20)
        sev     = str(r.get("severity", "low")).lower()
        mitre   = _mitre_badges(r.get("mitre_techniques", []))

        proc_access_html = _proc_access_detail(r)
        context_html     = _context_cell(r)

        # Alternating row bg for readability
        row_bg = f"background:{C_CARD}" if i % 2 == 0 else f"background:#0d1117"

        # Highlight process access rows with subtle left border
        is_pa = (eid == 10 or action == "process_access")
        row_style = f"{row_bg};border-left:3px solid {C_RED}66" if is_pa else f"{row_bg};border-left:3px solid transparent"

        # Process access detail column — shows content only for EventID 10
        pa_cell = (
            f'<td style="vertical-align:top;padding:8px 10px;min-width:180px">'
            f'{proc_access_html}'
            f'</td>'
            if proc_access_html else
            f'<td style="color:{C_MUTED};padding:8px 10px;font-size:10px;vertical-align:top">\u2014</td>'
        )

        rows += (
            f'<tr style="{row_style}">'

            # Timestamp + host
            f'<td style="vertical-align:top;padding:8px 10px;white-space:nowrap">'
            f'<span style="color:{C_TEXT};font-size:11px">{ts}</span><br>'
            f'<span style="color:{C_MUTED};font-size:10px">{host}</span>'
            f'</td>'

            # Channel badge + Event type label
            f'<td style="vertical-align:top;padding:8px 10px;white-space:nowrap">'
            f'{_channel_badge(channel)}<br>'
            f'<span style="margin-top:3px;display:inline-block">'
            f'{_action_icon(action, eid)}'
            f'</span>'
            f'</td>'

            # EventID + Event name
            f'<td style="vertical-align:top;padding:8px 10px;white-space:nowrap">'
            f'<span style="color:{C_MUTED};font-size:10px">EID </span>'
            f'<span style="color:{C_BLUE};font-weight:600">{eid}</span><br>'
            f'<span style="color:{C_MUTED};font-size:10px" title="{evname}">{_truncate(evname, 20)}</span>'
            f'</td>'

            # Executable (basename only, full path in tooltip)
            f'<td style="vertical-align:top;padding:8px 10px" title="{r.get("_process","")}">'
            f'<span style="color:{C_TEXT};font-size:11px">{proc}</span><br>'
            f'<span style="color:{C_MUTED};font-size:10px">{_severity_dot(sev)}{sev}</span>'
            f'</td>'

            # Parent process (basename)
            f'<td style="vertical-align:top;padding:8px 10px" title="{r.get("_parent","")}">'
            f'<span style="color:{C_MUTED};font-size:11px">{parent}</span>'
            f'</td>'

            # Context (cmd / net dst / dns query depending on event type)
            f'<td style="vertical-align:top;padding:8px 10px;max-width:220px">'
            f'{context_html}'
            f'</td>'

            # Process Access detail (target, granted access, call trace)
            + pa_cell +

            # MITRE tags
            f'<td style="vertical-align:top;padding:8px 10px">'
            f'{mitre}'
            f'</td>'

            f'</tr>\n'
        )

    return rows


def build_eval_pr_chart(evaluation: dict) -> go.Figure:
    fig = go.Figure()
    if not evaluation:
        fig.add_annotation(text="No evaluation data", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)
        fig.update_layout(**BASE_LAYOUT, title="Precision / Recall / F1", height=260)
        return fig
    wl = evaluation.get("window_level", {})
    metrics = [
        ("Precision", wl.get("precision", 0)),
        ("Recall", wl.get("recall", 0)),
        ("F1-Score", wl.get("f1_score", 0)),
    ]
    fig.add_trace(go.Bar(
        x=[m[0] for m in metrics], y=[m[1] for m in metrics],
        marker_color=[C_BLUE, C_GREEN, C_AMBER],
        hovertemplate="%{x}: %{y:.1%}<extra></extra>",
    ))
    fig.update_layout(
        **BASE_LAYOUT, title="ML vs Sigma – Precision / Recall / F1", height=260,
        yaxis=dict(tickformat=".0%", range=[0, 1], gridcolor=C_BORD),
        xaxis=dict(gridcolor=C_BORD),
    )
    return fig


def build_eval_confusion(evaluation: dict) -> go.Figure:
    fig = go.Figure()
    if not evaluation:
        fig.add_annotation(text="No evaluation data", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)
        fig.update_layout(**BASE_LAYOUT, title="Confusion Matrix (Sigma vs ML)", height=260)
        return fig
    wl = evaluation.get("window_level", {})
    cm = [[wl.get("true_negatives", 0), wl.get("false_positives", 0)],
          [wl.get("false_negatives", 0), wl.get("true_positives", 0)]]
    fig.add_trace(go.Heatmap(
        z=cm, x=["ML Normal", "ML Anomaly"], y=["Sigma Normal", "Sigma Anomaly"],
        colorscale="Reds", hovertemplate="%{x}<br>%{y}: %{z}<extra></extra>",
        xgap=3, ygap=3,
    ))
    fig.update_layout(
        **BASE_LAYOUT, title="Confusion Matrix (Sigma vs ML)", height=280,
        xaxis=dict(dtick=1), yaxis=dict(dtick=1),
    )
    return fig


def build_sigma_table(evaluation: dict) -> str:
    if not evaluation:
        return '<tr><td colspan="4" style="text-align:center;color:{C_MUTED}">No evaluation data</td></tr>'
    rows = ""
    wl = evaluation.get("window_level", {})
    el = evaluation.get("event_level", {})
    items = [
        ("Total Windows", str(wl.get("total_windows", 0))),
        ("ML+ Windows", str(wl.get("ml_positive_windows", 0))),
        ("Sigma+ Windows", str(wl.get("sigma_positive_windows", 0))),
        ("True Positives", str(wl.get("true_positives", 0))),
        ("False Positives", str(wl.get("false_positives", 0))),
        ("False Negatives", str(wl.get("false_negatives", 0))),
        ("True Negatives", str(wl.get("true_negatives", 0))),
        ("Precision", f"{wl.get('precision', 0):.1%}"),
        ("Recall", f"{wl.get('recall', 0):.1%}"),
        ("F1-Score", f"{wl.get('f1_score', 0):.1%}"),
        ("Sigma Matched Events", str(el.get("sigma_matched_events", 0))),
        ("Sigma Match Rate", f"{el.get('sigma_match_rate', 0):.1%}"),
    ]
    for label, val in items:
        rows += f"<tr><td style='color:{C_MUTED}'>{label}</td><td style='font-weight:600'>{val}</td></tr>"
    return rows


def build_dashboard(df, agg, suspicious_windows, threats, feat_deviation, out_path, evaluation=None):
    logger.info("Building dashboard...")

    if df is None or df.empty:
        logger.warning("DataFrame is empty. Skipping dashboard generation.")
        return

    fig1, fig2, fig3, fig4, fig5, fig6, fig7, fig8, fig9, fig10 = build_charts(
        df, agg, suspicious_windows, feat_deviation, threats
    )
    fig_attack = build_attack_matrix(df)

    seq_result = detect_sequences(df)
    fig_sankey = build_chain_sankey(seq_result.get("transitions"))
    fig_patterns = build_pattern_summary(seq_result.get("patterns"))

    fig_eval_pr = build_eval_pr_chart(evaluation or {})
    fig_eval_cm = build_eval_confusion(evaluation or {})
    sigma_rows = build_sigma_table(evaluation or {})

    window_rows = build_window_table(suspicious_windows)
    event_rows  = build_event_table(threats)

    kpi_total_events   = len(df)
    kpi_total_hosts    = df["_host"].nunique() if "_host" in df.columns else 0
    kpi_total_channels = df["_channel"].nunique() if "_channel" in df.columns else 0
    kpi_anomalous_win  = int(agg["is_anomaly"].sum()) if "is_anomaly" in agg.columns else 0
    kpi_threat_events  = len(threats) if threats is not None else 0
    generated_at       = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    def kc(val):
        return C_RED if val >= 1 else C_GREEN

    no_data = lambda col: (
        f'<tr><td colspan="{col}" '
        f'style="text-align:center;color:{C_MUTED};padding:20px;font-style:italic">'
        f'No anomalies detected</td></tr>'
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Windows Endpoint Behavioral Analysis</title>
<script src="https://cdn.plot.ly/plotly-2.32.0.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet"/>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:{C_BG};color:{C_TEXT};font-family:'JetBrains Mono',monospace;font-size:13px;line-height:1.5}}
.topbar{{background:#010409;border-bottom:1px solid {C_BORD};padding:12px 28px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:100}}
.topbar h1{{font-size:14px;font-weight:700;color:#fff}}
.badge{{background:{C_BORD};border-radius:4px;padding:2px 9px;font-size:11px;color:{C_MUTED}}}
.dot-red{{width:8px;height:8px;border-radius:50%;background:{C_RED};display:inline-block;animation:pulse 1.5s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.3}}}}
.main{{padding:24px 28px;max-width:1440px;margin:0 auto}}
.kpi-row{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:22px}}
.kpi{{background:{C_CARD};border:1px solid {C_BORD};border-radius:8px;padding:18px 20px}}
.kpi .lbl{{color:{C_MUTED};font-size:10px;text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px}}
.kpi .val{{font-size:28px;font-weight:700}}
.kpi .sub{{font-size:10px;color:{C_MUTED};margin-top:4px}}
.card{{background:{C_CARD};border:1px solid {C_BORD};border-radius:8px;overflow:hidden;padding:4px}}
.card-pad{{background:{C_CARD};border:1px solid {C_BORD};border-radius:8px;padding:18px 20px;overflow:auto}}
.section-title{{font-size:11px;color:{C_MUTED};text-transform:uppercase;letter-spacing:.7px;margin-bottom:12px;font-weight:600}}
.g1{{margin-bottom:14px}}
.g2{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}}
.g3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:14px}}
table{{width:100%;border-collapse:collapse;font-size:12px;table-layout:auto}}
thead tr{{background:#161b22;position:sticky;top:0;z-index:2}}
th{{padding:10px 12px;text-align:left;color:{C_MUTED};font-size:10px;text-transform:uppercase;
    letter-spacing:.6px;font-weight:700;border-bottom:2px solid {C_BORD};white-space:nowrap}}
td{{padding:9px 12px;border-bottom:1px solid {C_BORD}22;vertical-align:top}}
tr:hover td{{background:#1c2128}}
.card-pad table{{overflow-x:auto;display:block;max-height:520px;overflow-y:auto}}
.footer{{text-align:center;color:{C_MUTED};font-size:10px;padding:24px;border-top:1px solid {C_BORD};margin-top:22px}}
</style>
</head>
<body>
<div class="topbar">
  <div class="dot-red"></div>
  <h1>Windows Endpoint Behavioral Analysis</h1>
  <span class="badge">Behavioral Features</span>
  <span class="badge">Isolation Forest</span>
  <span class="badge">5-min Windows</span>
  <span class="badge">Channel-Aware</span>
  <span class="badge" style="margin-left:auto">{generated_at}</span>
</div>
<div class="main">

  <div class="kpi-row">
    <div class="kpi">
      <div class="lbl">Total Events</div>
      <div class="val" style="color:{C_BLUE}">{kpi_total_events:,}</div>
      <div class="sub">Raw log rows</div>
    </div>
    <div class="kpi">
      <div class="lbl">Hosts</div>
      <div class="val" style="color:{C_BLUE}">{kpi_total_hosts:,}</div>
      <div class="sub">Unique endpoints</div>
    </div>
    <div class="kpi">
      <div class="lbl">Channels</div>
      <div class="val" style="color:{C_PURPLE}">{kpi_total_channels:,}</div>
      <div class="sub">Log sources</div>
    </div>
    <div class="kpi">
      <div class="lbl">Anomalous Windows</div>
      <div class="val" style="color:{kc(kpi_anomalous_win)}">{kpi_anomalous_win}</div>
      <div class="sub">ML-flagged windows</div>
    </div>
    <div class="kpi">
      <div class="lbl">Threat Events</div>
      <div class="val" style="color:{kc(kpi_threat_events)}">{kpi_threat_events:,}</div>
      <div class="sub">In suspicious windows</div>
    </div>
  </div>

  <div class="card g1">{_div(fig_attack)}</div>

  <div class="g2">
    <div class="card">{_div(fig9)}</div>
    <div class="card">{_div(fig10)}</div>
  </div>

  <div class="g2">
    <div class="card">{_div(fig_sankey)}</div>
    <div class="card">{_div(fig_patterns)}</div>
  </div>

  <div class="card g1">{_div(fig1)}</div>

  <div class="g2">
    <div class="card">{_div(fig2)}</div>
    <div class="card">{_div(fig8)}</div>
  </div>

  <div class="g3">
    <div class="card">{_div(fig3)}</div>
    <div class="card">{_div(fig4)}</div>
    <div class="card">{_div(fig5)}</div>
  </div>

  <div class="g2">
    <div class="card">{_div(fig6)}</div>
    <div class="card">{_div(fig7)}</div>
  </div>

  <div class="card-pad g1">
    <div class="section-title">Evaluation Metrics – Sigma vs ML Comparison</div>
    <div class="g2">
      <div class="card">{_div(fig_eval_pr)}</div>
      <div class="card">{_div(fig_eval_cm)}</div>
    </div>
    <table>
      <thead><tr><th>Metric</th><th>Value</th></tr></thead>
      <tbody>{sigma_rows}</tbody>
    </table>
  </div>

  <div class="card-pad g1">
    <div class="section-title">Top Suspicious Behavioral Windows</div>
    <table>
      <thead>
        <tr>
          <th>Time Window</th>
          <th>Host</th>
          <th>Severity</th>
          <th>Score</th>
          <th>Anomaly Score</th>
          <th>Top Reasons</th>
        </tr>
      </thead>
      <tbody>{window_rows or no_data(6)}</tbody>
    </table>
  </div>

  <div class="card-pad">
    <div class="section-title">Top Events in Suspicious Windows (Channel + MITRE)</div>
    <table style="border-collapse:collapse">
      <thead>
        <tr>
            <th style="min-width:130px">Timestamp / Host</th>
            <th style="min-width:90px">Channel / Type</th>
            <th style="min-width:80px">Event</th>
            <th style="min-width:140px">Executable</th>
            <th style="min-width:120px">Parent</th>
            <th style="min-width:180px">Context (Cmd / Net / DNS)</th>
            <th style="min-width:180px">Process Access Detail</th>
            <th style="min-width:160px">MITRE Tags</th>
        </tr>
      </thead>
      <tbody>{event_rows or no_data(8)}</tbody>
    </table>
  </div>
</div>
<div class="footer">
  Windows Endpoint Behavioral Analysis | Isolation Forest | 5-min Time-Window Aggregation | Channel-Aware | {generated_at}
</div>
</body>
</html>"""

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info(f"Dashboard saved to {out_path}")
