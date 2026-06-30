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

MITRE_BOOST = 1.5  # weight per MITRE technique tagged on an event row


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

    df_in = df_in.copy()

    sort_col = (
        "severity_score"     if "severity_score"     in df_in.columns else
        "has_attack_sig_sum" if "has_attack_sig_sum" in df_in.columns else
        df_in.columns[0]
    )

    if "mitre_techniques" in df_in.columns:
        mitre_count = df_in["mitre_techniques"].apply(
            lambda x: len(x) if isinstance(x, list) else 0
        )
        df_in["_sort_score"] = df_in[sort_col].fillna(0) + (mitre_count * MITRE_BOOST)
    else:
        df_in["_sort_score"] = df_in[sort_col].fillna(0)

    df_plot = df_in.sort_values("_sort_score", ascending=False).head(max_rows)

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


def build_network_section(network_df) -> str:
    """Returns an HTML string for the Network Traffic tab, or '' if no data."""
    if network_df is None or network_df.empty:
        return ""

    total_flows = len(network_df)
    unique_src_ips = network_df["src_ip"].nunique() if "src_ip" in network_df.columns else 0
    unique_dst_ips = network_df["dst_ip"].nunique() if "dst_ip" in network_df.columns else 0
    suspicious_flows = 0
    if "severity" in network_df.columns:
        suspicious_flows = int((network_df["severity"].astype(str) != "low").sum())
    suricata_alerts = 0
    if "alert_signature" in network_df.columns:
        suricata_alerts = int(network_df["alert_signature"].notna().sum())

    # Chart 1: Flow count over time (5-min buckets)
    fig_net1 = go.Figure()
    if "@timestamp" in network_df.columns:
        ts_series = pd.to_datetime(network_df["@timestamp"], errors="coerce")
        ts_grp = ts_series.dt.floor("5min").value_counts().sort_index().reset_index()
        ts_grp.columns = ["ts", "count"]
        if not ts_grp.empty:
            fig_net1.add_trace(go.Scatter(
                x=ts_grp["ts"], y=ts_grp["count"],
                fill="tozeroy", fillcolor="rgba(88,166,255,0.12)",
                line=dict(color=C_BLUE, width=2), name="Flows",
            ))
    fig_net1.update_layout(**BASE_LAYOUT, title="Network Flow Volume Over Time", height=240)
    fig_net1.update_xaxes(gridcolor=C_BORD, zeroline=False)
    fig_net1.update_yaxes(gridcolor=C_BORD, zeroline=False)

    # Chart 2: Top 10 destination IPs by flow count
    fig_net2 = go.Figure()
    if "dst_ip" in network_df.columns:
        top_dsts = network_df["dst_ip"].value_counts().nlargest(10).reset_index()
        top_dsts.columns = ["dst_ip", "count"]
        if not top_dsts.empty:
            fig_net2.add_trace(go.Bar(
                x=top_dsts["count"], y=top_dsts["dst_ip"],
                orientation="h", marker_color=C_BLUE,
            ))
    fig_net2.update_layout(**BASE_LAYOUT, title="Top 10 Destination IPs by Flow Count", height=280)
    fig_net2.update_xaxes(gridcolor=C_BORD)
    fig_net2.update_yaxes(gridcolor=C_BORD)

    # Suspicious flows table (severity above low, sorted by score, capped at 50 rows)
    susp_df = network_df.copy()
    if "severity" in susp_df.columns:
        susp_df = susp_df[susp_df["severity"].astype(str) != "low"]
    if "severity_score" in susp_df.columns:
        susp_df = susp_df.sort_values("severity_score", ascending=False)
    susp_df = susp_df.head(50)

    _src_colors = {"suricata": C_AMBER, "zeek": C_BLUE, "pcap": C_PURPLE}

    net_rows = ""
    for _, r in susp_df.iterrows():
        ts = str(r.get("@timestamp", ""))[:19].replace("T", " ")

        sp = r.get("src_port")
        dp = r.get("dst_port")
        src_port_str = str(int(sp)) if pd.notna(sp) else ""
        dst_port_str = str(int(dp)) if pd.notna(dp) else ""
        src = f"{r.get('src_ip', '')}:{src_port_str}"
        dst = f"{r.get('dst_ip', '')}:{dst_port_str}"

        proto = str(r.get("proto", ""))

        sent = r.get("bytes_sent")
        recv = r.get("bytes_recv")
        if pd.notna(sent) and pd.notna(recv):
            bytes_info = f"{int(sent):,} / {int(recv):,}"
        elif pd.notna(sent):
            bytes_info = f"{int(sent):,}"
        else:
            bytes_info = "—"

        sev_badge = _severity_badge(str(r.get("severity", "low")))

        reason = str(r.get("top_reasons") or r.get("alert_signature") or "—")
        reason_display = reason[:60] + ("…" if len(reason) > 60 else "")

        source_type = str(r.get("_source_type", ""))
        sc = _src_colors.get(source_type, C_MUTED)
        source_badge = (
            f'<span style="background:{sc}22;border:1px solid {sc}44;'
            f'border-radius:3px;padding:1px 6px;font-size:10px;'
            f'color:{sc};font-weight:600">{source_type}</span>'
        )

        net_rows += (
            f"<tr>"
            f"<td>{ts}</td>"
            f"<td style='font-family:monospace'>{src}</td>"
            f"<td style='font-family:monospace'>{dst}</td>"
            f"<td>{proto}</td>"
            f"<td style='font-family:monospace'>{bytes_info}</td>"
            f"<td>{sev_badge}</td>"
            f"<td title='{reason}'>{reason_display}</td>"
            f"<td>{source_badge}</td>"
            f"</tr>\n"
        )

    if not net_rows:
        net_rows = (
            f'<tr><td colspan="8" style="text-align:center;color:{C_MUTED};'
            f'padding:24px;font-style:italic;font-size:11px">'
            f'No suspicious network flows detected</td></tr>'
        )

    return f"""<div class="section" id="s-network">
  <div class="s-head">
    <div class="s-icon ic-bl">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="#4a89c4" stroke-width="1.5">
        <circle cx="8" cy="8" r="3"/><line x1="8" y1="1" x2="8" y2="5"/>
        <line x1="8" y1="11" x2="8" y2="15"/><line x1="1" y1="8" x2="5" y2="8"/>
        <line x1="11" y1="8" x2="15" y2="8"/>
      </svg>
    </div>
    <span class="s-title">Network Traffic Telemetry</span>
    <span class="s-meta">Suricata · Zeek · pcap — parallel analysis pipeline</span>
  </div>
  <div class="kpi-row">
    <div class="kpi">
      <div class="kpi-bar"></div>
      <div class="kpi-lbl">Total Flows</div>
      <div class="kpi-val">{total_flows:,}</div>
      <div class="kpi-sub">Network flow records</div>
    </div>
    <div class="kpi">
      <div class="kpi-bar"></div>
      <div class="kpi-lbl">Unique Source IPs</div>
      <div class="kpi-val">{unique_src_ips:,}</div>
      <div class="kpi-sub">Distinct source addresses</div>
    </div>
    <div class="kpi">
      <div class="kpi-bar"></div>
      <div class="kpi-lbl">Unique Dest IPs</div>
      <div class="kpi-val">{unique_dst_ips:,}</div>
      <div class="kpi-sub">Distinct destination addresses</div>
    </div>
    <div class="kpi">
      <div class="kpi-bar"></div>
      <div class="kpi-lbl">Suspicious Flows</div>
      <div class="kpi-val">{suspicious_flows:,}</div>
      <div class="kpi-sub">Severity above low</div>
    </div>
    <div class="kpi">
      <div class="kpi-bar"></div>
      <div class="kpi-lbl">Suricata Alerts</div>
      <div class="kpi-val">{suricata_alerts:,}</div>
      <div class="kpi-sub">Native alert signatures</div>
    </div>
  </div>
  <div class="g2">
    <div class="card">{_div(fig_net1)}</div>
    <div class="card">{_div(fig_net2)}</div>
  </div>
  <div class="s-head" style="margin-top:16px">
    <div class="s-icon ic-re">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="#c94040" stroke-width="1.5">
        <path d="M8 2L1 14h14L8 2z"/><line x1="8" y1="7" x2="8" y2="10"/>
        <circle cx="8" cy="12.5" r=".5" fill="#c94040"/>
      </svg>
    </div>
    <span class="s-title">Suspicious Network Flows</span>
    <span class="s-meta">Heuristic-scored · severity above low · top 50</span>
  </div>
  <div class="card-p">
    <div class="toolbar">
      <div class="sw">
        <input class="si" id="fi-network" type="text"
          placeholder="Filter by IP, protocol, severity…"
          oninput="ft(this,'tb-network','rc-network')"/>
      </div>
      <span class="rc" id="rc-network"></span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Timestamp</th><th>Source</th><th>Destination</th>
          <th>Proto</th><th>Bytes (Sent/Recv)</th><th>Severity</th>
          <th>Reason / Alert</th><th>Source Type</th>
        </tr>
      </thead>
      <tbody id="tb-network">{net_rows}</tbody>
    </table>
  </div>
</div>"""


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



def build_dashboard(df, agg, suspicious_windows, threats, feat_deviation, out_path, evaluation=None, network_df=None):
    logger.info("Building dashboard...")

    if df is None or df.empty:
        logger.warning("DataFrame is empty. Skipping dashboard generation.")
        return

    network_section_html = build_network_section(network_df)
    network_nav_tab = (
        """<a class="nav-a" href="#s-network" onclick="goTo(this,'s-network')">&#127760; Network Traffic</a>"""
        if network_section_html else ""
    )

    fig1, fig2, fig3, fig4, fig5, fig6, fig7, fig8, fig9, fig10 = build_charts(
        df, agg, suspicious_windows, feat_deviation, threats
    )
    fig_attack  = build_attack_matrix(df)
    seq_result  = detect_sequences(df)
    fig_sankey  = build_chain_sankey(seq_result.get("transitions"))
    fig_patterns = build_pattern_summary(seq_result.get("patterns"))

    fig_eval_pr = build_eval_pr_chart(evaluation or {})
    fig_eval_cm = build_eval_confusion(evaluation or {})
    sigma_rows  = build_sigma_table(evaluation or {})

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
        f'style="text-align:center;color:{C_MUTED};padding:24px;font-style:italic;font-size:11px">'
        f'No data detected</td></tr>'
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Endpoint Behavioral Analysis – SOC Dashboard</title>
<script src="https://cdn.plot.ly/plotly-2.32.0.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet"/>
<style>
:root {{
  --bg:#0b0d11;--sur:#111620;--sur2:#171d28;--bord:#1f2a38;
  --mg:#4d7a5e;--mgb:#62a87a;--mgd:#2d4a38;
  --red:#c94040;--amb:#c9893a;--grn:#3fa066;--blu:#4a89c4;
  --txt:#dde4ed;--mut:#7a8fa6;--dim:#3d4e61;
  --r:8px;--t:140ms ease;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth}}
body{{background:var(--bg);color:var(--txt);font-family:'Inter',system-ui,sans-serif;font-size:13px;line-height:1.6}}
::-webkit-scrollbar{{width:5px;height:5px}}
::-webkit-scrollbar-track{{background:transparent}}
::-webkit-scrollbar-thumb{{background:var(--bord);border-radius:3px}}
::-webkit-scrollbar-thumb:hover{{background:#2a3a4a}}
*{{scrollbar-width:thin;scrollbar-color:var(--bord) transparent}}
.topbar{{
  background:rgba(7,9,13,.96);border-bottom:1px solid var(--bord);
  padding:0 28px;height:54px;display:flex;align-items:center;gap:12px;
  position:sticky;top:0;z-index:300;backdrop-filter:blur(16px);
}}
.t-brand{{display:flex;align-items:center;gap:10px}}
.t-icon{{
  width:30px;height:30px;border-radius:7px;
  background:linear-gradient(135deg,#2d4a3820,#4d7a5e44);
  border:1px solid #4d7a5e44;
  display:flex;align-items:center;justify-content:center;flex-shrink:0;
}}
.t-title{{font-size:13px;font-weight:700;color:#fff;letter-spacing:-.2px;font-family:'Inter',sans-serif}}
.t-sub{{font-size:10px;color:var(--mut);font-family:'Inter',sans-serif}}
.t-sep{{width:1px;height:22px;background:var(--bord);flex-shrink:0}}
.live-badge{{
  display:flex;align-items:center;gap:5px;
  font-size:9px;font-weight:700;letter-spacing:.8px;color:var(--mgb);
  background:var(--mgd);border:1px solid #4d7a5e44;
  border-radius:20px;padding:3px 9px;flex-shrink:0;font-family:'Inter',sans-serif;
}}
.live-dot{{width:6px;height:6px;border-radius:50%;background:var(--mgb);animation:livepulse 1.6s ease-in-out infinite}}
@keyframes livepulse{{
  0%,100%{{opacity:1;transform:scale(1)}}
  50%{{opacity:.4;transform:scale(.85)}}
}}
.chip{{background:var(--mgd);border:1px solid #4d7a5e44;border-radius:4px;padding:2px 8px;font-size:10px;color:var(--mgb);font-family:'Inter',sans-serif}}
.t-time{{margin-left:auto;font-size:10px;color:var(--mut);font-family:'JetBrains Mono',monospace}}
.nav{{
  background:#080a0e;border-bottom:1px solid var(--bord);
  padding:0 28px;display:flex;gap:0;
  position:sticky;top:54px;z-index:200;overflow-x:auto;
}}
.nav::-webkit-scrollbar{{height:0}}
.nav-a{{
  display:flex;align-items:center;gap:6px;padding:10px 16px;
  font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;
  color:var(--mut);border-bottom:2px solid transparent;
  cursor:pointer;text-decoration:none;
  transition:color var(--t),border-color var(--t);white-space:nowrap;font-family:'Inter',sans-serif;
}}
.nav-a:hover{{color:var(--txt)}}
.nav-a.active{{color:var(--mgb);border-bottom-color:var(--mg)}}
.n-pill{{background:var(--red);color:#fff;border-radius:10px;padding:0 5px;font-size:9px;font-weight:700;min-width:16px;text-align:center;line-height:1.6}}
.n-pill.ok{{background:var(--grn)}}
.main{{padding:24px 28px;max-width:1600px;margin:0 auto}}
.kpi-row{{display:grid;grid-template-columns:1fr 1fr 1fr 1fr 1fr;gap:12px;margin-bottom:24px}}
.kpi{{
  background:var(--sur);border:1px solid var(--bord);
  border-radius:var(--r);padding:18px 20px;
  position:relative;overflow:hidden;transition:border-color var(--t),transform var(--t);
}}
.kpi:hover{{border-color:#2a3e52;transform:translateY(-1px)}}
.kpi-bar{{position:absolute;top:0;left:0;right:0;height:2px;background:var(--mg)}}
.kpi-lbl{{font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--mut);margin-bottom:8px;font-family:'Inter',sans-serif}}
.kpi-val{{font-size:26px;font-weight:700;line-height:1;letter-spacing:-1.5px;color:var(--mgb);font-family:'JetBrains Mono',monospace}}
.kpi-sub{{font-size:10px;color:var(--mut);margin-top:6px;font-family:'Inter',sans-serif}}
.kpi-alert{{
  background:#0e1015;border:1px solid var(--bord);
  border-radius:var(--r);padding:18px 20px;
  position:relative;overflow:hidden;transition:border-color var(--t),transform var(--t);
}}
.kpi-alert:hover{{transform:translateY(-1px)}}
.kpi-alert .kpi-bar{{background:var(--red)}}
.kpi-alert .kpi-val{{font-size:34px;color:var(--red);font-family:'JetBrains Mono',monospace}}
.kpi-alert .kpi-lbl{{font-family:'Inter',sans-serif}}
.kpi-alert .kpi-sub{{font-family:'Inter',sans-serif}}
.kpi-alert.armed{{border-color:#c9404044;box-shadow:0 0 24px #c9404012}}
.kalert-badge{{
  display:inline-flex;align-items:center;gap:5px;
  font-size:8px;font-weight:700;letter-spacing:.8px;
  color:var(--red);background:#c9404015;border:1px solid #c9404033;
  border-radius:20px;padding:2px 7px;margin-top:8px;font-family:'Inter',sans-serif;
}}
.pulse-ring{{width:6px;height:6px;border-radius:50%;background:var(--red);animation:livepulse 1.2s ease-in-out infinite}}
.s-head{{
  display:flex;align-items:center;gap:10px;
  margin-bottom:14px;padding-bottom:11px;border-bottom:1px solid #1f2a3866;
}}
.s-icon{{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0}}
.ic-mg{{background:#4d7a5e26;border:1px solid #4d7a5e30}}
.ic-re{{background:#c9404026;border:1px solid #c9404030}}
.ic-bl{{background:#4a89c426;border:1px solid #4a89c430}}
.ic-am{{background:#c9893a26;border:1px solid #c9893a30}}
.s-title{{font-size:12px;font-weight:700;color:var(--txt);letter-spacing:.2px;font-family:'Inter',sans-serif}}
.s-meta{{font-size:10px;color:var(--mut);margin-left:auto;font-family:'Inter',sans-serif}}
.card{{background:var(--sur);border:1px solid var(--bord);border-radius:var(--r);overflow:hidden;padding:4px;transition:border-color var(--t)}}
.card:hover{{border-color:#2a3e52}}
.card-p{{background:var(--sur);border:1px solid var(--bord);border-radius:var(--r);padding:18px 20px;overflow:auto}}
.g1{{margin-bottom:14px}}
.g2{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}}
.g3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:14px}}
.mb{{margin-bottom:14px}}
.section{{margin-bottom:36px;scroll-margin-top:112px}}
.toolbar{{display:flex;align-items:center;gap:10px;margin-bottom:12px}}
.sw{{position:relative;display:inline-block}}
.sw::before{{content:'⌕';position:absolute;left:10px;top:50%;transform:translateY(-52%);font-size:14px;color:var(--mut);pointer-events:none}}
.si{{
  background:#080a0e;border:1px solid var(--bord);
  border-radius:6px;padding:6px 12px 6px 30px;
  color:var(--txt);font-family:'JetBrains Mono',monospace;font-size:11px;
  width:240px;outline:none;transition:border-color var(--t),box-shadow var(--t);
}}
.si::placeholder{{color:var(--mut)}}
.si:focus{{border-color:#4a89c466;box-shadow:0 0 0 2px #4a89c415}}
.rc{{font-size:10px;color:var(--mut);margin-left:auto;font-family:'JetBrains Mono',monospace}}
table{{width:100%;border-collapse:collapse;font-size:12px;table-layout:auto}}
thead tr{{background:#080a0d;position:sticky;top:0;z-index:2;box-shadow:0 1px 0 var(--bord)}}
th{{padding:9px 12px;text-align:left;color:var(--dim);font-size:9px;text-transform:uppercase;letter-spacing:.8px;font-weight:700;white-space:nowrap;font-family:'Inter',sans-serif}}
td{{padding:9px 12px;border-bottom:1px solid #1f2a3818;vertical-align:top}}
tr:hover td{{background:var(--sur2)}}
tr.xhide{{display:none}}
.card-p table{{overflow-x:auto;display:block;max-height:560px;overflow-y:auto}}
#tb-alerts td:nth-child(1),#tb-alerts td:nth-child(2),
#tb-alerts td:nth-child(4),#tb-alerts td:nth-child(5){{font-family:'JetBrains Mono',monospace}}
.log-panel{{background:#070910;border:1px solid var(--bord);border-radius:var(--r);overflow:hidden;position:relative}}
.log-panel::after{{
  content:'';position:absolute;inset:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,0,0,.12) 3px,rgba(0,0,0,.12) 4px);
  pointer-events:none;z-index:1;
}}
.log-hdr{{
  display:flex;align-items:center;gap:10px;
  padding:10px 16px;background:#04060a;
  border-bottom:1px solid var(--bord);position:relative;z-index:2;
}}
.log-toolbar{{
  display:flex;align-items:center;gap:10px;
  padding:8px 16px;background:#04060a;
  border-bottom:1px solid var(--bord);position:relative;z-index:2;
}}
.log-title{{font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600;color:var(--mgb);letter-spacing:.5px}}
.log-live{{margin-left:auto;display:flex;align-items:center;gap:5px;font-family:'JetBrains Mono',monospace;font-size:9px;font-weight:700;color:var(--grn);letter-spacing:.5px}}
.log-body{{overflow:auto;max-height:560px;position:relative;z-index:2}}
.log-body *{{font-family:'JetBrains Mono',monospace!important}}
.log-body table{{width:100%;border-collapse:collapse;font-size:12px}}
.log-body thead tr{{background:#020407;position:sticky;top:0;z-index:3;box-shadow:0 1px 0 var(--bord)}}
.log-body th{{padding:9px 12px;color:var(--dim);font-size:9px;text-transform:uppercase;letter-spacing:.8px;font-weight:700;white-space:nowrap}}
.log-body td{{padding:8px 12px;border-bottom:1px solid #1f2a3818;vertical-align:top}}
.log-body tr:hover td{{background:#0e1015}}
.crt-footer{{padding:6px 16px;font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--dim);letter-spacing:.5px;background:#04060a;border-top:1px solid var(--bord);position:relative;z-index:2}}
.footer{{text-align:center;color:var(--mut);font-size:10px;padding:20px;border-top:1px solid var(--bord);margin-top:24px;letter-spacing:.3px;font-family:'Inter',sans-serif}}
@media(max-width:900px){{
  .kpi-row{{grid-template-columns:1fr 1fr 1fr}}
  .g3{{grid-template-columns:1fr 1fr}}
}}
@media(max-width:600px){{
  .kpi-row{{grid-template-columns:1fr 1fr}}
  .g2,.g3{{grid-template-columns:1fr}}
}}
</style>
</head>
<body>

<div class="topbar">
  <div class="t-brand">
    <div class="t-icon">
      <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="#62a87a" stroke-width="1.5">
        <path d="M8 2L3 5v4c0 3 2.5 5 5 5s5-2 5-5V5L8 2z"/>
      </svg>
    </div>
    <div>
      <div class="t-title">Endpoint Behavioral Analysis</div>
      <div class="t-sub">Windows EDR · Isolation Forest · Sigma Rules</div>
    </div>
  </div>
  <div class="t-sep"></div>
  <div class="live-badge"><div class="live-dot"></div>ACTIVE</div>
  <span class="chip">5-min Windows</span>
  <span class="chip">Channel-Aware</span>
  <span class="chip">MITRE ATT&amp;CK</span>
  <span class="t-time">{generated_at}</span>
</div>

<nav class="nav">
  <a class="nav-a active" href="#s-overview" onclick="goTo(this,'s-overview')">
    <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="1" y="1" width="6" height="6" rx="1"/><rect x="9" y="1" width="6" height="6" rx="1"/><rect x="1" y="9" width="6" height="6" rx="1"/><rect x="9" y="9" width="6" height="6" rx="1"/></svg>
    Overview
  </a>
  <a class="nav-a" href="#s-timeline" onclick="goTo(this,'s-timeline')">
    <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="1,12 5,7 9,9 15,3"/></svg>
    Timeline
  </a>
  <a class="nav-a" href="#s-alerts" onclick="goTo(this,'s-alerts')">
    <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 2L1 14h14L8 2z"/><line x1="8" y1="7" x2="8" y2="10"/><circle cx="8" cy="12.5" r=".5" fill="currentColor"/></svg>
    Alert Windows <span class="n-pill{' ok' if kpi_anomalous_win == 0 else ''}">{kpi_anomalous_win}</span>
  </a>
  <a class="nav-a" href="#s-events" onclick="goTo(this,'s-events')">
    <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="2,4 6,8 2,12"/><line x1="8" y1="12" x2="14" y2="12"/></svg>
    Log Stream <span class="n-pill{' ok' if kpi_threat_events == 0 else ''}">{kpi_threat_events}</span>
  </a>
  <a class="nav-a" href="#s-eval" onclick="goTo(this,'s-eval')">
    <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="6"/><polyline points="5,8 7,10 11,6"/></svg>
    Evaluation
  </a>
  {network_nav_tab}
</nav>

<div class="main">

  <div class="kpi-row">
    <div class="kpi-alert{' armed' if kpi_anomalous_win > 0 else ''}">
      <div class="kpi-bar"></div>
      <div class="kpi-lbl">Anomalous Windows</div>
      <div class="kpi-val">{kpi_anomalous_win}</div>
      <div class="kpi-sub">ML-flagged 5-min windows</div>
      <div class="kalert-badge"><div class="pulse-ring"></div>ACTIVE THREATS</div>
    </div>
    <div class="kpi-alert{' armed' if kpi_threat_events > 0 else ''}">
      <div class="kpi-bar"></div>
      <div class="kpi-lbl">Threat Events</div>
      <div class="kpi-val">{kpi_threat_events:,}</div>
      <div class="kpi-sub">Events in suspicious windows</div>
      <div class="kalert-badge"><div class="pulse-ring"></div>ACTIVE THREATS</div>
    </div>
    <div class="kpi">
      <div class="kpi-bar"></div>
      <div class="kpi-lbl">Total Events</div>
      <div class="kpi-val">{kpi_total_events:,}</div>
      <div class="kpi-sub">Raw log entries ingested</div>
    </div>
    <div class="kpi">
      <div class="kpi-bar"></div>
      <div class="kpi-lbl">Monitored Hosts</div>
      <div class="kpi-val">{kpi_total_hosts:,}</div>
      <div class="kpi-sub">Unique endpoints</div>
    </div>
    <div class="kpi">
      <div class="kpi-bar"></div>
      <div class="kpi-lbl">Log Channels</div>
      <div class="kpi-val">{kpi_total_channels:,}</div>
      <div class="kpi-sub">Source channel types</div>
    </div>
  </div>

  <div class="section" id="s-overview">
    <div class="s-head">
      <div class="s-icon ic-mg">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="#62a87a" stroke-width="1.5"><rect x="1" y="1" width="6" height="6" rx="1"/><rect x="9" y="1" width="6" height="6" rx="1"/><rect x="1" y="9" width="6" height="6" rx="1"/><rect x="9" y="9" width="6" height="6" rx="1"/></svg>
      </div>
      <span class="s-title">MITRE ATT&amp;CK Coverage Matrix</span>
      <span class="s-meta">Technique activity heatmap across all channels</span>
    </div>
    <div class="card g1">{_div(fig_attack)}</div>
    <div class="g2">
      <div class="card">{_div(fig9)}</div>
      <div class="card">{_div(fig10)}</div>
    </div>
    <div class="s-head" style="margin-top:20px">
      <div class="s-icon ic-bl">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="#4a89c4" stroke-width="1.5"><polyline points="1,12 5,7 9,9 15,3"/><line x1="1" y1="14" x2="15" y2="14"/></svg>
      </div>
      <span class="s-title">Attack Chain Analysis</span>
      <span class="s-meta">Tactic transitions · known pattern sequences</span>
    </div>
    <div class="g2">
      <div class="card">{_div(fig_sankey)}</div>
      <div class="card">{_div(fig_patterns)}</div>
    </div>
  </div>

  <div class="section" id="s-timeline">
    <div class="s-head">
      <div class="s-icon ic-bl">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="#4a89c4" stroke-width="1.5"><polyline points="1,12 5,7 9,9 15,3"/></svg>
      </div>
      <span class="s-title">Threat Timeline &amp; Behavioral Signals</span>
      <span class="s-meta">Temporal anomaly distribution across 5-min windows</span>
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
  </div>

  <div class="section" id="s-alerts">
    <div class="s-head">
      <div class="s-icon ic-re">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="#c94040" stroke-width="1.5"><path d="M8 2L1 14h14L8 2z"/><line x1="8" y1="7" x2="8" y2="10"/><circle cx="8" cy="12.5" r=".5" fill="#c94040"/></svg>
      </div>
      <span class="s-title">Suspicious Behavioral Windows</span>
      <span class="s-meta">Sorted by severity score · top 15 shown</span>
    </div>
    <div class="card-p">
      <div class="toolbar">
        <div class="sw">
          <input class="si" id="fi-alerts" type="text"
            placeholder="Filter by host, severity, reason…"
            oninput="ft(this,'tb-alerts','rc-alerts')"/>
        </div>
        <span class="rc" id="rc-alerts"></span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Time Window</th><th>Host</th><th>Severity</th>
            <th>Score</th><th>Anomaly Score</th><th>Top Reasons</th>
          </tr>
        </thead>
        <tbody id="tb-alerts">{window_rows or no_data(6)}</tbody>
      </table>
    </div>
  </div>

  <div class="section" id="s-events">
    <div class="s-head">
      <div class="s-icon ic-bl">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="#4a89c4" stroke-width="1.5"><polyline points="2,4 6,8 2,12"/><line x1="8" y1="12" x2="14" y2="12"/></svg>
      </div>
      <span class="s-title">Events in Suspicious Windows</span>
      <span class="s-meta">Channel-tagged · MITRE-labeled · top 25 shown</span>
    </div>
    <div class="log-panel">
      <div class="log-hdr">
        <div style="display:flex;gap:4px">
          <div style="width:7px;height:7px;border-radius:50%;background:#c94040"></div>
          <div style="width:7px;height:7px;border-radius:50%;background:#c9893a"></div>
          <div style="width:7px;height:7px;border-radius:50%;background:#3fa066"></div>
        </div>
        <span class="log-title">ENDPOINT_EVENT_STREAM — SHIRE.COM</span>
        <div class="log-live">&#9679; LIVE</div>
      </div>
      <div class="log-toolbar">
        <div class="sw">
          <input class="si" id="fi-events" type="text"
            placeholder="Filter by host, process, MITRE tag…"
            oninput="ft(this,'tb-events','rc-events')"/>
        </div>
        <span class="rc" id="rc-events"></span>
      </div>
      <div class="log-body">
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
          <tbody id="tb-events">{event_rows or no_data(8)}</tbody>
        </table>
      </div>
      <div class="crt-footer">// CRT TERMINAL MODE — RAW FORENSIC EVENT STREAM</div>
    </div>
  </div>

  <div class="section" id="s-eval">
    <div class="s-head">
      <div class="s-icon ic-mg">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="#62a87a" stroke-width="1.5"><circle cx="8" cy="8" r="6"/><polyline points="5,8 7,10 11,6"/></svg>
      </div>
      <span class="s-title">ML vs Sigma Evaluation</span>
      <span class="s-meta">Window-level precision / recall / F1 comparison</span>
    </div>
    <div class="card-p">
      <div class="g2 mb">
        <div class="card">{_div(fig_eval_pr)}</div>
        <div class="card">{_div(fig_eval_cm)}</div>
      </div>
      <table>
        <thead><tr><th>Metric</th><th>Value</th></tr></thead>
        <tbody>{sigma_rows}</tbody>
      </table>
    </div>
  </div>

  {network_section_html}

</div>

<div class="footer">
  ◈ Windows Endpoint Behavioral Analysis &nbsp;·&nbsp;
  Isolation Forest + Sigma Rules &nbsp;·&nbsp;
  5-min Time-Window Aggregation &nbsp;·&nbsp;
  {generated_at}
</div>

<script>
function goTo(el, id) {{
  event.preventDefault();
  document.querySelectorAll('.nav-a').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  const sec = document.getElementById(id);
  if (sec) {{
    window.scrollTo({{ top: sec.getBoundingClientRect().top + scrollY - (54+42+16), behavior:'smooth' }});
  }}
}}
function ft(input, tbId, rcId) {{
  const tb = document.getElementById(tbId);
  const rc = document.getElementById(rcId);
  if (!tb) return;
  const q = input.value.toLowerCase().trim();
  let n = 0, total = 0;
  tb.querySelectorAll('tr').forEach(tr => {{
    total++;
    const show = !q || tr.textContent.toLowerCase().includes(q);
    tr.classList.toggle('xhide', !show);
    if (show) n++;
  }});
  if (rc) rc.textContent = q ? n + ' / ' + total + ' rows' : total + ' rows';
}}
function styleAlertRows() {{
  const tb = document.getElementById('tb-alerts');
  if (!tb) return;
  tb.querySelectorAll('tr').forEach(tr => {{
    const cells = tr.querySelectorAll('td');
    if (cells.length < 3) return;
    const sev = cells[2].textContent.toLowerCase().trim();
    if (sev === 'high' || sev === 'critical') {{
      tr.style.borderLeft = '3px solid var(--red)';
    }} else if (sev === 'medium') {{
      tr.style.borderLeft = '3px solid var(--amb)';
    }} else {{
      tr.style.borderLeft = '3px solid var(--mgb)';
    }}
  }});
}}
document.addEventListener('DOMContentLoaded', () => {{
  [['tb-alerts','rc-alerts'],['tb-events','rc-events'],['tb-network','rc-network']].forEach(([tbId, rcId]) => {{
    const tb = document.getElementById(tbId);
    const rc = document.getElementById(rcId);
    if (tb && rc) rc.textContent = tb.querySelectorAll('tr').length + ' rows';
  }});
  styleAlertRows();
}});
</script>
</body>
</html>"""

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info(f"Dashboard saved to {out_path}")