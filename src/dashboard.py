"""dashboard.py — Build dark-themed SOC HTML dashboard from analysis results"""

import pandas as pd
import plotly.graph_objects as go
import plotly.io as pio
from datetime import datetime

C_BG    = "#0d1117"
C_CARD  = "#161b22"
C_BORD  = "#21262d"
C_RED   = "#f85149"
C_AMBER = "#e3b341"
C_GREEN = "#3fb950"
C_BLUE  = "#58a6ff"
C_TEXT  = "#c9d1d9"
C_MUTED = "#8b949e"

BASE_LAYOUT = dict(
    paper_bgcolor=C_CARD, plot_bgcolor=C_CARD,
    font=dict(color=C_TEXT, family="'JetBrains Mono', monospace", size=12),
    margin=dict(l=50, r=20, t=44, b=40),
)

SYSMON_LABELS = {
    1:"Process Create", 3:"Network Conn", 7:"Image Load", 10:"Process Access",
    11:"File Create", 12:"Registry", 13:"Registry Set", 22:"DNS Query",
    23:"File Delete", 4656:"Object Access", 4658:"Handle Close",
    4663:"File Obj Access", 4673:"Privileged Svc", 4688:"Process Create(Sec)",
    4689:"Process Exit", 4690:"Handle Dup", 5156:"Net Filter", 5158:"Net Filter Bind",
}


def _div(fig):
    return pio.to_html(fig, full_html=False, include_plotlyjs=False)


def _severity_badge(s):
    c = {C_RED: "High", C_AMBER: "Medium", C_GREEN: "Low"}.get
    color = C_RED if s == "High" else C_AMBER if s == "Medium" else C_GREEN
    return f'<span style="color:{color};font-weight:600">{s}</span>'


def build_charts(df, agg, suspicious_windows, feat_deviation):
    # Chart 1: Threat Timeline
    tl = suspicious_windows.copy()
    tl["time_window"] = pd.to_datetime(tl["time_window"])
    tl_grp = tl.groupby("time_window").size().reset_index(name="count")
    fig1 = go.Figure()
    fig1.add_trace(go.Scatter(
        x=tl_grp["time_window"], y=tl_grp["count"],
        fill="tozeroy", fillcolor="rgba(248,81,73,0.12)",
        line=dict(color=C_RED, width=2), name="Suspicious Windows",
    ))
    fig1.update_layout(**BASE_LAYOUT, title="🕒 Threat Timeline (5-min windows)", height=240)
    fig1.update_xaxes(gridcolor=C_BORD, zeroline=False)
    fig1.update_yaxes(gridcolor=C_BORD, zeroline=False)

    # Chart 2: Top Suspicious Hosts
    top_hosts = (suspicious_windows.groupby("_host").size()
                 .reset_index(name="windows").nlargest(10, "windows"))
    fig2 = go.Figure(go.Bar(x=top_hosts["windows"], y=top_hosts["_host"],
                            orientation="h", marker_color=C_RED))
    fig2.update_layout(**BASE_LAYOUT, title="🖥️ Top Suspicious Hosts", height=280)
    fig2.update_xaxes(gridcolor=C_BORD)
    fig2.update_yaxes(gridcolor=C_BORD)

    # Chart 3: Event ID Distribution
    if "EventID" in df.columns:
        eid_df = df["EventID"].value_counts().nlargest(10).reset_index()
        eid_df.columns = ["EventID", "count"]
        eid_df["label"] = eid_df["EventID"].map(SYSMON_LABELS).fillna(eid_df["EventID"].astype(str))
        fig3 = go.Figure(go.Bar(x=eid_df["count"], y=eid_df["label"],
                                orientation="h", marker_color=C_BLUE))
    else:
        fig3 = go.Figure()
    fig3.update_layout(**BASE_LAYOUT, title="📊 Event ID Distribution", height=300)
    fig3.update_xaxes(gridcolor=C_BORD)
    fig3.update_yaxes(gridcolor=C_BORD)

    # Chart 4: Detection Rule Breakdown
    rule_labels = {
        "f_powershell": "PowerShell",        "f_encoded_cmd": "Encoded CMD",
        "f_long_cmd": "Long Command",        "f_office_spawn": "Office→Shell",
        "f_hack_tool": "Hack Tool",          "f_attack_sig": "Attack Signature",
        "f_unsigned": "Unsigned Binary",     "f_suspicious_dll": "Suspicious DLL",
        "f_lsass_access": "LSASS Access",    "f_temp_write": "Temp Write",
    }
    rule_series = pd.Series(
        {v: int(df[k].sum()) for k, v in rule_labels.items() if k in df.columns}
    ).sort_values()
    fig4 = go.Figure(go.Bar(
        x=rule_series.values, y=rule_series.index, orientation="h",
        marker_color=[C_RED if v > 0 else C_MUTED for v in rule_series.values],
    ))
    fig4.update_layout(**BASE_LAYOUT, title="🚨 Detection Rule Breakdown", height=320)
    fig4.update_xaxes(gridcolor=C_BORD)
    fig4.update_yaxes(gridcolor=C_BORD)

    # Chart 5: Feature Deviation
    fig5 = go.Figure(go.Bar(x=feat_deviation.values, y=feat_deviation.index,
                            orientation="h", marker_color=C_AMBER))
    fig5.update_layout(**BASE_LAYOUT, title="🤖 Feature Deviation (Anomaly vs All)", height=360)
    fig5.update_xaxes(gridcolor=C_BORD)
    fig5.update_yaxes(gridcolor=C_BORD)

    # Chart 6: Anomaly Score Distribution
    fig6 = go.Figure()
    fig6.add_trace(go.Histogram(x=agg[~agg["is_anomaly"]]["anomaly_score"],
                                name="Normal", marker_color=C_GREEN, opacity=0.7, nbinsx=30))
    fig6.add_trace(go.Histogram(x=agg[agg["is_anomaly"]]["anomaly_score"],
                                name="Anomaly", marker_color=C_RED, opacity=0.85, nbinsx=20))
    fig6.update_layout(**BASE_LAYOUT, barmode="overlay",
                       title="📉 Anomaly Score Distribution",
                       height=280, legend=dict(bgcolor="rgba(0,0,0,0)"))
    fig6.update_xaxes(gridcolor=C_BORD)
    fig6.update_yaxes(gridcolor=C_BORD)

    return fig1, fig2, fig3, fig4, fig5, fig6


def build_window_table(df_in, max_rows=15):
    rows = ""
    for _, r in df_in.sort_values("severity_score", ascending=False).head(max_rows).iterrows():
        sev = _severity_badge(str(r.get("severity", "—")))
        rows += (f"<tr>"
                 f"<td>{str(r.get('time_window',''))[:16]}</td>"
                 f"<td>{r.get('_host','')}</td>"
                 f"<td>{sev}</td>"
                 f"<td>{r.get('severity_score',0):.1f}</td>"
                 f"<td>{r.get('anomaly_score',0):.3f}</td>"
                 f"<td>{r.get('top_reasons','—')}</td>"
                 f"</tr>")
    return rows


def build_event_table(df_in, max_rows=20):
    rows = ""
    for _, r in df_in.sort_values("rule_score", ascending=False).head(max_rows).iterrows():
        rs  = int(r.get("rule_score", 0))
        sc  = C_RED if rs > 1 else C_AMBER if rs > 0 else C_GREEN
        sev = _severity_badge(str(r.get("severity", "—")))
        rows += (f"<tr>"
                 f"<td>{str(r.get('@timestamp',''))[:19]}</td>"
                 f"<td>{r.get('EventID','')}</td>"
                 f"<td title='{r.get('_process','')}' >{str(r.get('_process',''))[-50:]}</td>"
                 f"<td title='{r.get('_parent','')}' >{str(r.get('_parent',''))[-40:]}</td>"
                 f"<td style='color:{sc};text-align:center;font-weight:600'>{rs}</td>"
                 f"<td>{sev}</td>"
                 f"</tr>")
    return rows


def build_dashboard(df, agg, suspicious_windows, threats, feat_deviation, out_path):
    """Build and save the full HTML dashboard."""
    fig1, fig2, fig3, fig4, fig5, fig6 = build_charts(df, agg, suspicious_windows, feat_deviation)

    window_rows = build_window_table(suspicious_windows if len(suspicious_windows) else agg)
    event_rows  = build_event_table(threats if len(threats) else df)

    kpi_total_events  = len(df)
    kpi_total_hosts   = df["_host"].nunique()
    kpi_anomalous_win = int(agg["is_anomaly"].sum())
    kpi_threat_events = len(threats)
    kpi_encoded_ps    = int(df["f_encoded_cmd"].sum()) if "f_encoded_cmd" in df.columns else 0
    kpi_lsass         = int(df["f_lsass_access"].sum()) if "f_lsass_access" in df.columns else 0
    generated_at      = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    def kc(val): return C_RED if val >= 1 else C_GREEN

    no_data = lambda col: f'<tr><td colspan="{col}" style="text-align:center;color:{C_GREEN};padding:20px">✅ No data</td></tr>'

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
.kpi-row{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:22px}}
@media(max-width:1100px){{.kpi-row{{grid-template-columns:repeat(3,1fr)}}}}
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
table{{width:100%;border-collapse:collapse;font-size:12px}}
thead tr{{background:#1c2128}}
th{{padding:10px 12px;text-align:left;color:{C_MUTED};font-size:10px;text-transform:uppercase;letter-spacing:.6px;font-weight:700;border-bottom:1px solid {C_BORD}}}
td{{padding:9px 12px;border-bottom:1px solid {C_BORD};max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
tr:hover td{{background:#1c2128}}
.footer{{text-align:center;color:{C_MUTED};font-size:10px;padding:24px;border-top:1px solid {C_BORD};margin-top:22px}}
</style>
</head>
<body>
<div class="topbar">
  <div class="dot-red"></div>
  <h1>Windows Endpoint Behavioral Analysis</h1>
  <span class="badge">Isolation Forest</span>
  <span class="badge">5-min Behavioral Windows</span>
  <span class="badge" style="margin-left:auto">🕒 {generated_at}</span>
</div>
<div class="main">
<div class="kpi-row">
  <div class="kpi"><div class="lbl">Total Events</div><div class="val" style="color:{C_BLUE}">{kpi_total_events:,}</div><div class="sub">Raw log rows</div></div>
  <div class="kpi"><div class="lbl">Hosts</div><div class="val" style="color:{C_BLUE}">{kpi_total_hosts:,}</div><div class="sub">Unique endpoints</div></div>
  <div class="kpi"><div class="lbl">Anomalous Windows</div><div class="val" style="color:{kc(kpi_anomalous_win)}">{kpi_anomalous_win}</div><div class="sub">ML-flagged windows</div></div>
  <div class="kpi"><div class="lbl">Threat Events</div><div class="val" style="color:{kc(kpi_threat_events)}">{kpi_threat_events:,}</div><div class="sub">Events in suspicious windows</div></div>
  <div class="kpi"><div class="lbl">Encoded PowerShell</div><div class="val" style="color:{kc(kpi_encoded_ps)}">{kpi_encoded_ps}</div><div class="sub">-enc / -encodedcommand</div></div>
  <div class="kpi"><div class="lbl">LSASS Access</div><div class="val" style="color:{kc(kpi_lsass)}">{kpi_lsass}</div><div class="sub">Credential dump indicators</div></div>
</div>
<div class="card g1">{_div(fig1)}</div>
<div class="g2"><div class="card">{_div(fig2)}</div><div class="card">{_div(fig6)}</div></div>
<div class="g3"><div class="card">{_div(fig3)}</div><div class="card">{_div(fig4)}</div><div class="card">{_div(fig5)}</div></div>
<div class="card-pad g1">
  <div class="section-title">🔴 Top Suspicious Behavioral Windows</div>
  <table>
    <thead><tr><th>Time Window</th><th>Host</th><th>Severity</th><th>Score</th><th>Anomaly Score</th><th>Top Reasons</th></tr></thead>
    <tbody>{window_rows or no_data(6)}</tbody>
  </table>
</div>
<div class="card-pad">
  <div class="section-title">⚠️ Top Threat Events (raw)</div>
  <table>
    <thead><tr><th>Timestamp</th><th>EventID</th><th>Process</th><th>Parent</th><th>Rule Score</th><th>Severity</th></tr></thead>
    <tbody>{event_rows or no_data(6)}</tbody>
  </table>
</div>
</div>
<div class="footer">
  Windows Endpoint Behavioral Analysis &nbsp;|&nbsp; Isolation Forest &nbsp;|&nbsp;
  5-min Time-Window Aggregation &nbsp;|&nbsp; OTRF/Mordor-compatible &nbsp;|&nbsp; {generated_at}
</div>
</body></html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
