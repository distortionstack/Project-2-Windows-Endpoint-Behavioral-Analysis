"""
Windows Endpoint Behavioral Analysis Pipeline
Mordor-compatible | Time-Window Behavioral Features | Isolation Forest | HTML Dashboard
"""

from io import BytesIO
import warnings
import xml.etree.ElementTree as ET
from zipfile import ZipFile
import numpy as np
import pandas as pd
from datetime import datetime
from pathlib import Path
from sklearn.ensemble import IsolationForest
import plotly.graph_objects as go
import plotly.express as px
import plotly.io as pio
import requests

warnings.filterwarnings("ignore")

DATASET_URL = "https://github.com/OTRF/Security-Datasets/raw/refs/heads/master/datasets/atomic/windows/discovery/host/cmd_seatbelt_group_user.zip"
OUT_ALERTS = "outputs\\alerts_full.json"
OUT_AGG    = "outputs\\aggregated_windows.json"
OUT_DASH    = "outputs\\dashboard.html"

Path("outputs").mkdir(parents=True, exist_ok=True)

def load_dataset(source):
    """Load dataset from URL (zip), or local .json/.jsonl/.xml/.csv"""
    if str(source).startswith("http"):
        zf = ZipFile(BytesIO(requests.get(source).content))
        source = zf.extract(zf.namelist()[0])
    p = Path(source)
    if p.suffix in (".json", ".jsonl"):
        return pd.read_json(p, lines=True)
    elif p.suffix == ".xml":
        tree = ET.parse(p)
        rows = [{c.tag: c.text for c in event} for event in tree.getroot()]
        return pd.DataFrame(rows)
    else:  # .csv fallback
        return pd.read_csv(p, low_memory=False)

def safe_col(df, *names, default=np.nan):
    for n in names:
        if n in df.columns:
            return df[n]
    return pd.Series(default, index=df.index)

# ════════════════════════════════════════════════════════════════════
# STEP 1 — LOAD + NORMALIZE
# ════════════════════════════════════════════════════════════════════
print("[1/9] Loading & normalising...")

df = load_dataset(DATASET_URL)

df["@timestamp"]       = pd.to_datetime(df.get("@timestamp"), utc=True, errors="coerce")
df                     = df.dropna(subset=["@timestamp"]).copy()
df["_process"]         = safe_col(df, "Image", "NewProcessName").astype(str)
df["_parent"]          = safe_col(df, "ParentImage", "ParentProcessName").astype(str)
df["_cmd"]             = safe_col(df, "CommandLine").astype(str)
df["_host"]            = safe_col(df, "Hostname", "Computer").fillna("UNKNOWN").astype(str)
df["_user"]            = safe_col(df, "User").fillna("UNKNOWN").astype(str)
df["_image_loaded"]    = safe_col(df, "ImageLoaded").astype(str)
df["_target_image"]    = safe_col(df, "TargetImage").astype(str)
df["_target_filename"] = safe_col(df, "TargetFilename").astype(str)

# ════════════════════════════════════════════════════════════════════
# STEP 2 — RULE-BASED SECURITY FLAGS (event level)
# ════════════════════════════════════════════════════════════════════
print("[2/9] Running detection rules...")

df["f_powershell"]  = df["_process"].str.contains("powershell", case=False, na=False)
df["f_encoded_cmd"] = df["_cmd"].str.contains(r"-enc|-encodedcommand", case=False, na=False, regex=True)
df["f_long_cmd"]    = df["_cmd"].str.len().fillna(0) > 100
df["f_office_spawn"]= (
    df["_parent"].str.contains("winword|excel|outlook|onenote", case=False, na=False) &
    df["_process"].str.contains("powershell|cmd|wscript|cscript", case=False, na=False)
)
HACK_TOOLS = "mimikatz|sharpview|psexec|cobalt|meterpreter|rubeus|seatbelt|sharphound|bloodhound"
df["f_hack_tool"]   = df["_process"].str.contains(HACK_TOOLS, case=False, na=False, regex=True)
ATTACK_SIGS = r"Get-ObjectAcl|privilege::debug|sekurlsa|Invoke-Mimikatz|lsadump|net user /add|whoami /all|nltest"
df["f_attack_sig"]  = df["_cmd"].str.contains(ATTACK_SIGS, case=False, na=False, regex=True)

df["f_unsigned"] = False
if "EventID" in df.columns:
    m1 = df["EventID"] == 1
    if m1.any():
        signed  = safe_col(df, "Signed").astype(str).str.lower()
        sigstat = safe_col(df, "SignatureStatus").astype(str).str.lower()
        df.loc[m1, "f_unsigned"] = (
            signed[m1].isin(["false", "0", "nan"]) | ~sigstat[m1].str.contains("valid", na=False)
        )

df["f_suspicious_dll"] = False
if "EventID" in df.columns:
    m7 = df["EventID"] == 7
    if m7.any():
        df.loc[m7, "f_suspicious_dll"] = df.loc[m7, "_image_loaded"].str.contains(
            r"\\Temp\\|\\AppData\\|\\ProgramData\\", case=False, na=False, regex=True
        )

df["f_lsass_access"] = False
if "EventID" in df.columns:
    m10 = df["EventID"] == 10
    if m10.any():
        df.loc[m10, "f_lsass_access"] = df.loc[m10, "_target_image"].str.contains(
            "lsass", case=False, na=False
        )

df["f_temp_write"] = False
if "EventID" in df.columns:
    m11 = df["EventID"] == 11
    if m11.any():
        df.loc[m11, "f_temp_write"] = df.loc[m11, "_target_filename"].str.contains(
            r"\\Temp\\|\\AppData\\Local\\Temp\\", case=False, na=False, regex=True
        )

FLAG_COLS = [
    "f_powershell","f_encoded_cmd","f_long_cmd","f_office_spawn","f_hack_tool",
    "f_attack_sig","f_unsigned","f_suspicious_dll","f_lsass_access","f_temp_write"
]
df["rule_score"] = df[FLAG_COLS].sum(axis=1)
df["is_alert"]   = df["rule_score"] > 0

# ════════════════════════════════════════════════════════════════════
# STEP 3 — EVENT-LEVEL HELPER FEATURES
# ════════════════════════════════════════════════════════════════════
print("[3/9] Engineering event-level features...")

df["cmd_len"]       = df["_cmd"].str.len().fillna(0)
df["proc_depth"]    = df["_process"].str.count(r"\\").fillna(0)
df["hour_of_day"]   = df["@timestamp"].dt.hour.fillna(0).astype(int)
df["is_system_ctx"] = df["_process"].str.startswith("C:\\Windows\\System32", na=False).astype(int)
df["time_window"]   = df["@timestamp"].dt.floor("5min")

# ════════════════════════════════════════════════════════════════════
# STEP 4 — TIME-WINDOW BEHAVIORAL AGGREGATION
# ════════════════════════════════════════════════════════════════════
print("[4/9] Aggregating into 5-minute behavioral windows...")

eid = df.get("EventID", pd.Series(0, index=df.index))

agg = df.groupby(["_host", "time_window"]).agg(
    total_events       = ("_process",       "count"),
    proc_create_count  = ("EventID",        lambda x: (x == 1).sum()),
    network_conn_count = ("EventID",        lambda x: (x == 3).sum()),
    image_load_count   = ("EventID",        lambda x: (x == 7).sum()),
    proc_access_count  = ("EventID",        lambda x: (x == 10).sum()),
    file_create_count  = ("EventID",        lambda x: (x == 11).sum()),
    dns_query_count    = ("EventID",        lambda x: (x == 22).sum()),
    powershell_count   = ("f_powershell",   "sum"),
    encoded_cmd_count  = ("f_encoded_cmd",  "sum"),
    long_cmd_count     = ("f_long_cmd",     "sum"),
    office_spawn_count = ("f_office_spawn", "sum"),
    hack_tool_count    = ("f_hack_tool",    "sum"),
    attack_sig_count   = ("f_attack_sig",   "sum"),
    unsigned_count     = ("f_unsigned",     "sum"),
    suspicious_dll_count=("f_suspicious_dll","sum"),
    lsass_access_count = ("f_lsass_access", "sum"),
    temp_write_count   = ("f_temp_write",   "sum"),
    unique_processes   = ("_process",       "nunique"),
    unique_parents     = ("_parent",        "nunique"),
    unique_users       = ("_user",          "nunique"),
    avg_cmd_len        = ("cmd_len",        "mean"),
    max_cmd_len        = ("cmd_len",        "max"),
    avg_proc_depth     = ("proc_depth",     "mean"),
    system_ctx_count   = ("is_system_ctx",  "sum"),
).reset_index().fillna(0)

# ════════════════════════════════════════════════════════════════════
# STEP 5 — ISOLATION FOREST (on aggregated windows)
# ════════════════════════════════════════════════════════════════════
print("[5/9] Training Isolation Forest on behavioral windows...")

ML_FEATURES = [
    "total_events","proc_create_count","network_conn_count","image_load_count",
    "proc_access_count","file_create_count","dns_query_count",
    "powershell_count","encoded_cmd_count","long_cmd_count","office_spawn_count",
    "hack_tool_count","attack_sig_count","unsigned_count","suspicious_dll_count",
    "lsass_access_count","temp_write_count",
    "unique_processes","unique_parents","unique_users",
    "avg_cmd_len","max_cmd_len","avg_proc_depth","system_ctx_count",
]
ML_FEATURES = [f for f in ML_FEATURES if f in agg.columns]
X = agg[ML_FEATURES].fillna(0).astype(float)

iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
iso.fit(X)
agg["anomaly_score"] = iso.score_samples(X)
agg["is_anomaly"]    = iso.predict(X) == -1

# ════════════════════════════════════════════════════════════════════
# STEP 6 — EXPLAINABILITY
# ════════════════════════════════════════════════════════════════════
print("[6/9] Computing explainability...")

# A) Feature deviation
anomaly_mask   = agg["is_anomaly"]
feat_deviation = pd.Series({
    col: float(X[col][anomaly_mask].mean() - X[col].mean()) for col in ML_FEATURES
}).abs().sort_values(ascending=True)

# B) Window-level rule score
agg["rule_score"] = (
    agg["encoded_cmd_count"]   * 1 +
    agg["office_spawn_count"]  * 1 +
    agg["hack_tool_count"]     * 1 +
    agg["attack_sig_count"]    * 1 +
    agg["unsigned_count"]      * 1 +
    agg["suspicious_dll_count"]* 1 +
    agg["lsass_access_count"]  * 2 +
    agg["temp_write_count"]    * 1 +
    agg["powershell_count"]    * 0.5
)

# C) Anomaly risk (0–10 scale, lower score = more dangerous)
agg["anomaly_risk"] = (
    (-agg["anomaly_score"] - (-agg["anomaly_score"]).min()) /
    ((-agg["anomaly_score"]).max() - (-agg["anomaly_score"]).min() + 1e-9) * 10
)

# D) Severity score
agg["severity_score"] = agg["rule_score"] + agg["anomaly_risk"]

# E) Severity label
def severity_label(s):
    if s >= 12: return "High"
    if s >= 6:  return "Medium"
    return "Low"
agg["severity"] = agg["severity_score"].apply(severity_label)

# F) Top reasons per window
REASON_MAP = [
    ("encoded_cmd_count",    "Encoded PowerShell"),
    ("lsass_access_count",   "LSASS Access"),
    ("hack_tool_count",      "Hack Tool"),
    ("attack_sig_count",     "Attack Signature"),
    ("office_spawn_count",   "Office→Shell"),
    ("suspicious_dll_count", "Suspicious DLL"),
    ("temp_write_count",     "Temp Write"),
    ("unsigned_count",       "Unsigned Binary"),
    ("powershell_count",     "PowerShell"),
]
def top_reasons(row):
    hits = [label for col, label in REASON_MAP if row.get(col, 0) > 0]
    if not hits and row.get("is_anomaly"):
        return "Behavioral deviation"
    return ", ".join(hits[:4]) if hits else "—"

agg["top_reasons"] = agg.apply(top_reasons, axis=1)

# ════════════════════════════════════════════════════════════════════
# STEP 7 — MAP SUSPICIOUS WINDOWS → RAW EVENTS
# ════════════════════════════════════════════════════════════════════
print("[7/9] Mapping suspicious windows back to raw events...")

suspicious_windows = agg[(agg["is_anomaly"]) | (agg["rule_score"] > 0)][
    ["_host","time_window","severity","severity_score","anomaly_score","top_reasons","is_anomaly"]
].copy()

threats = df.merge(
    suspicious_windows[["_host","time_window","severity","severity_score","anomaly_score","top_reasons","is_anomaly"]],
    on=["_host","time_window"], how="inner"
)

# ════════════════════════════════════════════════════════════════════
# STEP 8 — EXPORT
# ════════════════════════════════════════════════════════════════════
print("[8/9] Exporting CSV files...")

EXPORT_COLS = [
    "@timestamp","_host","EventID","_process","_parent","_cmd",
    "rule_score","is_alert","anomaly_score","severity","top_reasons",
    "Hashes","Signed","SignatureStatus",
] + FLAG_COLS
export_cols_avail = [c for c in EXPORT_COLS if c in threats.columns]
threats[export_cols_avail].to_json(OUT_ALERTS, orient="records", indent=2)

agg.to_json(OUT_AGG, orient="records", indent=2)

# ════════════════════════════════════════════════════════════════════
# STEP 9 — HTML DASHBOARD
# ════════════════════════════════════════════════════════════════════
print("[9/9] Building HTML dashboard...")

C_BG    = "#0d1117"
C_CARD  = "#161b22"
C_BORD  = "#21262d"
C_RED   = "#f85149"
C_AMBER = "#e3b341"
C_GREEN = "#3fb950"
C_BLUE  = "#58a6ff"
C_PURP  = "#bc8cff"
C_TEXT  = "#c9d1d9"
C_MUTED = "#8b949e"

BASE_LAYOUT = dict(
    paper_bgcolor=C_CARD, plot_bgcolor=C_CARD,
    font=dict(color=C_TEXT, family="'JetBrains Mono', monospace", size=12),
    margin=dict(l=50, r=20, t=44, b=40),
)

def div(fig): return pio.to_html(fig, full_html=False, include_plotlyjs=False)

# ── Chart 1: Threat Timeline ───────────────────────────────────────
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

# ── Chart 2: Top Suspicious Hosts ─────────────────────────────────
top_hosts = (suspicious_windows.groupby("_host").size()
             .reset_index(name="windows").nlargest(10,"windows"))
fig2 = go.Figure(go.Bar(
    x=top_hosts["windows"], y=top_hosts["_host"],
    orientation="h", marker_color=C_RED,
))
fig2.update_layout(**BASE_LAYOUT, title="🖥️ Top Suspicious Hosts", height=280)
fig2.update_xaxes(gridcolor=C_BORD)
fig2.update_yaxes(gridcolor=C_BORD)

# ── Chart 3: Event ID Distribution ────────────────────────────────
SYSMON_LABELS = {
    1:"Process Create",3:"Network Conn",7:"Image Load",10:"Process Access",
    11:"File Create",12:"Registry",13:"Registry Set",22:"DNS Query",
    23:"File Delete",4656:"Object Access",4658:"Handle Close",
    4663:"File Obj Access",4673:"Privileged Svc",4688:"Process Create(Sec)",
    4689:"Process Exit",4690:"Handle Dup",5156:"Net Filter",5158:"Net Filter Bind",
}
if "EventID" in df.columns:
    eid_df = df["EventID"].value_counts().nlargest(10).reset_index()
    eid_df.columns = ["EventID","count"]
    eid_df["label"] = eid_df["EventID"].map(SYSMON_LABELS).fillna(eid_df["EventID"].astype(str))
    fig3 = go.Figure(go.Bar(
        x=eid_df["count"], y=eid_df["label"],
        orientation="h", marker_color=C_BLUE,
    ))
else:
    fig3 = go.Figure()
fig3.update_layout(**BASE_LAYOUT, title="📊 Event ID Distribution", height=300)
fig3.update_xaxes(gridcolor=C_BORD)
fig3.update_yaxes(gridcolor=C_BORD)

# ── Chart 4: Detection Rule Breakdown ─────────────────────────────
rule_labels = {
    "f_powershell":"PowerShell","f_encoded_cmd":"Encoded CMD","f_long_cmd":"Long Command",
    "f_office_spawn":"Office→Shell","f_hack_tool":"Hack Tool","f_attack_sig":"Attack Signature",
    "f_unsigned":"Unsigned Binary","f_suspicious_dll":"Suspicious DLL",
    "f_lsass_access":"LSASS Access","f_temp_write":"Temp Write",
}
rule_series = pd.Series({v: int(df[k].sum()) for k,v in rule_labels.items() if k in df.columns})
rule_series = rule_series.sort_values()
rule_colors = [C_RED if v > 0 else C_MUTED for v in rule_series.values]
fig4 = go.Figure(go.Bar(
    x=rule_series.values, y=rule_series.index,
    orientation="h", marker_color=rule_colors,
))
fig4.update_layout(**BASE_LAYOUT, title="🚨 Detection Rule Breakdown", height=320)
fig4.update_xaxes(gridcolor=C_BORD)
fig4.update_yaxes(gridcolor=C_BORD)

# ── Chart 5: Feature Importance / Deviation ───────────────────────
fig5 = go.Figure(go.Bar(
    x=feat_deviation.values, y=feat_deviation.index,
    orientation="h", marker_color=C_AMBER,
))
fig5.update_layout(**BASE_LAYOUT, title="🤖 Feature Deviation (Anomaly vs All)", height=360)
fig5.update_xaxes(gridcolor=C_BORD)
fig5.update_yaxes(gridcolor=C_BORD)

# ── Chart 6: Anomaly Score Distribution ───────────────────────────
fig6 = go.Figure()
fig6.add_trace(go.Histogram(
    x=agg[~agg["is_anomaly"]]["anomaly_score"],
    name="Normal", marker_color=C_GREEN, opacity=0.7, nbinsx=30,
))
fig6.add_trace(go.Histogram(
    x=agg[agg["is_anomaly"]]["anomaly_score"],
    name="Anomaly", marker_color=C_RED, opacity=0.85, nbinsx=20,
))
fig6.update_layout(
    **BASE_LAYOUT, barmode="overlay",
    title="📉 Anomaly Score Distribution (lower = more suspicious)",
    height=280, legend=dict(bgcolor="rgba(0,0,0,0)"),
)
fig6.update_xaxes(gridcolor=C_BORD)
fig6.update_yaxes(gridcolor=C_BORD)

# ── Tables ─────────────────────────────────────────────────────────
def severity_badge(s):
    colors = {"High": C_RED, "Medium": C_AMBER, "Low": C_GREEN}
    c = colors.get(s, C_MUTED)
    return f'<span style="color:{c};font-weight:600">{s}</span>'

def build_window_table(df_in, max_rows=15):
    cols = ["time_window","_host","severity","severity_score","anomaly_score","top_reasons"]
    avail = [c for c in cols if c in df_in.columns]
    rows = ""
    for _, r in df_in.sort_values("severity_score", ascending=False).head(max_rows).iterrows():
        sev = severity_badge(str(r.get("severity","—")))
        ts  = str(r.get("time_window",""))[:16]
        host= str(r.get("_host",""))
        ss  = f'{r.get("severity_score",0):.1f}'
        ans = f'{r.get("anomaly_score",0):.3f}'
        rsn = str(r.get("top_reasons","—"))
        rows += f"<tr><td>{ts}</td><td>{host}</td><td>{sev}</td><td>{ss}</td><td>{ans}</td><td>{rsn}</td></tr>"
    return rows

def build_event_table(df_in, max_rows=20):
    cols = ["@timestamp","EventID","_process","_parent","rule_score","severity"]
    avail = [c for c in cols if c in df_in.columns]
    rows = ""
    for _, r in df_in.sort_values("rule_score", ascending=False).head(max_rows).iterrows():
        ts  = str(r.get("@timestamp",""))[:19]
        eid = str(r.get("EventID",""))
        proc= str(r.get("_process",""))[-50:]
        par = str(r.get("_parent",""))[-40:]
        rs  = int(r.get("rule_score",0))
        sev = severity_badge(str(r.get("severity","—")))
        sc  = C_RED if rs > 1 else C_AMBER if rs > 0 else C_GREEN
        rows += f'<tr><td>{ts}</td><td>{eid}</td><td title="{r.get("_process","")}">{proc}</td><td title="{r.get("_parent","")}">{par}</td><td style="color:{sc};text-align:center;font-weight:600">{rs}</td><td>{sev}</td></tr>'
    return rows

window_table_rows = build_window_table(suspicious_windows if len(suspicious_windows) else agg)
event_table_rows  = build_event_table(threats if len(threats) else df)

# ── KPI values ────────────────────────────────────────────────────
kpi_total_events  = len(df)
kpi_total_hosts   = df["_host"].nunique()
kpi_anomalous_win = int(agg["is_anomaly"].sum())
kpi_threat_events = len(threats)
kpi_encoded_ps    = int(df["f_encoded_cmd"].sum()) if "f_encoded_cmd" in df.columns else 0
kpi_lsass         = int(df["f_lsass_access"].sum()) if "f_lsass_access" in df.columns else 0
generated_at      = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

def kpi_color(val, thres_red=1, thres_amber=0):
    if val >= thres_red: return C_RED
    return C_GREEN

# ── Build HTML ─────────────────────────────────────────────────────
html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Windows Endpoint Behavioral Analysis</title>
<script src="https://cdn.plot.ly/plotly-2.32.0.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,400;0,600;0,700&display=swap" rel="stylesheet"/>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:{C_BG};color:{C_TEXT};font-family:'JetBrains Mono',monospace;font-size:13px;line-height:1.5}}
a{{color:{C_BLUE};text-decoration:none}}

/* top bar */
.topbar{{background:#010409;border-bottom:1px solid {C_BORD};padding:12px 28px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:100}}
.topbar h1{{font-size:14px;font-weight:700;color:#fff;letter-spacing:.4px}}
.badge{{background:{C_BORD};border-radius:4px;padding:2px 9px;font-size:11px;color:{C_MUTED}}}
.dot-red{{width:8px;height:8px;border-radius:50%;background:{C_RED};display:inline-block;animation:pulse 1.5s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.3}}}}

/* layout */
.main{{padding:24px 28px;max-width:1440px;margin:0 auto}}

/* KPI */
.kpi-row{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:22px}}
@media(max-width:1100px){{.kpi-row{{grid-template-columns:repeat(3,1fr)}}}}
.kpi{{background:{C_CARD};border:1px solid {C_BORD};border-radius:8px;padding:18px 20px}}
.kpi .lbl{{color:{C_MUTED};font-size:10px;text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px}}
.kpi .val{{font-size:28px;font-weight:700}}
.kpi .sub{{font-size:10px;color:{C_MUTED};margin-top:4px}}

/* cards */
.card{{background:{C_CARD};border:1px solid {C_BORD};border-radius:8px;overflow:hidden;padding:4px}}
.card-pad{{background:{C_CARD};border:1px solid {C_BORD};border-radius:8px;padding:18px 20px;overflow:auto}}
.section-title{{font-size:11px;color:{C_MUTED};text-transform:uppercase;letter-spacing:.7px;margin-bottom:12px;font-weight:600}}

/* grid */
.g1{{margin-bottom:14px}}
.g2{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}}
.g3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:14px}}

/* table */
table{{width:100%;border-collapse:collapse;font-size:12px}}
thead tr{{background:#1c2128}}
th{{padding:10px 12px;text-align:left;color:{C_MUTED};font-size:10px;text-transform:uppercase;letter-spacing:.6px;font-weight:700;border-bottom:1px solid {C_BORD}}}
td{{padding:9px 12px;border-bottom:1px solid {C_BORD};max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
tr:hover td{{background:#1c2128}}

/* footer */
.footer{{text-align:center;color:{C_MUTED};font-size:10px;padding:24px;border-top:1px solid {C_BORD};margin-top:22px}}
</style>
</head>
<body>

<div class="topbar">
  <div class="dot-red"></div>
  <h1>Windows Endpoint Behavioral Analysis</h1>
  <span class="badge">Isolation Forest</span>
  <span class="badge">5-min Behavioral Windows</span>
  <span class="badge" style="margin-left:auto;color:{C_MUTED}">🕒 {generated_at}</span>
</div>

<div class="main">

<!-- KPI -->
<div class="kpi-row">
  <div class="kpi"><div class="lbl">Total Events</div><div class="val" style="color:{C_BLUE}">{kpi_total_events:,}</div><div class="sub">Raw log rows</div></div>
  <div class="kpi"><div class="lbl">Hosts</div><div class="val" style="color:{C_BLUE}">{kpi_total_hosts:,}</div><div class="sub">Unique endpoints</div></div>
  <div class="kpi"><div class="lbl">Anomalous Windows</div><div class="val" style="color:{kpi_color(kpi_anomalous_win)}">{kpi_anomalous_win}</div><div class="sub">ML-flagged 5-min windows</div></div>
  <div class="kpi"><div class="lbl">Threat Events</div><div class="val" style="color:{kpi_color(kpi_threat_events)}">{kpi_threat_events:,}</div><div class="sub">Raw events in suspicious windows</div></div>
  <div class="kpi"><div class="lbl">Encoded PowerShell</div><div class="val" style="color:{kpi_color(kpi_encoded_ps)}">{kpi_encoded_ps}</div><div class="sub">-enc / -encodedcommand</div></div>
  <div class="kpi"><div class="lbl">LSASS Access</div><div class="val" style="color:{kpi_color(kpi_lsass)}">{kpi_lsass}</div><div class="sub">Credential dump indicators</div></div>
</div>

<!-- Timeline full width -->
<div class="card g1">{div(fig1)}</div>

<!-- Charts row 2 -->
<div class="g2">
  <div class="card">{div(fig2)}</div>
  <div class="card">{div(fig6)}</div>
</div>

<!-- Charts row 3 -->
<div class="g3">
  <div class="card">{div(fig3)}</div>
  <div class="card">{div(fig4)}</div>
  <div class="card">{div(fig5)}</div>
</div>

<!-- Suspicious Windows Table -->
<div class="card-pad g1">
  <div class="section-title">🔴 Top Suspicious Behavioral Windows</div>
  <table>
    <thead><tr>
      <th>Time Window</th><th>Host</th><th>Severity</th>
      <th>Severity Score</th><th>Anomaly Score</th><th>Top Reasons</th>
    </tr></thead>
    <tbody>{window_table_rows if window_table_rows else '<tr><td colspan="6" style="text-align:center;color:'+C_GREEN+';padding:20px">✅ No suspicious windows detected</td></tr>'}</tbody>
  </table>
</div>

<!-- Threat Events Table -->
<div class="card-pad">
  <div class="section-title">⚠️ Top Threat Events (raw)</div>
  <table>
    <thead><tr>
      <th>Timestamp</th><th>EventID</th><th>Process</th>
      <th>Parent</th><th>Rule Score</th><th>Severity</th>
    </tr></thead>
    <tbody>{event_table_rows if event_table_rows else '<tr><td colspan="6" style="text-align:center;color:'+C_GREEN+';padding:20px">✅ No threat events</td></tr>'}</tbody>
  </table>
</div>

</div><!-- end main -->

<div class="footer">
  Windows Endpoint Behavioral Analysis &nbsp;|&nbsp;
  Isolation Forest (sklearn 200 estimators) &nbsp;|&nbsp;
  5-min Time-Window Aggregation &nbsp;|&nbsp;
  OTRF / Mordor-compatible &nbsp;|&nbsp;
  {generated_at}
</div>
</body>
</html>"""

with open(OUT_DASH, "w", encoding="utf-8") as f:
    f.write(html)

# ════════════════════════════════════════════════════════════════════
# STEP 10 — TERMINAL SUMMARY
# ════════════════════════════════════════════════════════════════════
print()
print("╔══════════════════════════════════════════════════════╗")
print("║     WINDOWS ENDPOINT BEHAVIORAL ANALYSIS RESULTS    ║")
print("╠══════════════════════════════════════════════════════╣")
print(f"║  Total events           : {len(df):>6,}                    ║")
print(f"║  Total hosts            : {df['_host'].nunique():>6,}                    ║")
print(f"║  5-min windows          : {len(agg):>6,}                    ║")
print(f"║  Anomalous windows (ML) : {int(agg['is_anomaly'].sum()):>6,}                    ║")
print(f"║  Suspicious windows     : {len(suspicious_windows):>6,}                    ║")
print(f"║  Suspicious events      : {len(threats):>6,}                    ║")
print(f"║  Encoded PowerShell     : {kpi_encoded_ps:>6,}                    ║")
print(f"║  LSASS access events    : {kpi_lsass:>6,}                    ║")
print("╠══════════════════════════════════════════════════════╣")
print(f"║  alerts_full.csv        → {OUT_ALERTS[-28:]}  ║")
print(f"║  aggregated_windows.csv → {OUT_AGG[-28:]}  ║")
print(f"║  dashboard.html         → {OUT_DASH[-28:]}  ║")
print("╚══════════════════════════════════════════════════════╝")