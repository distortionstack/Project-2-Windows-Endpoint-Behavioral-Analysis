"""
Windows Endpoint Behavioral Analysis Pipeline
Mordor-compatible | Time-Window Behavioral Features | Isolation Forest | HTML Dashboard
"""

import warnings
import webbrowser 
import os
from pathlib import Path
from detection import FLAG_COLS
from loader    import get_smart_data, normalize
from detection import run_detection
from ml        import run_ml
from dashboard import build_dashboard

warnings.filterwarnings("ignore")

# Use an array of URLs as requested
URLS = [
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_extract_keys.zip",
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/discovery/host/cmd_seatbelt_group_user.zip",
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/defense_evasion/host/cmd_bitsadmin_download_psh_script.zip",
    "https://github.com/OTRF/Security-Datasets/raw/refs/heads/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_sam_access.zip",
    "https://github.com/OTRF/Security-Datasets/raw/refs/heads/master/datasets/atomic/windows/credential_access/host/cmd_sam_copy_esentutl.zip"
]

OUT_ALERTS  = "outputs\\alerts_full.json"
OUT_AGG     = "outputs\\aggregated_windows.json"
OUT_DASH    = "outputs\\dashboard.html"

# Ensure output directory exists (handled by smart_data as well)
Path("outputs").mkdir(parents=True, exist_ok=True)

# ── Load ──────────────────────────────────────────────────────────
print("[1/4] Loading & normalising...")
raw_df = get_smart_data(URLS, force_update=False)
df = normalize(raw_df)

# ── Detect ────────────────────────────────────────────────────────
print("[2/4] Running detection rules...")
df = run_detection(df)

# ── ML ────────────────────────────────────────────────────────────
print("[3/4] Running ML pipeline...")
agg, feat_deviation, suspicious_windows, threats = run_ml(df)

# ── Export ────────────────────────────────────────────────────────
EXPORT_COLS = [
    "@timestamp", "_host", "EventID", "_process", "_parent", "_cmd",
    "rule_score", "is_alert", "anomaly_score", "severity", "top_reasons",
    "Hashes", "Signed", "SignatureStatus",
] + FLAG_COLS
export_avail = [c for c in EXPORT_COLS if c in threats.columns]

# Export to JSON
threats[export_avail].to_json(OUT_ALERTS, orient="records", indent=2)
agg.to_json(OUT_AGG, orient="records", indent=2)

# ── Dashboard ─────────────────────────────────────────────────────
print("[4/4] Building dashboard...")
build_dashboard(df, agg, suspicious_windows, threats, feat_deviation, OUT_DASH)

# ── Summary ───────────────────────────────────────────────────────
kpi_encoded_ps = int(df["f_encoded_cmd"].sum()) if "f_encoded_cmd" in df.columns else 0
kpi_lsass      = int(df["f_lsass_access"].sum()) if "f_lsass_access" in df.columns else 0

print()
print("+------------------------------------------------------+")
print("|     WINDOWS ENDPOINT BEHAVIORAL ANALYSIS RESULTS     |")
print("+------------------------------------------------------+")
print(f"|  Total events           : {len(df):>6,}                    |")
print(f"|  Total hosts            : {df['_host'].nunique():>6,}                    |")
print(f"|  5-min windows          : {len(agg):>6,}                    |")
print(f"|  Anomalous windows (ML) : {int(agg['is_anomaly'].sum()):>6,}                    |")
print(f"|  Suspicious windows     : {len(suspicious_windows):>6,}                    |")
print(f"|  Suspicious events      : {len(threats):>6,}                    |")
print(f"|  Encoded PowerShell     : {kpi_encoded_ps:>6,}                    |")
print(f"|  LSASS access events    : {kpi_lsass:>6,}                    |")
print("+------------------------------------------------------+")
print(f"|  alerts_full.json       -> {OUT_ALERTS[-28:]}  |")
print(f"|  aggregated_windows.json-> {OUT_AGG[-28:]}  |")
print(f"|  dashboard.html         -> {OUT_DASH[-28:]}  |")
print("+------------------------------------------------------+")


# Open the dashboard in the default web browser (Windows-specific)
dashboard_file_path = os.path.abspath(OUT_DASH)
webbrowser.open("file://" + dashboard_file_path)
