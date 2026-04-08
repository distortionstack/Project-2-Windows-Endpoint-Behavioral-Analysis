"""ml.py — Time-window aggregation, Isolation Forest, explainability, threat mapping"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

ML_FEATURES = [
    "total_events", "proc_create_count", "network_conn_count", "image_load_count",
    "proc_access_count", "file_create_count", "dns_query_count",
    "powershell_count", "encoded_cmd_count", "long_cmd_count", "office_spawn_count",
    "hack_tool_count", "attack_sig_count", "unsigned_count", "suspicious_dll_count",
    "lsass_access_count", "temp_write_count",
    "unique_processes", "unique_parents", "unique_users",
    "avg_cmd_len", "max_cmd_len", "avg_proc_depth", "system_ctx_count",
]

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


def aggregate(df):
    """Aggregate raw events into 5-minute behavioral windows per host."""
    agg = df.groupby(["_host", "time_window"]).agg(
        total_events        = ("_process",        "count"),
        proc_create_count   = ("EventID",         lambda x: (x == 1).sum()),
        network_conn_count  = ("EventID",         lambda x: (x == 3).sum()),
        image_load_count    = ("EventID",         lambda x: (x == 7).sum()),
        proc_access_count   = ("EventID",         lambda x: (x == 10).sum()),
        file_create_count   = ("EventID",         lambda x: (x == 11).sum()),
        dns_query_count     = ("EventID",         lambda x: (x == 22).sum()),
        powershell_count    = ("f_powershell",    "sum"),
        encoded_cmd_count   = ("f_encoded_cmd",   "sum"),
        long_cmd_count      = ("f_long_cmd",      "sum"),
        office_spawn_count  = ("f_office_spawn",  "sum"),
        hack_tool_count     = ("f_hack_tool",     "sum"),
        attack_sig_count    = ("f_attack_sig",    "sum"),
        unsigned_count      = ("f_unsigned",      "sum"),
        suspicious_dll_count= ("f_suspicious_dll","sum"),
        lsass_access_count  = ("f_lsass_access",  "sum"),
        temp_write_count    = ("f_temp_write",    "sum"),
        unique_processes    = ("_process",        "nunique"),
        unique_parents      = ("_parent",         "nunique"),
        unique_users        = ("_user",           "nunique"),
        avg_cmd_len         = ("cmd_len",         "mean"),
        max_cmd_len         = ("cmd_len",         "max"),
        avg_proc_depth      = ("proc_depth",      "mean"),
        system_ctx_count    = ("is_system_ctx",   "sum"),
    ).reset_index().fillna(0)
    return agg


def run_isolation_forest(agg):
    """Train Isolation Forest on aggregated windows and return agg with scores."""
    features = [f for f in ML_FEATURES if f in agg.columns]
    X = agg[features].fillna(0).astype(float)

    iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
    iso.fit(X)
    agg["anomaly_score"] = iso.score_samples(X)
    agg["is_anomaly"]    = iso.predict(X) == -1

    # Feature deviation (explainability)
    mask           = agg["is_anomaly"]
    feat_deviation = pd.Series({
        col: float(X[col][mask].mean() - X[col].mean()) for col in features
    }).abs().sort_values(ascending=True)

    return agg, feat_deviation


def add_severity(agg):
    """Add rule_score, anomaly_risk, severity_score, severity label, top_reasons."""
    agg["rule_score"] = (
        agg["encoded_cmd_count"]    * 1   +
        agg["office_spawn_count"]   * 1   +
        agg["hack_tool_count"]      * 1   +
        agg["attack_sig_count"]     * 1   +
        agg["unsigned_count"]       * 1   +
        agg["suspicious_dll_count"] * 1   +
        agg["lsass_access_count"]   * 2   +
        agg["temp_write_count"]     * 1   +
        agg["powershell_count"]     * 0.5
    )
    agg["anomaly_risk"] = (
        (-agg["anomaly_score"] - (-agg["anomaly_score"]).min()) /
        ((-agg["anomaly_score"]).max() - (-agg["anomaly_score"]).min() + 1e-9) * 10
    )
    agg["severity_score"] = agg["rule_score"] + agg["anomaly_risk"]
    agg["severity"]       = agg["severity_score"].apply(
        lambda s: "High" if s >= 12 else "Medium" if s >= 6 else "Low"
    )

    def _reasons(row):
        hits = [label for col, label in REASON_MAP if row.get(col, 0) > 0]
        if not hits and row.get("is_anomaly"):
            return "Behavioral deviation"
        return ", ".join(hits[:4]) if hits else "—"

    agg["top_reasons"] = agg.apply(_reasons, axis=1)
    return agg


def map_threats(df, agg):
    """Map suspicious windows back to raw event rows."""
    suspicious_windows = agg[(agg["is_anomaly"]) | (agg["rule_score"] > 0)][
        ["_host", "time_window", "severity", "severity_score", "anomaly_score", "top_reasons", "is_anomaly"]
    ].copy()

    threats = df.merge(
        suspicious_windows,
        on=["_host", "time_window"],
        how="inner"
    )
    return suspicious_windows, threats


def run_ml(df):
    """Full ML pipeline: aggregate → Isolation Forest → severity → map threats."""
    agg                       = aggregate(df)
    agg, feat_deviation       = run_isolation_forest(agg)
    agg                       = add_severity(agg)
    suspicious_windows, threats = map_threats(df, agg)
    return agg, feat_deviation, suspicious_windows, threats
