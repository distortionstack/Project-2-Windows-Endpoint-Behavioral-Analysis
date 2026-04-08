"""detection.py — Rule-based security flags + event-level helper features"""

import numpy as np
import pandas as pd
from loader import safe_col

FLAG_COLS = [
    "f_powershell", "f_encoded_cmd", "f_long_cmd", "f_office_spawn", "f_hack_tool",
    "f_attack_sig", "f_unsigned", "f_suspicious_dll", "f_lsass_access", "f_temp_write",
]

HACK_TOOLS  = "mimikatz|sharpview|psexec|cobalt|meterpreter|rubeus|seatbelt|sharphound|bloodhound"
ATTACK_SIGS = r"Get-ObjectAcl|privilege::debug|sekurlsa|Invoke-Mimikatz|lsadump|net user /add|whoami /all|nltest"


def run_detection(df):
    """Add all rule-based flags, rule_score, is_alert, and helper features."""

    # ── Rule flags ──────────────────────────────────────────────────
    df["f_powershell"]   = df["_process"].str.contains("powershell", case=False, na=False)
    df["f_encoded_cmd"]  = df["_cmd"].str.contains(r"-enc|-encodedcommand", case=False, na=False, regex=True)
    df["f_long_cmd"]     = df["_cmd"].str.len().fillna(0) > 100
    df["f_office_spawn"] = (
        df["_parent"].str.contains("winword|excel|outlook|onenote", case=False, na=False) &
        df["_process"].str.contains("powershell|cmd|wscript|cscript", case=False, na=False)
    )
    df["f_hack_tool"]    = df["_process"].str.contains(HACK_TOOLS, case=False, na=False, regex=True)
    df["f_attack_sig"]   = df["_cmd"].str.contains(ATTACK_SIGS, case=False, na=False, regex=True)

    df["f_unsigned"] = False
    if "EventID" in df.columns:
        m1 = df["EventID"] == 1
        if m1.any():
            signed  = safe_col(df, "Signed").astype(str).str.lower()
            sigstat = safe_col(df, "SignatureStatus").astype(str).str.lower()
            df.loc[m1, "f_unsigned"] = (
                signed[m1].isin(["false", "0", "nan"]) |
                ~sigstat[m1].str.contains("valid", na=False)
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

    df["rule_score"] = df[FLAG_COLS].sum(axis=1)
    df["is_alert"]   = df["rule_score"] > 0

    # ── Helper features ─────────────────────────────────────────────
    df["cmd_len"]       = df["_cmd"].str.len().fillna(0)
    df["proc_depth"]    = df["_process"].str.count(r"\\").fillna(0)
    df["hour_of_day"]   = df["@timestamp"].dt.hour.fillna(0).astype(int)
    df["is_system_ctx"] = df["_process"].str.startswith("C:\\Windows\\System32", na=False).astype(int)
    df["time_window"]   = df["@timestamp"].dt.floor("5min")

    return df
