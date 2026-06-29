"""normalize.py — Raw data normalization and column standardization."""

import logging

import numpy as np
import pandas as pd

from src.main.myapp.loader.loader import safe_col

logger = logging.getLogger(__name__)


def normalize(df: pd.DataFrame) -> pd.DataFrame:
    _df = df.copy()

    _df["winlog_event_id"]        = safe_col(_df, "winlog.event_id")
    _df["winlog_process_name"]    = safe_col(_df, "winlog.event_data.ProcessName")
    _df["winlog_parent_name"]     = safe_col(_df, "winlog.event_data.ParentProcessName")
    _df["winlog_command_line"]    = safe_col(_df, "winlog.event_data.CommandLine")
    _df["winlog_target_image"]    = safe_col(_df, "winlog.event_data.TargetImage")
    _df["winlog_image_loaded"]    = safe_col(_df, "winlog.event_data.ImageLoaded")
    _df["winlog_target_filename"] = safe_col(_df, "winlog.event_data.TargetFilename")
    _df["winlog_user"]            = safe_col(_df, "winlog.event_data.SubjectUserName")
    _df["winlog_user2"]           = safe_col(_df, "winlog.event_data.TargetUserName")
    _df["host_name"]              = safe_col(_df, "host.name")
    _df["winlog_computer_name"]   = safe_col(_df, "winlog.computer_name")
    _df["winlog_utctime"]         = safe_col(_df, "winlog.event_data.UtcTime")
    _df["winlog_timecreated"]     = safe_col(_df, "winlog.time_created")

    ts_series = safe_col(_df, "UtcTime", "winlog_utctime", "winlog.event_data.UtcTime")
    ts_parsed = pd.to_datetime(ts_series, utc=True, errors="coerce")

    fallback = pd.to_datetime(
        safe_col(_df, "@timestamp", "TimeCreated", "winlog_timecreated"),
        utc=True, errors="coerce",
    )
    _df["@timestamp"] = ts_parsed.fillna(fallback)

    if _df["@timestamp"].isna().all():
        raise ValueError(
            "Pipeline validation failed: every row has an invalid / missing timestamp. "
            "Ensure your source contains at least one of: @timestamp, UtcTime, TimeCreated."
        )

    _df["@timestamp"] = _df["@timestamp"].ffill().bfill()

    valid_ts = _df["@timestamp"].notna()
    dropped  = (~valid_ts).sum()
    if dropped > 0:
        logger.warning(
            f"Dropped {dropped} rows ({dropped / len(_df) * 100:.1f}%) with "
            f"invalid timestamps.  Range: {_df['@timestamp'].min()} - {_df['@timestamp'].max()}"
        )
    _df = _df[valid_ts].copy()

    _df["EventID"] = pd.to_numeric(
        safe_col(_df, "EventID", "event_id", "winlog_event_id"), errors="coerce"
    )
    if _df["EventID"].isna().all():
        logger.warning("[!] No EventID found. Defaulting all rows to EventID -1")
        _df["EventID"] = _df["EventID"].fillna(-1)

    _df = _df.dropna(subset=["EventID"]).copy()
    _df["EventID"] = _df["EventID"].astype(int)
    logger.info(f"EventID distribution: {_df['EventID'].value_counts().head().to_dict()}")

    channel_col = safe_col(_df, "Channel", "winlog.channel", "channel").astype(str).str.lower()

    _channel_conditions = [
        channel_col.str.contains("sysmon",      na=False),
        channel_col.str.contains("security",    na=False),
        channel_col.str.contains("powershell",  na=False),
        channel_col.str.contains("defender",    na=False),
        channel_col.str.contains("firewall",    na=False),
        channel_col.str.contains("application", na=False),
        channel_col.str.contains(r"^system$",   na=False, regex=True),
    ]
    _channel_choices = ["sysmon", "security", "powershell",
                        "defender", "firewall", "application", "system"]
    _df["_channel"] = np.select(_channel_conditions, _channel_choices, default="unknown")

    eid_col       = _df["EventID"]
    sysmon_mask   = channel_col.str.contains("sysmon",   na=False)
    security_mask = channel_col == "security"

    _action_conditions = [
        (sysmon_mask & (eid_col == 1))  | (security_mask & (eid_col == 4688)),
        (sysmon_mask & (eid_col == 3))  | (security_mask & (eid_col == 5156)),
        (sysmon_mask & (eid_col == 10)),
        (sysmon_mask & (eid_col.isin([12, 13, 14]))) | (security_mask & (eid_col == 4657)),
        (sysmon_mask & (eid_col == 11)) | (sysmon_mask & (eid_col == 23)),
        (sysmon_mask & (eid_col == 22)),
    ]
    _action_choices = [
        "process_create", "network_connect", "process_access",
        "registry_modify", "file_modify", "dns_query",
    ]
    _df["_action"] = np.select(_action_conditions, _action_choices, default="other_activity")

    for col in ["_process", "_parent", "_cmd", "_user", "_target", "_net_dst"]:
        _df[col] = None

    if sysmon_mask.any():
        _df.loc[sysmon_mask, "_process"] = safe_col(
            _df[sysmon_mask], "Image", "winlog.event_data.Image",
            "SourceImage", "winlog.event_data.SourceImage", as_str=True,
        )
        _df.loc[sysmon_mask, "_parent"] = safe_col(
            _df[sysmon_mask], "ParentImage", "winlog.event_data.ParentImage", as_str=True,
        )
        _df.loc[sysmon_mask, "_cmd"] = safe_col(
            _df[sysmon_mask], "CommandLine", "winlog.event_data.CommandLine", as_str=True,
        )
        _df.loc[sysmon_mask, "_user"] = safe_col(
            _df[sysmon_mask], "User", "winlog.event_data.User", as_str=True,
        )
        _df.loc[sysmon_mask, "_target"] = safe_col(
            _df[sysmon_mask],
            "TargetImage", "winlog.event_data.TargetImage",
            "TargetFilename", "winlog.event_data.TargetFilename",
            "TargetObject", "winlog.event_data.TargetObject",
            "QueryName", "winlog.event_data.QueryName",
            as_str=True,
        )
        dst_ip   = safe_col(_df[sysmon_mask], "DestinationIp",   "winlog.event_data.DestinationIp",   as_str=True)
        dst_port = safe_col(_df[sysmon_mask], "DestinationPort",  "winlog.event_data.DestinationPort", as_str=True)
        _df.loc[sysmon_mask, "_net_dst"] = dst_ip + ":" + dst_port

    if security_mask.any():
        _df.loc[security_mask, "_process"] = safe_col(
            _df[security_mask],
            "NewProcessName", "winlog.event_data.NewProcessName",
            "Application",    "winlog.event_data.Application",
            as_str=True,
        )
        _df.loc[security_mask, "_parent"] = safe_col(
            _df[security_mask], "ParentProcessName", "winlog.event_data.ParentProcessName", as_str=True,
        )
        _df.loc[security_mask, "_cmd"] = safe_col(
            _df[security_mask],
            "CommandLine", "winlog.event_data.CommandLine",
            "winlog.event_data.ProcessCommandLine",
            as_str=True,
        )
        _df.loc[security_mask, "_user"] = safe_col(
            _df[security_mask], "SubjectUserName", "winlog.event_data.SubjectUserName",
            "TargetUserName", as_str=True,
        )
        _df.loc[security_mask, "_target"] = safe_col(
            _df[security_mask], "ObjectName", "winlog.event_data.ObjectName", as_str=True,
        )
        s_ip   = safe_col(_df[security_mask], "DestAddress", "winlog.event_data.DestAddress", as_str=True)
        s_port = safe_col(_df[security_mask], "DestPort",    "winlog.event_data.DestPort",    as_str=True)
        _df.loc[security_mask, "_net_dst"] = s_ip + ":" + s_port

    handled_mask = sysmon_mask | security_mask
    if (~handled_mask).any():
        fallback_cols = {
            "_process": ("Image", "NewProcessName", "SourceImage", "Application"),
            "_parent":  ("ParentImage", "ParentProcessName"),
            "_cmd":     ("CommandLine", "winlog.event_data.CommandLine"),
            "_user":    ("User", "SubjectUserName", "TargetUserName"),
            "_target":  ("TargetImage", "TargetFilename", "TargetObject", "ObjectName"),
        }
        for target, names in fallback_cols.items():
            _df.loc[~handled_mask, target] = safe_col(_df[~handled_mask], *names, as_str=True)

    _df["_host"] = (
        safe_col(_df, "Hostname", "Computer", "host.name", "winlog.computer_name")
        .fillna("UNKNOWN")
        .astype(str)
    )
    for target in ["_process", "_parent", "_cmd", "_user", "_target", "_net_dst", "_action"]:
        _df[target] = _df[target].fillna("UNKNOWN").replace("nan:nan", "UNKNOWN").astype(str)

    _df["_image_loaded"]    = safe_col(_df, "ImageLoaded",    "winlog.event_data.ImageLoaded").fillna("").astype(str)
    _df["_target_image"]    = safe_col(_df, "TargetImage",    "winlog.event_data.TargetImage").fillna("").astype(str)
    _df["_target_filename"] = safe_col(_df, "TargetFilename", "winlog.event_data.TargetFilename").fillna("").astype(str)

    if logger.isEnabledFor(logging.DEBUG):
        proc_like = [
            c for c in _df.columns
            if any(k in c.lower() for k in ["process", "image", "newprocess", "application", "command"])
        ]
        logger.debug(f"Process-related columns found: {proc_like}")
        logger.debug(f"Channel distribution: {channel_col.value_counts().head(10).to_dict()}")

    return _df
