"""aggregate.py — Time-window aggregation (group_by_dynamic) for ML pipeline."""

import logging

import pandas as pd

from src.main.myapp.config.constants import SysmonEventIDs
from src.main.myapp.config.settings import get

logger = logging.getLogger(__name__)

DEFAULT_TIME_WINDOW = get("ml.time_window", "5min")


def aggregate(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["ml_time_window"] = pd.to_datetime(df["@timestamp"], errors="coerce").dt.floor(DEFAULT_TIME_WINDOW)

    df["is_proc_create"]  = (df["EventID"] == SysmonEventIDs.PROCESS_CREATE).astype("int8")
    df["is_net_conn"]     = (df["EventID"] == SysmonEventIDs.NETWORK_CONNECTION).astype("int8")
    df["is_img_load"]     = (df["EventID"] == SysmonEventIDs.DLL_IMAGE_LOAD).astype("int8")
    df["is_proc_access"]  = (df["EventID"] == SysmonEventIDs.PROCESS_ACCESS).astype("int8")
    df["is_file_create"]  = (df["EventID"] == SysmonEventIDs.FILE_CREATE).astype("int8")
    df["is_dns_query"]    = (df["EventID"] == SysmonEventIDs.DNS_QUERY).astype("int8")
    df["is_system_ctx"]   = df["is_system"].astype("int8")

    agg = df.groupby(["_host", "ml_time_window"]).agg(
        total_events            = ("_process",              "count"),
        proc_create_count       = ("_event_name", lambda x: x.str.contains("Process Create", na=False).sum()),
        network_conn_count      = ("_event_name", lambda x: x.isin(["Network Connection", "Firewall Permitted"]).sum()),
        image_load_count        = ("_event_name", lambda x: (x == "Image Loaded").sum()),
        proc_access_count       = ("_event_name", lambda x: (x == "Process Access").sum()),
        file_create_count       = ("_event_name", lambda x: (x == "File Create").sum()),
        dns_query_count         = ("_event_name", lambda x: (x == "DNS Query").sum()),
        has_powershell_sum      = ("has_powershell",        "sum"),
        has_base64_sum          = ("has_base64",            "sum"),
        has_certutil_sum        = ("has_certutil",          "sum"),
        has_wmic_sum            = ("has_wmic",              "sum"),
        has_mshta_sum           = ("has_mshta",             "sum"),
        has_rundll32_sum        = ("has_rundll32",          "sum"),
        has_attack_sig_sum      = ("has_attack_sig",        "sum"),
        office_spawned_shell_sum= ("office_spawned_shell",  "sum"),
        has_hack_tool_sum       = ("has_hack_tool",         "sum"),
        long_ps_cmd_sum         = ("long_ps_cmd",           "sum"),
        susp_port_sum           = ("susp_port",             "sum"),
        susp_ip_sum             = ("susp_ip",               "sum"),
        is_temp_write_sum       = ("is_temp_write",         "sum"),
        susp_dll_path_sum       = ("susp_dll_path",         "sum"),
        is_lsass_access_sum     = ("is_lsass_access",       "sum"),
        susp_dns_sum            = ("susp_dns",              "sum"),
        is_process_injection_sum= ("is_process_injection",  "sum"),
        unique_processes        = ("_process",              "nunique"),
        unique_parents          = ("_parent",               "nunique"),
        unique_users            = ("_user",                 "nunique"),
        avg_cmd_len             = ("cmd_len",               "mean"),
        max_cmd_len             = ("cmd_len",               "max"),
        avg_proc_depth          = ("proc_depth",            "mean"),
        system_ctx_count        = ("is_system_ctx",         "sum"),
        time_delta_mean         = ("time_delta_seconds",    "mean"),
    ).reset_index()

    return agg
