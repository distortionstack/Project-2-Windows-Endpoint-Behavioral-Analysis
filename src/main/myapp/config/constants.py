"""constants.py — Centralized constants: Event IDs, taxonomy, feature lists."""

from pathlib import Path


class SysmonEventIDs:
    PROCESS_CREATE         = 1
    NETWORK_CONNECTION     = 3
    DLL_IMAGE_LOAD         = 7
    CREATE_REMOTE_THREAD   = 8
    PROCESS_ACCESS         = 10
    FILE_CREATE            = 11
    DNS_QUERY              = 22


class WindowsSecurityEventIDs:
    LOGON_SUCCESS          = 4624
    LOGON_FAILURE          = 4625
    LOGOFF                 = 4634
    EXPLICIT_CREDENTIALS   = 4648
    USER_ACCOUNT_CREATED   = 4720
    USER_ACCOUNT_DELETED   = 4726
    USER_ACCOUNT_ENABLED   = 4722
    PASSWORD_CHANGED       = 4723
    PASSWORD_RESET         = 4724
    GROUP_MEMBER_ADDED     = 4732
    FIREWALL_PERMITTED     = 5156
    FIREWALL_BLOCKED       = 5157
    OBJECT_ACCESSED        = 4663
    NETWORK_SHARE_ACCESSED = 5140
    AUDIT_LOG_CLEARED      = 1102


EVENT_TAXONOMY: dict[tuple[str, int], str] = {
    ("sysmon", 1):   "Process Create",
    ("sysmon", 2):   "File Creation Time Changed",
    ("sysmon", 3):   "Network Connection",
    ("sysmon", 4):   "Sysmon Service State Changed",
    ("sysmon", 5):   "Process Terminated",
    ("sysmon", 6):   "Driver Loaded",
    ("sysmon", 7):   "Image Loaded",
    ("sysmon", 8):   "CreateRemoteThread",
    ("sysmon", 9):   "RawAccessRead",
    ("sysmon", 10):  "Process Access",
    ("sysmon", 11):  "File Create",
    ("sysmon", 12):  "Registry Event (Create/Delete)",
    ("sysmon", 13):  "Registry Event (Value Set)",
    ("sysmon", 14):  "Registry Event (Rename)",
    ("sysmon", 15):  "File Create Stream Hash",
    ("sysmon", 16):  "Sysmon Config Change",
    ("sysmon", 17):  "Pipe Created",
    ("sysmon", 18):  "Pipe Connected",
    ("sysmon", 19):  "WMI Filter",
    ("sysmon", 20):  "WMI Consumer",
    ("sysmon", 21):  "WMI Consumer Filter Bind",
    ("sysmon", 22):  "DNS Query",
    ("sysmon", 23):  "File Delete",
    ("sysmon", 24):  "Clipboard Change",
    ("sysmon", 25):  "Process Tampering",
    ("sysmon", 26):  "File Delete Detected",
    ("sysmon", 27):  "File Block Executable",
    ("sysmon", 28):  "File Block Shredding",
    ("sysmon", 29):  "File Executable Detected",
    ("sysmon", 255): "Sysmon Error",
    ("security", 4624): "Logon Success",
    ("security", 4625): "Logon Failure",
    ("security", 4634): "Logoff",
    ("security", 4648): "Explicit Credential Logon",
    ("security", 4657): "Registry Value Modified",
    ("security", 4663): "Object Accessed",
    ("security", 4672): "Special Privileges Assigned",
    ("security", 4688): "Process Create (Sec)",
    ("security", 4689): "Process Terminated (Sec)",
    ("security", 4698): "Scheduled Task Created",
    ("security", 4699): "Scheduled Task Deleted",
    ("security", 4702): "Scheduled Task Updated",
    ("security", 4720): "User Created",
    ("security", 4722): "User Enabled",
    ("security", 4723): "Password Change Attempt",
    ("security", 4724): "Password Reset",
    ("security", 4726): "User Deleted",
    ("security", 4732): "Member Added to Group",
    ("security", 4738): "User Account Changed",
    ("security", 4740): "Account Locked Out",
    ("security", 4768): "Kerberos TGT Request",
    ("security", 4769): "Kerberos Service Ticket",
    ("security", 4771): "Kerberos Pre-auth Failed",
    ("security", 4776): "NTLM Authentication",
    ("security", 4825): "RDP Logon Denied",
    ("security", 5140): "Network Share Accessed",
    ("security", 5145): "Network Share File Accessed",
    ("security", 5156): "Firewall Permitted",
    ("security", 5157): "Firewall Blocked",
    ("security", 1102): "Audit Log Cleared",
    ("powershell", 4100): "PS Engine Error",
    ("powershell", 4103): "PS Module Logging",
    ("powershell", 4104): "PS Script Block Logging",
    ("powershell", 4105): "PS Script Start",
    ("powershell", 4106): "PS Script End",
    ("system", 7031): "Service Crash",
    ("system", 7036): "Service State Change",
    ("system", 7040): "Service Start Type Changed",
    ("system", 7045): "Service Installed",
    ("system", 7041): "Service Info",
    ("defender", 1116): "Threat Detected",
    ("defender", 1117): "Threat Action Taken",
    ("defender", 1118): "Threat Action Failed",
    ("defender", 1150): "Defender Healthy",
    ("defender", 2001): "Defender Signature Updated",
    ("defender", 5007): "Defender Config Changed",
    ("application", 1000): "Application Error",
    ("application", 1001): "Application Crash",
    ("application", 1002): "Application Hang",
    ("firewall", 2004): "FW Rule Added",
    ("firewall", 2005): "FW Rule Modified",
    ("firewall", 2006): "FW Rule Deleted",
    ("firewall", 5152): "Packet Dropped",
    ("firewall", 5156): "Firewall Permitted (FW)",
    ("firewall", 5157): "Firewall Blocked (FW)",
}

_FLAT_TAXONOMY: dict[str, str] = {
    f"{channel}_{eid}": name
    for (channel, eid), name in EVENT_TAXONOMY.items()
}

BOOL_FEATURES = [
    "has_powershell", "has_base64", "has_certutil", "has_wmic",
    "has_mshta", "has_rundll32", "has_attack_sig",
    "office_spawned_shell", "has_hack_tool", "long_ps_cmd",
    "susp_port", "susp_ip",
    "is_temp_write", "susp_dll_path", "is_lsass_access", "susp_dns",
    "is_process_injection",
]

ML_FEATURES = [
    "total_events",
    "proc_create_count",
    "network_conn_count",
    "image_load_count",
    "proc_access_count",
    "file_create_count",
    "dns_query_count",
    "has_powershell_sum",
    "has_base64_sum",
    "has_certutil_sum",
    "has_wmic_sum",
    "has_mshta_sum",
    "has_rundll32_sum",
    "has_attack_sig_sum",
    "office_spawned_shell_sum",
    "has_hack_tool_sum",
    "long_ps_cmd_sum",
    "susp_port_sum",
    "susp_ip_sum",
    "is_temp_write_sum",
    "susp_dll_path_sum",
    "is_lsass_access_sum",
    "susp_dns_sum",
    "is_process_injection_sum",
    "unique_processes",
    "unique_parents",
    "unique_users",
    "avg_cmd_len",
    "max_cmd_len",
    "avg_proc_depth",
    "system_ctx_count",
    "time_delta_mean",
]

REASON_MAP = [
    ("is_lsass_access_sum",     "LSASS Access"),
    ("has_hack_tool_sum",       "Hack Tool"),
    ("has_attack_sig_sum",      "Attack Signature"),
    ("office_spawned_shell_sum","Office->Shell"),
    ("has_base64_sum",          "Encoded Command"),
    ("susp_dll_path_sum",       "Suspicious DLL"),
    ("is_temp_write_sum",       "Temp Write"),
    ("has_powershell_sum",      "PowerShell"),
    ("susp_ip_sum",             "Suspicious IP"),
    ("susp_port_sum",           "Suspicious Port"),
    ("susp_dns_sum",            "Suspicious DNS"),
    ("is_process_injection_sum","Process Injection"),
    ("has_certutil_sum",        "Certutil"),
    ("has_wmic_sum",            "WMIC"),
]

DATA_SUFFIXES    = (".json", ".jsonl", ".ndjson", ".csv", ".xml", ".cap", ".pcap", ".pcapng")
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz")
CACHE_DIR        = Path("data/raw")
