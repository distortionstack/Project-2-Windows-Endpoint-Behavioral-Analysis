"""theme.py — Color palette, layout presets, label maps, and HTML helpers."""

import plotly.io as pio


C_BG     = "#0d1117"
C_CARD   = "#161b22"
C_BORD   = "#21262d"
C_RED    = "#f85149"
C_AMBER  = "#e3b341"
C_GREEN  = "#3fb950"
C_BLUE   = "#58a6ff"
C_PURPLE = "#bc8cff"
C_TEXT   = "#c9d1d9"
C_MUTED  = "#8b949e"

C_MG     = "#4d7a5e"   # Military green — primary accent
C_MG_B   = "#62a87a"   # Military green bright — active/highlight
C_MG_D   = "#2d4a38"   # Military green dark — background tint


BASE_LAYOUT = dict(
    paper_bgcolor=C_CARD,
    plot_bgcolor=C_CARD,
    font=dict(color=C_TEXT, family="'JetBrains Mono', monospace", size=12),
    margin=dict(l=50, r=20, t=44, b=40),
)


SYSMON_LABELS = {
    1:    "Process Create",      3:  "Network Conn",    7:  "Image Load",
    10:   "Process Access",      11: "File Create",     12: "Registry",
    13:   "Registry Set",        22: "DNS Query",       23: "File Delete",
    4688: "Process Create(Sec)", 4689: "Process Exit",
    5156: "Net Filter",          5158: "Net Filter Bind",
}


BEHAVIORAL_LABELS = {
    "has_powershell_sum":        "PowerShell",
    "has_base64_sum":            "Encoded Cmd",
    "has_certutil_sum":          "Certutil",
    "has_wmic_sum":              "WMIC",
    "has_mshta_sum":             "MSHTA",
    "has_rundll32_sum":          "Rundll32",
    "has_attack_sig_sum":        "Attack Signature",
    "office_spawned_shell_sum":  "Office->Shell",
    "has_hack_tool_sum":         "Hack Tool",
    "long_ps_cmd_sum":           "Long PS Cmd",
    "susp_port_sum":             "Suspicious Port",
    "susp_ip_sum":               "Suspicious IP",
    "is_temp_write_sum":         "Temp Write",
    "susp_dll_path_sum":         "Susp DLL Path",
    "is_lsass_access_sum":       "LSASS Access",
    "susp_dns_sum":              "Suspicious DNS",
}


def _div(fig):
    if fig is None:
        return ""
    return pio.to_html(fig, full_html=False, include_plotlyjs=False)


def _severity_badge(s):
    s_str = str(s).lower()
    if s_str in ("high", "critical"):
        color = C_RED
    elif s_str == "medium":
        color = C_AMBER
    else:
        color = C_GREEN
    return f'<span style="color:{color};font-weight:600">{s}</span>'
