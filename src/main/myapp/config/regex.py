"""regex.py — Compiled regex patterns and builders (all config-driven)."""

import re

from .settings import get

PS_RE            = re.compile(r"\b(powershell|pwsh|windowspowershell)\b", re.I)
PS_RE_ADVANCED   = re.compile(r"\b(p[e\"^]*o[e\"^]*w[e\"^]*e[e\"^]*r[e\"^]*s[e\"^]*h[e\"^]*e[e\"^]*l[e\"^]*l|pwsh)\b", re.I)
ENC_RE           = re.compile(r"(-enc(odedcommand)?\s+[A-Za-z0-9+/=]{30,}|base64)", re.I)
CERTUTIL_RE      = re.compile(r"\bcertutil\b", re.I)
WMIC_RE          = re.compile(r"\bwmic\b", re.I)
MSHTA_RE         = re.compile(r"\bmshta\b", re.I)
RUNDLL32_RE      = re.compile(r"\brundll32\b", re.I)

OFFICE_RE        = re.compile(r"\b(winword|excel|outlook|onenote|powerpnt|msaccess|mspub)\.exe\b", re.I)
SUSP_CHILD_RE    = re.compile(r"\b(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|msiexec)\b", re.I)

LSASS_RE         = re.compile(r"lsass", re.I)
TEMP_DLL_RE      = re.compile(r"\\(temp|appdata|programdata)\\", re.I)
TEMP_FILE_RE     = re.compile(r"\\temp\\|\\appdata\\local\\temp\\", re.I)

DNS_SUSP_RE      = re.compile(r"(\.tk|\.ml|\.ga|\.cf|bit\.ly|tinyurl|pastebin|raw\.github)(?:$|[/:?])", re.I)


def _build_regex_from_config():
    hack_tools = get("detection.hack_tools", [])
    attack_sigs = get("detection.attack_signatures", [])

    hack_tools_pattern = "|".join(re.escape(tool) for tool in hack_tools) if hack_tools else "(?!.*)"
    attack_sig_pattern = "|".join(re.escape(sig) for sig in attack_sigs) if attack_sigs else "(?!.*)"

    return (
        re.compile(f"\\b({hack_tools_pattern})\\b", re.I) if hack_tools else re.compile(r"(?!.*)"),
        re.compile(attack_sig_pattern, re.I) if attack_sigs else re.compile(r"(?!.*)"),
    )


HACK_TOOLS_RE, SIG_RE = _build_regex_from_config()


def _build_susp_ip_regex():
    ip_patterns = get("detection.suspicious_ips", {})
    patterns = list(ip_patterns.values())
    if not patterns:
        return re.compile(r"(?!.*)")
    combined = "|".join(f"({p})" for p in patterns)
    return re.compile(f"^({combined})$")


SUSP_IP_RE = _build_susp_ip_regex()


def _build_dns_regex():
    domains = get("detection.suspicious_domains", [])
    if not domains:
        return re.compile(r"(?!.*)")
    escaped = [re.escape(d) for d in domains]
    pattern = "|".join(escaped)
    return re.compile(f"({pattern})(?:$|[/:?])", re.I)


DNS_SUSP_RE_DYNAMIC = _build_dns_regex()

SUSP_PORTS = set(get("detection.suspicious_ports", [445, 3389, 5985, 5986]))
