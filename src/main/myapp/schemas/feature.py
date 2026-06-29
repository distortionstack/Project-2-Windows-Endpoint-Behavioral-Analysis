"""feature.py — Behavioral feature vector schema."""
from dataclasses import dataclass, field


@dataclass
class FeatureVectorSchema:
    BOOL_FEATURES: list = field(default_factory=lambda: [
        "has_powershell", "has_base64", "has_certutil", "has_wmic",
        "has_mshta", "has_rundll32", "has_attack_sig", "office_spawned_shell",
        "has_hack_tool", "long_ps_cmd", "susp_port", "susp_ip",
        "is_temp_write", "susp_dll_path", "is_lsass_access", "susp_dns",
        "is_process_injection",
    ])
    META_FEATURES: list = field(default_factory=lambda: [
        "cmd_len", "cmd_entropy", "proc_depth", "hour",
        "is_system", "time_delta_seconds",
    ])

    def validate(self, df) -> list[str]:
        missing = [c for c in self.BOOL_FEATURES + self.META_FEATURES if c not in df.columns]
        return missing
