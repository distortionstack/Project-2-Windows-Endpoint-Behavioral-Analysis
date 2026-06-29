"""window.py — Aggregated time-window schema."""
from dataclasses import dataclass, field


@dataclass
class AggregatedWindowSchema:
    REQUIRED_COLUMNS: list = field(default_factory=lambda: [
        "_host", "ml_time_window", "total_events",
        "anomaly_score", "is_anomaly", "severity",
    ])
    OPTIONAL_COLUMNS: list = field(default_factory=lambda: [
        "supervised_technique", "supervised_confidence",
        "behavioral_hits", "severity_score", "top_reasons",
    ])

    def validate(self, df) -> list[str]:
        return [c for c in self.REQUIRED_COLUMNS if c not in df.columns]
