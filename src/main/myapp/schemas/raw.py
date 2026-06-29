"""raw.py — Raw Windows event log column schema."""
from dataclasses import dataclass, field


@dataclass
class RawEventSchema:
    REQUIRED_COLUMNS: list = field(default_factory=lambda: ["@timestamp", "EventID"])
    OPTIONAL_COLUMNS: list = field(default_factory=lambda: [
        "_channel", "_host", "_process", "_parent", "_cmd", "_user",
        "_target", "_net_dst", "_image_loaded", "_target_image", "_action",
        "_event_name",
    ])

    def validate(self, df) -> list[str]:
        import pandas as pd
        missing = [c for c in self.REQUIRED_COLUMNS if c not in df.columns]
        return missing
