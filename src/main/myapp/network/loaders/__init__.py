"""__init__.py — Network loader aggregator: detect format, dispatch, and concatenate."""

import logging
from pathlib import Path
from typing import List

import pandas as pd

from src.main.myapp.network.schemas import empty_network_df
from src.main.myapp.network.sniff import detect_network_source_type

logger = logging.getLogger(__name__)


def load_network_sources(paths: List[str]) -> pd.DataFrame:
    """Sniff each path, dispatch to the matching loader, and pd.concat the results."""
    from src.main.myapp.network.loaders.suricata_loader import load_suricata
    from src.main.myapp.network.loaders.zeek_loader import load_zeek
    from src.main.myapp.network.loaders.pcap_loader import load_pcap

    frames = []
    for p in paths:
        path = Path(p)
        if not path.exists():
            logger.warning(f"Network source not found: {path}")
            continue

        source_type = detect_network_source_type(path)

        try:
            if source_type == "suricata":
                df = load_suricata(path)
            elif source_type == "zeek":
                df = load_zeek(path)
            elif source_type == "pcap":
                df = load_pcap(path)
            else:
                logger.warning(f"Unknown network source type for {path}; skipping")
                continue

            if df is not None and not df.empty:
                frames.append(df)
                logger.info(f"Loaded {len(df)} network flows from {path} ({source_type})")
        except Exception:
            logger.warning(f"Failed to load network source {path}", exc_info=True)

    if not frames:
        return empty_network_df()

    return pd.concat(frames, ignore_index=True)
