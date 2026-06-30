"""sniff.py — Content-based network telemetry source type detection."""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def detect_network_source_type(path: Path) -> str:
    """Returns 'suricata' | 'zeek' | 'pcap' | 'unknown'."""
    path = Path(path)
    suffix = path.suffix.lower()

    # 1. Binary pcap: sniff by extension (content-sniffing binary files as text is unreliable)
    if suffix in (".pcap", ".pcapng", ".cap"):
        return "pcap"

    # 2. Peek first line for Zeek's literal #separator header
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            first_line = f.readline()
    except Exception:
        logger.warning(f"Could not read {path}", exc_info=True)
        return "unknown"

    if first_line.startswith("#separator"):
        return "zeek"

    # 3. Try JSON parse — Suricata always has event_type; Windows logs use EventID/winlog.*
    try:
        obj = json.loads(first_line.strip())
        if isinstance(obj, dict) and "event_type" in obj:
            return "suricata"
    except (json.JSONDecodeError, ValueError):
        pass

    logger.warning(f"Cannot determine network source type for {path}; skipping")
    return "unknown"
