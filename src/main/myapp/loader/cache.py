"""cache.py — Smart caching layer for data loading."""

import logging
from pathlib import Path

import pandas as pd

from src.main.myapp.config.constants import CACHE_DIR
from src.main.myapp.loader.loader import _source_key, _as_sources, load_source, _scan_ndjson_file

logger = logging.getLogger(__name__)


def get_smart_data(sources, force_update: bool = False) -> pd.DataFrame:
    sources    = _as_sources(sources)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    state_file  = CACHE_DIR / "source_url.txt"
    data_file   = CACHE_DIR / "current_dataset.ndjson"
    source_key  = _source_key(sources)

    if not force_update and data_file.exists() and state_file.exists():
        if state_file.read_text(encoding="utf-8").strip() == source_key:
            print(f"[*] Source unchanged. Loading cache: {data_file}")
            return _scan_ndjson_file(data_file)

    frames  = [load_source(source) for source in sources]
    combined = pd.concat(frames, ignore_index=True)

    combined.to_json(data_file, orient="records", lines=True)
    state_file.write_text(source_key, encoding="utf-8")
    print(f"[*] Cache updated: {data_file}")
    return combined
