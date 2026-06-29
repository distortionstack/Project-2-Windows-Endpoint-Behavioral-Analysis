"""settings.py — Load and manage JSON configuration (singleton pattern)."""

import json
import logging
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(__file__).resolve().parents[4] / "config"
CONFIG_FILE = CONFIG_DIR / "config.json"

_config: Dict[str, Any] | None = None


def load_config() -> Dict[str, Any]:
    global _config
    if _config is not None:
        return _config

    if not CONFIG_FILE.exists():
        print(CONFIG_FILE)
        raise FileNotFoundError(
            f"config.json not found at {CONFIG_FILE}. "
            "Please ensure config.json is in the same directory as the scripts."
        )

    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        _config = json.load(f)

    logger.info(f"Loaded config from {CONFIG_FILE}")
    return _config


def get_config() -> Dict[str, Any]:
    if _config is None:
        return load_config()
    return _config


def get(key: str, default: Any = None) -> Any:
    cfg = get_config()
    keys = key.split(".")
    value = cfg
    for k in keys:
        if isinstance(value, dict):
            value = value.get(k)
            if value is None:
                return default
        else:
            return default
    return value
