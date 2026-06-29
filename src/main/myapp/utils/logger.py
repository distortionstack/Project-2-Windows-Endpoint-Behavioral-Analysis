"""logger.py — Centralized logging configuration for the entire pipeline."""

import logging
import warnings


def setup_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    warnings.filterwarnings("ignore")
