"""parser.py — Parse Sigma YAML rules into structured dictionaries."""

import logging
import re

logger = logging.getLogger(__name__)


def parse_rule(raw: dict) -> dict | None:
    if not isinstance(raw, dict):
        return None
    if "title" not in raw or "detection" not in raw:
        return None

    rule = {
        "title": raw.get("title", ""),
        "id": raw.get("id", ""),
        "description": raw.get("description", ""),
        "references": raw.get("references", []),
        "level": raw.get("level", ""),
        "status": raw.get("status", ""),
        "logsource": raw.get("logsource", {}),
        "detection": raw.get("detection", {}),
        "fields": raw.get("fields", []),
        "falsepositives": raw.get("falsepositives", []),
        "tags": raw.get("tags", []),
    }

    rule["rule_id"] = rule["id"] or rule["title"].lower().replace(" ", "_")[:64]

    return rule


def get_logsource_filter(logsource: dict) -> dict:
    return {
        "category": logsource.get("category", ""),
        "product": logsource.get("product", ""),
        "service": logsource.get("service", ""),
    }


def list_detection_expressions(detection: dict) -> list[tuple[str, dict]]:
    expressions = []
    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, dict):
            expressions.append((key, value))
        elif isinstance(value, list):
            expressions.append((key, {"_list": value}))
    return expressions


def parse_condition(condition: str) -> dict:
    condition = condition.strip()

    m = re.match(r"^(\d+|any)\s+of\s+(them|(\w+)\*?)$", condition, re.IGNORECASE)
    if m:
        count_str = m.group(1)
        target = m.group(2)
        prefix = m.group(3) or ""
        return {
            "type": "count_of",
            "count": 1 if count_str in ("any", "1") else int(count_str),
            "target": target,
            "prefix": prefix,
        }

    m = re.match(r"^all\s+of\s+(them|(\w+)\*?)$", condition, re.IGNORECASE)
    if m:
        target = m.group(1)
        prefix = m.group(2) or ""
        return {
            "type": "all_of",
            "target": target,
            "prefix": prefix,
        }

    parts = re.split(r"\s+(and|or|not)\s+", condition, flags=re.IGNORECASE)
    if len(parts) > 1:
        tokens = []
        for p in parts:
            p = p.strip()
            if p.lower() in ("and", "or", "not"):
                tokens.append({"op": p.lower()})
            else:
                tokens.append({"expr": p})
        return {"type": "boolean", "tokens": tokens}

    return {"type": "direct", "expression": condition}
