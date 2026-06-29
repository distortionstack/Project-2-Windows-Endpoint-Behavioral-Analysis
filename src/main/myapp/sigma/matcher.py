"""matcher.py — Match Sigma rules against normalized Windows event DataFrame."""

import logging
import re
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


def _evaluate_condition(event: dict, detection: dict) -> bool:
    if not isinstance(detection, dict):
        return False

    condition = detection.get("condition", "")
    named = {k: v for k, v in detection.items() if k != "condition"}

    def _matches_selector(selector_name: str) -> bool:
        selector = named.get(selector_name)
        if selector is None:
            return False
        if isinstance(selector, list):
            return any(_check_value(event, item) for item in selector)
        if isinstance(selector, dict):
            return all(_field_match(event, field, vals) for field, vals in selector.items())
        return False

    def _check_value(event: dict, item: Any) -> bool:
        if isinstance(item, dict):
            return all(_field_match(event, field, vals) for field, vals in item.items())
        return False

    def _field_match(event: dict, field: str, vals: Any) -> bool:
        modifier = None
        if "|" in field:
            field, modifier = field.split("|", 1)
        raw = str(event.get(field) or "").lower()
        if isinstance(vals, list):
            return any(_val_match(raw, str(v), modifier) for v in vals)
        return _val_match(raw, str(vals), modifier)

    def _val_match(raw: str, pattern: str, modifier: str | None) -> bool:
        p = pattern.lower()
        if modifier in ("contains", "contains|all"):
            return p in raw
        if modifier == "startswith":
            return raw.startswith(p)
        if modifier == "endswith":
            return raw.endswith(p)
        if modifier == "re":
            try:
                return bool(re.search(pattern, raw, re.I))
            except re.error:
                return False
        p_re = re.escape(p).replace(r"\*", ".*").replace(r"\?", ".")
        return bool(re.fullmatch(p_re, raw))

    cond = condition.strip().lower()

    one_of = re.match(r"1 of (\w+)\*?", cond)
    if one_of:
        prefix = one_of.group(1)
        return any(_matches_selector(k) for k in named if k.startswith(prefix))

    all_of = re.match(r"all of (\w+)\*?", cond)
    if all_of:
        prefix = all_of.group(1)
        keys = [k for k in named if k.startswith(prefix)]
        return bool(keys) and all(_matches_selector(k) for k in keys)

    tokens = cond.replace("(", " ").replace(")", " ").split()
    result = None
    op = "or"
    negate_next = False

    for tok in tokens:
        if tok == "not":
            negate_next = True
            continue
        if tok in ("and", "or"):
            op = tok
            continue
        val = _matches_selector(tok) if tok in named else (tok == "true")
        if negate_next:
            val = not val
            negate_next = False
        if result is None:
            result = val
        elif op == "and":
            result = result and val
        else:
            result = result or val

    return bool(result)


def _try_fast_match(df, named_sels, condition, candidate_idx, get_col):
    if condition not in ("selection", "selection and not filter", "all of them"):
        return None
    sel = named_sels.get("selection")
    if not isinstance(sel, dict):
        return None

    mask = pd.Series(True, index=df.index[candidate_idx])
    for field, vals in sel.items():
        modifier = None
        if "|" in field:
            field, modifier = field.split("|", 1)
        col = get_col(field).loc[df.index[candidate_idx]]
        vals_list = vals if isinstance(vals, list) else [vals]
        vals_lower = [str(v).lower() for v in vals_list]
        sub = pd.Series(False, index=col.index)
        for v in vals_lower:
            if modifier in (None, "contains"):
                sub |= col.str.contains(re.escape(v), na=False)
            elif modifier == "startswith":
                sub |= col.str.startswith(v, na=False)
            elif modifier == "endswith":
                sub |= col.str.endswith(v, na=False)
            else:
                return None
        mask &= sub
    return mask


def match_rules(df: pd.DataFrame, rules: list[dict]) -> pd.DataFrame:
    """Add sigma_matched_rules column (list of matched rule titles) to df."""
    if df.empty or not rules:
        df = df.copy()
        df["sigma_matched_rules"] = [[] for _ in range(len(df))]
        return df

    df = df.copy()
    matched: list[list[str]] = [[] for _ in range(len(df))]
    str_cache: dict[str, pd.Series] = {}

    def get_col(col: str) -> pd.Series:
        if col not in str_cache:
            str_cache[col] = (
                df[col].fillna("").astype(str).str.lower()
                if col in df.columns
                else pd.Series([""] * len(df), index=df.index)
            )
        return str_cache[col]

    for rule in rules:
        title = rule.get("title", "Unknown Rule")
        detection = rule.get("detection")
        if not isinstance(detection, dict):
            continue

        category = rule.get("logsource", {}).get("category", "")
        category_mask = pd.Series(True, index=df.index)
        if category and "_event_name" in df.columns:
            ev_col = get_col("_event_name")
            category_mask = ev_col.str.contains(
                category.lower().replace("_", " ").split()[0], na=False
            )

        candidate_idx = df.index[category_mask]
        if candidate_idx.empty:
            continue

        named = {k: v for k, v in detection.items() if k != "condition"}
        condition = detection.get("condition", "selection").strip().lower()

        fast = _try_fast_match(df, named, condition, candidate_idx, get_col)
        if fast is not None:
            for idx in df.index[candidate_idx][fast]:
                matched[df.index.get_loc(idx)].append(title)
        else:
            for loc, idx in enumerate(df.index):
                if idx not in candidate_idx:
                    continue
                try:
                    if _evaluate_condition(df.loc[idx].to_dict(), detection):
                        matched[loc].append(title)
                except Exception:
                    pass

    df["sigma_matched_rules"] = matched
    total = sum(1 for m in matched if m)
    logger.info(f"Sigma matching: {total}/{len(df)} events matched at least one rule")
    return df
