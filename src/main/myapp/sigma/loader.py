"""loader.py — Download Sigma rules from GitHub and cache locally."""

import logging
from pathlib import Path

import requests
import yaml

logger = logging.getLogger(__name__)

SIGMA_REPO = "SigmaHQ/sigma"
SIGMA_BRANCH = "master"
SIGMA_RULES_PATH = "rules/windows"
CACHE_DIR = Path("data/sigma/rules")


def _github_api_url(path):
    return f"https://api.github.com/repos/{SIGMA_REPO}/contents/{path}?ref={SIGMA_BRANCH}"


def _raw_url(path):
    return f"https://raw.githubusercontent.com/{SIGMA_REPO}/{SIGMA_BRANCH}/{path}"


def _list_github_path(api_url):
    resp = requests.get(api_url, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _discover_rule_paths(max_rules=200):
    paths = []
    top_items = _list_github_path(_github_api_url(SIGMA_RULES_PATH))
    for item in top_items:
        if item["type"] != "dir":
            continue
        sub_items = _list_github_path(item["url"])
        for sub in sub_items:
            if sub["name"].endswith((".yml", ".yaml")):
                paths.append(sub["path"])
                if len(paths) >= max_rules:
                    return paths
    return paths


def _download_rule(path):
    resp = requests.get(_raw_url(path), timeout=30)
    resp.raise_for_status()
    return resp.text


def load_rules(force_update=False):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if not force_update:
        cached = sorted(CACHE_DIR.rglob("*.yml")) + sorted(CACHE_DIR.rglob("*.yaml"))
        if cached:
            rules = []
            for f in cached:
                try:
                    rule = yaml.safe_load(f.read_text(encoding="utf-8"))
                    if isinstance(rule, dict) and "title" in rule:
                        rules.append(rule)
                except Exception as e:
                    logger.debug(f"Skipping corrupt cache file {f}: {e}")
            if rules:
                logger.info(f"Loaded {len(rules)} cached Sigma rules from {CACHE_DIR}")
                return rules

    rule_paths = _discover_rule_paths()
    rules = []
    for path in rule_paths:
        try:
            content = _download_rule(path)
            rule = yaml.safe_load(content)
            if not isinstance(rule, dict) or "title" not in rule:
                continue
            local_path = CACHE_DIR / path
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_text(content, encoding="utf-8")
            rules.append(rule)
        except Exception as e:
            logger.warning(f"Failed to download {path}: {e}")

    logger.info(f"Downloaded {len(rules)} Sigma rules to {CACHE_DIR}")
    return rules
