"""sequence.py — Attack chain / kill-chain sequence detection."""

import logging
from collections import Counter

import pandas as pd

from src.main.myapp.config.mitre import TECHNIQUE_NAMES, TECHNIQUE_TACTIC, TACTIC_ORDER

logger = logging.getLogger(__name__)

KNOWN_PATTERNS: list[list[str]] = [
    ["Initial Access", "Execution", "Credential Access"],
    ["Initial Access", "Execution", "Defense Evasion"],
    ["Execution", "Defense Evasion", "Credential Access"],
    ["Initial Access", "Execution", "Command and Control"],
    ["Execution", "Command and Control", "Exfiltration"],
    ["Defense Evasion", "Execution", "Credential Access"],
]


def _technique_to_tactic(tech_id: str) -> str:
    return TECHNIQUE_TACTIC.get(tech_id, "Other")


def _tactic_short(tactic: str) -> str:
    short_names = {
        "Resource Development": "ResDev",
        "Initial Access":       "InitAcc",
        "Execution":            "Exec",
        "Persistence":          "Persist",
        "Privilege Escalation": "PrivEsc",
        "Defense Evasion":      "DefEv",
        "Credential Access":    "CredAcc",
        "Discovery":            "Disc",
        "Lateral Movement":     "LatMov",
        "Collection":           "Collect",
        "Command and Control":  "C2",
        "Exfiltration":         "Exfil",
        "Impact":               "Impact",
    }
    return short_names.get(tactic, tactic)


def detect_sequences(df: pd.DataFrame) -> dict:
    if "mitre_techniques" not in df.columns or "@timestamp" not in df.columns:
        logger.warning("detect_sequences: missing mitre_techniques or @timestamp")
        return {"transitions": pd.DataFrame(), "patterns": pd.DataFrame(), "sequences": []}

    df = df.dropna(subset=["@timestamp"]).sort_values("@timestamp")
    transitions: list[dict] = []
    sequences: list[dict] = []

    for host, grp in df.groupby("_host"):
        grp = grp.sort_values("@timestamp")
        tactics_seq: list[str] = []

        for _, row in grp.iterrows():
            techs = row.get("mitre_techniques")
            if not isinstance(techs, list) or not techs:
                continue
            for t in techs:
                tac = _technique_to_tactic(t)
                if not tactics_seq or tactics_seq[-1] != tac:
                    tactics_seq.append(tac)

        if len(tactics_seq) < 2:
            continue

        sequences.append({
            "host": host,
            "tactics_chain": tactics_seq,
            "chain_str": " → ".join(tactics_seq),
        })

        for i in range(len(tactics_seq) - 1):
            transitions.append({
                "host": host,
                "from_tactic": tactics_seq[i],
                "from_short": _tactic_short(tactics_seq[i]),
                "to_tactic": tactics_seq[i + 1],
                "to_short": _tactic_short(tactics_seq[i + 1]),
            })

    trans_df = pd.DataFrame(transitions) if transitions else pd.DataFrame()
    pattern_rows: list[dict] = []

    if trans_df is not None and not trans_df.empty:
        transition_counts = (
            trans_df.groupby(["from_tactic", "to_tactic"])
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
        )

        for seq_info in sequences:
            chain = seq_info["tactics_chain"]
            for pattern in KNOWN_PATTERNS:
                plen = len(pattern)
                for i in range(len(chain) - plen + 1):
                    if chain[i:i + plen] == pattern:
                        pattern_rows.append({
                            "host": seq_info["host"],
                            "pattern": " → ".join(pattern),
                            "pattern_len": plen,
                            "chain_str": seq_info["chain_str"],
                        })
                        break
    else:
        transition_counts = pd.DataFrame()

    pattern_df = pd.DataFrame(pattern_rows) if pattern_rows else pd.DataFrame()

    return {
        "transitions": transition_counts,
        "patterns": pattern_df,
        "sequences": sequences,
    }


def summarize_chains(sequence_result: dict) -> dict:
    summary = {
        "total_hosts_with_chains": 0,
        "total_transitions": 0,
        "total_pattern_matches": 0,
        "pattern_breakdown": {},
        "top_transitions": [],
    }

    sequences = sequence_result.get("sequences", [])
    summary["total_hosts_with_chains"] = len(set(s["host"] for s in sequences))
    summary["total_chains"] = len(sequences)

    trans_df = sequence_result.get("transitions")
    if trans_df is not None and not trans_df.empty:
        summary["total_transitions"] = int(trans_df["count"].sum())
        summary["top_transitions"] = (
            trans_df.head(10)
            .assign(label=trans_df["from_tactic"] + " → " + trans_df["to_tactic"])
            .to_dict(orient="records")
        )

    pattern_df = sequence_result.get("patterns")
    if pattern_df is not None and not pattern_df.empty:
        summary["total_pattern_matches"] = len(pattern_df)
        pc = pattern_df["pattern"].value_counts().to_dict()
        summary["pattern_breakdown"] = {k: int(v) for k, v in pc.items()}

    return summary
