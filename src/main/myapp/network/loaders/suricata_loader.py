"""suricata_loader.py — Parses Suricata eve.json into NetworkFlow rows."""

import json
import logging
from pathlib import Path

import pandas as pd

from src.main.myapp.network.schemas import NETWORK_FLOW_COLUMNS, empty_network_df

logger = logging.getLogger(__name__)


def load_suricata(path: Path) -> pd.DataFrame:
    """Stream-parse a Suricata eve.json file; return a DataFrame matching NETWORK_FLOW_COLUMNS."""
    path = Path(path)

    # Per-flow_id merged record: one output row per unique flow_id
    flows: dict = {}

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue

                etype = evt.get("event_type", "")
                flow_id = evt.get("flow_id")

                # Synthetic key for events with no flow_id
                if flow_id is None:
                    flow_id = f"_nofid_{evt.get('timestamp', id(evt))}"

                if flow_id not in flows:
                    flows[flow_id] = {
                        "@timestamp": None,
                        "src_ip": evt.get("src_ip"),
                        "src_port": evt.get("src_port"),
                        "dst_ip": evt.get("dest_ip"),
                        "dst_port": evt.get("dest_port"),
                        "proto": (evt.get("proto") or "").upper(),
                        "duration_sec": None,
                        "bytes_sent": None,
                        "bytes_recv": None,
                        "pkts_sent": None,
                        "pkts_recv": None,
                        "dns_query": None,
                        "tls_sni": None,
                        "conn_state": None,
                        "alert_signature": None,
                        "alert_severity": None,
                    }

                rec = flows[flow_id]

                # Fill src/dst on first encounter if still empty
                if rec["src_ip"] is None:
                    rec["src_ip"] = evt.get("src_ip")
                    rec["src_port"] = evt.get("src_port")
                    rec["dst_ip"] = evt.get("dest_ip")
                    rec["dst_port"] = evt.get("dest_port")
                    rec["proto"] = (evt.get("proto") or "").upper()

                if etype == "flow":
                    flow_sub = evt.get("flow", {})
                    start_ts = flow_sub.get("start") or evt.get("timestamp")
                    if start_ts and rec["@timestamp"] is None:
                        rec["@timestamp"] = pd.to_datetime(start_ts, utc=True, errors="coerce")
                    end_ts = flow_sub.get("end")
                    if start_ts and end_ts:
                        try:
                            t0 = pd.to_datetime(start_ts, utc=True, errors="coerce")
                            t1 = pd.to_datetime(end_ts, utc=True, errors="coerce")
                            if pd.notna(t0) and pd.notna(t1):
                                rec["duration_sec"] = (t1 - t0).total_seconds()
                        except Exception:
                            pass
                    rec["bytes_sent"] = flow_sub.get("bytes_toserver")
                    rec["bytes_recv"] = flow_sub.get("bytes_toclient")
                    rec["pkts_sent"] = flow_sub.get("pkts_toserver")
                    rec["pkts_recv"] = flow_sub.get("pkts_toclient")

                elif etype == "alert":
                    alert_sub = evt.get("alert", {})
                    rec["alert_signature"] = alert_sub.get("signature")
                    rec["alert_severity"] = alert_sub.get("severity")
                    if rec["@timestamp"] is None:
                        ts = evt.get("timestamp")
                        if ts:
                            rec["@timestamp"] = pd.to_datetime(ts, utc=True, errors="coerce")

                elif etype == "dns":
                    dns_sub = evt.get("dns", {})
                    if rec["dns_query"] is None:
                        rec["dns_query"] = dns_sub.get("rrname")
                    if rec["@timestamp"] is None:
                        ts = evt.get("timestamp")
                        if ts:
                            rec["@timestamp"] = pd.to_datetime(ts, utc=True, errors="coerce")

                elif etype == "tls":
                    tls_sub = evt.get("tls", {})
                    if rec["tls_sni"] is None:
                        rec["tls_sni"] = tls_sub.get("sni")

                elif etype == "http":
                    http_sub = evt.get("http", {})
                    # Reuse tls_sni column for HTTP hostname when no TLS SNI is set
                    if rec["tls_sni"] is None:
                        rec["tls_sni"] = http_sub.get("hostname")

    except Exception:
        logger.warning(f"Failed to parse Suricata file {path}", exc_info=True)
        return empty_network_df()

    if not flows:
        return empty_network_df()

    df = pd.DataFrame(list(flows.values()))
    df["_source_type"] = "suricata"

    for col in NETWORK_FLOW_COLUMNS:
        if col not in df.columns:
            df[col] = None

    return df[NETWORK_FLOW_COLUMNS]
