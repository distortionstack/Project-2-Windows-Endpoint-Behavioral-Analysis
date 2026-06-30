"""pcap_loader.py — Parses pcap files into NetworkFlow rows via scapy PcapReader."""

import logging
from pathlib import Path

import pandas as pd

from src.main.myapp.network.schemas import NETWORK_FLOW_COLUMNS, empty_network_df

logger = logging.getLogger(__name__)


def load_pcap(path: Path) -> pd.DataFrame:
    """
    Stream-parse a pcap file using scapy PcapReader (streaming — avoids loading whole file).

    Flows are reconstructed by grouping packets that share the same 5-tuple
    (src_ip, src_port, dst_ip, dst_port, proto) across the entire capture into one
    aggregated record. This intentionally omits TCP state-machine-based connection
    splitting (tracking SYN/FIN/RST boundaries); proper state-based splitting is a
    reasonable v2 enhancement.

    bytes_recv/pkts_recv are left None because raw pcap has no directionality
    information without reassembly — all bytes are counted in bytes_sent/pkts_sent.
    """
    # Lazy import to avoid penalising startup time for users who never use pcap
    try:
        from scapy.all import PcapReader, IP, TCP, UDP
    except ImportError:
        logger.error("scapy is not installed; run: pip install scapy")
        return empty_network_df()

    path = Path(path)
    flows: dict = {}  # key: (src_ip, src_port, dst_ip, dst_port, proto) → stats dict

    try:
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                if IP not in pkt:
                    continue

                if TCP in pkt:
                    proto = "TCP"
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                elif UDP in pkt:
                    proto = "UDP"
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                else:
                    proto = "OTHER"
                    sport = None
                    dport = None

                key = (pkt[IP].src, sport, pkt[IP].dst, dport, proto)
                ts = float(pkt.time)
                size = len(pkt)

                if key not in flows:
                    flows[key] = {"start": ts, "end": ts, "bytes": 0, "pkts": 0}
                f = flows[key]
                f["start"] = min(f["start"], ts)
                f["end"] = max(f["end"], ts)
                f["bytes"] += size
                f["pkts"] += 1

    except Exception:
        logger.warning(f"Failed to parse pcap {path}", exc_info=True)
        return empty_network_df()

    if not flows:
        return empty_network_df()

    rows = []
    for (src_ip, sport, dst_ip, dport, proto), stats in flows.items():
        ts = pd.to_datetime(stats["start"], unit="s", utc=True)
        duration = stats["end"] - stats["start"]
        rows.append({
            "@timestamp":   ts,
            "_source_type": "pcap",
            "src_ip":       src_ip,
            "src_port":     sport,
            "dst_ip":       dst_ip,
            "dst_port":     dport,
            "proto":        proto,
            "duration_sec": round(duration, 6),
            "bytes_sent":   stats["bytes"],
            "bytes_recv":   None,  # no directional data without reassembly
            "pkts_sent":    stats["pkts"],
            "pkts_recv":    None,
            "dns_query":    None,
            "tls_sni":      None,
            "conn_state":   None,
            "alert_signature": None,
            "alert_severity":  None,
        })

    df = pd.DataFrame(rows)
    for col in NETWORK_FLOW_COLUMNS:
        if col not in df.columns:
            df[col] = None

    return df[NETWORK_FLOW_COLUMNS]
