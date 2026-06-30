"""cap_reader.py — Parse PCAP files (libpcap format) and emit Sysmon rows."""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

import dpkt
import dpkt.dns
import dpkt.ethernet
import dpkt.ip
import dpkt.pcap
import dpkt.pcapng
import dpkt.tcp
import dpkt.udp
import pandas as pd

logger = logging.getLogger(__name__)

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def load_cap(path: Path) -> pd.DataFrame:
    """Parse a PCAP/PCAPng file and return a DataFrame with synthetic Sysmon rows.

    Each packet becomes either:
    - EventID 3 (network_connect) for TCP/UDP to ports != 53
    - EventID 22 (dns_query) for UDP port 53

    Columns match Sysmon raw schema so normalize.py processes them correctly.
    """
    rows: list[dict] = []
    pkt_count = 0

    try:
        with open(str(path), "rb") as f:
            pcap = _open_pcap(f)
            if pcap is None:
                logger.error(f"Unrecognised PCAP format in {path}")
                return pd.DataFrame()

            for ts, buf in pcap:
                pkt_count += 1
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                        continue

                    ip_pkt = eth.data
                    if not isinstance(ip_pkt, dpkt.ip.IP):
                        continue

                    src_ip = _ip_to_str(ip_pkt.src)
                    dst_ip = _ip_to_str(ip_pkt.dst)
                    proto = _proto_name(ip_pkt.p)

                    if not isinstance(ip_pkt.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                        continue

                    transport = ip_pkt.data
                    src_port = transport.sport
                    dst_port = transport.dport
                    payload_len = len(transport.data) if hasattr(transport, "data") else 0

                    timestamp = pd.Timestamp(ts, unit="s", tz="UTC")

                    if proto == "UDP" and dst_port == 53:
                        dns_name = _extract_dns_query(transport)
                        if dns_name:
                            rows.append({
                                "@timestamp":  timestamp,
                                "EventID":     22,
                                "Channel":     SYSMON_CHANNEL,
                                "Computer":    src_ip,
                                "Image":       "UNKNOWN",
                                "ParentImage": "UNKNOWN",
                                "CommandLine": "UNKNOWN",
                                "QueryName":   dns_name,
                                "src_ip":      src_ip,
                                "src_port":    src_port,
                                "dst_ip":      dst_ip,
                                "dst_port":    dst_port,
                                "proto":       proto,
                                "bytes":       payload_len,
                            })
                    else:
                        rows.append({
                            "@timestamp":      timestamp,
                            "EventID":         3,
                            "Channel":         SYSMON_CHANNEL,
                            "Computer":        src_ip,
                            "Image":           "UNKNOWN",
                            "ParentImage":     "UNKNOWN",
                            "CommandLine":     "UNKNOWN",
                            "DestinationIp":   dst_ip,
                            "DestinationPort": str(dst_port),
                            "src_ip":          src_ip,
                            "src_port":        src_port,
                            "dst_ip":          dst_ip,
                            "dst_port":        dst_port,
                            "proto":           proto,
                            "bytes":           len(ip_pkt),
                        })

                except Exception as exc:
                    logger.debug(f"Skipped malformed packet at ts={ts}: {exc}")
                    continue

    except Exception as exc:
        logger.error(f"Failed to parse PCAP {path}: {exc}", exc_info=True)
        return pd.DataFrame()

    logger.info(
        f"Parsed {pkt_count} packets, extracted {len(rows)} flow records from {path}"
    )

    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _open_pcap(f):
    """Try classic pcap, fall back to pcapng."""
    header = f.read(4)
    f.seek(0)
    # classic pcap magic (little-endian or big-endian)
    if header in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        return dpkt.pcap.Reader(f)
    # pcapng magic
    if header == b"\x0a\x0d\x0d\x0a":
        return dpkt.pcapng.Reader(f)
    return None


def _ip_to_str(ip_bytes: bytes) -> str:
    if len(ip_bytes) == 4:
        return ".".join(map(str, ip_bytes))
    return "UNKNOWN"


def _proto_name(proto_num: int) -> str:
    return {
        dpkt.ip.IP_PROTO_TCP:  "TCP",
        dpkt.ip.IP_PROTO_UDP:  "UDP",
        dpkt.ip.IP_PROTO_ICMP: "ICMP",
    }.get(proto_num, "OTHER")


def _extract_dns_query(udp_pkt) -> str | None:
    """Extract the first queried domain name from a DNS UDP payload."""
    try:
        dns = dpkt.dns.DNS(udp_pkt.data)
        if dns.qd:
            qname = dns.qd[0].name
            if isinstance(qname, bytes):
                return qname.decode("utf-8", errors="ignore")
            return str(qname)
    except Exception:
        pass
    return None
