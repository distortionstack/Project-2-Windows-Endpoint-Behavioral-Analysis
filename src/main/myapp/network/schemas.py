"""schemas.py — NetworkFlow column contract. Every network loader must
produce a DataFrame with exactly these columns, regardless of source format."""

NETWORK_FLOW_COLUMNS = [
    "@timestamp",       # pd.Timestamp, UTC — flow start time
    "_source_type",     # str — "suricata" | "zeek" | "pcap"
    "src_ip",           # str
    "src_port",         # float/int, nullable
    "dst_ip",           # str
    "dst_port",         # float/int, nullable
    "proto",            # str — "TCP" | "UDP" | "ICMP" | other
    "duration_sec",     # float, nullable
    "bytes_sent",       # int, nullable — orig/toserver direction
    "bytes_recv",       # int, nullable — resp/toclient direction
    "pkts_sent",        # int, nullable
    "pkts_recv",        # int, nullable
    "dns_query",        # str, nullable — queried domain if this flow is DNS
    "tls_sni",          # str, nullable — TLS SNI / HTTP hostname if present
    "conn_state",       # str, nullable — e.g. Zeek conn_state, or "" if unknown
    "alert_signature",  # str, nullable — native alert text (Suricata only)
    "alert_severity",   # int, nullable — native severity 1-3 (Suricata only, 1=highest)
]


def empty_network_df():
    import pandas as pd
    return pd.DataFrame(columns=NETWORK_FLOW_COLUMNS)
