import argparse
import os
from .pcap_runner import analyze_pcap, replay_pcap
# Live NFQUEUE runner removed for Windows builds
from .detector import DetectorConfig

def build_parser():
    p = argparse.ArgumentParser(prog="network-ips", description="Lightweight Network IPS")
    sub = p.add_subparsers(dest="cmd", required=True)

    # analyze
    a = sub.add_parser("analyze", help="Analyze a PCAP and print/block decisions (no live blocking)")
    a.add_argument("--pcap", required=True, help="Path to pcap file")
    a.add_argument("--max", type=int, default=0, help="Max packets to process (0 = all)")
    a.add_argument("--json", action="store_true", help="Print JSON decisions to stdout")

    # replay (simulate blocking decisions)
    r = sub.add_parser("replay", help="Replay a PCAP and simulate prevention decisions")
    r.add_argument("--pcap", required=True)
    r.add_argument("--max", type=int, default=0)

    # live (NFQUEUE)
    l = sub.add_parser("live", help="Live IPS via NFQUEUE (requires root)")
    l.add_argument("--queue", type=int, default=int(os.getenv("IPS_NFQ", "3")), help="NFQUEUE number")
    l.add_argument("--flush-log", action="store_true", help="Truncate logs/alerts.jsonl before start")

    # thresholds
    for sp in (a, r, l):
        sp.add_argument("--icmp-pps", type=int, default=int(os.getenv("IPS_ICMP_PPS", "100")),
                        help="ICMP packets/sec threshold per source")
        sp.add_argument("--syn-pend", type=int, default=int(os.getenv("IPS_SYN_PEND", "200")),
                        help="Max outstanding SYNs per source before drop")
        sp.add_argument("--scan-ports", type=int, default=int(os.getenv("IPS_SCAN_PORTS", "30")),
                        help="Distinct ports per 10s window to treat as scan")
        sp.add_argument("--http", action="store_true", help="Enable HTTP payload inspection")

    return p

def to_cfg(args) -> DetectorConfig:
    return DetectorConfig(
        icmp_pps_threshold=args.icmp_pps,
        syn_outstanding_threshold=args.syn_pend,
        scan_distinct_ports_per_10s=args.scan_ports,
        http_inspection=args.http
    )

def main():
    parser = build_parser()
    args = parser.parse_args()
    cfg = to_cfg(args)
    if args.cmd == "analyze":
        analyze_pcap(args.pcap, cfg, max_packets=args.max, print_json=args.json)
    elif args.cmd == "replay":
        replay_pcap(args.pcap, cfg, max_packets=args.max)
    elif args.cmd == "live":
        print("Live mode is not supported on Windows builds. Use WSL2 or a Linux VM for live blocking.")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
