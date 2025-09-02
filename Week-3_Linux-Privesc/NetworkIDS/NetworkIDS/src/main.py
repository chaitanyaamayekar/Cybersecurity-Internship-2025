import argparse
import os
from alerts import AlertSink
from detector import Detector
from parser import rdpcap, sniff

def process_pcap(det: Detector, pcap_path: str):
    if not rdpcap:
        raise RuntimeError("Scapy not available. Install dependencies from requirements.txt")
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")
    pkts = rdpcap(pcap_path)
    for pkt in pkts:
        det.handle_packet(pkt)

def process_live(det: Detector, iface: str | None):
    if not sniff:
        raise RuntimeError("Scapy not available. Install dependencies from requirements.txt")
    if iface == "auto":
        iface = None
    sniff(prn=det.handle_packet, store=False, iface=iface)

def main():
    ap = argparse.ArgumentParser(description="Lightweight Network IDS")
    ap.add_argument("--pcap", help="Path to PCAP file")
    ap.add_argument("--live", action="store_true", help="Sniff live traffic (admin required)")
    ap.add_argument("--iface", default="auto", help="Interface for live sniff (name or 'auto')")
    ap.add_argument("--log", default="alerts.log", help="Alerts log file path")
    args = ap.parse_args()

    sink = AlertSink(args.log if args.log else None)
    det = Detector(sink)

    try:
        if args.pcap:
            process_pcap(det, args.pcap)
        elif args.live:
            process_live(det, args.iface)
        else:
            ap.error("Choose either --pcap or --live")
    finally:
        sink.close()

if __name__ == "__main__":
    main()