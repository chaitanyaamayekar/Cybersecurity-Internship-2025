from scapy.all import rdpcap, TCP, IP, IPv6, ICMP, Raw, UDP
from .detector import IPSDetector, packet_meta_from_scapy, write_alert
from .detector import DetectorConfig

def analyze_pcap(pcap_path: str, cfg: DetectorConfig, max_packets: int = 0, print_json: bool = False):
    det = IPSDetector(cfg)
    pkts = rdpcap(pcap_path)
    count = 0
    for p in pkts:
        if max_packets and count >= max_packets:
            break
        meta = packet_meta_from_scapy(p)
        if not meta:
            continue
        decision = det.decide(meta)
        if decision["action"] == "DROP":
            write_alert(decision)
        if print_json:
            print(decision)
        count += 1
    print(f\"Processed {count} packets. Drops: {det.stats['drops']}, Allows: {det.stats['allows']}\")

def replay_pcap(pcap_path: str, cfg: DetectorConfig, max_packets: int = 0):
    # Same as analyze, but emphasize "simulate prevention" in output
    analyze_pcap(pcap_path, cfg, max_packets=max_packets, print_json=True)
