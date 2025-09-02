"""Optional helper to synthesize small PCAPs using Scapy.
Run with admin or from WSL/Lab; not required for unit tests.
"""
try:
    from scapy.all import IP, TCP, ICMP, wrpcap, Ether
except Exception as e:
    raise SystemExit("Scapy required to generate sample PCAPs: pip install scapy") from e

def build_normal():
    pkts = []
    for i in range(3):
        pkts.append(IP(src="10.0.0.2", dst="8.8.8.8")/ICMP(type=8))
        pkts.append(IP(src="8.8.8.8", dst="10.0.0.2")/ICMP(type=0))
    wrpcap("sample_normal.pcap", pkts)

def build_attack():
    pkts = []
    # SYN scan 25 ports
    for p in range(1000, 1025):
        pkts.append(IP(src="10.0.0.5", dst="10.0.0.9")/TCP(dport=p, flags="S"))
    # NULL scan 12 packets
    for _ in range(12):
        pkts.append(IP(src="10.0.0.6", dst="10.0.0.9")/TCP(flags=0))
    # ICMP flood 60 pings
    for _ in range(60):
        pkts.append(IP(src="10.0.0.7", dst="10.0.0.9")/ICMP(type=8))
    wrpcap("sample_attack.pcap", pkts)

if __name__ == "__main__":
    build_normal()
    build_attack()
    print("Wrote sample_normal.pcap and sample_attack.pcap")