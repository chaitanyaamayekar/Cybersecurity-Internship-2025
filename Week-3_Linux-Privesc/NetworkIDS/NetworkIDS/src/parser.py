from typing import Optional

try:
    from scapy.all import IP, IPv6, TCP, ICMP, rdpcap, sniff, Raw
except Exception:  # pragma: no cover - scapy might not be available during unit tests
    IP = IPv6 = TCP = ICMP = Raw = object  # type: ignore
    rdpcap = sniff = None  # type: ignore

def is_icmp_echo_request(pkt) -> bool:
    try:
        return pkt.haslayer(ICMP) and getattr(pkt[ICMP], "type", None) == 8
    except Exception:
        return False

def is_icmp_echo_reply(pkt) -> bool:
    try:
        return pkt.haslayer(ICMP) and getattr(pkt[ICMP], "type", None) == 0
    except Exception:
        return False

def tcp_flags(pkt) -> Optional[int]:
    try:
        if pkt.haslayer(TCP):
            return int(pkt[TCP].flags)
        return None
    except Exception:
        return None

def ip_tuple(pkt):
    try:
        if pkt.haslayer(IP):
            return pkt[IP].src, pkt[IP].dst
        if pkt.haslayer(IPv6):
            return pkt[IPv6].src, pkt[IPv6].dst
    except Exception:
        pass
    return None, None