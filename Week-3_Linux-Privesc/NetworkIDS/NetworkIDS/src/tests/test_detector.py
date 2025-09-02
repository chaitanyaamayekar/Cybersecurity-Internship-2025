# Basic logic tests that don't require scapy by mocking packet attributes
import types
from detector import Detector
from alerts import AlertSink

class Capture(AlertSink):
    def __init__(self):
        super().__init__(None)
        self.lines = []
    def _emit(self, level, msg):
        self.lines.append((level, msg))

def make_pkt(layer_flags=None, icmp_type=None, src="1.1.1.1", dst="2.2.2.2", dport=80):
    # Minimal mock object with attributes used by parser/detector
    pkt = types.SimpleNamespace()
    pkt.layers = {"TCP": types.SimpleNamespace(flags=layer_flags, dport=dport) if layer_flags is not None else None,
                  "ICMP": types.SimpleNamespace(type=icmp_type) if icmp_type is not None else None,
                  "IP": types.SimpleNamespace(src=src, dst=dst)}
    def haslayer(x):
        name = getattr(x, "__name__", str(x))
        return name in ["TCP","ICMP","IP"] and pkt.layers.get(name) is not None
    def getitem(key):
        return pkt.layers[key]
    pkt.haslayer = haslayer
    pkt.__getitem__ = getitem
    return pkt

def test_icmp_echo_and_flood():
    cap = Capture()
    det = Detector(cap)
    # 50 echo requests to trigger flood
    for _ in range(50):
        det.handle_packet(make_pkt(icmp_type=8))
    assert any("ICMP_FLOOD" in m for _, m in cap.lines)

def test_syn_scan_threshold():
    cap = Capture()
    det = Detector(cap)
    # 20 distinct ports => SYN scan alert
    for p in range(20):
        det.handle_packet(make_pkt(layer_flags=0x02, dport=1000+p))
    assert any("SYN_SCAN" in m for _, m in cap.lines)

def test_null_fin_scan_threshold():
    cap = Capture()
    det = Detector(cap)
    for _ in range(10):
        det.handle_packet(make_pkt(layer_flags=0x00))
    assert any("NULL_SCAN" in m for _, m in cap.lines)