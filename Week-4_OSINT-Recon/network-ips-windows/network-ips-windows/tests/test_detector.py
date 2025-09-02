import time
from ips.detector import IPSDetector, DetectorConfig

def test_icmp_flood_drop():
    cfg = DetectorConfig(icmp_pps_threshold=5)
    det = IPSDetector(cfg)
    now = time.time()
    src = "1.2.3.4"
    # simulate 7 ICMPs within 1s
    for i in range(7):
        meta = {"ts": now + i*0.1, "src": src, "dst": "5.6.7.8", "proto": "ICMP",
                "sport": None, "dport": None, "tcp_flags": None, "http_payload": None}
        rec = det.decide(meta)
    assert det.stats["drops"] >= 2  # last few should drop

def test_syn_flood():
    cfg = DetectorConfig(syn_outstanding_threshold=3)
    det = IPSDetector(cfg)
    src = "10.0.0.1"
    ts = time.time()
    # 4 SYNs without ACK
    for i in range(4):
        rec = det.decide({"ts": ts+i*0.01, "src": src, "dst": "10.0.0.2",
                          "proto": "TCP", "sport": 1234+i, "dport": 80,
                          "tcp_flags": 0x02, "http_payload": None})
    assert rec["action"] == "DROP"
    assert rec["ruleId"] == "SYN_FLOOD"

def test_port_scan():
    cfg = DetectorConfig(scan_distinct_ports_per_10s=3)
    det = IPSDetector(cfg)
    src = "a"
    dst = "b"
    t0 = time.time()
    for i, port in enumerate([10,11,12,13]):
        rec = det.decide({"ts": t0+i, "src": src, "dst": dst,
                          "proto": "TCP", "sport": 1000+i, "dport": port,
                          "tcp_flags": 0x02, "http_payload": None})
    assert rec["ruleId"] == "PORT_SCAN"

def test_http_sig():
    cfg = DetectorConfig(http_inspection=True)
    det = IPSDetector(cfg)
    t = time.time()
    payload = b\"GET /?q=' or 1=1 -- HTTP/1.1\\r\\nHost: test\\r\\n\\r\\n\"
    rec = det.decide({"ts": t, "src": "x", "dst": "y",
                      "proto": "TCP", "sport": 5555, "dport": 80,
                      "tcp_flags": 0x18, "http_payload": payload})
    assert rec["action"] == "DROP"
    assert rec["ruleId"] == "HTTP_SIG"
