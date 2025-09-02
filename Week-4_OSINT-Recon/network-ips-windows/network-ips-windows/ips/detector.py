from dataclasses import dataclass, field
from collections import defaultdict, deque
from typing import Dict, Deque, Tuple, Optional
import time, json, os
from scapy.all import TCP, IP, IPv6, ICMP, Raw, UDP
from .rules import http_payload_suspicious

ALERT_LOG = os.getenv("IPS_ALERT_LOG", "logs/alerts.jsonl")

@dataclass
class DetectorConfig:
    icmp_pps_threshold: int = 100
    syn_outstanding_threshold: int = 200
    scan_distinct_ports_per_10s: int = 30
    http_inspection: bool = False

def write_alert(rec: dict):
    os.makedirs(os.path.dirname(ALERT_LOG), exist_ok=True)
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(rec) + "\\n")

def now():
    return time.time()

def packet_meta_from_scapy(p):
    # Extract normalized meta independent of IPv4/IPv6
    ip = None
    proto = None
    if IP in p:
        ip = p[IP]
        src, dst = ip.src, ip.dst
    elif IPv6 in p:
        ip = p[IPv6]
        src, dst = ip.src, ip.dst
    else:
        return None

    ret = {
        "ts": now(),
        "src": src, "dst": dst,
        "proto": None,
        "sport": None, "dport": None,
        "tcp_flags": None,
        "payload_len": int(len(bytes(p))),
        "http_payload": None,
    }

    if p.haslayer(ICMP):
        ret["proto"] = "ICMP"
        return ret

    if p.haslayer(TCP):
        t = p[TCP]
        ret["proto"] = "TCP"
        ret["sport"] = t.sport
        ret["dport"] = t.dport
        ret["tcp_flags"] = t.flags
        if p.haslayer(Raw):
            ret["http_payload"] = bytes(p[Raw])
        return ret

    if p.haslayer(UDP):
        u = p[UDP]
        ret["proto"] = "UDP"
        ret["sport"] = u.sport
        ret["dport"] = u.dport
        if p.haslayer(Raw):
            ret["http_payload"] = bytes(p[Raw])
        return ret

    return ret

class IPSDetector:
    def __init__(self, cfg: DetectorConfig):
        self.cfg = cfg
        # rate tracking
        self.icmp_times: Dict[str, Deque[float]] = defaultdict(deque)  # src -> times
        self.syn_outstanding: Dict[str, int] = defaultdict(int)        # src -> count
        self.port_attempts: Dict[Tuple[str, str], Dict[int, float]] = defaultdict(dict)  # (src,dst) -> port->ts
        self.stats = {"drops": 0, "allows": 0}

    def decide(self, meta: dict) -> dict:
        ts = meta["ts"]
        src, dst = meta["src"], meta["dst"]
        action, rule, reason = "ALLOW", None, "ok"

        # 1) ICMP flood
        if meta["proto"] == "ICMP":
            dq = self.icmp_times[src]
            dq.append(ts)
            # keep last 1s window
            while dq and ts - dq[0] > 1.0:
                dq.popleft()
            if len(dq) > self.cfg.icmp_pps_threshold:
                action, rule, reason = "DROP", "ICMP_FLOOD", f"{len(dq)}/s > {self.cfg.icmp_pps_threshold}"
        
        # 2) TCP logic
        if meta["proto"] == "TCP":
            flags = meta["tcp_flags"] or 0
            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)
            fin = bool(flags & 0x01)
            rst = bool(flags & 0x04)

            # 2a) scan: NULL, FIN-only, XMAS (FIN+PSH+URG is 0x29; we check uncommon patterns)
            # If flags == 0 -> NULL scan
            if flags == 0:
                action, rule, reason = "DROP", "SCAN_NULL", "NULL flags"
            elif flags == 0x01 and not ack:
                action, rule, reason = "DROP", "SCAN_FIN", "FIN-only"
            elif flags & 0x29 == 0x29:  # FIN+PSH+URG set
                action, rule, reason = "DROP", "SCAN_XMAS", "FIN+PSH+URG"

            # 2b) port scan: many distinct dports in 10s window
            key = (src, dst)
            self.port_attempts[key][meta["dport"]] = ts
            # drop old entries
            self.port_attempts[key] = {p:t for p,t in self.port_attempts[key].items() if ts - t <= 10}
            if len(self.port_attempts[key]) > self.cfg.scan_distinct_ports_per_10s:
                action, rule, reason = "DROP", "PORT_SCAN", f"{len(self.port_attempts[key])} ports/10s"

            # 2c) syn flood / half-open
            if syn and not ack:
                self.syn_outstanding[src] += 1
                if self.syn_outstanding[src] > self.cfg.syn_outstanding_threshold:
                    action, rule, reason = "DROP", "SYN_FLOOD", f"pending={self.syn_outstanding[src]} > {self.cfg.syn_outstanding_threshold}"
            if ack and not syn:
                # assume ACK means a connection progressed; reduce outstanding if present
                if self.syn_outstanding[src] > 0:
                    self.syn_outstanding[src] -= 1

            # 2d) HTTP payload inspection (very naive; for demo only)
            if self.cfg.http_inspection and meta.get("http_payload"):
                sig = http_payload_suspicious(meta["http_payload"])
                if sig:
                    action, rule, reason = "DROP", "HTTP_SIG", sig

        # Record and return
        rec = {
            "ts": ts, "src": src, "dst": dst,
            "proto": meta.get("proto"), "sport": meta.get("sport"), "dport": meta.get("dport"),
            "action": action, "ruleId": rule, "reason": reason
        }
        if action == "DROP":
            self.stats["drops"] += 1
        else:
            self.stats["allows"] += 1
        return rec
