import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple, Set

from alerts import AlertSink
from parser import is_icmp_echo_request, is_icmp_echo_reply, tcp_flags, ip_tuple

# Default thresholds/windows (seconds/counts)
ICMP_WINDOW_S = 5
ICMP_FLOOD_THRESHOLD = 50

SYN_WINDOW_S = 10
SYN_DISTINCT_PORTS_THRESHOLD = 20
NULL_FIN_THRESHOLD = 10
HALF_OPEN_THRESHOLD = 30

class Detector:
    def __init__(self, sink: AlertSink):
        self.sink = sink
        # Sliding windows: store timestamps
        self.icmp_counts: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        self.syn_ports: Dict[str, Dict[str, Set[int]]] = defaultdict(lambda: defaultdict(set))
        self.syn_times: Dict[str, Deque[float]] = defaultdict(deque)
        self.null_fin_times: Dict[str, Deque[float]] = defaultdict(deque)
        self.half_open_tracker: Dict[Tuple[str, str, int], int] = defaultdict(int)

    @staticmethod
    def _now() -> float:
        return time.time()

    def _prune(self, dq: Deque[float], window: int) -> None:
        now = self._now()
        while dq and (now - dq[0] > window):
            dq.popleft()

    def handle_packet(self, pkt) -> None:
        src, dst = ip_tuple(pkt)

        # ICMP ping detection + flood
        if is_icmp_echo_request(pkt) or is_icmp_echo_reply(pkt):
            pair = (src, dst)
            dq = self.icmp_counts[pair]
            dq.append(self._now())
            self._prune(dq, ICMP_WINDOW_S)
            if len(dq) >= ICMP_FLOOD_THRESHOLD:
                self.sink.alert(f"ICMP_FLOOD src={src} dst={dst} count={len(dq)} window={ICMP_WINDOW_S}s")
            else:
                typ = "ECHO_REQ" if is_icmp_echo_request(pkt) else "ECHO_REP"
                self.sink.info(f"ICMP_{typ} src={src} dst={dst}")

        # TCP scans/attempts
        flags = tcp_flags(pkt)
        if flags is not None:
            syn = (flags & 0x02) != 0
            ack = (flags & 0x10) != 0
            fin = (flags & 0x01) != 0
            rst = (flags & 0x04) != 0
            null = flags == 0

            # SYN tracking (distinct ports per dst)
            try:
                dport = int(pkt["TCP"].dport)
            except Exception:
                dport = None

            if syn and not ack:
                # Connection attempt
                if src and dst and dport is not None:
                    self.syn_ports[src][dst].add(dport)
                    self.syn_times[src].append(self._now())
                    self._prune(self.syn_times[src], SYN_WINDOW_S)
                    distinct_ports = len(self.syn_ports[src][dst])
                    if distinct_ports >= SYN_DISTINCT_PORTS_THRESHOLD:
                        self.sink.alert(f"SYN_SCAN src={src} dst={dst} distinct_ports={distinct_ports} window={SYN_WINDOW_S}s")
                    # Half-open tracker increments on SYN
                    key = (src, dst, dport)
                    self.half_open_tracker[key] += 1

            # NULL/FIN scans
            if null or (fin and not ack and not rst):
                dq = self.null_fin_times[src]
                dq.append(self._now())
                self._prune(dq, SYN_WINDOW_S)
                if len(dq) >= NULL_FIN_THRESHOLD:
                    mode = "NULL" if null else "FIN"
                    self.sink.alert(f"{mode}_SCAN src={src} count={len(dq)} window={SYN_WINDOW_S}s")

            # Half-open reduction when ACK seen (handshake completes)
            if syn and ack and src and dst and dport is not None:
                key = (src, dst, dport)
                if key in self.half_open_tracker and self.half_open_tracker[key] > 0:
                    self.half_open_tracker[key] -= 1

            # Half-open surge detection (aggregate)
            total_half_open = sum(c for c in self.half_open_tracker.values() if c > 0)
            if total_half_open >= HALF_OPEN_THRESHOLD:
                self.sink.alert(f"HALF_OPEN_SURGE total_unacked_syn={total_half_open} window≈{SYN_WINDOW_S}s")