# Network IDS — Short Report

**Objective.** Detect ICMP pings, TCP connection attempts, common scan patterns (SYN/NULL/FIN),
and a few simple suspicious behaviors (ICMP floods, high-rate SYNs).

## Detection Logic

**ICMP.** We inspect `ICMP` type/code. Echo-request (8) and echo-reply (0) are logged.
We keep a sliding window of counts per (src,dst). If echo-requests exceed a threshold in the
window (default 50 within 5s), we raise an `ICMP_FLOOD` alert with a burst summary.

**TCP.**
- **Connection attempts:** SYN without ACK indicates the start of a handshake. We track tuples
  (src,dst,dport). A high rate of SYNs with few subsequent ACKs suggests half-open or SYN-flood activity.
- **Scans:**
  - **SYN scan:** many distinct destination ports quickly from the same source.
  - **NULL/FIN scan:** packets with flags == 0 (NULL) or flags == FIN only, often used for stealth scanning.

**Suspicious behaviors.**
- **Half-open surge:** many SYNs with no corresponding ACKs in a 10s window.
- **Distributed probing:** the same source hitting many hosts over many ports within a short window.

## False Positives & Mitigations

- **NAT gateways / load balancers** can produce odd flag patterns.
- **ICMP bursts** from monitoring tools (e.g., health checks) may mimic floods.
- **CDN / scanning services** (e.g., CSPM, vulnerability scanners) can appear as scans but are legitimate.
- **Mitigations:** allowlists, raising thresholds during known maintenance windows, heuristic backoff,
  and combining features (e.g., flags + timing + response behavior) to reduce noise.

## Next Steps

- Add TCP stream reassembly to better confirm half-open states.
- Include UDP scan detection (e.g., closed-port ICMP responses).
- Export alerts in JSON and send to SIEM.
- Add rule engine (YAML) for tuning environment-specific thresholds.