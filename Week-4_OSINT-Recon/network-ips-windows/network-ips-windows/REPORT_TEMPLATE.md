# Network IPS — Short Report (1–2 pages)

## Overview
Describe the IPS goal and scope.

## Prevention Logic
- ICMP flood logic (thresholds, windows)
- SYN flood / half-open tracking
- Scan detection (NULL/FIN/XMAS, port sweeps)
- HTTP payload signatures (naive SQLi)

## False Positives / Tuning
- Which benign patterns could trigger?
- How thresholds can be tuned
- Ways to whitelist (future work)

## Results (PCAP Demos)
- Normal PCAP: number of packets, drops, why zero/low
- Malicious PCAP: examples of drops with ruleId & reason

## Next Steps
- Stateful TCP tracking, SYN cookies integration
- Better HTTP parsing, URI decoding, method-based rules
- Config file, rule engine pluggability
- eBPF/XDP fast path for Linux


## Windows Demo Notes
If running on Windows, include screenshots or JSONL alert excerpts from the `logs/alerts.jsonl` produced by `analyze` on the two PCAPs.
