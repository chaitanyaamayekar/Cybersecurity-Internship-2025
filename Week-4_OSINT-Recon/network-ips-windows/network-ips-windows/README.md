# Network IPS — Lightweight Intrusion Prevention System

A lightweight Intrusion Prevention System (IPS) that can **detect and block** common patterns:
- ICMP ping floods
- TCP SYN floods / half-open connections
- Simple scan patterns (SYN/NULL/FIN scans, repeated port attempts)
- Suspicious HTTP payloads (basic SQLi patterns)

Supports **live prevention** using Linux `iptables` + `NFQUEUE`, and **offline analysis/replay** for PCAPs.

## Features at a glance
- Stateful, per-source rate limiting and tracking
- Clear rule IDs, reasons, and JSONL alert log
- CLI with three modes: `live`, `analyze`, `replay`
- Unit tests for core prevention logic
- Minimal external deps

## Quick start (Linux)
```bash
# 1) Create and activate a virtualenv (recommended)
python3 -m venv .venv && source .venv/bin/activate

# 2) Install requirements
pip install -r requirements.txt

# 3) Dry run on a PCAP (no root needed)
python -m ips.main analyze --pcap examples/normal.pcap

# 4) Live prevention (requires root and Linux)
# Send packets to NFQUEUE 3
sudo ./scripts/iptables_enable.sh
# Run the IPS
sudo -E python -m ips.main live --queue 3

# 5) Stop live mode and restore iptables
sudo ./scripts/iptables_disable.sh
```

> **Note:** Live mode requires Linux, `iptables`/`nfqueue`, and root privileges. On WSL, use with care. Offline modes work cross‑platform.

## Project layout
```
ips/
  __init__.py
  main.py            # CLI entrypoint
  detector.py        # Stateful prevention engine
  rules.py           # Signature/regex rules
  nfqueue_runner.py  # Live mode (NFQUEUE)
  pcap_runner.py     # Offline PCAP analyze/replay
logs/                # JSONL alerts
tests/               # unit tests
scripts/             # iptables helper scripts
examples/            # place sample pcaps here
```

## What gets blocked?
- **ICMP flood:** rate threshold per source (packets/sec).
- **SYN flood/half-open:** too many outstanding SYNs without ACK per source.
- **Scan patterns:** abnormal flag combos (NULL, FIN, XMAS), or repeated port attempts.
- **HTTP payloads:** naïve SQLi strings (`union select`, `' or 1=1`, etc.).

Each decision yields an **action** (`ALLOW`/`DROP`) and a **reason** (rule ID + human text).

## Configuration
See `ips/detector.py` for thresholds. You can tune them via env vars or CLI flags.

## Logging
Decisions and alerts are written as JSONL to `logs/alerts.jsonl` (append‑only). Each record includes timestamp, 5‑tuple, action, ruleId, and reason.

## Tests
```
pytest -q
```

## License
MIT
