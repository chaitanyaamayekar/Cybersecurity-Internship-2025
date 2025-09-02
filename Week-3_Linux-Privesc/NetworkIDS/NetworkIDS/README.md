# NetworkIDS (Windows-friendly)

A lightweight Network Intrusion Detection System that monitors live traffic (with admin rights)
or parses a PCAP file and raises alerts for:
- ICMP pings (echo request/reply), including floods
- TCP connection attempts (SYNs, half-open)
- Common scan patterns (SYN/NULL/FIN scans, sweeping many ports quickly)
- Suspicious behaviors (high-rate SYNs to many ports)

## Quick Start (Windows)
1. Install Python 3.10+ and add it to PATH.
2. Open **Command Prompt (Run as Administrator)** if you want to sniff live traffic.
3. Install dependencies:
   ```bat
   pip install -r requirements.txt
   ```
4. Run against a PCAP (recommended first run):
   ```bat
   python src\main.py --pcap src\tests\sample_attack.pcap
   ```
   (Drop your PCAPs into `src/tests/` and update the path.)
5. Live capture (requires admin):
   ```bat
   python src\main.py --live --iface auto
   ```

## Demo
Double-click `run_demo.bat`. It processes two PCAPs (normal + attack) and writes `alerts.log`.

> Note: The sample PCAPs here are placeholders. Replace them with your own PCAPs
> or generate using the provided helper in `src/tests/make_sample_pcaps.py` (optional).

## Project Layout
```
NetworkIDS/
├─ src/
│  ├─ main.py
│  ├─ detector.py
│  ├─ parser.py
│  ├─ alerts.py
│  └─ tests/
│     ├─ test_detector.py
│     ├─ sample_normal.pcap        (placeholder)
│     ├─ sample_attack.pcap        (placeholder)
│     └─ make_sample_pcaps.py      (optional helper if Scapy privileges available)
├─ docs/
│  ├─ REPORT.md
│  └─ README.md
├─ requirements.txt
└─ run_demo.bat
```

## Thresholds (defaults)
- ICMP flood: ≥ 50 echo-requests within 5s per (src,dst)
- SYN scan: ≥ 20 distinct ports within 10s from same src to same dst (or same src to many dsts)
- NULL/FIN scan: ≥ 10 such packets within 10s window
- Half-open surge: ≥ 30 SYNs without ACKs within 10s

Tune via `--syn-window`, `--icmp-window`, and env vars or edit `detector.py` constants.

## Tests
```bat
pytest -q
```

## Future Work
- Add UDP-based scans (e.g., UDP “ping”, amplification hints)
- Persist state to SQLite for long-running sessions
- Add JSON alert output and Syslog forwarding
- Whitelisting/noise suppression rules