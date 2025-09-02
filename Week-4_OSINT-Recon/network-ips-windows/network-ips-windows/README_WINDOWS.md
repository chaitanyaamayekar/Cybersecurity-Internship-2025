# Windows Notes for Network IPS (Windows build)

This Windows-friendly package removes Linux-only live-blocking components (NFQUEUE + iptables)
so you can run the **offline analysis**, **replay**, and **unit tests** on Windows without errors.

What was removed:
- ips/nfqueue_runner.py
- scripts/iptables_enable.sh
- scripts/iptables_disable.sh
- requirements.txt no longer contains netfilterqueue

How to run (PowerShell):
1. Unzip and enter directory:
   ```powershell
   tar -xf network-ips-windows.zip
   cd network-ips
   ```
2. Create & activate venv:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\activate
   ```
3. Install requirements:
   ```powershell
   pip install -r requirements.txt
   ```
4. Place your PCAPs in the `examples\` folder. Two demo PCAPs recommended:
   - `examples\normal.pcap` (benign traffic)
   - `examples\malicious.pcap` (contains ping flood, SYN flood, port scan, HTTP SQLi)
5. Run analysis on each:
   ```powershell
   python -m ips.main analyze --pcap examples\normal.pcap --http
   python -m ips.main analyze --pcap examples\malicious.pcap --http
   ```
6. Replay mode (simulates decisions):
   ```powershell
   python -m ips.main replay --pcap examples\malicious.pcap
   ```
7. Run unit tests:
   ```powershell
   pytest -q
   ```

If you later want **live blocking**, use WSL2 or a Linux VM and the original project (network-ips.zip) which includes NFQUEUE support.
