#!/usr/bin/env bash
set -euo pipefail
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
echo "[*] If you plan to run live mode, install netfilterqueue system deps:"
echo "    sudo apt-get install -y build-essential python3-dev libnetfilter-queue-dev"
