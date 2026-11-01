#!/usr/bin/env bash
# Trigger every alert type once, for a live demo. Start `python main.py` in another terminal first.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
PY="${PYTHON:-python3}"

echo "### 1/5 Failed logins (HIGH)";                  ./simulate_failed_logins.sh 5;            echo
echo "### 2/5 Suspicious process (MEDIUM, popup)";    ./simulate_suspicious_process.sh 15 &     sleep 1; echo
echo "### 3/5 CPU-intensive process (blocked)";       "$PY" simulate_cpu_load.py --seconds 20;  echo
echo "### 4/5 Memory-hungry process (blocked)";       "$PY" simulate_memory_hog.py --seconds 20; echo
wait
echo "### 5/5 File tampering (MEDIUM / LOW, popup)";  "$PY" simulate_file_tamper.py --pause 12
echo
echo "Demo complete. Check the dashboard and ~/.cybershield/logs/security_events.log"
