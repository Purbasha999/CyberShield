#!/usr/bin/env bash
# Write simulated SSH brute-force lines into /var/log/auth.log through syslog.
# Uses `logger`, so no password guessing happens and no SSH server is needed.
# 203.0.113.0/24 is a reserved documentation range, not a real attacker.
#
#   ./scripts/simulate_failed_logins.sh        # 5 attempts -> HIGH alert (threshold is 3)
#   ./scripts/simulate_failed_logins.sh 2      # 2 attempts -> logged, no alert
#
# For a real failed login instead, run `su root` (or `sudo -k; sudo true`) and type a wrong password.
set -euo pipefail

COUNT="${1:-5}"
IP="203.0.113.$(( RANDOM % 200 + 20 ))"

echo "Simulating $COUNT failed SSH logins from $IP"
for i in $(seq 1 "$COUNT"); do
    logger -p authpriv.warning -t sshd -i "Failed password for invalid user admin from $IP port $(( 40000 + i )) ssh2"
    echo "  attempt $i"
    sleep 0.5
done
echo "Done. Expect HIGH 'Multiple failed login attempts' if count > max_failed_attempts."
