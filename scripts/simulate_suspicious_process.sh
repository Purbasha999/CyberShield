#!/usr/bin/env bash
# Run a harmless copy of the Python interpreter, renamed to "xmrig" (a crypto-miner name),
# from /tmp. It only sleeps. Triggers two MEDIUM alerts: suspicious process name and
# process running from a temp directory.
set -euo pipefail

SECONDS_TO_RUN="${1:-30}"
FAKE="/tmp/xmrig"

cp "$(readlink -f "$(command -v python3)")" "$FAKE"
chmod 755 "$FAKE"
trap 'rm -f "$FAKE"' EXIT

echo "Running harmless $FAKE for ${SECONDS_TO_RUN}s (a renamed Python that only sleeps)..."
"$FAKE" -c "import time; time.sleep($SECONDS_TO_RUN)"
echo "Done, removed $FAKE."
