#!/usr/bin/env bash
# One-time setup for CyberShield OS on Ubuntu / WSL2.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${CYBERSHIELD_VENV:-$HOME/.venvs/cybershield}"

echo "==> Checking system packages"
missing=()
python3 -c "import ensurepip" 2>/dev/null || missing+=(python3-venv)
command -v logger >/dev/null || missing+=(bsdutils)
[ -f /var/log/auth.log ] || missing+=(rsyslog)
if [ ${#missing[@]} -gt 0 ]; then
    echo "    Installing: ${missing[*]} (needs sudo)"
    sudo apt-get update -q && sudo apt-get install -y "${missing[@]}"
fi

echo "==> Creating virtual environment in $VENV"
python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --timeout 120 --retries 10 -r "$PROJECT_DIR/requirements-dev.txt"

echo "==> Creating demo watch folder ~/cybershield_watch"
mkdir -p "$HOME/cybershield_watch"
[ -f "$HOME/cybershield_watch/important.txt" ] || echo "Quarterly results: CONFIDENTIAL" > "$HOME/cybershield_watch/important.txt"
[ -f "$HOME/cybershield_watch/app.conf" ] || printf "debug=false\nadmin_user=admin\n" > "$HOME/cybershield_watch/app.conf"

echo "==> Checking access to /var/log/auth.log"
if [ -r /var/log/auth.log ]; then
    echo "    OK"
else
    echo "    Adding $USER to the 'adm' group so auth.log can be read without sudo"
    sudo usermod -aG adm "$USER"
    echo "    Run 'wsl --shutdown' from Windows, reopen Ubuntu, then start CyberShield."
fi

echo
echo "Setup complete. Next:"
echo "  source $VENV/bin/activate"
echo "  cd \"$PROJECT_DIR\" && python main.py"
