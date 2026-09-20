#!/bin/bash
# Starts the companion with a pairing key read from a 0600 file, so a phone paired once keeps
# working across restarts (a key generated at startup is different every run). The key is never
# echoed.
#
# Bind: leave ARROWBRIDGE_BIND unset for loopback only, or set it to the ONE address of the
# interface your phone shares with this machine, for example ARROWBRIDGE_BIND=192.0.2.10 (yours
# is whatever `ip addr` / `ifconfig` / `ipconfig` shows for that adapter). Never 0.0.0.0; the
# server refuses to start on it.
set -euo pipefail
cd "$(dirname "$0")"
KEYFILE="${ARROWBRIDGE_PAIR_KEY_FILE:-$HOME/.arrowbridge-pair-key}"
if [ ! -s "$KEYFILE" ]; then
    echo "no pairing key at $KEYFILE" >&2
    echo "create one:  python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > \"$KEYFILE\" && chmod 600 \"$KEYFILE\"" >&2
    exit 1
fi
: "${ARROWBRIDGE_UPSTREAM_MODEL:?set ARROWBRIDGE_UPSTREAM_MODEL to the model name your local server loads}"
export ARROWBRIDGE_UPSTREAM_URL="${ARROWBRIDGE_UPSTREAM_URL:-http://127.0.0.1:8080}"
export ARROWBRIDGE_PAIR_KEY="$(cat "$KEYFILE")"  # never printed
exec "${PYTHON:-python3}" companion_server.py
