#!/usr/bin/env bash
# Starts MiniSOC: the web app and the collector together.
# Place this file in ~/MiniSOC (the folder that contains eduportal/ and minisoc/).
# Usage:  ./run.sh      (stop everything with Ctrl+C)

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT" || exit 1

# Activate the virtualenv if it is not already active.
if [ -z "$VIRTUAL_ENV" ]; then
    for v in venv .venv eduportal/venv minisoc/venv; do
        if [ -f "$ROOT/$v/bin/activate" ]; then
            source "$ROOT/$v/bin/activate"
            break
        fi
    done
fi

# Create the MiniSOC database tables if needed.
python -m minisoc.storage

# 1) Web app (must run from eduportal/ so security.log is created there).
( cd "$ROOT/eduportal" && exec python app.py ) &
APP_PID=$!

# Wait for security.log to exist (max 10 seconds).
for i in $(seq 1 20); do
    [ -f "$ROOT/eduportal/security.log" ] && break
    sleep 0.5
done

# 2) Collector (must run from the parent folder as a module).
python -u -m minisoc.collector &
COLLECTOR_PID=$!

echo "App PID: $APP_PID | Collector PID: $COLLECTOR_PID"
echo "Dashboard: http://localhost:5000/minisoc"
echo "Press Ctrl+C to stop both."

# Stop both processes on Ctrl+C or when the script exits.
cleanup() {
    echo; echo "Stopping..."
    pkill -P $APP_PID 2>/dev/null   # Flask debug reloader child
    kill $APP_PID $COLLECTOR_PID 2>/dev/null
    wait 2>/dev/null
    exit 0
}
trap cleanup INT TERM

# If either process dies, stop the other one too.
wait -n
cleanup
