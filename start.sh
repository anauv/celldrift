#!/bin/bash
# Start the CellDrift in a detached screen session (or with nohup when screen is missing).
# Usage: ./start.sh [--no-initial]     attach: screen -r celldrift     detach: Ctrl+A, D
cd "$(dirname "$0")" || exit 1
SESSION=celldrift
if screen -list 2>/dev/null | grep -q "\.$SESSION\s"; then
    echo "logger already running in screen '$SESSION'"
    exit 0
fi
if [ -f logger.pid ] && kill -0 "$(cat logger.pid)" 2>/dev/null; then
    echo "logger already running (pid $(cat logger.pid))"
    exit 0
fi
[ -x ./make_cert.sh ] && command -v openssl >/dev/null 2>&1 && ./make_cert.sh
CMD="python3 -u celldrift.py --config config.json $*"
if command -v screen >/dev/null 2>&1; then
    screen -dmS "$SESSION" bash -c "$CMD 2>&1 | tee -a logger.log"
    sleep 2
    if screen -list | grep -q "\.$SESSION\s"; then
        echo "logger started in screen '$SESSION' (view: screen -r $SESSION), log: $(pwd)/logger.log"
        exit 0
    fi
else
    setsid nohup $CMD >> logger.log 2>&1 < /dev/null &
    echo $! > logger.pid
    sleep 2
    if kill -0 "$(cat logger.pid)" 2>/dev/null; then
        echo "logger started with nohup (pid $(cat logger.pid)), log: $(pwd)/logger.log"
        exit 0
    fi
fi
echo "start failed, see logger.log:"
tail -n 20 logger.log
exit 1
