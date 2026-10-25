#!/bin/bash
# Stop the CellDrift, whether it runs in screen or with nohup.
cd "$(dirname "$0")" || exit 1
SESSION=celldrift
stopped=0
if screen -list 2>/dev/null | grep -q "\.$SESSION\s"; then
    screen -S "$SESSION" -X quit && echo "screen session '$SESSION' stopped" && stopped=1
fi
if [ -f logger.pid ] && kill -0 "$(cat logger.pid)" 2>/dev/null; then
    kill "$(cat logger.pid)" && echo "logger stopped (pid $(cat logger.pid))" && stopped=1
fi
rm -f logger.pid
[ "$stopped" = 1 ] || echo "logger was not running"
