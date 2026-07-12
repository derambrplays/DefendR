#!/bin/bash
if [ "$EUID" -ne 0 ]; then
    exec pkexec /usr/local/bin/defendr-sudo.sh
fi
cd "$(dirname "$0")"
export DISPLAY=:0
python3 defendr.py > /tmp/defendr.log 2>&1