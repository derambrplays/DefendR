#!/bin/bash
# Detect if we need to elevate privileges
if [ "$EUID" -ne 0 ]; then
    if command -v pkexec &>/dev/null; then
        exec pkexec /usr/local/bin/defendr-sudo.sh
    elif command -v sudo &>/dev/null; then
        exec sudo "$0" "$@"
    fi
fi
cd "$(dirname "$0")"
export DISPLAY=:0
python3 defendr.py > /tmp/defendr.log 2>&1