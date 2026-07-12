#!/bin/bash
export DISPLAY=:0
cd "$(dirname "$0")"
python3 defendr.py > /tmp/defendr.log 2>&1
