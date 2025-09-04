#!/bin/bash

cpu_vendor=$(grep -m1 vendor_id /proc/cpuinfo | awk -F ":" '{print $2}' | tr -d ' ')

if [ "$cpu_vendor" = "GenuineIntel" ]; then
    arch="intel"
elif [ "$cpu_vendor" = "AuthenticAMD" ]; then
    arch="amd"
else
    echo "Unknown CPU vendor"
fi

check_file() {
    if [ ! -f "$1" ]; then
        echo "Error: File $1 does not exist."
        exit 1
    fi
}


CONFIG_PATH="$SCRIPT_DIR/../../config.yaml"  # default path