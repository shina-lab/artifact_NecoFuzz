#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source $SCRIPT_DIR/utilities.sh
check_file $CONFIG_PATH

COVOUT_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["coverage_outputs"])' < $CONFIG_PATH 2>/dev/null)
COVOUT_DIR=$(SCRIPT_DIR/../../$COVOUT_DIR)
if [ $? -ne 0 ] || [ -z "$COVOUT_DIR" ] || [ "$COVOUT_DIR" = "/" ]; then
    echo "Error: Invalid or missing coverage output directory"
    exit 1
fi

sudo rm -rf "$COVOUT_DIR"/*
rm /dev/shm/kvm_arch_coverage /dev/shm/kvm_coverage /dev/shm/xen_coverage /dev/shm/bitmap_coverage -f
