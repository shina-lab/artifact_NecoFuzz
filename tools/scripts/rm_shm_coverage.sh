#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source $SCRIPT_DIR/utilities.sh
check_file $CONFIG_PATH

rm /dev/shm/kvm_arch_coverage /dev/shm/kvm_coverage /dev/shm/xen_coverage /dev/shm/bitmap_coverage -f
