#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CONFIG_PATH="./config.yaml"  # default path
TARGET_HYPERVISOR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["fuzzing"]["target"])' < $CONFIG_PATH)

do_fuzz() {
    local file_path="$1"
    if [ "$TARGET_HYPERVISOR" = "kvm" ] || [ "$TARGET_HYPERVISOR" = "xen" ]; then
        sudo cp "$file_path" afl_input
        sudo $SCRIPT_DIR/../bin/fuzz_runner
    else
        cp "$file_path" afl_input
        $SCRIPT_DIR/../bin/fuzz_runner
    fi
}

if [ -d "$1" ]; then
    for var in `ls $1 | grep $2`
    do
        echo "$1/$var"
        do_fuzz "$1/$var"
    done
elif [ -f "$1" ]; then
    echo "$1"
    do_fuzz "$1"
else
    echo "Error: $1 is not a valid file or directory"
    exit 1
fi