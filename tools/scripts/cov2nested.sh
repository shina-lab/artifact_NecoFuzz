#!/bin/bash
set -euo pipefail

# Check required arguments
if [[ -z "${1:-}" ]]; then
    echo "Error: Coverage file is required." >&2
    echo "Usage: $0 <coverage_file> [output_file]" >&2
    exit 1
fi

# Set variables
COVERAGE_FILE="$1"
OUTPUT_FILE="${2:-tmp}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
TEMP_DIR=$(mktemp -d)

# Cleanup function
cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Source utilities
source "$SCRIPT_DIR/utilities.sh"

# Process coverage file
COV_OUT=$("$SCRIPT_DIR/../bin/decode_coverage" "$COVERAGE_FILE")
check_file "$COV_OUT"
check_file "$CONFIG_PATH"

# Get KVM directory from config
KVM_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["kvm_dir"])' < "$CONFIG_PATH")
KVM_DIR=$SCRIPT_DIR/../../$KVM_DIR

# Detect architecture if not set
if [[ -z "${arch:-}" ]]; then
    arch=$(uname -m)
    case "$arch" in
        x86_64) arch="intel" ;;  # or "amd" depending on CPU
        *)
            # Try to detect from available modules
            if [[ -f "$KVM_DIR/kvm-intel.ko" ]]; then
                arch="intel"
            elif [[ -f "$KVM_DIR/kvm-amd.ko" ]]; then
                arch="amd"
            else
                echo "Error: Cannot determine KVM architecture module" >&2
                exit 1
            fi
            ;;
    esac
fi

# Verify KVM module exists
KVM_MODULE="$KVM_DIR/kvm-${arch}.ko"
check_file "$KVM_MODULE"

# Process addresses to source lines
addr2line -e "$KVM_MODULE" -i < "$COV_OUT" \
    | cut -d "/" -f5- \
    | cut -d "(" -f1 \
    | sed -e 's/[[:space:]]//g' -e 's/\/\.\//\//g' \
    | sort | uniq > "$TEMP_DIR/raw_lines"

# Normalize paths and sort by file:line
python3 -c "
import os.path
with open('$TEMP_DIR/raw_lines') as f:
    lines = [os.path.normpath(line.strip()) for line in f if line.strip()]

# Sort by filename, then line number
def sort_key(line):
    if ':' in line:
        file, line_num = line.split(':', 1)
        try:
            return (file, int(line_num))
        except ValueError:
            return (file, 0)
    return (line, 0)

sorted_lines = sorted(set(lines), key=sort_key)
with open('$OUTPUT_FILE', 'w') as f:
    for line in sorted_lines:
        f.write(line + '\n')
"

# Extract and sort nested.c line numbers
grep "nested.c:" "$TEMP_DIR/raw_lines" \
    | cut -d ":" -f2 \
    | sed 's/[[:space:]]//g' \
    | sort -n \
    | uniq