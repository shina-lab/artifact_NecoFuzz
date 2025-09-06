#!/bin/bash
set -eu

usage() {
    echo "Usage: $0 <directory>"
    echo "  directory: Coverage data directory path"
    exit 1
}

# Check arguments
if [ "$#" -ne 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
fi

DIR="$1"

# Source utilities and check config
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
source "$SCRIPT_DIR/utilities.sh"
check_file "$CONFIG_PATH"
# Get Linux directory from config
KVM_UNIT_TESTS_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["kvm_unit_tests_dir"])' < "$CONFIG_PATH")
# Save original directory
ORIGINAL_DIR="$(pwd)"

# Create directory if it doesn't exist
if [ ! -d "$DIR" ]; then
    echo "Directory $DIR does not exist. Creating it..."
    mkdir -p "$DIR"
fi

# Convert DIR to absolute path
DIR="$(realpath "$DIR")"
echo "Using absolute path: $DIR"

sudo rm -f /dev/shm/kvm_arch_coverage /dev/shm/kvm_coverage
qemu_path=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["program"]["qemu"])' < $CONFIG_PATH)
qemu_path=$(realpath $qemu_path)
if [ ! -x "$qemu_path" ]; then
    echo "Error: QEMU binary not found or not executable at $qemu_path" >&2
    exit 1
fi
export QEMU=$qemu_path
export ACCEL=kvm
export ACCEL_PROPS="-cpu host"

# Change to KVM parent directory
cd $KVM_UNIT_TESTS_DIR
echo "Changed directory to: $(pwd)"

./configure
make

sudo -E ./run_tests.sh

# Return to original directory
cd "$ORIGINAL_DIR"
echo "Returned to original directory: $(pwd)"

COVERAGE_FILE=$DIR/cover_raw
FINAL_COVERAGE_FILE=$DIR/final_coverage
NESTED_COVERAGE_FILE=$DIR/final_nested_coverage

if [ ! -f /dev/shm/kvm_arch_coverage ]; then
    echo "Error: Coverage file not found at /dev/shm/kvm_arch_coverage" >&2
    exit 1
fi

cp /dev/shm/kvm_arch_coverage $COVERAGE_FILE

LINE_COUNT=$("$SCRIPT_DIR/../tools/scripts/cov2nested.sh" "$COVERAGE_FILE" $FINAL_COVERAGE_FILE | wc -l)

grep "nested.c" $FINAL_COVERAGE_FILE > $NESTED_COVERAGE_FILE 2>/dev/null || true
nested_count=$(grep -c "nested.c" "$FINAL_COVERAGE_FILE" 2>/dev/null || echo "0")

echo "Found $nested_count nested.c references in $NESTED_COVERAGE_FILE"

