#!/bin/bash
set -eu

usage() {
    echo "Usage: $0 <directory> <clean|make|run>"
    echo "  directory: Coverage data directory path"
    echo "  action:"
    echo "    clean - Clean KVM selftests build"
    echo "    make  - Build KVM selftests"
    echo "    run   - Run KVM selftests"
    exit 1
}

# Check arguments
if [ "$#" -ne 2 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
fi

DIR="$1"
ACTION="$2"

# Source utilities and check config
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
source "$SCRIPT_DIR/utilities.sh"
check_file "$CONFIG_PATH"
# Get Linux directory from config
LINUX_SOURCE_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["linux_source_dir"])' < "$CONFIG_PATH")
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

# Change to KVM parent directory
cd $LINUX_SOURCE_DIR
echo "Changed directory to: $(pwd)"

make headers

# Export COVERAGE_BASE_PATH
export COVERAGE_BASE_PATH="$DIR"
echo "COVERAGE_BASE_PATH set to: $COVERAGE_BASE_PATH"

# Execute action
case $ACTION in
    clean)
        echo "Cleaning KVM selftests..."
        make -C tools/testing/selftests/ TARGETS=kvm clean
        ;;
    make)
        echo "Building KVM selftests..."
        make -C tools/testing/selftests/ TARGETS=kvm
        ;;
    run)
        echo "Running KVM selftests..."
        sudo --preserve-env=COVERAGE_BASE_PATH make -C tools/testing/selftests/ TARGETS=kvm run_tests
        ;;
    *)
        echo "Invalid action: $ACTION"
        usage
        ;;
esac

# Process coverage files
if ls "$DIR"/COVERAGE_ARCH_* 1> /dev/null 2>&1; then
    cat "$DIR"/COVERAGE_ARCH_* > tmp
    cat tmp | sort | uniq > "$DIR"/all_kvm_arch
    echo "Generated all_kvm_arch from COVERAGE_ARCH_* files"
fi

if ls "$DIR"/COVERAGE_KVM_* 1> /dev/null 2>&1; then
    cat "$DIR"/COVERAGE_KVM_* > tmp
    cat tmp | sort | uniq > "$DIR"/all_kvm
    echo "Generated all_kvm from COVERAGE_KVM_* files"
fi

# Clean up temporary file
rm -f tmp

# Return to original directory
cd "$ORIGINAL_DIR"
echo "Returned to original directory: $(pwd)"

FINAL_COVERAGE_FILE=$DIR/final_coverage
NESTED_COVERAGE_FILE=$DIR/final_nested_coverage

# Process arch coverage with hexcov2nested.sh
if [ -f "$DIR"/all_kvm_arch ]; then
    echo "Processing arch coverage with hexcov2nested.sh..."
    LINE_COUNT=$("$SCRIPT_DIR/hexcov2nested.sh" "$DIR"/all_kvm_arch $FINAL_COVERAGE_FILE | wc -l)
    grep "nested.c" $FINAL_COVERAGE_FILE > $NESTED_COVERAGE_FILE 2>/dev/null || true
    nested_count=$(grep -c "nested.c" "$FINAL_COVERAGE_FILE" 2>/dev/null || echo "0")

    echo "Found $nested_count nested.c references in $NESTED_COVERAGE_FILE"
fi