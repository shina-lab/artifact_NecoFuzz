#!/bin/bash
set -eu

usage() {
    echo "Usage: $0 <output_dir>"
    echo "  output_dir: Path to output directory for results"
    exit 1
}

# Check arguments
if [ "$#" -lt 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
fi

# Source utilities and check config
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
source "$SCRIPT_DIR/utilities.sh"
check_file "$CONFIG_PATH"
# Get KVM directory from config
XEN_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["xen_dir"])' < "$CONFIG_PATH")
XTF_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["xtf_dir"])' < "$CONFIG_PATH")

XEN_DIR="$(realpath "$XEN_DIR")"
XTF_DIR="$(realpath "$XTF_DIR")"
OUTPUT_DIR="$1"

# Create output directory
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(realpath "$OUTPUT_DIR")"
# Save original directory
ORIGINAL_DIR="$(pwd)"

ORIGINAL_DIR=$(pwd)

cpu_vendor=$(grep -m1 vendor_id /proc/cpuinfo | awk -F ":" '{print $2}' | tr -d ' ')

if [ "$cpu_vendor" = "GenuineIntel" ]; then
    arch="intel"
    TARGET_FILES=("arch/x86/hvm/vmx/vvmx.c")
    GCDA_FILES=("arch/x86/hvm/vmx/.vvmx.o.gcda")
elif [ "$cpu_vendor" = "AuthenticAMD" ]; then
    arch="amd"
    TARGET_FILES=("arch/x86/hvm/svm/nestedsvm.c")
    GCDA_FILES=("arch/x86/hvm/svm/.nestedsvm.o.gcda")
else
    echo "Unknown CPU vendor"
    exit 1
fi

COVERAGE_FILE=$OUTPUT_DIR/"coverage.dat"
JSON_COVERAGE_FILE=$OUTPUT_DIR/"coverage.json"
touch $JSON_COVERAGE_FILE

cd $XTF_DIR

make
sudo xencov reset
sudo ./xtf-runner --all --non-default hvm pv || true
sudo xencov read > $COVERAGE_FILE

cd /
sudo xencov_split $COVERAGE_FILE > /dev/null

cd $XEN_DIR/xen

for gcda_file in "${GCDA_FILES[@]}"; do
    if [ -f "$gcda_file" ]; then
        # Output JSON to stdout (avoid writing .gcov.json.gz files)
        gcov-11 --json-format --stdout "$gcda_file" >> "$JSON_COVERAGE_FILE"
    else
        echo "Warning: $gcda_file not found" >&2
    fi
done

cd $ORIGINAL_DIR
echo "Coverage results:"
total_lines=0
for target_file in "${TARGET_FILES[@]}"; do
    echo -n "$(basename "$target_file"): "

    # instrumented_line: all line numbers instrumented in this file
    # final_nested_coverage: line numbers with count > 0 (executed lines)
    # Multiple gcda files may overlap, so use uniq/sort
    mapfile -t all_lines < <(
        jq -r -s --arg f "$target_file" '
          map(.files[]?)                         # Flatten files from all JSON objects
          | map(select(.file == $f))             # Only keep the matching file
          | .[] | .lines[]?                      # Iterate over line entries
          | .line_number                         # Extract line numbers
        ' "$JSON_COVERAGE_FILE" | sort -n -u
    )

    mapfile -t covered_lines < <(
        jq -r -s --arg f "$target_file" '
          map(.files[]?)
          | map(select(.file == $f))
          | .[] | .lines[]?
          | select(.count > 0)                   # Executed lines only
          | .line_number
        ' "$JSON_COVERAGE_FILE" | sort -n -u
    )

    # Write output files (overwrite each time)
    printf "%s\n" "${all_lines[@]}"     >  "$OUTPUT_DIR/instrumented_line"
    printf "%s\n" "${covered_lines[@]}" >  "$OUTPUT_DIR/final_nested_coverage"

    # Count for display (executed lines)
    line_count=${#covered_lines[@]}
    echo "$line_count"

    total_lines=$((total_lines + line_count))
done

echo "----------------------------------------"
echo "Total covered lines: $total_lines"


cd "$ORIGINAL_DIR"
echo "Returned to original directory: $(pwd)"
