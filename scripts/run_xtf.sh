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
elif [ "$cpu_vendor" = "AuthenticAMD" ]; then
    arch="amd"
    TARGET_FILES=("arch/x86/hvm/svm/nestedsvm.c")
else
    echo "Unknown CPU vendor"
    exit 1
fi


GCDA_FILES=(
    "arch/x86/hvm/vmx/vvmx.gcda"
    "arch/x86/hvm/vmx/vmx.gcda"
    "arch/x86/hvm/svm/svm.gcda"
    "arch/x86/hvm/svm/nestedsvm.gcda"
)

COVERAGE_FILE=$OUTPUT_DIR/"coverage.dat"
TXT_COVERAGE_FILE=$OUTPUT_DIR/"coverage.txt"
TEMP=$(mktemp)

cd $XTF_DIR

make
sudo xencov reset
sudo ./xtf-runner hvm pv || true
sudo xencov read > $COVERAGE_FILE

xencov_split $COVERAGE_FILE > /dev/null

cd $XEN_DIR/xen

for gcda_file in "${GCDA_FILES[@]}"; do
    if [ -f "$gcda_file" ]; then
        gcov-11 -t "$gcda_file" >> "$TEMP"
    else
        echo "Warning: $gcda_file not found" >&2
    fi
done

cp $TEMP $TXT_COVERAGE_FILE

cd $ORIGINAL_DIR
echo "Coverage results:"
total_lines=0
for i in "${!TARGET_FILES[@]}"; do
    target_file="${TARGET_FILES[$i]}"
    echo -n "$(basename "$target_file"): "

    extracted=$(awk -v file="$target_file" '
    BEGIN { print_data=0 }
    $0 ~ "  -:    0:Source:" && print_data { exit }
    $0 ~ "Source:"file { print_data=1 }
    print_data { print }
    ' "$TEMP" | grep -v "\-:" | cut -d ":" -f 2-)

    echo "$extracted"  > "$OUTPUT_DIR/instrumented_line"

    if ! echo "$extracted" | grep -q "#####"; then
        {
            echo "$extracted"
        } > "$OUTPUT_DIR/final_nested_coverage"
    fi
    line_count=$(printf "%s\n" "$extracted" | wc -l)
    echo "$line_count"

    total_lines=$((total_lines + line_count))
done

echo "----------------------------------------"
echo "Total covered lines: $total_lines"

rm -f $TEMP


cd "$ORIGINAL_DIR"
echo "Returned to original directory: $(pwd)"
