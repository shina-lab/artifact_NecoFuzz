#!/bin/bash
set -eu

# Configuration
readonly VERSION=$(uname -r)
readonly BASE_DIR="kvm_baseline"
readonly OUTDIR="$BASE_DIR/$VERSION"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly TMP_DIR=$(mktemp -d)

# Cleanup function
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Source utilities and check config
source "$SCRIPT_DIR/utilities.sh"
check_file "$CONFIG_PATH"

# Get KVM directory from config
readonly KVM_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["kvm_dir"])' < "$CONFIG_PATH")

# Create output directory
mkdir -p "$OUTDIR"

# Function to process KVM module
process_kvm_module() {
    local module_path="$1"
    local output_prefix="$2"
    local addr_cut_fields="$3"

    echo "Processing $module_path..."

    # Extract coverage trace addresses
    objdump -d -M intel "$module_path" -r \
        | grep 'cov_trace_pc' \
        | grep 'R_X86_64_PLT32' \
        | cut -d ':' -f1 \
        | sed -e 's/^[[:space:]]*//' -e 's/^/0x/' \
        > "$TMP_DIR/raw_addrs"

    # Adjust addresses (+4) and sort
    python3 -c "
with open('$TMP_DIR/raw_addrs') as f:
    addrs = [hex(int(line.strip(), 16) + 4) for line in f]
with open('$TMP_DIR/adjusted_addrs', 'w') as f:
    for addr in sorted(set(addrs), key=lambda x: int(x, 16)):
        f.write(addr + '\n')
"

    # Convert addresses to source locations
    addr2line -e "$module_path" -i < "$TMP_DIR/adjusted_addrs" \
        | cut -d '/' -f5- \
        | cut -d ':' "$addr_cut_fields" \
        | cut -d '(' -f1 \
        | sed -e 's/[[:space:]]//g' -e 's/\/\.\//\//g' \
        > "$TMP_DIR/raw_locations"

    # Normalize paths and sort
    python3 -c "
import os.path
with open('$TMP_DIR/raw_locations') as f:
    locations = [os.path.normpath(line.strip()) for line in f if line.strip()]
with open('$OUTDIR/${output_prefix}_all', 'w') as f:
    for loc in sorted(set(locations), key=lambda x: (x.split(':')[0], int(x.split(':')[1]) if ':' in x and x.split(':')[1].isdigit() else 0)):
        f.write(loc + '\n')
"

    # Save processed addresses
    cp "$TMP_DIR/adjusted_addrs" "$OUTDIR/$output_prefix"
}

# Check if arch variable is defined, if not try to determine it
if [[ -z "${arch:-}" ]]; then
    arch=$(uname -m)
    echo "Warning: \$arch not set, using detected architecture: $arch"
fi

# Process both KVM modules
if [[ -f "$KVM_DIR/kvm-$arch.ko" ]]; then
    process_kvm_module "$KVM_DIR/kvm-$arch.ko" "kvm_$arch" "-f1-2"
else
    echo "Warning: $KVM_DIR/kvm-$arch.ko not found"
fi

if [[ -f "$KVM_DIR/kvm.ko" ]]; then
    process_kvm_module "$KVM_DIR/kvm.ko" "kvm" "-f1-2"
else
    echo "Warning: $KVM_DIR/kvm.ko not found"
fi

echo "KVM baseline extraction completed successfully!"
echo "Results saved in: $OUTDIR"
