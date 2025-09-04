#!/bin/bash
set -euo pipefail

usage() {
    echo "Usage: $0 <output_dir> [kernel_source_dir]"
    echo "  output_dir: Path to output directory for results"
    echo "  kernel_source_dir: Path to kernel source directory (optional)"
    echo ""
    echo "If kernel_source_dir is not provided, it will be read from CONFIG_PATH"
    exit 1
}

# Check arguments
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

# Set output directory from first argument
OUTPUT_DIR="$1"
# Set kernel directory
if [ "$#" -eq 2 ]; then
    # Use command line argument
    KERNEL_DIR="$2"
    echo "Using kernel directory from command line: $KERNEL_DIR"
else
    # Try to read from config file
    CONFIG_PATH="${CONFIG_PATH:-config.yaml}"
    if [ -f "$CONFIG_PATH" ]; then
        KERNEL_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["linux_source_dir"])' < "$CONFIG_PATH" 2>/dev/null || echo "")
        if [ -z "$KERNEL_DIR" ]; then
            echo "Error: Could not read linux_source_dir from config file: $CONFIG_PATH"
            echo "Make sure the config file contains: directories.linux_source_dir"
            echo "Or provide kernel_source_dir as second argument"
            exit 1
        fi
        echo "Using kernel directory from config: $KERNEL_DIR"
    else
        echo "Error: No kernel directory provided and config file not found: $CONFIG_PATH"
        echo "Please provide kernel_source_dir as second argument or create config file"
        exit 1
    fi
fi

ORIGINAL_DIR="$(pwd)"

OUTPUT_DIR="$(realpath "$OUTPUT_DIR")"
KERNEL_DIR="$(realpath "$KERNEL_DIR")"

echo "Using output directory: $OUTPUT_DIR"
echo "Using kernel directory: $KERNEL_DIR"

# Validate directories
if [ ! -d "$KERNEL_DIR" ]; then
    echo "Error: Kernel directory does not exist: $KERNEL_DIR"
    exit 1
fi

if [ ! -f "$KERNEL_DIR/arch/x86/boot/bzImage" ]; then
    echo "Error: Kernel image not found: $KERNEL_DIR/arch/x86/boot/bzImage"
    echo "Make sure the kernel is built"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/coverage"
mkdir -p "$OUTPUT_DIR/coverage/out"

SYZKALLER_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["syzkaller_dir"])' < "$CONFIG_PATH" 2>/dev/null || echo "")
SYZKALLER_DIR="$(realpath "$SYZKALLER_DIR")"
# Validate syzkaller setup
if [ ! -d "$SYZKALLER_DIR" ]; then
    echo "Error: Syzkaller directory does not exist: $SYZKALLER_DIR"
    exit 1
fi

# Change to syzkaller directory
cd "$SYZKALLER_DIR"

# Set syzkaller paths
IMAGE="./image"
IMAGE_FILE="$IMAGE/bullseye.img"
RSA_KEY="$IMAGE/bullseye.id_rsa"



if [ ! -f "$IMAGE_FILE" ]; then
    echo "Error: VM image not found: $IMAGE_FILE"
    exit 1
fi

if [ ! -f "$RSA_KEY" ]; then
    echo "Error: SSH key not found: $RSA_KEY"
    exit 1
fi

# Create configuration file
echo "Creating syzkaller configuration..."
cat > my.cfg << EOF
{
    "target": "linux/amd64",
    "http": "127.0.0.1:10021",
    "workdir": "$OUTPUT_DIR",
    "kernel_obj": "$KERNEL_DIR",
    "image": "$IMAGE_FILE",
    "sshkey": "$RSA_KEY",
    "syzkaller": ".",
    "procs": 8,
    "type": "qemu",
    "vm": {
        "count": 4,
        "kernel": "$KERNEL_DIR/arch/x86/boot/bzImage",
        "cmdline": "net.ifnames=0 nokaslr",
        "cpu": 2,
        "mem": 2048,
        "qemu_args": "-machine accel=kvm -cpu host,+vmx -enable-kvm"
    },
    "enable_syscalls": [
        "openat\$kvm",
        "ioctl\$KVM*",
        "syz_kvm_setup_cpu\$x86"
    ]
}
EOF

echo "Configuration created at: my.cfg"

# Function to cleanup background processes
cleanup() {
    echo ""
    echo "Cleaning up..."

    # Kill the entire process group to ensure all background processes are terminated
    if [ -n "${COVERAGE_PID:-}" ]; then
        # Kill the coverage collection process and its children
        kill -TERM $COVERAGE_PID 2>/dev/null || true
        # Wait a moment for graceful termination
        sleep 1
        # Force kill if still running
        kill -KILL $COVERAGE_PID 2>/dev/null || true
        echo "Coverage collection stopped"
    fi

    # Kill any remaining wget processes that might be hanging
    pkill -f "wget.*rawcover" 2>/dev/null || true

    echo "Cleanup completed"

    cd "$ORIGINAL_DIR"
    exit 0
}

# Set trap for cleanup
trap cleanup INT TERM EXIT

# Start coverage collection in background with process group
echo "Starting coverage collection..."
(
    # Create a new process group
    set -m

    # Read KVM base address once at startup
    KVM_INFO_FILE="$SYZKALLER_DIR/kvm_module_info.txt"
    if [ -f "$KVM_INFO_FILE" ]; then
        KVM_BASE=$(grep "^KVM_BASE=" "$KVM_INFO_FILE" | cut -d'=' -f2)
        echo "Using KVM_BASE: $KVM_BASE"
    else
        echo "Warning: KVM module info file not found: $KVM_INFO_FILE"
        echo "Coverage will be saved as absolute addresses"
        KVM_BASE=""
    fi

    while true; do
        sleep 30
        timestamp=$(date +%Y%m%d_%H%M%S)
        raw_coverage="$OUTPUT_DIR/coverage/cover_raw.txt"
        current_coverage="$OUTPUT_DIR/coverage/cover_$timestamp.txt"

        # Fetch raw coverage
        if wget -q --timeout=10 --tries=1 "http://127.0.0.1:10021/rawcover" -O "$raw_coverage" 2>/dev/null; then
            # Check if raw coverage file is not empty
            if [ ! -s "$raw_coverage" ]; then
                echo "Raw coverage file is empty at $timestamp"
                continue
            fi

            # Convert absolute addresses to relative addresses if KVM_BASE is available
            if [ -n "$KVM_BASE" ]; then
                python3 -c "
import sys

# Read KVM base address
try:
    kvm_base = int('$KVM_BASE', 16)
except ValueError:
    print('Error: Invalid KVM_BASE format: $KVM_BASE', file=sys.stderr)
    sys.exit(1)

# Process coverage file
processed_count = 0
with open('$raw_coverage', 'r') as f, open('$current_coverage', 'w') as out:
    for line in f:
        line = line.strip()
        if line and line.startswith('0x'):
            try:
                addr = int(line, 16)
                # Calculate relative address (offset)
                relative_addr = addr - kvm_base
                # Only process addresses that are within the KVM module range
                if relative_addr >= 0:
                    out.write(f'0x{relative_addr:x}\\n')
                    processed_count += 1
            except ValueError:
                continue

print(f'Processed {processed_count} addresses (relative to KVM_BASE)', file=sys.stderr)
"
            else
                # If no KVM_BASE, just copy the raw file
                cp "$raw_coverage" "$current_coverage"
                echo "Saved coverage as absolute addresses"
            fi

            # Check if processed coverage file is not empty
            if [ ! -s "$current_coverage" ]; then
                echo "Processed coverage file is empty at $timestamp"
                continue
            fi

            total_count=$(wc -l < "$current_coverage" 2>/dev/null || echo "0")
            echo "Coverage saved: $total_count addresses at $timestamp"

            # Run hexcov2nested.sh
            output_nested="$OUTPUT_DIR/coverage/out/kvm_arch_$timestamp"
            FINAL_COVERAGE_FILE="$OUTPUT_DIR/coverage/out/final_coverage"
            NESTED_COVERAGE_FILE=$OUTPUT_DIR/coverage/out/final_nested_coverage
            if [ -f "$SCRIPT_DIR/hexcov2nested.sh" ]; then
                echo "Running hexcov2nested.sh..."
                if "$SCRIPT_DIR/hexcov2nested.sh" "$current_coverage" "$output_nested" >/dev/null 2>&1; then
                    nested_lines=$(wc -l < "$output_nested")

                    local my_timestamp
                    my_timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                    # Create CSV file with header if it doesn't exist
                    local csv_file="$OUTPUT_DIR/coverage_timeline.csv"
                    if [[ ! -f "$csv_file" ]]; then
                        echo "timestamp,nested_count" > "$csv_file"
                    fi
                    # Append current data to CSV
                    echo "$my_timestamp,$nested_count" >> "$csv_file"

                    cp $output_nested $FINAL_COVERAGE_FILE
                    grep nested.c $FINAL_COVERAGE_FILE > $NESTED_COVERAGE_FILE
                    echo "Processed coverage: $nested_lines lines saved to nested_$timestamp.txt"
                else
                    echo "Failed to run hexcov2nested.sh"
                fi
            else
                echo "Warning: hexcov2nested.sh not found at $SCRIPT_DIR/hexcov2nested.sh"
            fi
        else
            echo "Failed to fetch coverage at $timestamp (syzkaller may not be ready yet)"
        fi
    done
) &
COVERAGE_PID=$!

echo "Coverage collection started (PID: $COVERAGE_PID)"
echo "Coverage files will be saved to: $OUTPUT_DIR/coverage/"

# Wait a moment for syzkaller to start
sleep 2

echo "Starting syzkaller manager..."
echo "Press Ctrl+C to stop"
echo "Web interface available at: http://127.0.0.1:10021"

# Run syzkaller manager in foreground
sudo ./bin/syz-manager -config=my.cfg