#!/bin/bash
set -euo pipefail

usage() {
    echo "Usage: $0 [kernel_source_dir]"
    echo "  kernel_source_dir: Path to kernel source directory (optional)"
    echo "                     If not provided, will read from config file"
    exit 1
}

# Check for help flags (safe way with set -u)
if [ "$#" -gt 0 ] && ([ "$1" = "-h" ] || [ "$1" = "--help" ]); then
    usage
fi

# Source utilities and check config
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
source "$SCRIPT_DIR/utilities.sh"
check_file "$CONFIG_PATH"

ORIGINAL_DIR="$(pwd)"
IMAGE="./external/syzkaller/image"
IMAGE="$(realpath "$IMAGE")"
IMAGE_FILE=$IMAGE/bullseye.img
RSA_KEY=$IMAGE/bullseye.id_rsa

# Handle kernel directory argument
if [ "$#" -eq 0 ]; then
    # No argument provided, read from config
    KERNEL_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["syzkaller_linux_source_dir"])' < "$CONFIG_PATH" 2>/dev/null || echo "")
    if [ -z "$KERNEL_DIR" ]; then
        echo "Error: Could not read kernel directory from config file" >&2
        echo "Please provide kernel directory as argument or check config file" >&2
        exit 1
    fi
    echo "Using kernel directory from config: $KERNEL_DIR"
elif [ "$#" -eq 1 ]; then
    # Argument provided
    KERNEL_DIR="$1"
    echo "Using provided kernel directory: $KERNEL_DIR"
else
    # Too many arguments
    echo "Error: Too many arguments" >&2
    usage
fi

KERNEL_DIR="$(realpath "$KERNEL_DIR")"

SYZKALLER_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["syzkaller_dir"])' < "$CONFIG_PATH" 2>/dev/null || echo "")



# Cleanup function
cleanup() {
    if [ -f vm.pid ]; then
        echo "Shutting down VM..."
        kill $(cat vm.pid) 2>/dev/null || true
        rm -f vm.pid
    fi
}
trap cleanup EXIT

echo "Starting VM to detect KVM module locations..."

# Start QEMU in background
qemu-system-x86_64 \
    -m 2G \
    -smp 2 \
    -cpu host,$qemu_cpu \
    -kernel $KERNEL_DIR/arch/x86/boot/bzImage \
    -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 nokaslr" \
    -drive file=$IMAGE_FILE,format=raw \
    -netdev user,id=net0,hostfwd=tcp::10021-:22 \
    -device e1000e,netdev=net0 \
    -enable-kvm \
    -display none \
    -pidfile vm.pid > /dev/null 2>&1 &

QEMU_PID=$!

echo "Waiting for VM to boot..."
# Give QEMU a moment to start up or fail (2-3 seconds should be sufficient)
sleep 3

# Check if the process started successfully
if [ ! -f vm.pid ] || ! kill -0 $(cat vm.pid) 2>/dev/null; then
    echo "Error: Failed to start QEMU VM" >&2
    exit 1
else
    echo "QEMU VM started with PID $QEMU_PID"
fi

# Wait for SSH to become available
for i in {1..60}; do
    if ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no -p 10021 root@localhost -i $RSA_KEY "echo 'VM ready'" 2>/dev/null; then
        break
    fi
    sleep 2
    if [ $i -eq 60 ]; then
        echo "VM failed to boot within 2 minutes"
        exit 1
    fi
done

echo "Detecting KVM module information..."

# Detect which KVM module is loaded and get its address
KVM_MODULE=$(ssh -o StrictHostKeyChecking=no -p 10021 root@localhost -i $RSA_KEY "lsmod | grep 'kvm_' | awk '{print \$1}' | head -1")
if [ -z "$KVM_MODULE" ]; then
    echo "Error: No KVM module found (kvm_intel or kvm_amd)"
    exit 1
fi

echo "Found KVM module: $KVM_MODULE"

# Get module information
KVM_BASE=$(ssh -o StrictHostKeyChecking=no -p 10021 root@localhost -i $RSA_KEY "cat /sys/module/$KVM_MODULE/sections/.text 2>/dev/null || echo 'unknown'")
KVM_SIZE=$(ssh -o StrictHostKeyChecking=no -p 10021 root@localhost -i $RSA_KEY "grep '^$KVM_MODULE ' /proc/modules | awk '{print \$2}'")

echo "KVM Module Information:"
echo "  Module: $KVM_MODULE"
echo "  Base Address: $KVM_BASE"
echo "  Size: $KVM_SIZE bytes"

# Save to file for later use
cat > $SYZKALLER_DIR/kvm_module_info.txt << EOF
KVM_MODULE=$KVM_MODULE
KVM_BASE=$KVM_BASE
KVM_SIZE=$KVM_SIZE
EOF

echo "Module information saved to kvm_module_info.txt"
echo "VM will be terminated automatically."