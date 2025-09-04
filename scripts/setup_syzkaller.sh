#!/bin/bash
set -euo pipefail

usage() {
    echo "Usage: $0 [kernel_source_dir]"
    echo "  kernel_source_dir: Optional path to kernel source directory"
    echo "                     If not provided, reads from CONFIG_PATH yaml: directories.linux_source_dir"
    exit 1
}

# Check for help
if [ "$#" -gt 1 ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
fi


# Save original directory
ORIGINAL_DIR="$(pwd)"
CONFIG_PATH="./config.yaml"

check_file() {
    if [ ! -f "$1" ]; then
        echo "Error: File $1 does not exist."
        exit 1
    fi
}
check_file $CONFIG_PATH
# Get Linux directory from config
# Determine kernel directory
if [ "$#" -eq 1 ]; then
    # Use command line argument
    KERNEL_DIR="$1"
    echo "Using kernel directory from command line: $KERNEL_DIR"
else
    KERNEL_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["linux_source_dir"])' < "$CONFIG_PATH" 2>/dev/null || echo "")
    if [ -z "$KERNEL_DIR" ]; then
        echo "Error: Could not read linux_source_dir from config file: $CONFIG_PATH"
        echo "Make sure the config file contains: directories.linux_source_dir"
        exit 1
    fi
fi

$KERNEL_DIR="$(realpath "$KERNEL_DIR")"

SYZKALLER_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["syzkaller_dir"])' < "$CONFIG_PATH" 2>/dev/null || echo "")
cd $SYZKALLER_DIR

# Install Go and build syzkaller (only if needed)
# Check if Go is already available
if ! command -v go &> /dev/null || [[ $(go version | grep -o 'go[0-9.]*' | cut -c3-) < "1.23" ]]; then
    echo "Installing Go 1.23.6..."
    if [ ! -d "go" ]; then
        wget https://dl.google.com/go/go1.23.6.linux-amd64.tar.gz
        tar -xf go1.23.6.linux-amd64.tar.gz
        rm go1.23.6.linux-amd64.tar.gz
    fi
    export GOROOT=`pwd`/go
    export PATH=$GOROOT/bin:$PATH
else
    echo "Go is already installed: $(go version)"
fi

# Check if syzkaller is already built
if [ ! -f "bin/syz-manager" ] || [ ! -f "bin/syz-fuzzer" ]; then
    echo "Building syzkaller..."
    make
else
    echo "Syzkaller already built"
fi

cd "$ORIGINAL_DIR"

KERNEL_DIR="$(realpath "$KERNEL_DIR")"
echo "Using absolute path: $KERNEL_DIR"

echo "Create a Debian Bullseye Linux image with the minimal set of required packages."
IMAGE="$SYZKALLER_DIR/image"
mkdir -p $IMAGE
cd $IMAGE/
IMAGE_FILE=bullseye.img

wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
chmod +x create-image.sh

rm -f $IMAGE_FILE
./create-image.sh

# Check if files exist
if [ ! -f "$IMAGE_FILE" ]; then
    echo "Error: Image file $IMAGE_FILE not found" >&2
    exit 1
fi

if [ ! -d "$KERNEL_DIR" ]; then
    echo "Error: Kernel source directory $KERNEL_DIR not found" >&2
    exit 1
fi

# Cleanup function
cleanup() {
    if [ -n "${LOOP_DEV:-}" ]; then
        echo "Cleaning up..."
        sudo umount /mnt 2>/dev/null || true
        sudo losetup -d "$LOOP_DEV" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "Installing KVM modules to $IMAGE_FILE"
echo "Using kernel source: $KERNEL_DIR"

# Mount the image
LOOP_DEV=$(sudo losetup -f --show "$IMAGE_FILE")
echo "Using loop device: $LOOP_DEV"

sudo mkdir -p /mnt
sudo mount "$LOOP_DEV" /mnt

# Change to kernel directory
cd "$KERNEL_DIR"

# Get kernel version
KERNEL_VERSION=$(make kernelrelease)
echo "Kernel version: $KERNEL_VERSION"

# Create module directories
sudo mkdir -p "/mnt/lib/modules/$KERNEL_VERSION/kernel/arch/x86/kvm"
sudo mkdir -p "/mnt/lib/modules/$KERNEL_VERSION/kernel/virt/kvm"

# Copy KVM modules
echo "Copying KVM modules..."
sudo cp arch/x86/kvm/*.ko "/mnt/lib/modules/$KERNEL_VERSION/kernel/arch/x86/kvm/" 2>/dev/null || true
sudo cp virt/kvm/*.ko "/mnt/lib/modules/$KERNEL_VERSION/kernel/virt/kvm/" 2>/dev/null || true

# Copy required files for depmod
echo "Copying module metadata..."
sudo cp modules.order "/mnt/lib/modules/$KERNEL_VERSION/"
sudo cp modules.builtin "/mnt/lib/modules/$KERNEL_VERSION/"

# Generate module dependencies
echo "Generating module dependencies..."
sudo chroot /mnt depmod "$KERNEL_VERSION"

# Add modules to auto-load configuration
echo "Configuring auto-load..."
if ! sudo grep -q "^kvm$" /mnt/etc/modules; then
    echo "kvm" | sudo tee -a /mnt/etc/modules
fi
if ! sudo grep -q "^kvm_intel$" /mnt/etc/modules; then
    echo "kvm_intel" | sudo tee -a /mnt/etc/modules
fi

# Verify installation
echo "Verifying installation..."
echo "Installed KVM modules:"
sudo find "/mnt/lib/modules/$KERNEL_VERSION" -name "kvm*.ko" -ls

echo "Auto-load configuration:"
sudo grep -E "^kvm" /mnt/etc/modules

# Cleanup will be handled by trap
echo "KVM module installation completed successfully!"
echo "The image is ready to use with KVM modules."

cd "$ORIGINAL_DIR"